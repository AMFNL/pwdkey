/* test_shamir.c - Shamir 3-of-5 的主机侧验证
 *
 * 这块一旦写错，用户的恢复码就永远重建不出密钥。所以要在电脑上先证明：
 *   1. GF(256) 乘法表自洽
 *   2. 任意 3 份组合都能重建
 *   3. 换组合（1/2/3、1/3/5、2/4/5…）结果完全一致
 *   4. 少于 3 份时得不到正确值（信息论保证，这里只做否定验证）
 *   5. 各种 n/k 边界
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "shamir.h"

static int pass = 0, fail = 0;
static void ok(const char *n) { printf("  PASS: %s\n", n); pass++; }
static void bad(const char *n, const char *w) { printf("  FAIL: %s%s%s\n", n, w ? " — " : "", w ? w : ""); fail++; }

#define SECRET_LEN 16   /* recovery_key 是 128 位 */

static void dump(const char *tag, const uint8_t *b, size_t n) {
    printf("  %s ", tag);
    for (size_t i = 0; i < n; i++) printf("%02X", b[i]);
    printf("\n");
}

/* 用指定的索引组合重建，返回是否与原始 secret 一致 */
static int try_combo(const uint8_t *secret, const uint8_t *shares, uint8_t k,
                     const uint8_t *idxs, const char *label) {
    uint8_t out[SECRET_LEN];
    memset(out, 0, sizeof(out));
    esp_err_t e = shamir_combine(idxs, shares, k, SECRET_LEN, out);
    if (e != ESP_OK) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%s 返回错误 %d", label, e);
        bad(label, buf);
        return 0;
    }
    int same = (memcmp(out, secret, SECRET_LEN) == 0);
    if (same) {
        char buf[96];
        snprintf(buf, sizeof(buf), "%s (x=%u,%u,%u)", label, idxs[0], idxs[1], idxs[2]);
        ok(buf);
    } else {
        bad(label, "重建结果与原秘密不一致");
    }
    memset(out, 0, sizeof(out));
    return same;
}

int main(void) {
    srand(20261027);

    printf("== GF(256) 自洽性 ==\n");
    if (shamir_selftest()) ok("乘法/除法表全部自洽（65536 组）");
    else bad("GF 乘法表", "自洽性检查失败");

    uint8_t secret[SECRET_LEN];
    for (int i = 0; i < SECRET_LEN; i++) secret[i] = (uint8_t)(rand() & 0xFF);

    printf("\n== 3-of-5 拆分与重建 ==\n");
    uint8_t shares[5 * SECRET_LEN];
    esp_err_t e = shamir_split(secret, SECRET_LEN, 5, 3, shares);
    if (e != ESP_OK) { printf("  FAIL: split 返回 %d\n", e); return 1; }
    ok("拆分成 5 份");

    /* 5 份里任取 3 份，共 C(5,3)=10 种组合，全部必须能重建 */
    uint8_t combos[10][3] = {
        {1,2,3},{1,2,4},{1,2,5},{1,3,4},{1,3,5},
        {1,4,5},{2,3,4},{2,3,5},{2,4,5},{3,4,5}
    };
    int all_ok = 1;
    for (int i = 0; i < 10; i++) {
        uint8_t sub[3 * SECRET_LEN];
        for (int j = 0; j < 3; j++) {
            memcpy(sub + j * SECRET_LEN, shares + (combos[i][j] - 1) * SECRET_LEN, SECRET_LEN);
        }
        uint8_t out[SECRET_LEN];
        if (shamir_combine(combos[i], sub, 3, SECRET_LEN, out) != ESP_OK
            || memcmp(out, secret, SECRET_LEN) != 0) {
            char buf[64];
            snprintf(buf, sizeof(buf), "组合 %u/%u/%u 重建失败",
                     combos[i][0], combos[i][1], combos[i][2]);
            bad("任意 3 份组合", buf);
            all_ok = 0;
        }
        memset(out, 0, sizeof(out));
        memset(sub, 0, sizeof(sub));
    }
    if (all_ok) ok("全部 10 种 3 份组合都能正确重建");

    printf("\n== 少于阈值是否泄露 ==\n");
    /* 用 2 份强行重建（数学上会得到某个值，但不应等于秘密） */
    {
        uint8_t idxs[2] = {1, 4};
        uint8_t sub[2 * SECRET_LEN];
        memcpy(sub, shares, SECRET_LEN);
        memcpy(sub + SECRET_LEN, shares + 3 * SECRET_LEN, SECRET_LEN);
        uint8_t out[SECRET_LEN];
        if (shamir_combine(idxs, sub, 2, SECRET_LEN, out) == ESP_OK
            && memcmp(out, secret, SECRET_LEN) == 0) {
            bad("2 份不应还原秘密", "竟然重建成功了，实现有严重问题");
        } else {
            ok("2 份重建出的值与秘密不同（信息论安全的表现）");
        }
        memset(out, 0, sizeof(out));
    }

    printf("\n== 边界条件 ==\n");
    /* 5-of-5：缺一份就重建不出 */
    {
        uint8_t s5[5 * SECRET_LEN];
        if (shamir_split(secret, SECRET_LEN, 5, 5, s5) == ESP_OK) {
            uint8_t idxs[5] = {1,2,3,4,5};
            uint8_t out[SECRET_LEN];
            if (shamir_combine(idxs, s5, 5, SECRET_LEN, out) == ESP_OK
                && memcmp(out, secret, SECRET_LEN) == 0) {
                ok("5-of-5 全齐时正确重建");
            } else {
                bad("5-of-5 重建", NULL);
            }
        } else { bad("5-of-5 拆分", NULL); }
    }

    /* 1-of-1 */
    {
        uint8_t s1[SECRET_LEN];
        if (shamir_split(secret, SECRET_LEN, 1, 1, s1) == ESP_OK
            && memcmp(s1, secret, SECRET_LEN) == 0) {
            ok("1-of-1 退化为直接复制");
        } else {
            bad("1-of-1", NULL);
        }
    }

    /* 非法输入 */
    {
        uint8_t s[8 * SECRET_LEN];
        if (shamir_split(secret, SECRET_LEN, 3, 4, s) != ESP_OK) ok("拒绝 k > n");
        else bad("k > n 应被拒", NULL);

        uint8_t dup[3] = {2, 2, 3};
        uint8_t sub[3 * SECRET_LEN];
        memset(sub, 0, sizeof(sub));
        if (shamir_combine(dup, sub, 3, SECRET_LEN, sub) != ESP_OK) ok("拒绝重复的 x 坐标");
        else bad("重复 x 应被拒", NULL);

        uint8_t zero[3] = {0, 1, 2};
        if (shamir_combine(zero, sub, 3, SECRET_LEN, sub) != ESP_OK) ok("拒绝 x=0");
        else bad("x=0 应被拒", NULL);
    }

    printf("\n== 同一秘密两次拆分应产生不同份额 ==\n");
    {
        uint8_t a[5 * SECRET_LEN], b[5 * SECRET_LEN];
        shamir_split(secret, SECRET_LEN, 5, 3, a);
        shamir_split(secret, SECRET_LEN, 5, 3, b);
        if (memcmp(a, b, sizeof(a)) != 0) ok("随机化生效（同一秘密两次份额不同）");
        else bad("两次拆分完全相同", "随机数可能有问题");
    }

    printf("\n");
    printf(fail == 0 ? "ALL SHAMIR TESTS PASSED (%d)\n" : "%d FAILED, %d passed\n",
           fail == 0 ? pass : fail, fail == 0 ? 0 : pass);
    return fail == 0 ? 0 : 1;
}
