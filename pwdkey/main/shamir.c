/* shamir.c - GF(256) 上的 Shamir 秘密分享
 *
 * 域选取：GF(2^8)，既约多项式 x^8 + x^4 + x^3 + x^2 + 1 (0x11D)，
 * 与 AES 用的是同一个域，实现简单且经过充分检验。
 *
 * 核心原理：对每个字节独立构造一个 k-1 次多项式
 *     f(x) = s + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
 * 其中 s 是秘密字节，a1..a(k-1) 随机，f(0) 就是秘密。
 * 把 (1, f(1)), (2, f(2)), ..., (n, f(n)) 分给 n 个人，
 * 任意 k 个点用拉格朗日插值在 x=0 处求值即可还原。
 *
 * 安全性：少于 k 个点时有 k - (点数) 个自由度，秘密在 [0,255] 上均匀分布，
 * 这是**信息论安全**，不依赖计算困难假设。
 */
#include "shamir.h"

#include <string.h>
#include <stdbool.h>

#include "esp_random.h"
#include "esp_log.h"

static const char *TAG = "shamir";

#define GF_POLY   0x11D
#define GF_ORDER  255

static uint8_t  s_exp[512];
static uint8_t  s_log[256];
static bool     s_ready;

static void gf_init(void)
{
    if (s_ready) {
        return;
    }
    uint16_t x = 1;
    for (int i = 0; i < GF_ORDER; i++) {
        s_exp[i] = (uint8_t)x;
        s_log[x] = (uint8_t)i;
        x <<= 1;
        if (x & 0x100) {
            x ^= GF_POLY;
        }
    }
    for (int i = GF_ORDER; i < 512; i++) {
        s_exp[i] = s_exp[i - GF_ORDER];
    }
    s_log[0] = 0;                 /* 未定义，调用方保证不取 log(0) */
    s_ready = true;
}

static inline uint8_t gf_mul(uint8_t a, uint8_t b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    return s_exp[s_log[a] + s_log[b]];
}

static inline uint8_t gf_div(uint8_t a, uint8_t b)
{
    if (a == 0) {
        return 0;
    }
    if (b == 0) {
        return 0;                 /* 调用方保证 b != 0 */
    }
    int d = (int)s_log[a] - (int)s_log[b];
    if (d < 0) {
        d += GF_ORDER;
    }
    return s_exp[d];
}

esp_err_t shamir_split(const uint8_t *secret, size_t len, uint8_t n, uint8_t k, uint8_t *shares)
{
    if (!secret || !shares || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (n < 1 || n > SHAMIR_MAX_SHARES || k < 1 || k > n || k > SHAMIR_MAX_K) {
        return ESP_ERR_INVALID_ARG;
    }
    gf_init();

    uint8_t coeffs[SHAMIR_MAX_K];
    for (size_t i = 0; i < len; i++) {
        coeffs[0] = secret[i];
        for (uint8_t j = 1; j < k; j++) {
            coeffs[j] = (uint8_t)(esp_random() & 0xFF);
        }
        /* 对 x = 1..n 求值（x 从 1 开始，因为 f(0) 本身就是秘密） */
        for (uint8_t s = 1; s <= n; s++) {
            uint8_t y = 0;
            for (int j = (int)k - 1; j >= 0; j--) {
                y = (uint8_t)(gf_mul(y, s) ^ coeffs[j]);
            }
            shares[(size_t)(s - 1) * len + i] = y;
        }
    }
    memset(coeffs, 0, sizeof(coeffs));
    return ESP_OK;
}

esp_err_t shamir_combine(const uint8_t *xs, const uint8_t *shares, uint8_t k, size_t len, uint8_t *out)
{
    if (!xs || !shares || !out || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (k < 1 || k > SHAMIR_MAX_K) {
        return ESP_ERR_INVALID_ARG;
    }
    /* x 必须互不相同且在 1..n 内，否则插值无解 */
    for (uint8_t a = 0; a < k; a++) {
        if (xs[a] == 0 || xs[a] > SHAMIR_MAX_SHARES) {
            return ESP_ERR_INVALID_ARG;
        }
        for (uint8_t b = a + 1; b < k; b++) {
            if (xs[a] == xs[b]) {
                return ESP_ERR_INVALID_ARG;
            }
        }
    }
    gf_init();

    for (size_t i = 0; i < len; i++) {
        uint8_t acc = 0;
        for (uint8_t a = 0; a < k; a++) {
            /* 拉格朗日基多项式在 x=0 处的值：
             *   L_a(0) = Π_{b≠a} (0 - x_b) / (x_a - x_b)
             * 在 GF(2^8) 里减法就是 XOR，0 - x = x。 */
            uint8_t num = 1;
            uint8_t den = 1;
            for (uint8_t b = 0; b < k; b++) {
                if (a == b) {
                    continue;
                }
                num = gf_mul(num, xs[b]);
                den = gf_mul(den, (uint8_t)(xs[a] ^ xs[b]));
            }
            uint8_t la = gf_div(num, den);
            acc ^= gf_mul(shares[(size_t)a * len + i], la);
        }
        out[i] = acc;
    }
    return ESP_OK;
}

bool shamir_selftest(void)
{
    gf_init();
    /* 逐对验证 (a*b)/b == a，覆盖乘法表全部非零组合 */
    for (int a = 1; a < 256; a++) {
        for (int b = 1; b < 256; b++) {
            uint8_t p = gf_mul((uint8_t)a, (uint8_t)b);
            if (gf_div(p, (uint8_t)b) != (uint8_t)a) {
                ESP_LOGE(TAG, "GF mul/div mismatch a=%d b=%d", a, b);
                return false;
            }
        }
    }
    return true;
}
