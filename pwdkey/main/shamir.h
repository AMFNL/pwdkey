/* shamir.h - GF(256) 上的 Shamir 秘密分享（k-of-n）
 *
 * 为什么用它：恢复码要"任意 3 份能重建，缺 1-2 份不丢数据"。
 * 直接存 5 份相同密钥等于 5 倍泄露风险；Shamir 保证少于 k 份时**信息论意义上
 * 得不到任何信息**（不是计算困难，是数学上不可能）。
 *
 * 本实现分享的是 128 位 recovery_key，每份 16 字节 → Base32 后 26 字符，
 * 去掉易混字符后按 24+校验 呈现给用户。
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#define SHAMIR_MAX_SHARES  8      /* 最多 8 份 */
#define SHAMIR_MAX_K       8      /* 至少 k 份才能重建 */

/**
 * 把 secret 拆成 n 份，任意 k 份可重建。
 *
 * @param secret  len 字节的秘密
 * @param len     秘密长度（字节）
 * @param n       总份数（1..SHAMIR_MAX_SHARES）
 * @param k       阈值（1..n）
 * @param shares  输出缓冲，n*len 字节，第 i 份从 shares + i*len 开始
 * @return ESP_OK / ESP_ERR_INVALID_ARG
 */
esp_err_t shamir_split(const uint8_t *secret, size_t len, uint8_t n, uint8_t k, uint8_t *shares);

/**
 * 用 k 份重建秘密。
 *
 * @param xs      每份的 x 坐标（1..n，**不能重复**）
 * @param shares  k*len 字节，第 i 份从 shares + i*len 开始
 * @param k       份数
 * @param len     秘密长度
 * @param out     输出 len 字节
 * @return ESP_OK / ESP_ERR_INVALID_ARG（x 重复或越界）
 */
esp_err_t shamir_combine(const uint8_t *xs, const uint8_t *shares, uint8_t k, size_t len, uint8_t *out);

/* 仅供测试：验证 GF(256) 乘法表自洽（a*b/b == a） */
bool shamir_selftest(void);
