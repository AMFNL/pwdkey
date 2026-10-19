/* kdf.h - key derivation & crypto helpers (all mbedtls based) */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

/* PBKDF2-HMAC-SHA256 (PBKDF2), dkLen = 32 */
esp_err_t kdf_pbkdf2(const char *pwd, size_t pwd_len,
                     const uint8_t salt[16], uint32_t iters, uint8_t out_kek[32]);

/* HKDF-SHA256, salt = NULL, L = 32 */
esp_err_t kdf_hkdf32(const uint8_t kek[32], const char *info, uint8_t out[32]);

/* plain HMAC-SHA256 */
esp_err_t kdf_hmac_sha256(const uint8_t *key, size_t key_len,
                          const uint8_t *msg, size_t msg_len, uint8_t out[32]);

/* VERIFIER = HMAC-SHA256(KEK, "PWD_MGR_VERIFIER_V1") */
esp_err_t kdf_verifier(const uint8_t kek[32], uint8_t out_verifier[32]);

/* constant-time compare (never use memcmp for secrets) */
bool ct_mem_equal(const void *a, const void *b, size_t n);

/* stage 0.8 helper: find iteration count whose runtime approximates target_ms.
 * Returns 0 on error. Call from a dedicated task (feeds TWDT internally). */
uint32_t kdf_bench_iterations(uint32_t target_ms);
