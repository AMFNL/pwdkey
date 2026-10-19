/* kdf.c - PBKDF2 / HKDF / HMAC / constant-time compare / benchmark */
#include "kdf.h"

#include <string.h>
#include <inttypes.h>

#include "esp_timer.h"
#include "esp_task_wdt.h"
#include "esp_log.h"

#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/hkdf.h"

static const char *TAG = "kdf";

#define KDF_INFO_VERIFIER   "PWD_MGR_VERIFIER_V1"

esp_err_t kdf_pbkdf2(const char *pwd, size_t pwd_len,
                     const uint8_t salt[16], uint32_t iters, uint8_t out_kek[32])
{
    int rc = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
             (const unsigned char *)pwd, pwd_len,
             salt, 16, (unsigned int)iters, 32, out_kek);
    return rc == 0 ? ESP_OK : ESP_FAIL;
}

esp_err_t kdf_hkdf32(const uint8_t kek[32], const char *info, uint8_t out[32])
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL) {
        return ESP_FAIL;
    }
    int rc = mbedtls_hkdf(md, NULL, 0,               /* salt = NULL (RFC 5869 allows) */
                          kek, 32,
                          (const unsigned char *)info, strlen(info),
                          out, 32);
    return rc == 0 ? ESP_OK : ESP_FAIL;
}

esp_err_t kdf_hmac_sha256(const uint8_t *key, size_t key_len,
                          const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL) {
        return ESP_FAIL;
    }
    int rc = mbedtls_md_hmac(md, key, key_len, msg, msg_len, out);
    return rc == 0 ? ESP_OK : ESP_FAIL;
}

esp_err_t kdf_verifier(const uint8_t kek[32], uint8_t out_verifier[32])
{
    return kdf_hmac_sha256(kek, 32,
                           (const uint8_t *)KDF_INFO_VERIFIER,
                           strlen(KDF_INFO_VERIFIER), out_verifier);
}

bool ct_mem_equal(const void *a, const void *b, size_t n)
{
    const uint8_t *x = a, *y = b;
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) {
        d |= (uint8_t)(x[i] ^ y[i]);
    }
    return d == 0;
}

/* ---------------------------------------------------------------- */
/* Stage-0.8 benchmark: proportional extrapolation, WDT-safe.        */
/* Every individual PBKDF2 run stays near the target duration,       */
/* so a single call never risks tripping the 5s task watchdog.       */
/* ---------------------------------------------------------------- */
uint32_t kdf_bench_iterations(uint32_t target_ms)
{
    if (target_ms < 100) {
        target_ms = 100;
    }

    bool wdt_ok = (esp_task_wdt_add(NULL) == ESP_OK);
    uint8_t salt[16] = {0};
    uint8_t out[32];
    uint32_t iter = 10000;

    for (int round = 0; round < 5; round++) {
        if (wdt_ok) {
            esp_task_wdt_reset();
        }
        int64_t t0 = esp_timer_get_time();
        if (kdf_pbkdf2("benchmark-password", 18, salt, iter, out) != ESP_OK) {
            iter = 0;
            break;
        }
        int64_t dt = (esp_timer_get_time() - t0) / 1000;
        if (dt < 1) {
            dt = 1;
        }
        ESP_LOGI(TAG, "bench: iter=%"PRIu32" dt=%lldms", iter, (long long)dt);

        /* within +-10% of target -> good enough */
        if (dt >= (int64_t)target_ms * 90 / 100 && dt <= (int64_t)target_ms * 110 / 100) {
            break;
        }
        uint64_t next = (uint64_t)iter * (uint64_t)target_ms / (uint64_t)dt;
        if (next < 1000) {
            next = 1000;
        }
        if (next > 4000000ULL) {
            next = 4000000ULL;
        }
        if (next == iter) {
            break;
        }
        iter = (uint32_t)next;
    }

    if (wdt_ok) {
        esp_task_wdt_delete(NULL);
    }
    return iter;
}
