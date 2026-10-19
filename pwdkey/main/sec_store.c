/* sec_store.c - NVS + application-layer AES-256-GCM secure storage.
 *
 * Record layout (spec v1.2 section 6.6, revision 4):
 *   off 0   4  magic 'P','W','D','1'
 *   off 4   1  version = 1
 *   off 5   1  L (password length 0..128)
 *   off 6   1  M (name length 0..64)
 *   off 7   12 nonce (fresh random on every write)
 *   off 19  L+M ciphertext (AES-256-GCM, key = K_enc)
 *   19+L+M  16 GCM tag
 *   35+L+M  4 created (seconds)
 *   39+L+M  4 updated (seconds)
 *   43+L+M  4 use_count
 *   47+L+M  4 last_used (seconds)
 *   AAD = magic(4) || version(1) || entry_id(8)
 */
#include "sec_store.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include "mbedtls/gcm.h"

#include "app_cfg.h"
#include "kdf.h"

static const char *TAG = "sec_store";

#define NS_SYS      "sys"
#define NS_CRED     "cred"
#define NS_IDX      "idx"
#define NS_PWD      "pwd"
#define NS_PWDNEW   "pwdnew"

#define KEY_VER     "ver"
#define KEY_REKEY   "rekey_state"
#define KEY_DEVNAME "dev_name"
#define KEY_SALT    "salt"
#define KEY_ITER    "iter"
#define KEY_VERIF   "verifier"
#define KEY_REC     "rec_hint"
#define KEY_COUNT   "count"
#define KEY_IDS     "ids"

#define REC_HDR     19
#define REC_MAX     (51 + CFG_SECRET_MAX + CFG_NAME_MAX)   /* 243 bytes */

/* info strings (must match spec exactly) */
#define HKDF_INFO_KENC  "PWDKEY-ENTRY-ENC-V1"
#define HKDF_INFO_KREC  "PWDKEY-RECOVERY-V1"
#define HMAC_INFO_RECH  "PWD_MGR_RECOVERY_V1"

/* base32 alphabet without 0/O/1/I */
static const char B32[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

static SemaphoreHandle_t s_mtx;
static nvs_handle_t s_h_sys, s_h_cred, s_h_idx, s_h_pwd, s_h_pwdnew;
/* nvs_handle_t is an integer, not a pointer - track readiness explicitly
 * instead of comparing it against NULL (old compilers warned / some -Werror
 * configurations reject it). */
static bool s_open;

static uint32_t now_s(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000000);
}

/* ---------------- AES-256-GCM wrappers (spec 6.5) ---------------- */

static esp_err_t aes_gcm_encrypt(const uint8_t k_enc[32], const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *pt, size_t pt_len,
                                 uint8_t *ct, uint8_t tag[16])
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, k_enc, 256);
    if (rc == 0) {
        rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, pt_len,
                                       nonce, 12, aad, aad_len, pt, ct, 16, tag);
    }
    mbedtls_gcm_free(&ctx);
    return rc == 0 ? ESP_OK : ESP_FAIL;
}

static esp_err_t aes_gcm_decrypt(const uint8_t k_enc[32], const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *ct, size_t ct_len,
                                 const uint8_t tag[16], uint8_t *pt)
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, k_enc, 256);
    if (rc == 0) {
        rc = mbedtls_gcm_auth_decrypt(&ctx, ct_len, nonce, 12, aad, aad_len,
                                      tag, 16, ct, pt);
    }
    mbedtls_gcm_free(&ctx);
    return rc == 0 ? ESP_OK : ESP_ERR_INVALID_CRC;
}

/* ---------------- helpers ---------------- */

static void make_pwd_key(const uint8_t id[8], char out[10])
{
    out[0] = 'p';
    memcpy(out + 1, id, 8);
    out[9] = '\0';
}

static void gen_entry_id(uint8_t id[8])
{
    uint8_t rnd[5];
    esp_fill_random(rnd, sizeof(rnd));
    uint64_t v = 0;
    for (int i = 0; i < 5; i++) {
        v = (v << 8) | rnd[i];
    }
    for (int i = 7; i >= 0; i--) {
        id[i] = (uint8_t)B32[v & 0x1F];
        v >>= 5;
    }
}

static esp_err_t derive_kenc(const uint8_t kek[32], uint8_t k_enc[32])
{
    return kdf_hkdf32(kek, HKDF_INFO_KENC, k_enc);
}

/* Pack a full record into rec[]. Returns record length, or 0 on error. */
static uint16_t rec_pack(uint8_t *rec, const uint8_t id[8],
                         const char *pwd, uint8_t L, const char *name, uint8_t M,
                         const uint8_t k_enc[32],
                         uint32_t created, uint32_t updated,
                         uint32_t use_count, uint32_t last_used)
{
    uint8_t pt[CFG_SECRET_MAX + CFG_NAME_MAX];
    uint8_t nonce[12];
    uint8_t aad[13];

    if (L > CFG_SECRET_MAX || M > CFG_NAME_MAX) {
        return 0;
    }
    memcpy(pt, pwd, L);
    memcpy(pt + L, name, M);

    esp_fill_random(nonce, 12);

    memcpy(rec, "PWD1", 4);
    rec[4] = 1;
    rec[5] = L;
    rec[6] = M;
    memcpy(rec + 7, nonce, 12);

    memcpy(aad, "PWD1", 4);
    aad[4] = 1;
    memcpy(aad + 5, id, 8);

    uint8_t *ct = rec + REC_HDR;
    uint8_t *tag = ct + L + M;
    if (aes_gcm_encrypt(k_enc, nonce, aad, sizeof(aad), pt, (size_t)L + M, ct, tag) != ESP_OK) {
        memset(pt, 0, sizeof(pt));
        return 0;
    }
    memset(pt, 0, sizeof(pt));

    uint16_t off = (uint16_t)(REC_HDR + L + M + 16);
    memcpy(rec + off, &created, 4);
    memcpy(rec + off + 4, &updated, 4);
    memcpy(rec + off + 8, &use_count, 4);
    memcpy(rec + off + 12, &last_used, 4);
    return (uint16_t)(off + 16);
}

/* Unpack + decrypt. Returns ESP_OK and fills lengths on success. */
static esp_err_t rec_unpack(const uint8_t *rec, uint16_t rec_len, const uint8_t id[8],
                            const uint8_t k_enc[32],
                            char *out_pwd, uint8_t *pwd_len,
                            char *out_name, uint8_t *name_len)
{
    if (rec_len < REC_HDR + 16 + 16) {
        return ESP_ERR_INVALID_SIZE;
    }
    if (memcmp(rec, "PWD1", 4) != 0 || rec[4] != 1) {
        return ESP_ERR_INVALID_VERSION;
    }
    uint8_t L = rec[5];
    uint8_t M = rec[6];
    if ((uint32_t)REC_HDR + L + M + 32 > rec_len) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t aad[13];
    memcpy(aad, "PWD1", 4);
    aad[4] = 1;
    memcpy(aad + 5, id, 8);

    uint8_t pt[CFG_SECRET_MAX + CFG_NAME_MAX];
    const uint8_t *ct = rec + REC_HDR;
    const uint8_t *tag = ct + L + M;
    esp_err_t err = aes_gcm_decrypt(k_enc, rec + 7, aad, sizeof(aad), ct, (size_t)L + M, tag, pt);
    if (err != ESP_OK) {
        memset(pt, 0, sizeof(pt));
        return err;     /* tag mismatch -> whole record fails (never partial plaintext) */
    }

    if (out_pwd != NULL && pwd_len != NULL) {
        if (*pwd_len < L) {
            err = ESP_ERR_INVALID_SIZE;     /* caller buffer too small */
        } else {
            memcpy(out_pwd, pt, L);
            *pwd_len = L;
        }
    }
    if (err == ESP_OK && out_name != NULL && name_len != NULL) {
        if (*name_len < M) {
            err = ESP_ERR_INVALID_SIZE;
        } else {
            memcpy(out_name, pt + L, M);
            *name_len = M;
        }
    }
    memset(pt, 0, sizeof(pt));
    return err;
}

/* ---------------- index helpers (caller holds mutex) ---------------- */

static esp_err_t idx_load(uint8_t (*ids)[8], uint16_t *count)
{
    size_t sz = 0;
    *count = 0;
    esp_err_t err = nvs_get_blob(s_h_idx, KEY_IDS, NULL, &sz);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK;
    }
    if (err != ESP_OK) {
        return err;
    }
    if (sz > sizeof(uint8_t) * 8 * CFG_ENTRY_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }
    err = nvs_get_blob(s_h_idx, KEY_IDS, ids, &sz);
    if (err != ESP_OK) {
        return err;
    }
    *count = (uint16_t)(sz / 8);
    return ESP_OK;
}

static esp_err_t idx_save(const uint8_t (*ids)[8], uint16_t count)
{
    return nvs_set_blob(s_h_idx, KEY_IDS, ids, (size_t)count * 8);
}

static int idx_find(const uint8_t (*ids)[8], uint16_t count, const uint8_t id[8])
{
    for (uint16_t i = 0; i < count; i++) {
        if (memcmp(ids[i], id, 8) == 0) {
            return i;
        }
    }
    return -1;
}

/* ---------------- init ---------------- */

esp_err_t sec_store_init(void)
{
    s_mtx = xSemaphoreCreateMutex();
    if (s_mtx == NULL) {
        return ESP_ERR_NO_MEM;
    }
    esp_err_t err;
    err = nvs_open(NS_SYS, NVS_READWRITE, &s_h_sys);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_open(NS_CRED, NVS_READWRITE, &s_h_cred);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_open(NS_IDX, NVS_READWRITE, &s_h_idx);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_open(NS_PWD, NVS_READWRITE, &s_h_pwd);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_open(NS_PWDNEW, NVS_READWRITE, &s_h_pwdnew);
    if (err != ESP_OK) {
        return err;
    }

    /* data structure version */
    uint8_t ver = 0;
    if (nvs_get_u8(s_h_sys, KEY_VER, &ver) != ESP_OK) {
        nvs_set_u8(s_h_sys, KEY_VER, CFG_DATA_VER);
        nvs_commit(s_h_sys);
    }
    s_open = true;
    ESP_LOGI(TAG, "store ready, %u entries", (unsigned)store_entry_count());
    return ESP_OK;
}

/* ---------------- credentials ---------------- */

bool cred_exists(void)
{
    size_t sz = 0;
    return nvs_get_blob(s_h_cred, KEY_VERIF, NULL, &sz) == ESP_OK && sz == 32;
}

esp_err_t cred_get_salt(uint8_t salt[16])
{
    size_t sz = 16;
    return nvs_get_blob(s_h_cred, KEY_SALT, salt, &sz);
}

esp_err_t cred_get_iter(uint32_t *iters)
{
    return nvs_get_u32(s_h_cred, KEY_ITER, iters);
}

esp_err_t cred_get_verifier(uint8_t out[32])
{
    size_t sz = 32;
    return nvs_get_blob(s_h_cred, KEY_VERIF, out, &sz);
}

esp_err_t cred_set_verifier(const uint8_t verifier[32])
{
    esp_err_t err = nvs_set_blob(s_h_cred, KEY_VERIF, verifier, 32);
    if (err == ESP_OK) {
        err = nvs_commit(s_h_cred);
    }
    return err;
}

esp_err_t cred_set_salt(const uint8_t salt[16])
{
    esp_err_t err = nvs_set_blob(s_h_cred, KEY_SALT, salt, 16);
    if (err == ESP_OK) {
        err = nvs_commit(s_h_cred);
    }
    return err;
}

esp_err_t cred_set_iter(uint32_t iters)
{
    esp_err_t err = nvs_set_u32(s_h_cred, KEY_ITER, iters);
    if (err == ESP_OK) {
        err = nvs_commit(s_h_cred);
    }
    return err;
}

esp_err_t cred_check_verifier(const uint8_t verifier[32])
{
    uint8_t stored[32];
    size_t sz = sizeof(stored);
    esp_err_t err = nvs_get_blob(s_h_cred, KEY_VERIF, stored, &sz);
    if (err != ESP_OK || sz != 32) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    bool ok = ct_mem_equal(stored, verifier, 32);
    memset(stored, 0, sizeof(stored));
    return ok ? ESP_OK : ESP_ERR_INVALID_CRC;
}

esp_err_t cred_gen_salt(uint8_t out_salt[16])
{
    esp_fill_random(out_salt, 16);
    return cred_set_salt(out_salt);
}

esp_err_t cred_set_rec_hint(const uint8_t hint[32])
{
    esp_err_t err = nvs_set_blob(s_h_cred, KEY_REC, hint, 32);
    if (err == ESP_OK) {
        err = nvs_commit(s_h_cred);
    }
    return err;
}

esp_err_t cred_check_rec_hint(const uint8_t hint[32])
{
    uint8_t stored[32];
    size_t sz = sizeof(stored);
    esp_err_t err = nvs_get_blob(s_h_cred, KEY_REC, stored, &sz);
    if (err != ESP_OK || sz != 32) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    bool ok = ct_mem_equal(stored, hint, 32);
    memset(stored, 0, sizeof(stored));
    return ok ? ESP_OK : ESP_ERR_INVALID_CRC;
}

esp_err_t sec_store_compute_verifier(const uint8_t kek[32], uint8_t out[32])
{
    return kdf_verifier(kek, out);
}

esp_err_t sec_store_compute_rec_hint(const char *code, size_t code_len,
                                     uint8_t out_hint[32])
{
    /* recovery hint = HMAC-SHA256(recovery_code, "PWD_MGR_RECOVERY_V1")
     * (see header note: verifiable without any KEK) */
    return kdf_hmac_sha256((const uint8_t *)code, code_len,
                           (const uint8_t *)HMAC_INFO_RECH,
                           strlen(HMAC_INFO_RECH), out_hint);
}

/* ---------------- entries ---------------- */

uint16_t store_entry_count(void)
{
    uint16_t cnt = 0;
    if (s_open) {
        nvs_get_u16(s_h_idx, KEY_COUNT, &cnt);
    }
    return cnt;
}

esp_err_t store_list_ids(uint8_t (*out_ids)[8], uint16_t max, uint16_t *out_count)
{
    uint8_t (*ids)[8] = calloc(CFG_ENTRY_MAX, 8);
    if (ids == NULL) {
        return ESP_ERR_NO_MEM;
    }
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    uint16_t count = 0;
    esp_err_t err = idx_load(ids, &count);
    xSemaphoreGive(s_mtx);
    if (err != ESP_OK) {
        free(ids);
        return err;
    }
    uint16_t n = count < max ? count : max;
    memcpy(out_ids, ids, (size_t)n * 8);
    *out_count = n;
    free(ids);
    return ESP_OK;
}

esp_err_t store_add_entry(const uint8_t kek[32],
                          const char *pwd, uint8_t pwd_len,
                          const char *name, uint8_t name_len,
                          uint8_t out_id[8])
{
    return store_add_entry_opt(kek, NULL, pwd, pwd_len, name, name_len, out_id);
}

esp_err_t store_add_entry_opt(const uint8_t kek[32], const uint8_t id_in[8],
                              const char *pwd, uint8_t pwd_len,
                              const char *name, uint8_t name_len,
                              uint8_t out_id[8])
{
    if (pwd == NULL || pwd_len == 0 || pwd_len > CFG_SECRET_MAX ||
        name_len > CFG_NAME_MAX) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t k_enc[32];
    uint8_t rec[REC_MAX];
    uint8_t (*ids)[8] = calloc(CFG_ENTRY_MAX, 8);
    if (ids == NULL) {
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = derive_kenc(kek, k_enc);
    if (err != ESP_OK) {
        free(ids);
        return err;
    }

    xSemaphoreTake(s_mtx, portMAX_DELAY);
    uint16_t count = 0;
    err = idx_load(ids, &count);
    if (err != ESP_OK) {
        goto out;
    }
    if (count >= CFG_ENTRY_MAX) {
        err = ESP_ERR_NO_MEM;       /* full -> 0x2001 by mgmt layer */
        goto out;
    }

    if (id_in != NULL) {
        /* caller-provided id: validate charset + uniqueness */
        memcpy(out_id, id_in, 8);
        for (int i = 0; i < 8; i++) {
            if (strchr(B32, (char)out_id[i]) == NULL) {
                err = ESP_ERR_INVALID_ARG;
                goto out;
            }
        }
        if (idx_find(ids, count, out_id) >= 0) {
            err = ESP_ERR_INVALID_STATE;        /* conflict -> 0x2003 */
            goto out;
        }
    } else {
        /* generate a non-conflicting id */
        for (int tries = 0; tries < 10; tries++) {
            gen_entry_id(out_id);
            if (idx_find(ids, count, out_id) < 0) {
                break;
            }
        }
        if (idx_find(ids, count, out_id) >= 0) {
            err = ESP_ERR_INVALID_STATE;
            goto out;
        }
    }

    uint32_t t = now_s();
    uint16_t rlen = rec_pack(rec, out_id, pwd, pwd_len, name ? name : "", name_len,
                             k_enc, t, t, 0, 0);
    if (rlen == 0) {
        err = ESP_FAIL;
        goto out;
    }

    char key[10];
    make_pwd_key(out_id, key);
    err = nvs_set_blob(s_h_pwd, key, rec, rlen);
    if (err != ESP_OK) {
        goto out;
    }
    memcpy(ids[count], out_id, 8);
    count++;
    err = idx_save(ids, count);
    if (err == ESP_OK) {
        err = nvs_set_u16(s_h_idx, KEY_COUNT, count);
    }
    if (err == ESP_OK) {
        nvs_commit(s_h_pwd);
        nvs_commit(s_h_idx);
    }
out:
    xSemaphoreGive(s_mtx);
    memset(k_enc, 0, sizeof(k_enc));
    memset(rec, 0, sizeof(rec));
    free(ids);
    return err;
}

esp_err_t store_update_entry(const uint8_t kek[32], const uint8_t id[8],
                             const char *pwd, uint8_t pwd_len,
                             const char *name, uint8_t name_len)
{
    if ((pwd == NULL) && (name == NULL)) {
        return ESP_ERR_INVALID_ARG;
    }
    if ((pwd != NULL && (pwd_len == 0 || pwd_len > CFG_SECRET_MAX)) ||
        (name != NULL && name_len > CFG_NAME_MAX)) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t k_enc[32];
    uint8_t rec[REC_MAX];
    char key[10];
    make_pwd_key(id, key);

    esp_err_t err = derive_kenc(kek, k_enc);
    if (err != ESP_OK) {
        return err;
    }

    xSemaphoreTake(s_mtx, portMAX_DELAY);
    size_t rlen = sizeof(rec);
    err = nvs_get_blob(s_h_pwd, key, rec, &rlen);
    if (err != ESP_OK) {
        goto out;
    }

    /* decrypt existing to merge fields */
    char old_pwd[CFG_SECRET_MAX];
    char old_name[CFG_NAME_MAX];
    uint8_t old_L = CFG_SECRET_MAX, old_M = CFG_NAME_MAX;
    err = rec_unpack(rec, (uint16_t)rlen, id, k_enc,
                     old_pwd, &old_L, old_name, &old_M);
    if (err != ESP_OK) {
        goto out;
    }

    uint32_t created, use_count, last_used;
    uint16_t foot = (uint16_t)(REC_HDR + old_L + old_M + 16);
    memcpy(&created, rec + foot, 4);
    memcpy(&use_count, rec + foot + 8, 4);
    memcpy(&last_used, rec + foot + 12, 4);

    const char *np = (pwd != NULL) ? pwd : old_pwd;
    uint8_t nL = (pwd != NULL) ? pwd_len : old_L;
    const char *nn = (name != NULL) ? name : old_name;
    uint8_t nM = (name != NULL) ? name_len : old_M;

    uint16_t nrlen = rec_pack(rec, id, np, nL, nn, nM, k_enc,
                              created, now_s(), use_count, last_used);
    if (nrlen == 0) {
        err = ESP_FAIL;
        goto out;
    }
    err = nvs_set_blob(s_h_pwd, key, rec, nrlen);
    if (err == ESP_OK) {
        nvs_commit(s_h_pwd);
    }
out:
    xSemaphoreGive(s_mtx);
    memset(k_enc, 0, sizeof(k_enc));
    memset(rec, 0, sizeof(rec));
    memset(old_pwd, 0, sizeof(old_pwd));
    memset(old_name, 0, sizeof(old_name));
    return err;
}

esp_err_t store_delete_entry(const uint8_t id[8])
{
    uint8_t (*ids)[8] = calloc(CFG_ENTRY_MAX, 8);
    if (ids == NULL) {
        return ESP_ERR_NO_MEM;
    }
    char key[10];
    make_pwd_key(id, key);

    xSemaphoreTake(s_mtx, portMAX_DELAY);
    uint16_t count = 0;
    esp_err_t err = idx_load(ids, &count);
    if (err != ESP_OK) {
        goto out;
    }
    int pos = idx_find(ids, count, id);
    if (pos < 0) {
        err = ESP_ERR_NOT_FOUND;
        goto out;
    }
    err = nvs_erase_key(s_h_pwd, key);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        err = ESP_OK;   /* already gone */
    }
    if (err != ESP_OK) {
        goto out;
    }
    if (pos < count - 1) {
        memmove(ids[pos], ids[pos + 1], (size_t)(count - 1 - pos) * 8);
    }
    count--;
    err = idx_save(ids, count);
    if (err == ESP_OK) {
        err = nvs_set_u16(s_h_idx, KEY_COUNT, count);
    }
    if (err == ESP_OK) {
        nvs_commit(s_h_pwd);
        nvs_commit(s_h_idx);
    }
out:
    xSemaphoreGive(s_mtx);
    free(ids);
    return err;
}

esp_err_t store_read_entry(const uint8_t kek[32], const uint8_t id[8],
                           char *out_pwd, uint8_t *inout_pwd_cap,
                           char *out_name, uint8_t *inout_name_cap)
{
    uint8_t k_enc[32];
    uint8_t rec[REC_MAX];
    char key[10];
    make_pwd_key(id, key);

    esp_err_t err = derive_kenc(kek, k_enc);
    if (err != ESP_OK) {
        return err;
    }

    xSemaphoreTake(s_mtx, portMAX_DELAY);
    size_t rlen = sizeof(rec);
    err = nvs_get_blob(s_h_pwd, key, rec, &rlen);
    xSemaphoreGive(s_mtx);
    if (err != ESP_OK) {
        memset(k_enc, 0, sizeof(k_enc));
        return err;
    }

    err = rec_unpack(rec, (uint16_t)rlen, id, k_enc,
                     out_pwd, inout_pwd_cap, out_name, inout_name_cap);
    memset(k_enc, 0, sizeof(k_enc));
    memset(rec, 0, sizeof(rec));
    return err;
}

/* ---------------- rekey transaction ---------------- */

esp_err_t store_rekey_begin(void)
{
    esp_err_t err;
    if (store_entry_count() > CFG_ENTRY_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }
    err = nvs_set_u8(s_h_sys, KEY_REKEY, 1);
    if (err == ESP_OK) {
        err = nvs_commit(s_h_sys);
    }
    return err;
}

esp_err_t store_rekey_apply(const uint8_t kek_old[32], const uint8_t kek_new[32],
                            const uint8_t new_salt[16], uint32_t new_iter,
                            const uint8_t new_verifier[32], const uint8_t new_rec_hint[32])
{
    uint8_t (*ids)[8] = calloc(CFG_ENTRY_MAX, 8);
    if (ids == NULL) {
        return ESP_ERR_NO_MEM;
    }
    uint8_t ko[32], kn[32];
    uint8_t rec[REC_MAX], rec2[REC_MAX];
    esp_err_t err = ESP_OK;

    err = derive_kenc(kek_old, ko);
    if (err == ESP_OK) {
        err = derive_kenc(kek_new, kn);
    }
    if (err != ESP_OK) {
        goto cleanup_keys;
    }

    xSemaphoreTake(s_mtx, portMAX_DELAY);
    uint16_t count = 0;
    err = idx_load(ids, &count);
    if (err != ESP_OK) {
        goto out;
    }

    /* phase 1: decrypt with old KEK, re-encrypt with new KEK into pwdnew */
    for (uint16_t i = 0; i < count; i++) {
        char key[10];
        make_pwd_key(ids[i], key);
        size_t rlen = sizeof(rec);
        err = nvs_get_blob(s_h_pwd, key, rec, &rlen);
        if (err != ESP_OK) {
            break;
        }
        char pwd[CFG_SECRET_MAX], nm[CFG_NAME_MAX];
        uint8_t L = CFG_SECRET_MAX, M = CFG_NAME_MAX;
        err = rec_unpack(rec, (uint16_t)rlen, ids[i], ko, pwd, &L, nm, &M);
        if (err != ESP_OK) {
            memset(pwd, 0, sizeof(pwd));
            memset(nm, 0, sizeof(nm));
            break;
        }
        uint32_t created, use_count, last_used;
        uint16_t foot = (uint16_t)(REC_HDR + L + M + 16);
        memcpy(&created, rec + foot, 4);
        memcpy(&use_count, rec + foot + 8, 4);
        memcpy(&last_used, rec + foot + 12, 4);

        uint16_t nrlen = rec_pack(rec2, ids[i], pwd, L, nm, M, kn,
                                  created, now_s(), use_count, last_used);
        memset(pwd, 0, sizeof(pwd));
        memset(nm, 0, sizeof(nm));
        if (nrlen == 0) {
            err = ESP_FAIL;
            break;
        }
        err = nvs_set_blob(s_h_pwdnew, key, rec2, nrlen);
        if (err != ESP_OK) {
            break;
        }
        memset(rec, 0, sizeof(rec));
        memset(rec2, 0, sizeof(rec2));
    }
    if (err == ESP_OK) {
        nvs_commit(s_h_pwdnew);
    } else {
        /* rollback: wipe temp namespace */
        for (uint16_t i = 0; i < count; i++) {
            char key[10];
            make_pwd_key(ids[i], key);
            nvs_erase_key(s_h_pwdnew, key);
        }
        nvs_set_u8(s_h_sys, KEY_REKEY, 0);
        nvs_commit(s_h_sys);
        goto out;
    }

    /* phase 2: commit credentials, mark state=2 */
    err = nvs_set_blob(s_h_cred, KEY_SALT, new_salt, 16);
    if (err == ESP_OK) {
        err = nvs_set_u32(s_h_cred, KEY_ITER, new_iter);
    }
    if (err == ESP_OK) {
        err = nvs_set_blob(s_h_cred, KEY_VERIF, new_verifier, 32);
    }
    if (err == ESP_OK) {
        err = nvs_set_blob(s_h_cred, KEY_REC, new_rec_hint, 32);
    }
    if (err == ESP_OK) {
        err = nvs_commit(s_h_cred);
    }
    if (err == ESP_OK) {
        err = nvs_set_u8(s_h_sys, KEY_REKEY, 2);
    }
    if (err == ESP_OK) {
        err = nvs_commit(s_h_sys);
    }
    if (err != ESP_OK) {
        goto out;
    }

    /* phase 3: move pwdnew -> pwd, then clear state (idempotent) */
    for (uint16_t i = 0; i < count; i++) {
        char key[10];
        make_pwd_key(ids[i], key);
        size_t rlen = sizeof(rec2);
        err = nvs_get_blob(s_h_pwdnew, key, rec2, &rlen);
        if (err != ESP_OK) {
            break;
        }
        err = nvs_set_blob(s_h_pwd, key, rec2, rlen);
        if (err != ESP_OK) {
            break;
        }
        nvs_erase_key(s_h_pwdnew, key);
    }
    if (err == ESP_OK) {
        nvs_commit(s_h_pwd);
        nvs_commit(s_h_pwdnew);
        err = nvs_set_u8(s_h_sys, KEY_REKEY, 0);
        if (err == ESP_OK) {
            err = nvs_commit(s_h_sys);
        }
    }
out:
    xSemaphoreGive(s_mtx);
cleanup_keys:
    memset(ko, 0, sizeof(ko));
    memset(kn, 0, sizeof(kn));
    memset(rec, 0, sizeof(rec));
    memset(rec2, 0, sizeof(rec2));
    free(ids);
    return err;
}

void store_rekey_rollback_recover_on_boot(void)
{
    uint8_t state = 0;
    if (nvs_get_u8(s_h_sys, KEY_REKEY, &state) != ESP_OK || state == 0) {
        return;
    }
    uint8_t (*ids)[8] = calloc(CFG_ENTRY_MAX, 8);
    if (ids == NULL) {
        return;
    }
    uint16_t count = 0;
    if (idx_load(ids, &count) != ESP_OK) {
        free(ids);
        return;
    }

    if (state == 1) {
        /* rollback: drop temp namespace */
        for (uint16_t i = 0; i < count; i++) {
            char key[10];
            make_pwd_key(ids[i], key);
            nvs_erase_key(s_h_pwdnew, key);
        }
        nvs_commit(s_h_pwdnew);
        ESP_LOGW(TAG, "rekey state=1 -> rolled back");
    } else if (state == 2) {
        /* roll forward: copy pwdnew -> pwd */
        uint8_t rec[REC_MAX];
        for (uint16_t i = 0; i < count; i++) {
            char key[10];
            make_pwd_key(ids[i], key);
            size_t rlen = sizeof(rec);
            if (nvs_get_blob(s_h_pwdnew, key, rec, &rlen) != ESP_OK) {
                continue;
            }
            nvs_set_blob(s_h_pwd, key, rec, rlen);
            nvs_erase_key(s_h_pwdnew, key);
        }
        nvs_commit(s_h_pwd);
        nvs_commit(s_h_pwdnew);
        ESP_LOGW(TAG, "rekey state=2 -> rolled forward");
    }
    nvs_set_u8(s_h_sys, KEY_REKEY, 0);
    nvs_commit(s_h_sys);
    free(ids);
}

esp_err_t store_recovery_reset(const uint8_t new_salt[16], uint32_t new_iter,
                               const uint8_t new_verifier[32],
                               const uint8_t new_rec_hint[32])
{
    uint8_t (*ids)[8] = calloc(CFG_ENTRY_MAX, 8);
    if (ids == NULL) {
        return ESP_ERR_NO_MEM;
    }
    esp_err_t err = ESP_OK;

    xSemaphoreTake(s_mtx, portMAX_DELAY);
    uint16_t count = 0;
    err = idx_load(ids, &count);
    if (err != ESP_OK) {
        goto out;
    }

    /* wipe every entry in both namespaces */
    for (uint16_t i = 0; i < count; i++) {
        char key[10];
        make_pwd_key(ids[i], key);
        nvs_erase_key(s_h_pwd, key);
        nvs_erase_key(s_h_pwdnew, key);
    }
    nvs_commit(s_h_pwd);
    nvs_commit(s_h_pwdnew);

    /* reset index */
    nvs_erase_key(s_h_idx, KEY_IDS);
    nvs_set_u16(s_h_idx, KEY_COUNT, 0);
    nvs_commit(s_h_idx);

    /* fresh credentials */
    nvs_erase_key(s_h_cred, KEY_SALT);
    nvs_erase_key(s_h_cred, KEY_ITER);
    nvs_erase_key(s_h_cred, KEY_VERIF);
    nvs_erase_key(s_h_cred, KEY_REC);
    err = nvs_set_blob(s_h_cred, KEY_SALT, new_salt, 16);
    if (err == ESP_OK) {
        err = nvs_set_u32(s_h_cred, KEY_ITER, new_iter);
    }
    if (err == ESP_OK) {
        err = nvs_set_blob(s_h_cred, KEY_VERIF, new_verifier, 32);
    }
    if (err == ESP_OK && new_rec_hint != NULL) {
        err = nvs_set_blob(s_h_cred, KEY_REC, new_rec_hint, 32);
    }
    if (err == ESP_OK) {
        nvs_commit(s_h_cred);
    }
out:
    xSemaphoreGive(s_mtx);
    free(ids);
    return err;
}

/* ---------------- device identity ---------------- */

esp_err_t sec_store_get_dev_name(char *buf, size_t cap)
{
    if (buf == NULL || cap < 12) {
        return ESP_ERR_INVALID_ARG;
    }
    size_t len = cap;
    esp_err_t err = nvs_get_str(s_h_sys, KEY_DEVNAME, buf, &len);
    if (err == ESP_OK && len > 1) {
        return ESP_OK;
    }
    /* generate and persist "PwdKey-XXXX" (4 random hex), <= 22 bytes */
    snprintf(buf, cap, "PwdKey-%04X", (unsigned)(esp_random() & 0xFFFF));
    nvs_set_str(s_h_sys, KEY_DEVNAME, buf);
    nvs_commit(s_h_sys);
    ESP_LOGI(TAG, "device name generated: %s", buf);
    return ESP_OK;
}
