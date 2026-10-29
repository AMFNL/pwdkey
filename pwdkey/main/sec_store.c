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
#include "shamir.h"
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
#define HKDF_INFO_REC   "PWDKEY-REC-WRAP-V1"   /* 128->256 位，用于包裹 DEK */
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

/* ---------------- DEK 数据加密密钥 ----------------
 *
 * 为什么要有这一层：恢复码必须能"不经过主密码"解开数据。
 * 如果条目直接用 KEK（主密码派生）加密，主密码一忘数据就永久锁死。
 *
 *   DEK ──HKDF──▶ k_enc ──AES-GCM──▶ 条目
 *    ├── 被 KEK 包裹（日常解锁）
 *    └── 被 recovery_key 包裹（恢复码用，下一步接）
 *
 * 换主密码时只需重新包裹 DEK，不用重加密所有条目。
 *
 * s_use_dek 为 false 时完全走旧路径（KEK 直接派生），所以这套代码
 * 在迁移之前对现有行为零影响。
 */
#define KEY_DEK_WRAP   "dek_wrap"    /* nonce(12) + ct(32) + tag(16) = 60 字节 */
#define KEY_DEK_READY  "dek_ready"   /* u8，1 = 条目已全部改用 DEK 加密 */
#define AAD_DEK        "PWDKEY-DEK-V1"

static bool s_use_dek;

static esp_err_t dek_unlock(const uint8_t kek[32], uint8_t out_dek[32]);
static esp_err_t dek_create(const uint8_t kek[32], uint8_t out_dek[32]);
static esp_err_t dek_store_wrap(const uint8_t kek[32], const uint8_t dek[32]);

static esp_err_t derive_kenc(const uint8_t kek[32], uint8_t k_enc[32])
{
    if (!s_use_dek) {
        return kdf_hkdf32(kek, HKDF_INFO_KENC, k_enc);   /* 旧路径：KEK 直接派生 */
    }
    uint8_t dek[32];
    esp_err_t err = dek_unlock(kek, dek);
    if (err != ESP_OK) {
        return err;
    }
    err = kdf_hkdf32(dek, HKDF_INFO_KENC, k_enc);
    memset(dek, 0, sizeof(dek));
    return err;
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
    err = VAULT_NVS_OPEN(NS_SYS, NVS_READWRITE, &s_h_sys);
    if (err != ESP_OK) {
        return err;
    }
    err = VAULT_NVS_OPEN(NS_CRED, NVS_READWRITE, &s_h_cred);
    if (err != ESP_OK) {
        return err;
    }
    err = VAULT_NVS_OPEN(NS_IDX, NVS_READWRITE, &s_h_idx);
    if (err != ESP_OK) {
        return err;
    }
    err = VAULT_NVS_OPEN(NS_PWD, NVS_READWRITE, &s_h_pwd);
    if (err != ESP_OK) {
        return err;
    }
    err = VAULT_NVS_OPEN(NS_PWDNEW, NVS_READWRITE, &s_h_pwdnew);
    if (err != ESP_OK) {
        return err;
    }

    /* ---- 数据格式版本校验 ----
     * 这是"升级不丢数据"的最后一道保险。
     * 之前的实现只写版本号、从不读回，等于没有保护：
     * 用旧固件去读新格式数据时会照常解析，可能把数据写坏。
     */
    uint8_t ver = 0;
    esp_err_t verr = nvs_get_u8(s_h_sys, KEY_VER, &ver);
    if (verr == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGI(TAG, "fresh vault, data ver -> %u", (unsigned)CFG_DATA_VER);
        nvs_set_u8(s_h_sys, KEY_VER, CFG_DATA_VER);
        nvs_commit(s_h_sys);
    } else if (verr != ESP_OK) {
        ESP_LOGE(TAG, "read data ver failed: %s", esp_err_to_name(verr));
        return verr;
    } else if (ver > CFG_DATA_VER) {
        /* 数据来自更新版本的固件（降级场景）。旧代码不理解新格式，
         * 继续运行可能写坏数据 —— 宁可拒绝启动，让用户刷回新固件。 */
        ESP_LOGE(TAG, "data ver %u > firmware ver %u, REFUSING to start (protect data)",
                 (unsigned)ver, (unsigned)CFG_DATA_VER);
        return ESP_ERR_INVALID_VERSION;
    } else if (ver < CFG_DATA_VER) {
        /* 旧数据 + 新固件：数据迁移点。
         * 当前 CFG_DATA_VER = 1，无迁移需求；将来版本号递增时在这里逐级升级，
         * 迁移完成后再写回新版本号。 */
        ESP_LOGW(TAG, "data ver %u -> %u (migration point)",
                 (unsigned)ver, (unsigned)CFG_DATA_VER);
        nvs_set_u8(s_h_sys, KEY_VER, CFG_DATA_VER);
        nvs_commit(s_h_sys);
    }
    s_open = true;
    store_dek_load_flag();       /* 读到 dek_ready 就切到 DEK 路径，否则保持旧行为 */
    ESP_LOGI(TAG, "store ready, %u entries%s", (unsigned)store_entry_count(),
             s_use_dek ? " (DEK)" : "");
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

    /* ---- DEK 模式：只换锁，不碰数据 ----
     *
     * 这一步非常关键。DEK 模式下 derive_kenc(kek_new) 需要先解开 dek_wrap，
     * 而此时 dek_wrap 还是用旧 KEK 包裹的 —— 用新 KEK 去解必然失败，
     * 走原来的全量重加密路径会让改密码直接报错。
     *
     * 正确做法：解出新旧 DEK（同一个），用新 KEK 重新包裹即可。
     * 条目一个字节都不用动，也不用重加密。 */
    if (s_use_dek) {
        uint8_t dek[32];
        esp_err_t e = dek_unlock(kek_old, dek);
        if (e != ESP_OK) {
            ESP_LOGE(TAG, "rekey: unlock DEK with old KEK failed: %s", esp_err_to_name(e));
            err = e;
            goto cleanup_keys;
        }
        e = dek_store_wrap(kek_new, dek);
        memset(dek, 0, sizeof(dek));
        if (e != ESP_OK) {
            ESP_LOGE(TAG, "rekey: re-wrap DEK failed: %s", esp_err_to_name(e));
            err = e;
            goto cleanup_keys;
        }
        /* 凭据元数据照常更新 */
        err = cred_set_salt(new_salt);
        if (err == ESP_OK) { err = cred_set_iter(new_iter); }
        if (err == ESP_OK) { err = cred_set_verifier(new_verifier); }
        if (err == ESP_OK && new_rec_hint != NULL) {
            err = cred_set_rec_hint(new_rec_hint);
        }
        if (err == ESP_OK) {
            nvs_set_u8(s_h_sys, KEY_REKEY, 0);
            nvs_commit(s_h_sys);
            ESP_LOGI(TAG, "rekey done (DEK mode, entries untouched)");
        }
        goto cleanup_keys;
    }

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

/* ---------------- 加密导出（明文永不出设备）----------------
 *
 * 设计要点：设备只知道 KEK（= KDF(主密码, device_salt)），不知道主密码，
 * 所以无法用"主密码派生"的密钥加密。这里的做法是：
 *
 *   K_export = 随机 32B（一次性）
 *   data     = AES-GCM(K_export, 条目明文)      ← 明文只在本函数内存在
 *   wrapped  = AES-GCM(KEK, K_export)           ← 用 KEK 锁住 K_export
 *
 * App 收到 wrapped + data 后，用 KEK 解出 K_export，再用主密码派生的新密钥
 * 重新包裹 K_export 写进文件 —— 全程不碰条目明文。
 *
 * 内存：明文原地加密（mbedtls GCM 支持 src == dst），只需一块缓冲。
 */

#define EXPORT_CAP   20480      /* 100 条 × (1+64+1+128) ≈ 19.4 KB，留余量 */

static uint8_t s_exp_buf[EXPORT_CAP];
static size_t  s_exp_len;
static bool    s_exp_ready;

esp_err_t store_export_build(const uint8_t kek[32],
                             uint8_t out_wrapped[60],
                             uint8_t out_data_nonce[12],
                             size_t *out_len)
{
    if (!s_open) {
        return ESP_ERR_INVALID_STATE;
    }
    if (out_wrapped == NULL || out_data_nonce == NULL || out_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    store_export_finish();

    uint8_t ids[CFG_ENTRY_MAX][8];
    uint16_t n = 0;
    esp_err_t err = store_list_ids(ids, CFG_ENTRY_MAX, &n);
    if (err != ESP_OK) {
        return err;
    }
    if (n == 0) {
        return ESP_ERR_NOT_FOUND;
    }

    /* 明文格式：count(2 LE) + [name_len(1) name pwd_len(1) pwd]... */
    size_t off = 0;
    s_exp_buf[off++] = (uint8_t)(n & 0xFF);
    s_exp_buf[off++] = (uint8_t)(n >> 8);

    uint16_t packed = 0;
    for (uint16_t i = 0; i < n; i++) {
        char pwd[CFG_SECRET_MAX + 1];
        char name[CFG_NAME_MAX + 1];
        uint8_t pcap = sizeof(pwd);
        uint8_t ncap = sizeof(name);

        if (store_read_entry(kek, ids[i], pwd, &pcap, name, &ncap) != ESP_OK) {
            memset(pwd, 0, sizeof(pwd));
            continue;               /* 单条读不出来不毁掉整次导出 */
        }
        size_t pl = strlen(pwd);
        size_t nl = strlen(name);
        if (pl > 255 || nl > 255 || off + 2 + nl + pl > EXPORT_CAP) {
            memset(pwd, 0, sizeof(pwd));
            return ESP_ERR_NO_MEM;  /* 条目过多，超出缓冲区 */
        }
        s_exp_buf[off++] = (uint8_t)nl;
        memcpy(s_exp_buf + off, name, nl);
        off += nl;
        s_exp_buf[off++] = (uint8_t)pl;
        memcpy(s_exp_buf + off, pwd, pl);
        off += pl;
        memset(pwd, 0, sizeof(pwd));
        packed++;
    }
    if (packed == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    s_exp_buf[0] = (uint8_t)(packed & 0xFF);
    s_exp_buf[1] = (uint8_t)(packed >> 8);

    static const uint8_t aad[] = "PWDKEY-EXPORT-V1";

    /* 一次性数据密钥 + 原地加密 */
    uint8_t kexp[32];
    uint8_t data_nonce[12];
    uint8_t tag[16];
    esp_fill_random(kexp, sizeof(kexp));
    esp_fill_random(data_nonce, sizeof(data_nonce));

    err = aes_gcm_encrypt(kexp, data_nonce, aad, sizeof(aad) - 1,
                          s_exp_buf, off, s_exp_buf, tag);
    if (err != ESP_OK) {
        memset(kexp, 0, sizeof(kexp));
        memset(s_exp_buf, 0, sizeof(s_exp_buf));
        return err;
    }
    /* WebCrypto 的 AES-GCM 约定密文末尾带 tag，这里照它的格式拼 */
    memcpy(s_exp_buf + off, tag, sizeof(tag));
    s_exp_len = off + sizeof(tag);

    /* 用 KEK 包裹 K_export：nonce(12) + ct(32) + tag(16) */
    uint8_t wrap_nonce[12];
    uint8_t wrapped_ct[32];
    uint8_t wrap_tag[16];
    esp_fill_random(wrap_nonce, sizeof(wrap_nonce));

    err = aes_gcm_encrypt(kek, wrap_nonce, aad, sizeof(aad) - 1,
                          kexp, sizeof(kexp), wrapped_ct, wrap_tag);
    memset(kexp, 0, sizeof(kexp));
    if (err != ESP_OK) {
        memset(s_exp_buf, 0, sizeof(s_exp_buf));
        return err;
    }

    memcpy(out_wrapped, wrap_nonce, 12);
    memcpy(out_wrapped + 12, wrapped_ct, 32);
    memcpy(out_wrapped + 44, wrap_tag, 16);
    memcpy(out_data_nonce, data_nonce, 12);

    s_exp_ready = true;
    *out_len = s_exp_len;
    ESP_LOGI(TAG, "export built: %u entries, %u bytes", (unsigned)packed, (unsigned)s_exp_len);
    return ESP_OK;
}

esp_err_t store_export_chunk(uint16_t offset, uint8_t *out, uint16_t cap, uint16_t *out_len)
{
    if (!s_exp_ready) {
        return ESP_ERR_INVALID_STATE;
    }
    if (out == NULL || out_len == NULL || offset >= s_exp_len) {
        return ESP_ERR_INVALID_ARG;
    }
    size_t n = s_exp_len - offset;
    if (n > cap) {
        n = cap;
    }
    memcpy(out, s_exp_buf + offset, n);
    *out_len = (uint16_t)n;
    return ESP_OK;
}

void store_export_finish(void)
{
    memset(s_exp_buf, 0, sizeof(s_exp_buf));
    s_exp_len = 0;
    s_exp_ready = false;
}

bool store_export_active(void)
{
    return s_exp_ready;
}

/* ---------------- 导出冷却标记（持久化） ----------------
 *
 * 为什么需要持久化：原来冷却时间只记在 RAM，被胁迫者只要拔电重启就能立刻
 * 再导一次，限速形同虚设。设备没有 RTC，无法算真实时间差，所以采用保守策略：
 * 标记存在 NVS 里，重启后仍然从"本次上电时刻"重新等满一个冷却周期。
 */

#define KEY_EXP_COOL "exp_cool"

esp_err_t store_export_cooldown_set(bool active)
{
    if (!s_open) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t err = nvs_set_u8(s_h_sys, KEY_EXP_COOL, active ? 1 : 0);
    if (err == ESP_OK) {
        err = nvs_commit(s_h_sys);
    }
    return err;
}

bool store_export_cooldown_get(void)
{
    if (!s_open) {
        return false;
    }
    uint8_t v = 0;
    return nvs_get_u8(s_h_sys, KEY_EXP_COOL, &v) == ESP_OK && v != 0;
}

/* ---------------- DEK 实现与迁移 ---------------- */

static esp_err_t dek_unlock(const uint8_t kek[32], uint8_t out_dek[32])
{
    uint8_t blob[60];
    size_t len = sizeof(blob);
    if (nvs_get_blob(s_h_sys, KEY_DEK_WRAP, blob, &len) != ESP_OK || len != sizeof(blob)) {
        memset(blob, 0, sizeof(blob));
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t err = aes_gcm_decrypt(kek, blob, (const uint8_t *)AAD_DEK, strlen(AAD_DEK),
                                    blob + 12, 32, blob + 44, out_dek);
    memset(blob, 0, sizeof(blob));
    return err;
}

/** 用 kek 包裹 dek 并写入 NVS（不生成新 DEK，换主密码时用它） */
static esp_err_t dek_store_wrap(const uint8_t kek[32], const uint8_t dek[32])
{
    uint8_t blob[60];
    uint8_t nonce[12];
    uint8_t tag[16];
    esp_fill_random(nonce, sizeof(nonce));

    esp_err_t err = aes_gcm_encrypt(kek, nonce, (const uint8_t *)AAD_DEK, strlen(AAD_DEK),
                                    dek, 32, blob + 12, tag);
    if (err != ESP_OK) {
        memset(blob, 0, sizeof(blob));
        return err;
    }
    memcpy(blob, nonce, 12);
    memcpy(blob + 44, tag, 16);
    err = nvs_set_blob(s_h_sys, KEY_DEK_WRAP, blob, sizeof(blob));
    if (err == ESP_OK) {
        err = nvs_commit(s_h_sys);
    }
    memset(blob, 0, sizeof(blob));
    return err;
}

static esp_err_t dek_create(const uint8_t kek[32], uint8_t out_dek[32])
{
    esp_fill_random(out_dek, 32);
    return dek_store_wrap(kek, out_dek);
}

bool store_use_dek(void)
{
    return s_use_dek;
}

/* 由 init 在打开命名空间后调用：读到标记就切到 DEK 路径 */
void store_dek_load_flag(void)
{
    uint8_t v = 0;
    s_use_dek = (nvs_get_u8(s_h_sys, KEY_DEK_READY, &v) == ESP_OK && v == 1);
}

/**
 * 把现有条目从「KEK 直接加密」迁移到「DEK 加密」。
 *
 * 为什么不能简单粗暴地全量重写：NVS 每条是独立 key，写入虽然原子，
 * 但 N 条之间没有事务。所以顺序是：
 *   1. 先生成并持久化 DEK（这一步成功，后面即使中断数据也能解开）
 *   2. 逐条：旧 k_enc 解密 → 新 k_enc 加密 → 原子写回
 *   3. 全部成功才置 dek_ready 标记（此前 s_use_dek 一直是 false，
 *      所以中途失败的话，下一次启动仍走旧路径，数据完好）
 *
 * 注意：rec_pack 需要元数据，这里拿不到历史值，统一重置为 0。
 * 密码与名称不受影响。
 */
esp_err_t store_migrate_to_dek(const uint8_t kek[32])
{
    if (s_use_dek) {
        return ESP_OK;
    }
    if (!s_open) {
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t dek[32];
    esp_err_t err = dek_unlock(kek, dek);
    if (err == ESP_ERR_NOT_FOUND) {
        err = dek_create(kek, dek);        /* 首次：生成并包裹 */
    }
    if (err != ESP_OK) {
        memset(dek, 0, sizeof(dek));
        ESP_LOGE(TAG, "dek prepare failed: %s", esp_err_to_name(err));
        return err;
    }

    uint8_t k_old[32];
    uint8_t k_new[32];
    err = kdf_hkdf32(kek, HKDF_INFO_KENC, k_old);
    if (err == ESP_OK) {
        err = kdf_hkdf32(dek, HKDF_INFO_KENC, k_new);
    }
    memset(dek, 0, sizeof(dek));
    if (err != ESP_OK) {
        memset(k_old, 0, sizeof(k_old));
        return err;
    }

    uint8_t ids[CFG_ENTRY_MAX][8];
    uint16_t n = 0;
    err = store_list_ids(ids, CFG_ENTRY_MAX, &n);
    if (err != ESP_OK) {
        goto out;
    }

    /* ---- 预检：所有条目必须能用旧密钥解开，否则一条都不动 ----
     *
     * 这一步是必需的。之前的实现边检边写、失败就 continue，但循环结束仍会
     * 置 dek_ready —— 被跳过的那条还是 KEK 密文，切到 DEK 之后永远解不开，
     * 等于静默丢数据。改成"要么全成功，要么原地不动"。 */
    for (uint16_t i = 0; i < n; i++) {
        uint8_t rec[REC_MAX];
        char key[10];
        char pwd[CFG_SECRET_MAX + 1];
        char name[CFG_NAME_MAX + 1];
        uint8_t pcap = sizeof(pwd);
        uint8_t ncap = sizeof(name);

        make_pwd_key(ids[i], key);
        xSemaphoreTake(s_mtx, portMAX_DELAY);
        size_t rlen = sizeof(rec);
        esp_err_t e2 = nvs_get_blob(s_h_pwd, key, rec, &rlen);
        xSemaphoreGive(s_mtx);

        if (e2 == ESP_OK) {
            e2 = rec_unpack(rec, (uint16_t)rlen, ids[i], k_old, pwd, &pcap, name, &ncap);
        }
        memset(pwd, 0, sizeof(pwd));
        memset(rec, 0, sizeof(rec));
        if (e2 != ESP_OK) {
            ESP_LOGE(TAG, "precheck failed at entry %u (%s), abort migration",
                     (unsigned)i, esp_err_to_name(e2));
            err = ESP_FAIL;
            goto out;
        }
    }

    uint16_t moved = 0;
    for (uint16_t i = 0; i < n; i++) {
        uint8_t rec[REC_MAX];
        char key[10];
        make_pwd_key(ids[i], key);

        xSemaphoreTake(s_mtx, portMAX_DELAY);
        size_t rlen = sizeof(rec);
        esp_err_t e2 = nvs_get_blob(s_h_pwd, key, rec, &rlen);
        xSemaphoreGive(s_mtx);
        if (e2 != ESP_OK) {
            err = e2;
            goto out;
        }

        char pwd[CFG_SECRET_MAX + 1];
        char name[CFG_NAME_MAX + 1];
        uint8_t pcap = sizeof(pwd);
        uint8_t ncap = sizeof(name);
        e2 = rec_unpack(rec, (uint16_t)rlen, ids[i], k_old, pwd, &pcap, name, &ncap);
        if (e2 != ESP_OK) {
            memset(pwd, 0, sizeof(pwd));
            memset(rec, 0, sizeof(rec));
            err = e2;
            goto out;
        }

        uint16_t nrlen = rec_pack(rec, ids[i], pwd, (uint8_t)strlen(pwd),
                                  name, (uint8_t)strlen(name), k_new,
                                  0, 0, 0, 0);
        memset(pwd, 0, sizeof(pwd));
        if (nrlen == 0) {
            memset(rec, 0, sizeof(rec));
            continue;
        }

        xSemaphoreTake(s_mtx, portMAX_DELAY);
        e2 = nvs_set_blob(s_h_pwd, key, rec, nrlen);
        if (e2 == ESP_OK) {
            e2 = nvs_commit(s_h_pwd);
        }
        xSemaphoreGive(s_mtx);
        memset(rec, 0, sizeof(rec));
        if (e2 != ESP_OK) {
            /* 写失败立刻停：已迁移的条目用 DEK、未迁移的用 KEK，
             * 但 dek_ready 没置位，所以下次启动仍按旧路径读 —— 数据不会坏。 */
            ESP_LOGE(TAG, "migrate write failed at %u: %s", i, esp_err_to_name(e2));
            err = e2;
            goto out;
        }
        moved++;
    }

    s_use_dek = true;
    nvs_set_u8(s_h_sys, KEY_DEK_READY, 1);
    nvs_commit(s_h_sys);
    ESP_LOGI(TAG, "migrated %u/%u entries to DEK", (unsigned)moved, (unsigned)n);
    err = ESP_OK;

out:
    memset(k_old, 0, sizeof(k_old));
    memset(k_new, 0, sizeof(k_new));
    return err;
}

/* ---------------- 恢复码（3-of-5，不清除数据）----------------
 *
 * 目标：主密码忘了也能救回数据，且【不擦除】。
 *
 *   recovery_key = 128 位随机
 *   Shamir 3-of-5 → 5 份（每份 16 字节 → base32 后 26 字符）
 *   dek_rec = AES-GCM(recovery_key, DEK)      ← 存 NVS
 *
 * 恢复：任意 3 份 → 重建 recovery_key → 解 dek_rec → 拿到 DEK
 *       → 用新主密码派生的 KEK 重新包裹 DEK → 条目一个字节都不动
 *
 * 安全语义：任意 3 份 = 直接拿到 DEK，不需要主密码。这是 Shamir 的数学
 * 必然而非缺陷。所以 5 张纸必须分开保管，不能放在一起。
 */

#define KEY_DEK_REC    "dek_rec"     /* nonce(12) + ct(32) + tag(16) */
#define AAD_REC        "PWDKEY-REC-V1"
#define REC_SHARE_LEN  16
#define REC_SHARE_N    5
#define REC_THRESHOLD  3

esp_err_t store_recovery_setup(const uint8_t kek[32], uint8_t *out_shares)
{
    if (!s_open || out_shares == NULL || kek == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* 恢复码包裹的是 DEK，所以先确保 DEK 存在（首次会触发迁移） */
    esp_err_t err = store_migrate_to_dek(kek);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "recovery setup: migrate failed: %s", esp_err_to_name(err));
        return err;
    }

    uint8_t dek[32];
    err = dek_unlock(kek, dek);
    if (err != ESP_OK) {
        memset(dek, 0, sizeof(dek));
        return err;
    }

    uint8_t rkey[REC_SHARE_LEN];
    esp_fill_random(rkey, sizeof(rkey));
    err = shamir_split(rkey, sizeof(rkey), REC_SHARE_N, REC_THRESHOLD, out_shares);
    if (err != ESP_OK) {
        memset(rkey, 0, sizeof(rkey));
        memset(dek, 0, sizeof(dek));
        return err;
    }

    /* recovery_key 是 128 位（为了恢复码只有 24-26 个字符），
     * 但 AES-256 需要 256 位密钥，kdf_hkdf32 又要求 32 字节输入，
     * 所以先零填充到 32 字节再派生。填充不影响安全性：
     * 高 128 位是随机的，低 128 位固定为 0。 */
    uint8_t rkey32[32];
    memset(rkey32, 0, sizeof(rkey32));
    memcpy(rkey32, rkey, REC_SHARE_LEN);
    uint8_t k_rec[32];
    err = kdf_hkdf32(rkey32, HKDF_INFO_REC, k_rec);
    memset(rkey32, 0, sizeof(rkey32));
    if (err != ESP_OK) {
        memset(rkey, 0, sizeof(rkey));
        memset(dek, 0, sizeof(dek));
        return err;
    }

    uint8_t blob[60];
    uint8_t nonce[12];
    uint8_t tag[16];
    esp_fill_random(nonce, sizeof(nonce));
    err = aes_gcm_encrypt(k_rec, nonce, (const uint8_t *)AAD_REC, strlen(AAD_REC),
                          dek, 32, blob + 12, tag);
    memset(k_rec, 0, sizeof(k_rec));
    memset(rkey, 0, sizeof(rkey));
    memset(dek, 0, sizeof(dek));
    if (err != ESP_OK) {
        memset(blob, 0, sizeof(blob));
        return err;
    }
    memcpy(blob, nonce, 12);
    memcpy(blob + 44, tag, 16);

    err = nvs_set_blob(s_h_sys, KEY_DEK_REC, blob, sizeof(blob));
    if (err == ESP_OK) {
        err = nvs_commit(s_h_sys);
    }
    memset(blob, 0, sizeof(blob));
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "recovery shares generated (3-of-5)");
    }
    return err;
}

bool store_recovery_ready(void)
{
    size_t sz = 0;
    return nvs_get_blob(s_h_sys, KEY_DEK_REC, NULL, &sz) == ESP_OK && sz == 60;
}

/**
 * 用 k 份恢复码重建 DEK，并用新的 KEK 重新包裹。
 * 条目数据完全不动 —— 这是"不擦除"的核心。
 *
 * @param xs        每份的序号（1..5），不能重复
 * @param shares    k*16 字节
 * @param k         份数（>=3）
 * @param new_kek   新主密码派生的 KEK（32 字节）
 */
esp_err_t store_recovery_restore(const uint8_t *xs, const uint8_t *shares, uint8_t k,
                                 const uint8_t new_kek[32])
{
    if (!s_open || xs == NULL || shares == NULL || new_kek == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (k < REC_THRESHOLD) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t rkey[REC_SHARE_LEN];
    esp_err_t err = shamir_combine(xs, shares, k, REC_SHARE_LEN, rkey);
    if (err != ESP_OK) {
        memset(rkey, 0, sizeof(rkey));
        return err;
    }

    uint8_t blob[60];
    size_t len = sizeof(blob);
    if (nvs_get_blob(s_h_sys, KEY_DEK_REC, blob, &len) != ESP_OK || len != sizeof(blob)) {
        memset(rkey, 0, sizeof(rkey));
        memset(blob, 0, sizeof(blob));
        return ESP_ERR_NOT_FOUND;
    }

    uint8_t rkey32[32];
    memset(rkey32, 0, sizeof(rkey32));
    memcpy(rkey32, rkey, REC_SHARE_LEN);
    uint8_t k_rec[32];
    err = kdf_hkdf32(rkey32, HKDF_INFO_REC, k_rec);
    memset(rkey32, 0, sizeof(rkey32));
    memset(rkey, 0, sizeof(rkey));
    if (err != ESP_OK) {
        memset(k_rec, 0, sizeof(k_rec));
        memset(blob, 0, sizeof(blob));
        return err;
    }

    uint8_t dek[32];
    err = aes_gcm_decrypt(k_rec, blob, (const uint8_t *)AAD_REC, strlen(AAD_REC),
                          blob + 12, 32, blob + 44, dek);
    memset(k_rec, 0, sizeof(k_rec));
    if (err != ESP_OK) {
        /* GCM 校验失败：码不对，或份数不足导致插值结果错误 */
        memset(dek, 0, sizeof(dek));
        memset(blob, 0, sizeof(blob));
        return ESP_ERR_INVALID_CRC;
    }

    /* 用新 KEK 重新包裹 DEK，替换原来的 dek_wrap */
    uint8_t nonce[12];
    uint8_t tag[16];
    esp_fill_random(nonce, sizeof(nonce));
    err = aes_gcm_encrypt(new_kek, nonce, (const uint8_t *)AAD_DEK, strlen(AAD_DEK),
                          dek, 32, blob + 12, tag);
    memset(dek, 0, sizeof(dek));
    if (err != ESP_OK) {
        memset(blob, 0, sizeof(blob));
        return err;
    }
    memcpy(blob, nonce, 12);
    memcpy(blob + 44, tag, 16);

    err = nvs_set_blob(s_h_sys, KEY_DEK_WRAP, blob, sizeof(blob));
    if (err == ESP_OK) {
        err = nvs_commit(s_h_sys);
    }
    memset(blob, 0, sizeof(blob));

    if (err == ESP_OK) {
        /* 恢复码是一次性的：用掉立刻作废。
         * 否则一旦这 3 份码被旁人看到（截图、抄写的纸），他们可以反复重置
         * 你的主密码，等于永久后门。清掉 dek_rec 后旧码全部失效，
         * 用户需要到设置页重新生成一套。 */
        esp_err_t e2 = nvs_erase_key(s_h_sys, KEY_DEK_REC);
        if (e2 == ESP_OK) {
            e2 = nvs_commit(s_h_sys);
        }
        if (e2 != ESP_OK) {
            ESP_LOGW(TAG, "recovery used but invalidate failed: %s", esp_err_to_name(e2));
        }
        ESP_LOGI(TAG, "recovery restore OK: DEK re-wrapped, old shares invalidated");
    }
    return err;
}
