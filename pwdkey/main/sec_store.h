/* sec_store.h - NVS + AES-256-GCM secure storage (entries, credentials, identity) */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

esp_err_t sec_store_init(void);

/* --- primary credential (cred namespace) --- */
bool      cred_exists(void);                                   /* false = S0 factory state */
esp_err_t cred_get_salt(uint8_t salt[16]);
esp_err_t cred_get_iter(uint32_t *iters);
esp_err_t cred_get_verifier(uint8_t out[32]);                  /* raw read, for PROOF recompute */
esp_err_t cred_set_verifier(const uint8_t verifier[32]);
esp_err_t cred_set_salt(const uint8_t salt[16]);
esp_err_t cred_set_iter(uint32_t iters);
esp_err_t cred_check_verifier(const uint8_t verifier[32]);     /* constant time */
esp_err_t cred_gen_salt(uint8_t out_salt[16]);

/* --- recovery code --- */
esp_err_t cred_set_rec_hint(const uint8_t hint[32]);
esp_err_t cred_check_rec_hint(const uint8_t hint[32]);

/* helpers for the mgmt layer */
esp_err_t sec_store_compute_verifier(const uint8_t kek[32], uint8_t out[32]);
/* rec_hint = HMAC-SHA256(recovery_code, "PWD_MGR_RECOVERY_V1")
 * NOTE: engineering resolution of a spec gap - the hint must be verifiable
 * WITHOUT the old KEK (recovery happens when the old password is lost).
 * Keyed-hashing the code itself keeps the 120-bit code space safe while
 * making verification KEK-independent. See deployment manual, section "spec
 * deviation notes". */
esp_err_t sec_store_compute_rec_hint(const char *code, size_t code_len,
                                     uint8_t out_hint[32]);

/* addition used by PWD_ADD when the App supplies an explicit entry id
 * (id_in NULL -> device generates). store_add_entry() wraps this. */
esp_err_t store_add_entry_opt(const uint8_t kek[32], const uint8_t id_in[8],
                              const char *pwd, uint8_t pwd_len,
                              const char *name, uint8_t name_len,
                              uint8_t out_id[8]);

/* --- entries (pwd namespace + idx index) --- */
uint16_t  store_entry_count(void);
esp_err_t store_list_ids(uint8_t (*out_ids)[8], uint16_t max, uint16_t *out_count);

/* kek is provided by the session; on success fills the generated ID */
esp_err_t store_add_entry(const uint8_t kek[32],
                          const char *pwd, uint8_t pwd_len,
                          const char *name, uint8_t name_len,
                          uint8_t out_id[8]);

esp_err_t store_update_entry(const uint8_t kek[32], const uint8_t id[8],
                             const char *pwd, uint8_t pwd_len,      /* NULL = keep */
                             const char *name, uint8_t name_len);   /* NULL = keep */

esp_err_t store_delete_entry(const uint8_t id[8]);

/* read + decrypt (for PWD_TYPE and ATTR_GET; caller must zero buffers after use) */
esp_err_t store_read_entry(const uint8_t kek[32], const uint8_t id[8],
                           char *out_pwd, uint8_t *inout_pwd_cap,
                           char *out_name, uint8_t *inout_name_cap);

/* --- rekey transaction (power-loss safe) --- */
esp_err_t store_rekey_begin(void);
esp_err_t store_rekey_apply(const uint8_t kek_old[32], const uint8_t kek_new[32],
                            const uint8_t new_salt[16], uint32_t new_iter,
                            const uint8_t new_verifier[32], const uint8_t new_rec_hint[32]);
void      store_rekey_rollback_recover_on_boot(void);

/* recovery reset: wipe all entries and install fresh credentials.
 * rec_hint == NULL clears the recovery hint (old recovery code invalidated). */
esp_err_t store_recovery_reset(const uint8_t new_salt[16], uint32_t new_iter,
                               const uint8_t new_verifier[32],
                               const uint8_t new_rec_hint[32]);

/* --- device identity (sys namespace) --- */
esp_err_t sec_store_get_dev_name(char *buf, size_t cap);
