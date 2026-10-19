/* sec_session.h - session state, nonce table, failure counting & locking.
 * KEK lives in RAM only (session context); wiped on session destruction.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

void sec_session_init(void);

/* --- sessions (created on successful auth; KEK in RAM only) ---
 * session_create returns false when a session already exists for this conn;
 * in that case the existing session is refreshed (new KEK / auth time). */
bool     session_create(uint16_t conn_handle, const uint8_t kek[32]);
bool     session_valid(uint16_t conn_handle);
uint32_t session_age_ms(uint16_t conn_handle);   /* ms since last successful AUTH_VERIFY */
void     session_touch(uint16_t conn_handle);    /* reset 60s idle timer */
void     session_lock(uint16_t conn_handle);
void     session_on_disconnect(uint16_t conn_handle);   /* destroy + wipe KEK */
const uint8_t *session_kek(uint16_t conn_handle);       /* NULL if no session */

/* Periodic check driven by the mgmt task (every ~1s).
 * Destroys idle-expired sessions; returns true if any session expired. */
bool     sec_session_expire_check(void);

/* --- auth nonce (one pending nonce per connection; re-issue invalidates old) --- */
esp_err_t nonce_issue(uint16_t conn_handle, uint8_t out_nonce[32], uint32_t *out_seq);
bool      nonce_consume(uint16_t conn_handle, const uint8_t nonce[32], uint32_t seq);
/* seq of the currently pending nonce (used to recompute PROOF on the device side) */
esp_err_t nonce_pending_seq(uint16_t conn_handle, uint32_t *out_seq);

/* --- failure counting & locking (persisted) --- */
uint8_t  sys_fail_count(void);
void     sys_fail_bump(void);                /* +1 (persisted); arms 3/6/10 thresholds */
void     sys_fail_clear(void);
uint8_t  sys_lock_state(void);               /* dynamic: 0=ok 1=temp 2=permanent */
uint32_t sys_lock_remaining_s(void);
