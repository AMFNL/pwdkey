/* btn_confirm.h - BOOT (GPIO0) button: short press = confirm, long press >= 2s = cancel.
 * Single consumer: one pending request slot at a time.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

typedef enum {
    BTN_REQ_NONE = 0,
    BTN_REQ_PAIRING,          /* Numeric Comparison confirm */
    BTN_REQ_PWD_TYPE,         /* confirm password output */
    BTN_REQ_ENTER_PAIRING,    /* confirm opening the HID pairing window */
    BTN_REQ_FACTORY_RESET,    /* second-confirm factory reset */
    BTN_REQ_AUTH_NEW,         /* confirm primary password set/change */
} btn_req_type_t;

typedef struct {
    btn_req_type_t type;
    uint16_t conn_handle;     /* originator connection (0xFFFF if none) */
    uint32_t   arg;           /* informational (e.g. numcmp value) */
} btn_req_t;

esp_err_t btn_confirm_init(void);
bool      btn_is_pressed(void);

/* Single consumer: returns ESP_ERR_INVALID_STATE when a request/wait is already active. */
esp_err_t btn_confirm_post(const btn_req_t *req);

/* Block until one press result arrives: 1 = short press (confirm), 0 = long press / timeout.
 * Only for non-host tasks. */
int  btn_wait_result(btn_req_type_t type, uint32_t timeout_ms);

/* Outcome of the *last* btn_wait_result(): 0 = timeout, 1 = short press, 2 = long cancel.
 * Lets the caller distinguish 0x3003 (timeout) from 0x3004 (user cancelled). */
uint8_t btn_last_outcome(void);

/* Power-on hold >= 5s detection: true = factory reset requested (caller erases + reboots). */
bool btn_boot_factory_reset_check(void);

/* Cancel a pending pairing confirmation (e.g. S2 window expiry); no-op when none. */
void btn_confirm_cancel_pairing(void);
