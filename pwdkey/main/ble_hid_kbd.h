/* ble_hid_kbd.h - HID keyboard: report map, keycode map, typing engine */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "host/ble_gatt.h"

esp_err_t hid_kbd_init(void);

/* called from ble_hs_cfg.gatts_register_cb (DSC 0x2908 capture) */
void hid_kbd_on_gatt_register(struct ble_gatt_register_ctxt *ctxt, void *arg);

/* Typing engine: queues the string to the typing task.
 * NOTE (C19): this is asynchronous - ESP_OK only means "accepted";
 * the final result is reported through the done callback. */
esp_err_t hid_kbd_type_string(uint16_t conn_handle, const char *ascii, uint8_t len);

/* v2.1 (C19): typing completion callback, invoked in the typing task context.
 * result = ESP_OK (all chars sent) | ESP_ERR_INVALID_STATE (HID link dropped or abort). */
typedef void (*hid_kbd_done_cb_t)(uint16_t conn_handle, esp_err_t result);
void hid_kbd_set_done_cb(hid_kbd_done_cb_t cb);

void hid_kbd_abort(void);
bool hid_kbd_busy(void);

/* GAP subscribe event helper: is this attr handle our input report characteristic? */
bool hid_kbd_is_report_char(uint16_t attr_handle);

/* self-test (task 0.3): print both handles over serial */
void hid_kbd_dump_handles(void);
