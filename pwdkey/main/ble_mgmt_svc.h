/* ble_mgmt_svc.h - management GATT service (0xFFF0): framing, TLV, command dispatch */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

esp_err_t mgmt_svc_init(void);

/* Frame and notify one response (HALF-SYNC / ASYNC alike) via the Response char. */
esp_err_t mgmt_send_response(uint16_t conn_handle, uint8_t opcode,
                             const uint8_t *tlv, uint16_t tlv_len);

/* Current STATE bitmap (global view; per-connection bits are computed internally). */
uint16_t  mgmt_state_bitmap(void);

/* Notify STATE changes (sleep / lock / link changes). */
void mgmt_notify_status(void);

/* GAP subscribe event helper: is this attr handle Response / Status? */
bool mgmt_is_notify_char(uint16_t attr_handle);
