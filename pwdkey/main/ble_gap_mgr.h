/* ble_gap_mgr.h - advertising (S0/S1/S2), connection tracking, pairing events */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

typedef enum { GAP_MODE_S0 = 0, GAP_MODE_S1, GAP_MODE_S2 } gap_mode_t;

esp_err_t ble_gap_mgr_init(void);           /* creates tables + pairing task */
void      ble_gap_mgr_on_sync(void);        /* attach to ble_hs_cfg.sync_cb */
void      ble_gap_mgr_on_reset(int reason);
esp_err_t gap_mgr_set_mode(gap_mode_t mode);/* restart adv window (S0=120s / S2=60s / S1=stop) */

uint8_t   gap_mgr_hid_link_count(void);     /* connections with HID input report subscribed */
uint16_t  gap_mgr_hid_link_at(uint8_t idx);
bool      gap_mgr_hid_addr_at(uint8_t idx, uint8_t out_addr[6], uint8_t *out_type);
esp_err_t gap_mgr_start_adv_for_second_central(void);   /* stage 0.2 validation helper */

/* --- peer identity addresses (stable keys for the named-host registry) --- */
bool      gap_mgr_conn_addr(uint16_t conn, uint8_t out_addr[6], uint8_t *out_type);
bool      gap_mgr_addr_is_online(const uint8_t addr[6]);
uint16_t  gap_mgr_conn_by_addr(const uint8_t addr[6]);   /* 0xFFFF if offline */
void      gap_mgr_refresh_addrs(void);      /* re-resolve after RPA resolution */

bool      gap_mgr_conn_alive(uint16_t conn_handle);
void      gap_mgr_terminate_all(void);
uint8_t   gap_mgr_conn_count(void);

/* additions (implementation support) */
gap_mode_t gap_mgr_get_mode(void);
uint8_t   gap_mgr_mgmt_link_count(void);    /* connections subscribed to mgmt Response/Status */
uint16_t  gap_mgr_mgmt_link_at(uint8_t idx);
