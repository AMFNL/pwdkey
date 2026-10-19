/* ble_hid_kbd.c - HID keyboard over NimBLE.
 *
 * Key mechanisms (all verified against ESP-IDF v5.5.5 sources):
 *  - report handle capture via DSC (Report Reference 0x2908) callback,
 *    mirroring the official esp_hid component (nimble_hidd.c).
 *  - sending 8-byte raw input reports via ble_gatts_notify_custom().
 *  - typing delays use a >=1 tick fallback (100Hz tick: pdMS_TO_TICKS(8)==0).
 */
#include "ble_hid_kbd.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/ble_att.h"
#include "host/util/util.h"
#include "os/os_mbuf.h"
#include "services/hid/ble_svc_hid.h"

#include "app_cfg.h"
#include "ble_gap_mgr.h"

static const char *TAG = "hid_kbd";

/* ---------------- report map (65 bytes, spec 2.3) ---------------- */
static const uint8_t k_report_map[] = {
    /* --- keyboard application collection --- */
    0x05, 0x01,        /* Usage Page (Generic Desktop)               */
    0x09, 0x06,        /* Usage (Keyboard)                           */
    0xA1, 0x01,        /* Collection (Application)                   */
    0x85, 0x01,        /*   Report ID (1)                            */
    /* --- input: 8 modifier bits --- */
    0x05, 0x07,        /*   Usage Page (Keyboard/Keypad)             */
    0x19, 0xE0,        /*   Usage Min (0xE0 LeftCtrl)                */
    0x29, 0xE7,        /*   Usage Max (0xE7 RightGUI)                */
    0x15, 0x00,        /*   Logical Min (0)                          */
    0x25, 0x01,        /*   Logical Max (1)                          */
    0x75, 0x01,        /*   Report Size (1)                          */
    0x95, 0x08,        /*   Report Count (8)  -> modifier byte       */
    0x81, 0x02,        /*   Input (Data,Var,Abs)                     */
    /* --- input: reserved byte --- */
    0x95, 0x01,        /*   Report Count (1)                         */
    0x75, 0x08,        /*   Report Size (8)                          */
    0x81, 0x01,        /*   Input (Const)      -> reserved byte      */
    /* --- output: LED (1 byte) --- */
    0x05, 0x08,        /*   Usage Page (LEDs)                        */
    0x19, 0x01,        /*   Usage Min (Num Lock)                     */
    0x29, 0x05,        /*   Usage Max (Kana)                         */
    0x95, 0x05,        /*   Report Count (5)                         */
    0x75, 0x01,        /*   Report Size (1)                          */
    0x91, 0x02,        /*   Output (Data,Var,Abs)  -> LED output     */
    0x95, 0x01,        /*   Report Count (1)                         */
    0x75, 0x03,        /*   Report Size (3)                          */
    0x91, 0x01,        /*   Output (Const)         -> LED padding    */
    /* --- input: 6 key slots --- */
    0x95, 0x06,        /*   Report Count (6)                         */
    0x75, 0x08,        /*   Report Size (8)                          */
    0x15, 0x00,        /*   Logical Min (0)                          */
    0x25, 0x65,        /*   Logical Max (101)                        */
    0x05, 0x07,        /*   Usage Page (Keyboard/Keypad)             */
    0x19, 0x00,        /*   Usage Min (0)                            */
    0x29, 0x65,        /*   Usage Max (101)                          */
    0x81, 0x00,        /*   Input (Data,Array,Abs) -> keycodes       */
    0xC0,              /* End Collection                             */
};

/* ---------------- state ---------------- */
static struct ble_svc_hid_params s_hid_params;   /* must be static (1.1KB) */

static uint16_t s_rpt_in_handle;      /* Report ID=1, Type=Input  <- typing uses this */
static uint16_t s_rpt_out_handle;     /* Report ID=1, Type=Output (LED, bookkeeping) */

static TaskHandle_t s_kbd_task;
static volatile bool s_abort;
static volatile bool s_busy;
static char    s_buf[CFG_SECRET_MAX + 8];
static uint16_t s_conn;
static uint8_t  s_len;
static hid_kbd_done_cb_t s_done_cb;

/* full ASCII map 0x20..0x7E (95 entries), cross-checked against USB HID Usage Page 0x07
 * NOTE (C1 fixed): '&' = Shift+7 = 0x24 */
#define KMOD_NONE   0x00
#define KMOD_LSHIFT 0x02

static const struct { uint8_t mod; uint8_t code; } k_ascii_map[95] = {
 /*0x20*/ {0,0x2C}, {KMOD_LSHIFT,0x1E}/*!*/, {KMOD_LSHIFT,0x34}/*"*/,
 /*0x23*/ {KMOD_LSHIFT,0x20}/*#*/, {KMOD_LSHIFT,0x21}/*$*/, {KMOD_LSHIFT,0x22}/*%*/,
 /*0x26*/ {KMOD_LSHIFT,0x24}/*&*/, {0,0x34}/*'*/, {KMOD_LSHIFT,0x26}/*(*/,
 /*0x29*/ {KMOD_LSHIFT,0x27}/*)*/, {KMOD_LSHIFT,0x25}/**/, {KMOD_LSHIFT,0x2E}/*+*/,
 /*0x2C*/ {0,0x36}/*,*/, {0,0x2D}/*-*/, {0,0x37}/*.*/, {0,0x38}/*/*/,
 /*0x30*/ {0,0x27}/*0*/, {0,0x1E}/*1*/, {0,0x1F}/*2*/, {0,0x20}/*3*/,
 /*0x34*/ {0,0x21}/*4*/, {0,0x22}/*5*/, {0,0x23}/*6*/, {0,0x24}/*7*/,
 /*0x38*/ {0,0x25}/*8*/, {0,0x26}/*9*/, {KMOD_LSHIFT,0x33}/*:*/, {0,0x33}/*;*/,
 /*0x3C*/ {KMOD_LSHIFT,0x36}/*<*/, {0,0x2E}/*=*/, {KMOD_LSHIFT,0x37}/*>*/, {KMOD_LSHIFT,0x38}/*?*/,
 /*0x40*/ {KMOD_LSHIFT,0x1F}/*@*/, {KMOD_LSHIFT,0x04}/*A*/, {KMOD_LSHIFT,0x05}/*B*/,
 /*0x43*/ {KMOD_LSHIFT,0x06}/*C*/, {KMOD_LSHIFT,0x07}/*D*/, {KMOD_LSHIFT,0x08}/*E*/,
 /*0x46*/ {KMOD_LSHIFT,0x09}/*F*/, {KMOD_LSHIFT,0x0A}/*G*/, {KMOD_LSHIFT,0x0B}/*H*/,
 /*0x49*/ {KMOD_LSHIFT,0x0C}/*I*/, {KMOD_LSHIFT,0x0D}/*J*/, {KMOD_LSHIFT,0x0E}/*K*/,
 /*0x4C*/ {KMOD_LSHIFT,0x0F}/*L*/, {KMOD_LSHIFT,0x10}/*M*/, {KMOD_LSHIFT,0x11}/*N*/,
 /*0x4F*/ {KMOD_LSHIFT,0x12}/*O*/, {KMOD_LSHIFT,0x13}/*P*/, {KMOD_LSHIFT,0x14}/*Q*/,
 /*0x52*/ {KMOD_LSHIFT,0x15}/*R*/, {KMOD_LSHIFT,0x16}/*S*/, {KMOD_LSHIFT,0x17}/*T*/,
 /*0x55*/ {KMOD_LSHIFT,0x18}/*U*/, {KMOD_LSHIFT,0x19}/*V*/, {KMOD_LSHIFT,0x1A}/*W*/,
 /*0x58*/ {KMOD_LSHIFT,0x1B}/*X*/, {KMOD_LSHIFT,0x1C}/*Y*/, {KMOD_LSHIFT,0x1D}/*Z*/,
 /*0x5B*/ {0,0x2F}/*[*/, {0,0x31}/*\*/, {0,0x30}/*]*/, {KMOD_LSHIFT,0x23}/*^*/,
 /*0x5F*/ {KMOD_LSHIFT,0x2D}/*_*/, {0,0x35}/*`*/,
 /*0x61*/ {0,0x04}/*a*/, {0,0x05}/*b*/, {0,0x06}/*c*/, {0,0x07}/*d*/,
 /*0x65*/ {0,0x08}/*e*/, {0,0x09}/*f*/, {0,0x0A}/*g*/, {0,0x0B}/*h*/,
 /*0x69*/ {0,0x0C}/*i*/, {0,0x0D}/*j*/, {0,0x0E}/*k*/, {0,0x0F}/*l*/,
 /*0x6D*/ {0,0x10}/*m*/, {0,0x11}/*n*/, {0,0x12}/*o*/, {0,0x13}/*p*/,
 /*0x71*/ {0,0x14}/*q*/, {0,0x15}/*r*/, {0,0x16}/*s*/, {0,0x17}/*t*/,
 /*0x75*/ {0,0x18}/*u*/, {0,0x19}/*v*/, {0,0x1A}/*w*/, {0,0x1B}/*x*/,
 /*0x79*/ {0,0x1C}/*y*/, {0,0x1D}/*z*/,
 /*0x7B*/ {KMOD_LSHIFT,0x2F}/*{*/, {KMOD_LSHIFT,0x31}/*|*/, {KMOD_LSHIFT,0x30}/*}*/,
 /*0x7E*/ {KMOD_LSHIFT,0x35}/*~*/,
};

/* control chars handled separately: '\t'=(0,0x2B) '\n'/'\r'=(0,0x28) '\b'=(0,0x2A) */
static bool kbd_lookup(uint8_t c, uint8_t *mod, uint8_t *code)
{
    if (c == '\t') { *mod = 0; *code = 0x2B; return true; }
    if (c == '\n' || c == '\r') { *mod = 0; *code = 0x28; return true; }
    if (c == '\b') { *mod = 0; *code = 0x2A; return true; }
    if (c >= 0x20 && c <= 0x7E) {
        *mod = k_ascii_map[c - 0x20].mod;
        *code = k_ascii_map[c - 0x20].code;
        return true;
    }
    return false;       /* non-ASCII / unsupported control chars */
}

static bool kbd_ascii_supported(uint8_t c)
{
    return (c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\n' ||
           c == '\r' || c == '\b';
}

/* ---------------- report handle capture (DSC method, spec 2.1) ---------------- */

void hid_kbd_on_gatt_register(struct ble_gatt_register_ctxt *ctxt, void *arg)
{
    (void)arg;
    if (ctxt->op != BLE_GATT_REGISTER_OP_DSC) {
        return;
    }
    if (ble_uuid_u16(ctxt->dsc.dsc_def->uuid) != 0x2908) {
        return;     /* only Report Reference descriptors */
    }

    uint8_t id = 0, type = 0;
    struct os_mbuf *om = NULL;
    if (ble_att_svr_read_local(ctxt->dsc.handle, &om) == 0 && om != NULL) {
        if (OS_MBUF_PKTLEN(om) >= 2) {
            uint8_t v[2] = {0};
            ble_hs_mbuf_to_flat(om, v, 2, NULL);
            id = v[0];
            type = v[1];
        }
        os_mbuf_free_chain(om);
    }
    /* handle storage address: ble_svc_hid put &rpts[i].handle into dsc_def->arg */
    uint16_t val_handle = *(uint16_t *)ctxt->dsc.dsc_def->arg;

    if (type == 0x01 && id == 1) {
        s_rpt_in_handle = val_handle;
    } else if (type == 0x02 && id == 1) {
        s_rpt_out_handle = val_handle;
    }
}

void hid_kbd_dump_handles(void)
{
    ESP_LOGI(TAG, "report handles: in=%u out=%u (in!=0 && in!=out == capture OK)",
             s_rpt_in_handle, s_rpt_out_handle);
}

bool hid_kbd_is_report_char(uint16_t attr_handle)
{
    return attr_handle == s_rpt_in_handle;
}

/* ---------------- report write callback (LED output etc., informational) -------- */

static void hid_kbd_on_report_write(uint16_t attr_handle, uint8_t report_type,
                                    uint8_t report_id, const uint8_t *data, uint16_t len)
{
    ESP_LOGD(TAG, "report write: attr=%u type=%u id=%u len=%u",
             attr_handle, report_type, report_id, len);
}

/* ---------------- send ---------------- */

static int hid_kbd_send(uint16_t conn_handle, const uint8_t rpt[8])
{
    struct os_mbuf *om = ble_hs_mbuf_from_flat(rpt, 8);
    if (om == NULL) {
        return -1;
    }
    /* om is taken over by the stack whether or not this succeeds */
    return ble_gatts_notify_custom(conn_handle, s_rpt_in_handle, om);
}

/* >=1 tick delay fallback: at 100Hz, pdMS_TO_TICKS(8) would be 0 (no delay!) */
static inline void kbd_delay_ms(uint32_t ms)
{
    TickType_t t = pdMS_TO_TICKS(ms);
    vTaskDelay(t > 0 ? t : 1);
}

/* ---------------- typing task ---------------- */

static void kbd_task(void *arg)
{
    (void)arg;
    uint8_t press[8] = {0};
    uint8_t release[8] = {0};

    for (;;) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        esp_err_t result = ESP_OK;

        for (uint8_t i = 0; i < s_len; i++) {
            uint8_t mod = 0, code = 0;
            if (s_abort) {
                result = ESP_ERR_INVALID_STATE;
                break;
            }
            if (!gap_mgr_conn_alive(s_conn)) {
                result = ESP_ERR_INVALID_STATE;     /* -> 0x3005 */
                break;
            }
            if (!kbd_lookup((uint8_t)s_buf[i], &mod, &code)) {
                result = ESP_ERR_INVALID_ARG;
                break;
            }
            press[0] = mod;
            press[2] = code;
            hid_kbd_send(s_conn, press);
            kbd_delay_ms(CFG_INTER_CHAR_MS);
            hid_kbd_send(s_conn, release);
            kbd_delay_ms(CFG_INTER_CHAR_MS);
            press[0] = 0;
            press[2] = 0;
        }

        uint16_t conn = s_conn;
        memset(s_buf, 0, sizeof(s_buf));    /* wipe in every path */
        s_len = 0;

        /* report result; auditing is done by the mgmt layer in this callback */
        if (s_done_cb) {
            s_done_cb(conn, result);
        }
        s_busy = false;
    }
}

/* ---------------- public API ---------------- */

void hid_kbd_set_done_cb(hid_kbd_done_cb_t cb)
{
    s_done_cb = cb;
}

esp_err_t hid_kbd_init(void)
{
    memset(&s_hid_params, 0, sizeof(s_hid_params));

    /* 1) Protocol Mode characteristic (required by HOGP) */
    s_hid_params.proto_mode_present = 1;
    s_hid_params.proto_mode = BLE_SVC_HID_PROTO_MODE_REPORT;

    /* 2) Boot keyboard in/out characteristics (kept for compatibility) */
    s_hid_params.kbd_inp_present = 1;
    s_hid_params.kbd_out_present = 1;
    s_hid_params.kbd_inp_write_perm = 0;

    /* 3) Report map */
    memcpy(s_hid_params.report_map, k_report_map, sizeof(k_report_map));
    s_hid_params.report_map_len = sizeof(k_report_map);
    s_hid_params.external_rpt_ref = 0x180F;

    /* 4) HID information: bcdHID=1.11, country=0, flags=0x03 */
    s_hid_params.hid_info = 0x03000111;

    /* 5) reports: INPUT(id=1, 8B) + OUTPUT(id=1, 1B) */
    s_hid_params.rpts_len = 2;
    s_hid_params.rpts[0].type = BLE_SVC_HID_RPT_TYPE_INPUT;
    s_hid_params.rpts[0].id = 1;
    s_hid_params.rpts[1].type = BLE_SVC_HID_RPT_TYPE_OUTPUT;
    s_hid_params.rpts[1].id = 1;

    /* 6) register (add must precede ble_svc_hid_init()) */
    int rc = ble_svc_hid_add(s_hid_params);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_svc_hid_add failed: %d", rc);
        return ESP_FAIL;
    }

    /* 7) informational callbacks (LED output writes) */
    ble_svc_hid_register_report_write_cb(hid_kbd_on_report_write);

    /* typing task (stack 4096, prio 5 per spec) */
    BaseType_t ok = xTaskCreate(kbd_task, "kbd_task", 4096, NULL, 5, &s_kbd_task);
    if (ok != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "HID keyboard ready (map %u bytes)", (unsigned)sizeof(k_report_map));
    return ESP_OK;
}

esp_err_t hid_kbd_type_string(uint16_t conn_handle, const char *ascii, uint8_t len)
{
    if (s_busy) {
        return ESP_ERR_INVALID_STATE;       /* -> 0x3006 ERR_HID_BUSY */
    }
    if (ascii == NULL || len == 0 || len > CFG_SECRET_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_rpt_in_handle == 0) {
        return ESP_ERR_INVALID_STATE;       /* handles not ready yet */
    }
    /* second charset gate: reject the whole string, never skip characters */
    for (uint8_t i = 0; i < len; i++) {
        if (!kbd_ascii_supported((uint8_t)ascii[i])) {
            return ESP_ERR_INVALID_ARG;     /* -> 0x2007/0x3007 */
        }
    }
    s_busy = true;
    memcpy(s_buf, ascii, len);
    s_len = len;
    s_conn = conn_handle;
    s_abort = false;
    xTaskNotifyGive(s_kbd_task);
    return ESP_OK;
}

void hid_kbd_abort(void)
{
    s_abort = true;
}

bool hid_kbd_busy(void)
{
    return s_busy;
}
