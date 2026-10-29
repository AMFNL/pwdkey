/* usb_hid_kbd.c - USB HID 键盘后端（TinyUSB）
 *
 * 与 ble_hid_kbd.c 并列：都是"把一段 ASCII 逐字符敲出去"，只是物理通道不同。
 *
 * 三条实现要点，全部来自实测踩坑：
 *   1. tud_hid_report() 在端点忙时**静默返回 false 并丢弃报文**。
 *      丢的若是"松开"报文，主机会认为键一直按着 -> Windows typematic 无限重复。
 *      所以每次发送都必须等 tud_hid_ready() 并检查返回值。
 *   2. 每个字符之后必须确认松开；整段输出结束再补发几次。
 *   3. 万一连 release 都发不出去，主动断开 USB 让主机清空按键状态。
 *
 * 前置条件：console 必须已切到 UART（CONFIG_ESP_CONSOLE_UART_DEFAULT=y），
 * 否则 USB-Serial-JTAG 会占着 GPIO19/20，与 USB OTG 冲突。
 */
#include "usb_hid_kbd.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"

#include "tinyusb.h"
#include "class/hid/hid_device.h"

#include "app_cfg.h"

static const char *TAG = "usb_hid";

#define REPORT_ID_KBD     1
#define INTER_CHAR_MS     25      /* press 后、release 后各等这么久；12ms 实测会丢 */
#define TASK_STACK        4096
#define TASK_PRIO         5

/* ---------------- HID 报告描述符（标准 6KRO 键盘）---------------- */

static const uint8_t hid_report_desc[] = {
    TUD_HID_REPORT_DESC_KEYBOARD(HID_REPORT_ID(REPORT_ID_KBD))
};

/* ---------------- USB 描述符 ---------------- */

static const tusb_desc_device_t desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    .bDeviceClass       = 0x00,
    .bDeviceSubClass    = 0x00,
    .bDeviceProtocol    = 0x00,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = 0x303A,       /* Espressif */
    .idProduct          = 0x4001,       /* PwdKey 键盘 */
    .bcdDevice          = 0x0100,
    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,
    .bNumConfigurations = 0x01,
};

static const char *string_desc[] = {
    (const char[]){ 0x09, 0x04 },
    "PwdKey",
    "PwdKey Keyboard",
    "0001",
};

enum { ITF_NUM_HID = 0, ITF_NUM_TOTAL };
#define CONFIG_TOTAL_LEN  (TUD_CONFIG_DESC_LEN + TUD_HID_DESC_LEN)
#define EPNUM_HID         0x81

static const uint8_t desc_configuration[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0, 100),
    TUD_HID_DESCRIPTOR(ITF_NUM_HID, 0, HID_ITF_PROTOCOL_KEYBOARD,
                       sizeof(hid_report_desc), EPNUM_HID, 8, 10),
};

/* ---------------- TinyUSB 回调 ---------------- */

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance)
{
    (void)instance;
    return hid_report_desc;
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                               hid_report_type_t report_type,
                               uint8_t *buffer, uint16_t reqlen)
{
    (void)instance; (void)report_id; (void)report_type; (void)buffer; (void)reqlen;
    return 0;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                           hid_report_type_t report_type,
                           uint8_t const *buffer, uint16_t bufsize)
{
    (void)instance; (void)report_id; (void)report_type; (void)buffer; (void)bufsize;
}

/* ---------------- 键位表（US 布局，与 ble_hid_kbd.c 保持一致）---------------- */

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

static bool kbd_lookup(uint8_t c, uint8_t *mod, uint8_t *code)
{
    if (c >= 0x20 && c <= 0x7E) {
        *mod  = k_ascii_map[c - 0x20].mod;
        *code = k_ascii_map[c - 0x20].code;
        return true;
    }
    switch (c) {
    case '\t': *mod = 0; *code = 0x2B; return true;
    case '\n':
    case '\r': *mod = 0; *code = 0x28; return true;
    case '\b': *mod = 0; *code = 0x2A; return true;
    default:   return false;
    }
}

/* ---------------- 发送 ---------------- */

static SemaphoreHandle_t s_sig;
static TaskHandle_t      s_task;
static volatile bool     s_busy;
static volatile bool     s_abort;
static usb_hid_done_cb_t s_done_cb;

static char    s_buf[CFG_SECRET_MAX + 1];
static uint8_t s_len;

/** 等端点就绪再发；返回值必须检查，否则丢报文会导致粘键 */
static bool send_report(const uint8_t *rpt, size_t len)
{
    int guard = 0;
    while (!tud_hid_ready()) {
        if (++guard > 500) { return false; }     /* 最多等 1 秒 */
        vTaskDelay(pdMS_TO_TICKS(2));
    }
    return tud_hid_report(REPORT_ID_KBD, rpt, len);
}

/** 松开所有键，失败重试 */
static bool release_all(void)
{
    static const uint8_t zeros[8] = { 0 };
    for (int i = 0; i < 8; i++) {
        if (send_report(zeros, sizeof(zeros))) { return true; }
        vTaskDelay(pdMS_TO_TICKS(5));
    }
    return false;
}

static void usb_hid_task(void *arg)
{
    (void)arg;
    while (true) {
        /* 用带超时的等待：超时说明空闲，顺手补一次"全松开"。
         * Windows 的按键重复延迟默认 500ms，300ms 一次足够在它开始重复前纠正。
         * 这样即使别处漏了 release，也不会出现主机一直重复某个键。 */
        if (xSemaphoreTake(s_sig, pdMS_TO_TICKS(300)) != pdTRUE) {
            if (!s_busy && tud_mounted() && tud_hid_ready()) {
                static const uint8_t zeros[8] = { 0 };
                tud_hid_report(REPORT_ID_KBD, zeros, sizeof(zeros));
            }
            continue;
        }

        s_abort = false;
        esp_err_t res = ESP_OK;
        int sent = 0;

        if (!tud_mounted()) {
            ESP_LOGW(TAG, "not mounted, drop output");
            res = ESP_ERR_INVALID_STATE;
        } else {
            for (uint8_t i = 0; i < s_len; i++) {
                if (s_abort) { res = ESP_ERR_INVALID_STATE; break; }

                uint8_t mod = 0, code = 0;
                if (!kbd_lookup((uint8_t)s_buf[i], &mod, &code)) { continue; }

                uint8_t press[8] = { mod, 0, code, 0, 0, 0, 0, 0 };
                if (!send_report(press, sizeof(press))) {
                    ESP_LOGW(TAG, "press failed at %d", i);
                    res = ESP_FAIL;
                    break;
                }
                vTaskDelay(pdMS_TO_TICKS(INTER_CHAR_MS));

                if (!release_all()) {          /* 必须确认松开 */
                    res = ESP_FAIL;
                    break;
                }
                vTaskDelay(pdMS_TO_TICKS(INTER_CHAR_MS));
                sent++;
            }

            /* 收尾：再补几次，确保最后一个字符（尤其回车）不粘 */
            bool ok = false;
            for (int i = 0; i < 3; i++) {
                ok = release_all();
                if (ok) { break; }
                vTaskDelay(pdMS_TO_TICKS(10));
            }
            if (!ok) {
                /* 端点已经卡死，主动断开让主机清空按键状态 */
                ESP_LOGW(TAG, "release stuck, disconnect USB to clear host key state");
                tud_disconnect();
                vTaskDelay(pdMS_TO_TICKS(300));
                tud_connect();
            }
        }

        s_busy = false;
        if (res == ESP_OK) {
            ESP_LOGI(TAG, "typed %d chars over USB", sent);
        }
        if (s_done_cb) { s_done_cb(res); }
    }
}

/* ---------------- 公开 API ---------------- */

esp_err_t usb_hid_init(void)
{
    s_sig = xSemaphoreCreateBinary();
    if (!s_sig) { return ESP_ERR_NO_MEM; }

    const tinyusb_config_t cfg = {
        .port = TINYUSB_PORT_FULL_SPEED_0,
        .task = {
            .size     = 4096,
            .priority = 5,
        },
        .descriptor = {
            .device            = &desc_device,
            .string            = string_desc,
            .string_count      = (int)(sizeof(string_desc) / sizeof(string_desc[0])),
            .full_speed_config = desc_configuration,
        },
    };
    esp_err_t err = tinyusb_driver_install(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tinyusb install failed: %s", esp_err_to_name(err));
        return err;
    }

    if (xTaskCreate(usb_hid_task, "usb_hid", TASK_STACK, NULL, TASK_PRIO, &s_task) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "USB HID backend ready");
    return ESP_OK;
}

bool usb_hid_mounted(void)
{
    return tud_mounted();
}

bool usb_hid_busy(void)
{
    return s_busy;
}

esp_err_t usb_hid_type_string(const char *ascii, uint8_t len)
{
    if (!ascii || len == 0) { return ESP_ERR_INVALID_ARG; }
    if (s_busy) { return ESP_ERR_INVALID_STATE; }
    if (len > CFG_SECRET_MAX) { len = CFG_SECRET_MAX; }

    memcpy(s_buf, ascii, len);
    s_len = len;
    s_busy = true;
    s_abort = false;

    xSemaphoreGive(s_sig);
    return ESP_OK;
}

void usb_hid_abort(void)
{
    if (s_busy) { s_abort = true; }
}

void usb_hid_set_done_cb(usb_hid_done_cb_t cb)
{
    s_done_cb = cb;
}

void usb_hid_keepalive(void)
{
    /* 空闲时补一次"全松开"：万一别处漏了 release，最迟一次调用后就被纠正，
     * 不会出现主机一直重复某个键。由上层定时调用（建议 300ms）。 */
    if (s_busy) { return; }
    if (!tud_mounted() || !tud_hid_ready()) { return; }
    static const uint8_t zeros[8] = { 0 };
    tud_hid_report(REPORT_ID_KBD, zeros, sizeof(zeros));
}
