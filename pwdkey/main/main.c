/* main.c - PwdKey initialization sequence (firmware manual v2.1 section 4.2).
 *
 * Order (two red lines included):
 *  A. btn_confirm_init()                 GPIO0 input, no NVS dependency
 *  B. nvs_flash_init()                   MUST precede NimBLE (red line 1)
 *  C. btn_boot_factory_reset_check()     hold >=5s at boot -> erase + reboot
 *  D. sec_store / rekey recovery / sec_session / audit_log
 *  E. nimble_port_init()                 controller + host
 *  F. ble_hs_cfg security params + 3 callbacks  (MUST precede host task)
 *  G. GAP/GATT services + device name
 *  H. hid_kbd_init()                     fill params -> ble_svc_hid_add()
 *  I. mgmt_svc_init()                    custom service count + add
 *  J. bas/dis init, battery = 100, PnP ID
 *  K. ble_svc_hid_init()                 MUST come after H
 *  L. nimble_port_freertos_init(host_task) -> sync_cb -> advertising
 *  M. app_main returns (frees the small main task stack)
 */
#include "esp_err.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_sm.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "services/bas/ble_svc_bas.h"
#include "services/dis/ble_svc_dis.h"
#include "services/hid/ble_svc_hid.h"

#include "app_cfg.h"
#include "btn_confirm.h"
#include "kdf.h"
#include "sec_store.h"
#include "sec_session.h"
#include "audit_log.h"
#include "ble_hid_kbd.h"
#include "host_reg.h"
#include "ble_mgmt_svc.h"
#include "ble_gap_mgr.h"

static const char *TAG = "main";

/* static buffers: DIS/GAP setters store pointers only */
static char s_dev_name[24];                            /* loaded from NVS sys.dev_name (C13) */
static const char s_manufacturer[] = "PwdKey";
/* PnP ID = 7 data bytes + 1 strlen terminator. ble_svc_dis_pnp_id_set() computes
 * the length with strlen() => all 7 bytes MUST be non-zero (C16).
 * Values: VendorIDSource=0x02(USB), VID=0x0303, PID=0x0101, Version=0x0101 */
static const char s_pnp_id[8] = { 0x02, 0x03, 0x03, 0x01, 0x01, 0x01, 0x01, 0x00 };

static void nimble_host_task(void *arg)
{
    (void)arg;
    nimble_port_run();                 /* does not return */
    nimble_port_freertos_deinit();
}

void app_main(void)
{
    /* A. button first (no NVS needed) */
    ESP_ERROR_CHECK(btn_confirm_init());

    /* B. NVS - must precede NimBLE */
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    /* C. power-on hold >=5s on BOOT = factory reset (pure physical path) */
    if (btn_boot_factory_reset_check()) {
        ESP_LOGW(TAG, "Factory reset by BOOT key, rebooting...");
        nvs_flash_erase();
        esp_restart();
    }

    /* D. storage / sessions / audit */
    ESP_ERROR_CHECK(sec_store_init());
    store_rekey_rollback_recover_on_boot();    /* power-loss recovery for rekey */
    sec_session_init();
    ESP_ERROR_CHECK(audit_log_init());
    ESP_ERROR_CHECK(host_reg_init());      /* named-host registry (own NVS namespace) */

    /* E. NimBLE controller + host */
    ESP_ERROR_CHECK(nimble_port_init());

    /* F. security parameters (global singleton; set before host task starts) */
    ble_hs_cfg.sm_bonding        = 1;
    ble_hs_cfg.sm_mitm           = 0;                     /* stage 0; stage 1: 1 + SM_LVL=3 */
    ble_hs_cfg.sm_io_cap         = BLE_SM_IO_CAP_NO_IO;   /* stage 1: BLE_SM_IO_CAP_DISP_YES_NO */
    ble_hs_cfg.sm_our_key_dist   = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sync_cb           = ble_gap_mgr_on_sync;
    ble_hs_cfg.reset_cb          = ble_gap_mgr_on_reset;
    ble_hs_cfg.gatts_register_cb = hid_kbd_on_gatt_register;  /* HID report handle capture */

    /* G. GAP / GATT base services */
    sec_store_get_dev_name(s_dev_name, sizeof(s_dev_name));
    ble_svc_gap_device_name_set(s_dev_name);
    ble_svc_gap_device_appearance_set(0x03C1);            /* Keyboard */
    ble_svc_gap_init();
    ble_svc_gatt_init();

    /* G2. GAP manager (pairing task etc.) */
    ESP_ERROR_CHECK(ble_gap_mgr_init());

    /* H. HID keyboard (add must precede ble_svc_hid_init) */
    ESP_ERROR_CHECK(hid_kbd_init());

    /* I. custom management service */
    ESP_ERROR_CHECK(mgmt_svc_init());

    /* J. BAS / DIS */
    ble_svc_bas_init();
    ble_svc_bas_battery_level_set(100);
    ble_svc_dis_init();
    ble_svc_dis_manufacturer_name_set(s_manufacturer);
    ble_svc_dis_pnp_id_set(s_pnp_id);   /* iOS requirement; value has no 0x00 (C16) */

    /* K. HID service registration (after H, before host start) */
    ble_svc_hid_init();

    /* L. start host task */
    nimble_port_freertos_init(nimble_host_task);

    /* M. app_main returns - frees the main task stack */
    ESP_LOGI(TAG, "init done");
}
