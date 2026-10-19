/* ble_gap_mgr.c - GAP: advertising (S0/S1/S2), connection tracking, events,
 * pairing (Numeric Comparison via BOOT button), dual-central support.
 * Based on firmware manual v2.1 section 6.9 (incl. C5/C6/C17 fixes).
 */
#include "ble_gap_mgr.h"

#include <string.h>
#include <assert.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/ble_store.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"

#include "app_cfg.h"
#include "audit_log.h"
#include "btn_confirm.h"
#include "ble_hid_kbd.h"
#include "ble_mgmt_svc.h"
#include "sec_session.h"
#include "sec_store.h"
#include "host_reg.h"
#include "host_name_probe.h"

static const char *TAG = "gap_mgr";

static uint8_t  s_own_addr_type;
static int32_t  s_adv_deadline_ms;      /* window deadline (replays use remaining time) */
static gap_mode_t s_mode = GAP_MODE_S1;

/* A connection is identified by handle (volatile) AND peer identity address
 * (stable). The registry of named hosts is keyed on the latter. */
typedef struct {
    uint16_t conn;
    uint8_t  addr[6];
    uint8_t  addr_type;
} conn_slot_t;

static conn_slot_t s_conns[CFG_MAX_LINKS];
static uint8_t     s_conn_cnt;

static uint16_t s_hid[2];
static uint8_t  s_hid_cnt;
static uint16_t s_mgmt[2];
static uint8_t  s_mgmt_cnt;

static TaskHandle_t s_pair_task;
static volatile bool s_pair_pending;
static volatile uint16_t s_pair_conn;

static int32_t now_ms(void)
{
    return (int32_t)(esp_timer_get_time() / 1000);
}

/* Remaining advertising window: BLE_HS_FOREVER for S1 (continuous low-rate
 * advertising keeps the device reachable for management); 0 when expired. */
static int32_t adv_left(void)
{
    if (s_mode == GAP_MODE_S1) {
        return BLE_HS_FOREVER;
    }
    int32_t left = s_adv_deadline_ms - now_ms();
    return left > 0 ? left : 0;
}

static int gap_event_cb(struct ble_gap_event *event, void *arg);

/* ---------------- small-table helpers ---------------- */

static void link_mark(uint16_t conn, uint16_t *arr, uint8_t *cnt, int on)
{
    for (int i = 0; i < *cnt; i++) {
        if (arr[i] == conn) {
            for (int j = i; j < *cnt - 1; j++) {
                arr[j] = arr[j + 1];
            }
            (*cnt)--;
            break;
        }
    }
    if (on && *cnt < 2) {
        arr[*cnt] = conn;
        (*cnt)++;
    }
}

static void link_remove(uint16_t conn, uint16_t *arr, uint8_t *cnt)
{
    link_mark(conn, arr, cnt, 0);
}

static void conn_track_add(uint16_t conn)
{
    for (int i = 0; i < s_conn_cnt; i++) {
        if (s_conns[i].conn == conn) {
            return;
        }
    }
    if (s_conn_cnt >= CFG_MAX_LINKS) {
        return;
    }
    conn_slot_t *slot = &s_conns[s_conn_cnt++];
    memset(slot, 0, sizeof(*slot));
    slot->conn = conn;

    /* Resolve the *identity* address: for bonded peers carrying a resolvable
     * RPA this is the real MAC, which is what we key names on. Falling back to
     * the connect-time address keeps things working before IRK resolution. */
    struct ble_gap_conn_desc d;
    if (ble_gap_conn_find(conn, &d) == 0 && d.peer_id_addr.type != 0xFF) {
        memcpy(slot->addr, d.peer_id_addr.val, 6);
        slot->addr_type = d.peer_id_addr.type;
    } else {
        memset(slot->addr, 0, 6);
        slot->addr_type = 0xFF;
    }
}

static void conn_track_remove(uint16_t conn)
{
    for (int i = 0; i < s_conn_cnt; i++) {
        if (s_conns[i].conn == conn) {
            for (int j = i; j < s_conn_cnt - 1; j++) {
                s_conns[j] = s_conns[j + 1];
            }
            s_conn_cnt--;
            return;
        }
    }
}

bool gap_mgr_conn_addr(uint16_t conn, uint8_t out_addr[6], uint8_t *out_type)
{
    for (int i = 0; i < s_conn_cnt; i++) {
        if (s_conns[i].conn == conn) {
            if (s_conns[i].addr_type == 0xFF) {
                return false;
            }
            if (out_addr != NULL) {
                memcpy(out_addr, s_conns[i].addr, 6);
            }
            if (out_type != NULL) {
                *out_type = s_conns[i].addr_type;
            }
            return true;
        }
    }
    return false;
}

bool gap_mgr_addr_is_online(const uint8_t addr[6])
{
    if (addr == NULL) {
        return false;
    }
    for (int i = 0; i < s_conn_cnt; i++) {
        if (s_conns[i].addr_type != 0xFF &&
            memcmp(s_conns[i].addr, addr, 6) == 0) {
            return true;
        }
    }
    return false;
}

uint16_t gap_mgr_conn_by_addr(const uint8_t addr[6])
{
    if (addr == NULL) {
        return 0xFFFF;
    }
    for (int i = 0; i < s_conn_cnt; i++) {
        if (s_conns[i].addr_type != 0xFF &&
            memcmp(s_conns[i].addr, addr, 6) == 0) {
            return s_conns[i].conn;
        }
    }
    return 0xFFFF;
}

/* ---------------- advertising ---------------- */

static int gap_adv_start(gap_mode_t mode, int32_t dur_ms)
{
    struct ble_hs_adv_fields f = {0};
    struct ble_hs_adv_fields r = {0};
    struct ble_gap_adv_params p = {0};
    static const ble_uuid16_t hid_uuid = BLE_UUID16_INIT(0x1812);
    static const ble_uuid16_t mgmt_uuid = BLE_UUID16_INIT(0xFFF0);
    static ble_uuid16_t rsp_uuids[2];

    ble_gap_adv_stop();     /* harmless if not advertising */

    /* --- main advertising packet --- */
    f.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;   /* = 0x06 */
    const char *name = ble_svc_gap_device_name();
    f.name = (uint8_t *)name;
    f.name_len = strlen(name);                                     /* <= 22 bytes */
    f.name_is_complete = 1;
    if (mode == GAP_MODE_S2) {
        f.appearance = 0x03C1;                                     /* Keyboard */
        f.appearance_is_present = 1;
    }
    if (ble_gap_adv_set_fields(&f) != 0) {
        return -1;
    }

    /* --- scan response --- */
    if (mode == GAP_MODE_S2) {
        rsp_uuids[0] = hid_uuid;
        rsp_uuids[1] = mgmt_uuid;
        r.uuids16 = rsp_uuids;
        r.num_uuids16 = 2;
        r.uuids16_is_complete = 1;
    } else {
        r.uuids16 = &mgmt_uuid;
        r.num_uuids16 = 1;
        r.uuids16_is_complete = 1;
    }
    if (ble_gap_adv_rsp_set_fields(&r) != 0) {
        return -1;
    }

    /* --- start with a timed window (S1: continuous low-rate advertising) --- */
    p.conn_mode = BLE_GAP_CONN_MODE_UND;
    p.disc_mode = BLE_GAP_DISC_MODE_GEN;
    if (mode == GAP_MODE_S1) {
        p.itvl_min = 1600;      /* 1.0s : low-frequency, power-friendly */
        p.itvl_max = 2400;      /* 1.5s */
    } else {
        p.itvl_min = 160;       /* 100ms (unit 0.625ms) */
        p.itvl_max = 240;       /* 150ms */
    }
    if (dur_ms == BLE_HS_FOREVER) {
        s_adv_deadline_ms = INT32_MAX;
    } else {
        s_adv_deadline_ms = now_ms() + dur_ms;
    }
    int rc = ble_gap_adv_start(s_own_addr_type, NULL, dur_ms, &p, gap_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_start failed rc=%d", rc);
    }
    return rc;
}

esp_err_t gap_mgr_set_mode(gap_mode_t mode)
{
    s_mode = mode;
    if (mode == GAP_MODE_S1) {
        /* IMPORTANT: S1 must stay advertising (connectable, low-rate).
         * Without this the device would be unreachable once configured -
         * even ENTER_PAIRING could never be issued (chicken-and-egg). */
        return gap_adv_start(GAP_MODE_S1, BLE_HS_FOREVER) == 0 ? ESP_OK : ESP_FAIL;
    }
    int32_t dur = (mode == GAP_MODE_S0) ? CFG_S0_WINDOW_MS : CFG_S2_WINDOW_MS;
    return gap_adv_start(mode, dur) == 0 ? ESP_OK : ESP_FAIL;
}

gap_mode_t gap_mgr_get_mode(void)
{
    return s_mode;
}

esp_err_t gap_mgr_start_adv_for_second_central(void)
{
    int32_t left = adv_left();
    if (left == 0) {
        left = 1000;    /* small grace window for stage 0.2 validation */
    }
    return gap_adv_start(s_mode, left) == 0 ? ESP_OK : ESP_FAIL;
}

/* ---------------- pairing task (Numeric Comparison via BOOT) ---------------- */

static void gap_pair_task(void *arg)
{
    (void)arg;
    for (;;) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        if (!s_pair_pending) {
            continue;
        }
        uint16_t conn = s_pair_conn;
        s_pair_pending = false;

        /* C6: window must stay below the SM procedure timeout -> 25s */
        int r = btn_wait_result(BTN_REQ_PAIRING, 25000);

        struct ble_sm_io io = {0};
        io.action = BLE_SM_IOACT_NUMCMP;
        io.numcmp_accept = (r == 1) ? 1 : 0;
        int rc = ble_sm_inject_io(conn, &io);
        if (rc == BLE_HS_ENOENT) {
            /* pairing procedure already finished (host timed out / disconnected) */
            ESP_LOGW(TAG, "inject_io: pairing proc gone, rc=%d", rc);
        }
        audit_append(0x0D, conn, NULL, rc == 0 ? 0x0000 : 0x0001);
    }
}

esp_err_t ble_gap_mgr_init(void)
{
    memset(s_conns, 0, sizeof(s_conns));
    s_conn_cnt = 0;
    s_hid_cnt = 0;
    s_mgmt_cnt = 0;
    BaseType_t ok = xTaskCreate(gap_pair_task, "gap_pair", 3072, NULL, 5, &s_pair_task);
    return ok == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
}

/* ---------------- GAP event callback ---------------- */

static int gap_event_cb(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            conn_track_add(event->connect.conn_handle);
            ESP_LOGI(TAG, "connected: conn=%u (total %u)",
                     event->connect.conn_handle, s_conn_cnt);
            /* Register the peer so it shows up in the host list right away,
             * even before its role (HID vs management) is known. */
            if (gap_mgr_conn_addr(event->connect.conn_handle, NULL, NULL)) {
                uint8_t addr[6];
                uint8_t atype;
                gap_mgr_conn_addr(event->connect.conn_handle, addr, &atype);
                host_reg_upsert(addr, atype);
                host_reg_touch(addr);
                name_probe_request(event->connect.conn_handle);
            }
            /* keep advertising while we have room for another central */
            int32_t left = adv_left();
            if (s_conn_cnt < CFG_MAX_LINKS && left != 0) {
                gap_adv_start(s_mode, left);
            } else {
                ble_gap_adv_stop();
            }
        } else {
            int32_t left = adv_left();
            if (left != 0) {
                gap_adv_start(s_mode, left);
            }
        }
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "disconnected: conn=%u reason=%d",
                 event->disconnect.conn.conn_handle, event->disconnect.reason);
        name_probe_abort(event->disconnect.conn.conn_handle);
        conn_track_remove(event->disconnect.conn.conn_handle);
        session_on_disconnect(event->disconnect.conn.conn_handle);
        link_remove(event->disconnect.conn.conn_handle, s_hid, &s_hid_cnt);
        link_remove(event->disconnect.conn.conn_handle, s_mgmt, &s_mgmt_cnt);
        {
            int32_t left = adv_left();
            if (left != 0) {
                gap_adv_start(s_mode, left);
            }
        }
        mgmt_notify_status();
        return 0;

    case BLE_GAP_EVENT_ADV_COMPLETE:
        if (s_mode == GAP_MODE_S0) {
            /* spec 5.5: S0 timeout -> reboot back into S0 */
            ESP_LOGW(TAG, "S0 window expired, restarting into factory state");
            esp_restart();
        } else if (s_mode == GAP_MODE_S2) {
            ESP_LOGI(TAG, "S2 window expired -> S1");
            s_mode = GAP_MODE_S1;
            btn_confirm_cancel_pairing();
            gap_adv_start(GAP_MODE_S1, BLE_HS_FOREVER);
            mgmt_notify_status();
        } else {
            /* defensive: S1 advertises forever, should not reach here */
            gap_adv_start(GAP_MODE_S1, BLE_HS_FOREVER);
        }
        return 0;

    case BLE_GAP_EVENT_SUBSCRIBE:
        if (hid_kbd_is_report_char(event->subscribe.attr_handle)) {
            link_mark(event->subscribe.conn_handle, s_hid, &s_hid_cnt,
                      event->subscribe.cur_notify);
        } else if (mgmt_is_notify_char(event->subscribe.attr_handle)) {
            link_mark(event->subscribe.conn_handle, s_mgmt, &s_mgmt_cnt,
                      event->subscribe.cur_notify);
        }
        mgmt_notify_status();
        return 0;

    case BLE_GAP_EVENT_MTU:
        ESP_LOGI(TAG, "mtu=%u (conn=%u)", event->mtu.value, event->mtu.conn_handle);
        return 0;

    case BLE_GAP_EVENT_ENC_CHANGE:
        ESP_LOGI(TAG, "enc_change status=%d", event->enc_change.status);
        /* Once encrypted, NimBLE can resolve a private resolvable address into
         * the peer's real MAC - that MAC is what the host registry keys on. */
        if (event->enc_change.status == 0) {
            gap_mgr_refresh_addrs();
            uint8_t addr[6];
            uint8_t atype;
            if (gap_mgr_conn_addr(event->enc_change.conn_handle, addr, &atype)) {
                name_probe_request(event->enc_change.conn_handle);
            }
        }
        /* note: no audit entry here - the event table has no matching type;
         * AUTH_VERIFY (0x06) auditing happens in the mgmt layer */
        return 0;

    case BLE_GAP_EVENT_PASSKEY_ACTION: {
        /* C17: this branch must never fall through - handle and return! */
        struct ble_gap_passkey_params *pp = &event->passkey.params;
        if (pp->action == BLE_SM_IOACT_NUMCMP) {
            btn_req_t req = { .type = BTN_REQ_PAIRING,
                              .conn_handle = event->passkey.conn_handle,
                              .arg = pp->numcmp };
            if (btn_confirm_post(&req) != ESP_OK) {
                /* C6: another waiter is busy -> reject immediately, do not queue */
                struct ble_sm_io rej = { .action = BLE_SM_IOACT_NUMCMP, .numcmp_accept = 0 };
                ble_sm_inject_io(event->passkey.conn_handle, &rej);
            } else {
                s_pair_conn = event->passkey.conn_handle;
                s_pair_pending = true;
                xTaskNotifyGive(s_pair_task);
            }
        } else if (pp->action != BLE_SM_IOACT_NONE) {
            struct ble_sm_io rej = { .action = pp->action, .numcmp_accept = 0 };
            ble_sm_inject_io(event->passkey.conn_handle, &rej);
        }
        return 0;
    }

    case BLE_GAP_EVENT_REPEAT_PAIRING: {
        struct ble_gap_conn_desc d;
        if (ble_gap_conn_find(event->repeat_pairing.conn_handle, &d) == 0) {
            ble_store_util_delete_peer(&d.peer_id_addr);
        }
        return BLE_GAP_REPEAT_PAIRING_RETRY;
    }

    case BLE_GAP_EVENT_CONN_UPDATE:
        return 0;

    default:
        return 0;
    }
}

/* ---------------- sync / reset ---------------- */

void ble_gap_mgr_on_sync(void)
{
    int rc = ble_hs_util_ensure_addr(0);
    assert(rc == 0);
    rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
    assert(rc == 0);

    hid_kbd_dump_handles();     /* task 0.3 self test */

    if (!cred_exists()) {
        gap_mgr_set_mode(GAP_MODE_S0);      /* factory state: advertise 120s */
    } else {
        gap_mgr_set_mode(GAP_MODE_S1);      /* normal: silent until ENTER_PAIRING */
    }
}

void ble_gap_mgr_on_reset(int reason)
{
    ESP_LOGE(TAG, "NimBLE host reset, reason=%d", reason);
}

/* ---------------- queries ---------------- */

uint8_t gap_mgr_hid_link_count(void)
{
    return s_hid_cnt;
}

uint16_t gap_mgr_hid_link_at(uint8_t idx)
{
    return idx < s_hid_cnt ? s_hid[idx] : 0;
}

/* Identity address of HID link #idx. Returns false when the address has not
 * been resolved yet (unresolved RPA) - callers must treat that as "unknown". */
bool gap_mgr_hid_addr_at(uint8_t idx, uint8_t out_addr[6], uint8_t *out_type)
{
    if (idx >= s_hid_cnt) {
        return false;
    }
    return gap_mgr_conn_addr(s_hid[idx], out_addr, out_type);
}

/* Re-resolve identity addresses for every live link. Called after encryption
 * changes, which is when NimBLE finally resolves a peer's RPA into its real
 * MAC. Without this, bonded hosts would stay "unknown address" forever. */
void gap_mgr_refresh_addrs(void)
{
    for (int i = 0; i < s_conn_cnt; i++) {
        struct ble_gap_conn_desc d;
        if (ble_gap_conn_find(s_conns[i].conn, &d) != 0) {
            continue;
        }
        if (d.peer_id_addr.type == 0xFF) {
            continue;               /* still unresolved, keep as-is */
        }
        memcpy(s_conns[i].addr, d.peer_id_addr.val, 6);
        s_conns[i].addr_type = d.peer_id_addr.type;
        host_reg_upsert(s_conns[i].addr, s_conns[i].addr_type);
    }
}

uint8_t gap_mgr_mgmt_link_count(void)
{
    return s_mgmt_cnt;
}

uint16_t gap_mgr_mgmt_link_at(uint8_t idx)
{
    return idx < s_mgmt_cnt ? s_mgmt[idx] : 0;
}

bool gap_mgr_conn_alive(uint16_t conn_handle)
{
    struct ble_gap_conn_desc d;
    return ble_gap_conn_find(conn_handle, &d) == 0;
}

uint8_t gap_mgr_conn_count(void)
{
    return s_conn_cnt;
}

void gap_mgr_terminate_all(void)
{
    for (int i = 0; i < s_conn_cnt; i++) {
        ble_gap_terminate(s_conns[i].conn, BLE_ERR_REM_USER_CONN_TERM);
    }
}
