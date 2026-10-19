/* host_name_probe.c - best-effort discovery of the *central's* Bluetooth name.
 *
 * A BLE peripheral never sees the central's advertising data, so the only way
 * to learn a PC's name is to turn the link around: after connecting, act as a
 * GATT client against the peer and read its GAP "Device Name" (0x2A00).
 *
 * Reality check (documented in the user manual):
 *   - Android / iOS / Linux BlueZ expose a GATT server -> the name is readable.
 *   - Windows usually does NOT -> the peer keeps its MAC-derived fallback name.
 * Either way nothing breaks: every host always has a fallback name, and a user
 * assigned name always takes precedence over whatever we probe here.
 *
 * Everything here runs in NimBLE host-task context (the GAP event callback and
 * the GATT callbacks), so no extra locking is needed. One probe at a time.
 */
#include "host_name_probe.h"

#include <string.h>

#include "esp_log.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/ble_hs_mbuf.h"
#include "host/ble_uuid.h"
#include "os/os_mbuf.h"

#include "ble_gap_mgr.h"
#include "host_reg.h"

static const char *TAG = "name_probe";

#define UUID_GAP_SERVICE     0x1800
#define UUID_DEVICE_NAME     0x2A00

typedef enum { ST_FREE = 0, ST_SVC, ST_CHR, ST_READ } probe_state_t;

static struct {
    probe_state_t state;
    uint16_t      conn;
    uint8_t       addr[6];
    uint8_t       addr_type;
    uint16_t      svc_start;
    uint16_t      svc_end;
    uint16_t      name_handle;
} s_probe;

static void probe_reset(void)
{
    memset(&s_probe, 0, sizeof(s_probe));
    s_probe.state = ST_FREE;
}

/* ---------------- step 3: read 0x2A00 ---------------- */

static int read_cb(uint16_t conn, const struct ble_gatt_error *error,
                   struct ble_gatt_attr *attr, void *arg)
{
    (void)arg;
    if (s_probe.state != ST_READ || s_probe.conn != conn) {
        return 0;
    }
    if (error->status != 0 || attr == NULL || attr->om == NULL) {
        ESP_LOGD(TAG, "name read failed: %d", error->status);
        probe_reset();
        return 0;
    }
    size_t total = OS_MBUF_PKTLEN(attr->om);
    if (total == 0) {
        probe_reset();
        return 0;
    }
    if (total > HOST_NAME_MAX - 1) {
        total = HOST_NAME_MAX - 1;
    }
    char buf[HOST_NAME_MAX];
    if (ble_hs_mbuf_to_flat(attr->om, buf, (uint16_t)total, NULL) != 0) {
        probe_reset();
        return 0;
    }
    buf[total] = '\0';

    uint8_t addr[6];
    uint8_t atype;
    memcpy(addr, s_probe.addr, 6);
    atype = s_probe.addr_type;
    host_reg_set_autoname(addr, atype, buf, total);
    probe_reset();
    return 0;
}

/* ---------------- step 2: discover characteristics inside GAP ---------------- */

static int chr_cb(uint16_t conn, const struct ble_gatt_error *error,
                  const struct ble_gatt_chr *chr, void *arg)
{
    (void)arg;
    if (s_probe.state != ST_CHR || s_probe.conn != conn) {
        return 0;
    }
    if (error->status == BLE_HS_EDONE) {
        if (s_probe.name_handle != 0) {
            int rc = ble_gattc_read(conn, s_probe.name_handle, read_cb, NULL);
            if (rc != 0) {
                ESP_LOGD(TAG, "read start failed: %d", rc);
                probe_reset();
                return 0;
            }
            s_probe.state = ST_READ;
            return 0;
        }
        ESP_LOGD(TAG, "peer has no Device Name characteristic");
        probe_reset();
        return 0;
    }
    if (error->status != 0) {
        probe_reset();
        return 0;
    }
    if (chr == NULL) {
        return 0;
    }
    if (chr->uuid.u.type == BLE_UUID_TYPE_16 &&
        chr->uuid.u16.value == UUID_DEVICE_NAME) {
        s_probe.name_handle = chr->val_handle;
    }
    return 0;
}

/* ---------------- step 1: discover all services ---------------- */

static int svc_cb(uint16_t conn, const struct ble_gatt_error *error,
                  const struct ble_gatt_svc *svc, void *arg)
{
    (void)arg;
    if (s_probe.state != ST_SVC || s_probe.conn != conn) {
        return 0;
    }
    if (error->status == BLE_HS_EDONE) {
        if (s_probe.svc_start != 0) {
            int rc = ble_gattc_disc_all_chrs(conn, s_probe.svc_start,
                                             s_probe.svc_end, chr_cb, NULL);
            if (rc != 0) {
                ESP_LOGD(TAG, "chr discovery failed: %d", rc);
                probe_reset();
                return 0;
            }
            s_probe.state = ST_CHR;
            return 0;
        }
        ESP_LOGD(TAG, "peer exposes no GAP service");
        probe_reset();
        return 0;
    }
    if (error->status != 0) {
        probe_reset();
        return 0;
    }
    if (svc == NULL) {
        return 0;
    }
    if (svc->uuid.u.type == BLE_UUID_TYPE_16 &&
        svc->uuid.u16.value == UUID_GAP_SERVICE) {
        s_probe.svc_start = svc->start_handle;
        s_probe.svc_end = svc->end_handle;
    }
    return 0;
}

/* ---------------- public API ---------------- */

void name_probe_request(uint16_t conn)
{
    uint8_t addr[6];
    uint8_t atype;
    if (!gap_mgr_conn_addr(conn, addr, &atype)) {
        return;                     /* address not resolved yet */
    }
    const host_rec_t *r = host_reg_find(addr);
    if (r != NULL && (r->flags & HOST_FLAG_USER_NAMED)) {
        return;                     /* user already named it - leave it alone */
    }

    probe_reset();
    s_probe.conn = conn;
    memcpy(s_probe.addr, addr, 6);
    s_probe.addr_type = atype;

    int rc = ble_gattc_disc_all_svcs(conn, svc_cb, NULL);
    if (rc != 0) {
        ESP_LOGD(TAG, "svc discovery failed to start: %d", rc);
        probe_reset();
        return;
    }
    s_probe.state = ST_SVC;
    ESP_LOGD(TAG, "probing name of conn=%u", conn);
}

void name_probe_abort(uint16_t conn)
{
    if (s_probe.conn == conn && s_probe.state != ST_FREE) {
        probe_reset();
    }
}
