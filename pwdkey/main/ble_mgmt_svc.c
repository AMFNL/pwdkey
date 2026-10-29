/* ble_mgmt_svc.c - management GATT service (0xFFF0), spec v1.2.
 *
 * Responsibilities:
 *  - GATT table: 0xFFF1 Challenge (R), 0xFFF2 AuthRsp (W), 0xFFF3 Command (W),
 *                0xFFF4 Response (R+N), 0xFFF5 Status (R+N)
 *  - frame reassembly (6-byte header), TLV codec, command dispatch (15 ops)
 *  - HALF-SYNC / ASYNC responses over 0xFFF4
 *  - slow operations (PWD_TYPE / AUTH_NEW / FACTORY_RESET / ENTER_PAIRING)
 *    run on a dedicated worker so the command task never blocks.
 *
 * Design notes implemented per spec v1.2:
 *  - STATE is 16-bit LE, PWD_TYPE requires auth fresher than 30s (0x400B),
 *    PWD_TYPE HALF-SYNC carries TIMEOUT_MS, AUTH_NEW step2 PROOF uses the
 *    OLD verifier, nonce re-issue invalidates the previous one.
 */
#include "ble_mgmt_svc.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/ble_gatt.h"
#include "host/ble_gap.h"
#include "host/util/util.h"
#include "os/os_mbuf.h"

#include "app_cfg.h"
#include "kdf.h"
#include "audit_log.h"
#include "btn_confirm.h"
#include "sec_store.h"
#include "sec_session.h"
#include "ble_gap_mgr.h"
#include "ble_hid_kbd.h"
#include "usb_hid_kbd.h"
#include "host_reg.h"

static const char *TAG = "mgmt";

/* 加密导出命令（实现放在文件末尾，这里先声明） */
static void h_pwd_export_begin(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len);
static void h_pwd_export_chunk(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len);
static void export_cooldown_boot(void);
static void h_recovery_setup(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len);
static void h_recovery_restore(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len);

/* ---------------- constants ---------------- */

#define MGMT_SVC_UUID16     0xFFF0
#define MGMT_SVC_BASE_FLAGS (BLE_GATT_CHR_F_READ_ENC | BLE_GATT_CHR_F_WRITE_ENC)

/* opcodes */
#define OP_DEVICE_INFO      0x01
#define OP_AUTH_START       0x02
#define OP_AUTH_VERIFY      0x03
#define OP_AUTH_LOCK        0x04
#define OP_AUTH_STATUS      0x05
#define OP_AUTH_NEW         0x06
#define OP_FACTORY_RESET    0x07
#define OP_PWD_LIST         0x20
#define OP_PWD_ADD          0x21
#define OP_PWD_UPDATE       0x22
#define OP_PWD_DELETE       0x23
#define OP_PWD_TYPE         0x24
#define OP_ATTR_GET         0x25
#define OP_PWD_EXPORT_BEGIN 0x26      /* 开始加密导出（需 BOOT 确认） */
#define OP_PWD_EXPORT_CHUNK 0x27      /* 按偏移取密文块 */
#define OP_RECOVERY_SETUP   0x28      /* 生成 5 份恢复码（需 BOOT） */
#define OP_RECOVERY_RESTORE 0x29      /* 用 3 份恢复码重设主密码 */
#define OP_ENTER_PAIRING    0x40
#define OP_AUDIT_READ       0x41
#define OP_HOST_LIST        0x42      /* named hosts (connected PCs) */
#define OP_HOST_RENAME      0x43      /* assign a user-defined name to a MAC */
#define OP_HOST_DISCONNECT  0x44      /* drop one specific host link */

/* TLV tags */
#define T_ENTRY_ID      0x01
#define T_NAME          0x02
#define T_SECRET        0x03
#define T_NONCE         0x04
#define T_PROOF         0x05
#define T_SESSION_ID    0x06
#define T_REQUEST_ID    0x07
#define T_RESULT_CODE   0x08
#define T_STATE         0x09
#define T_FW_VERSION    0x0A
#define T_ENTRY_COUNT   0x0B
#define T_LOCK_SECONDS  0x0C
#define T_AUDIT_RECORD  0x0D
#define T_AUDIT_OFFSET  0x0E
#define T_RECOVERY_CODE 0x10
#define T_CONFIRM_TOKEN 0x11
#define T_TARGET_HANDLE 0x12
#define T_LAYOUT        0x13
#define T_TIMEOUT_MS    0x14
#define T_ERR_DETAIL    0x16
#define T_PAGE_INDEX    0x17
#define T_PART_INDEX    0x18
#define T_SALT          0x19
#define T_KDF_ITER      0x1A
#define T_SESSION_SEQ   0x1B
#define T_KEK_BLOB      0x1C
#define T_NEW_SALT      0x1D
#define T_HOST_ADDR     0x20      /* 6 bytes, peer identity address */
#define T_HOST_NAME     0x21      /* UTF-8, <= HOST_NAME_MAX-1 */
#define T_HOST_FLAGS    0x22      /* 1 byte, see HOST_FLAG_* */
#define T_HOST_COUNT    0x23      /* 1 byte, total records (for paging) */
/* 加密导出（0x26/0x27） */
#define T_EXPORT_WRAPPED 0x30     /* 60B: wrap_nonce(12)+ct(32)+tag(16) */
#define T_EXPORT_NONCE   0x31     /* 12B: data 的 GCM nonce */
#define T_EXPORT_TOTAL   0x32     /* 4B LE: 密文总长 */
#define T_EXPORT_OFFSET  0x33     /* 4B LE: 块偏移 */
#define T_EXPORT_DATA    0x34     /* 密文块 */
/* 恢复码（0x28/0x29） */
#define T_REC_IDX   0x35          /* 1 字节：第几份（1..5） */
#define T_REC_DATA  0x36          /* 16 字节：该份内容 */

/* errors */
#define E_OK            0x0000
#define E_INTERNAL      0x0001
#define E_BUSY          0x0002
#define E_UNSUPPORTED   0x1000
#define E_MISSING       0x1001
#define E_VERSION       0x1002
#define E_MALFORMED     0x1003
#define E_BAD_MAGIC     0x1004
#define E_SEQUENCE      0x1005
#define E_ASM_TIMEOUT   0x1006
#define E_FRAME_LARGE   0x1007
#define E_STORAGE_FULL  0x2001
#define E_NAME_LONG     0x2002
#define E_ID_CONFLICT   0x2003
#define E_SECRET_LONG   0x2004
#define E_NOT_FOUND     0x2005
#define E_STORAGE_IO    0x2006
#define E_CHARSET       0x2007
#define E_NO_HID        0x3001
#define E_HID_AMBIG     0x3002
#define E_CONF_TIMEOUT  0x3003
#define E_CONF_DENIED   0x3004
#define E_HID_DISC      0x3005
#define E_HID_BUSY      0x3006
#define E_LAYOUT        0x3007
#define E_AUTH_FAILED   0x4001
#define E_NOT_AUTH      0x4002
#define E_LOCKED_TEMP   0x4003
#define E_LOCKED_PERM   0x4004
#define E_NONCE         0x4005
#define E_NOT_ALLOWED   0x4006
#define E_WEAK_SECRET   0x4008
#define E_RECOVERY_BAD  0x4009
#define E_KEK_MISSING   0x400A
#define E_AUTH_STALE    0x400B

/* frame flags */
#define F_CRITICAL  0x01
#define F_MORE      0x02
#define F_LAST      0x04
#define F_RESP      0x08

#define FW_MAJOR 0
#define FW_MINOR 1
#define FW_PATCH 0

#define CFG_DEFAULT_KDF_ITER    200000UL      /* stage-0.8 benchmark will overwrite */

/* ---------------- GATT table ---------------- */

static uint16_t s_h_chal, s_h_authrsp, s_h_cmd, s_h_resp, s_h_status;
static const ble_uuid16_t u_svc = BLE_UUID16_INIT(MGMT_SVC_UUID16);

static int mgmt_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                          struct ble_gatt_access_ctxt *ctxt, void *arg);

static const struct ble_gatt_svc_def s_mgmt_svc[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &u_svc.u,
        .characteristics = (struct ble_gatt_chr_def[]) {
            {   /* 0xFFF1 Auth Challenge: Read -> NONCE(32) || SEQ(4, LE) */
                .uuid = BLE_UUID16_DECLARE(0xFFF1), .access_cb = mgmt_access_cb,
                .flags = BLE_GATT_CHR_F_READ | MGMT_SVC_BASE_FLAGS, .val_handle = &s_h_chal,
            },
            {   /* 0xFFF2 Auth Response: Write (reserved channel) */
                .uuid = BLE_UUID16_DECLARE(0xFFF2), .access_cb = mgmt_access_cb,
                .flags = BLE_GATT_CHR_F_WRITE | MGMT_SVC_BASE_FLAGS, .val_handle = &s_h_authrsp,
            },
            {   /* 0xFFF3 Command: Write Request - App command entry */
                .uuid = BLE_UUID16_DECLARE(0xFFF3), .access_cb = mgmt_access_cb,
                .flags = BLE_GATT_CHR_F_WRITE | MGMT_SVC_BASE_FLAGS, .val_handle = &s_h_cmd,
            },
            {   /* 0xFFF4 Response: Read + Notify */
                .uuid = BLE_UUID16_DECLARE(0xFFF4), .access_cb = mgmt_access_cb,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY | MGMT_SVC_BASE_FLAGS,
                .val_handle = &s_h_resp,
            },
            {   /* 0xFFF5 Status: Read + Notify */
                .uuid = BLE_UUID16_DECLARE(0xFFF5), .access_cb = mgmt_access_cb,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY | MGMT_SVC_BASE_FLAGS,
                .val_handle = &s_h_status,
            },
            { 0 }
        },
    },
    { 0 }
};

/* ---------------- internal state ---------------- */

typedef struct {
    uint16_t conn;
    uint16_t len;
    uint8_t  data[260];
} rx_item_t;

typedef struct {
    bool     active;
    uint16_t conn;
    uint8_t  opcode;
    uint16_t total_len;
    uint16_t recv;
    int64_t  last_ms;
    uint8_t  buf[CFG_TLV_VALUE_MAX + 8];
} reasm_t;

typedef enum {
    JOB_PWD_TYPE = 1,
    JOB_AUTHNEW_SETUP,
    JOB_AUTHNEW_STEP1,
    JOB_AUTHNEW_STEP2,
    JOB_AUTHNEW_RECOVERY,
    JOB_FACTORY_EXEC,
    JOB_ENTER_PAIRING,
} heavy_job_type_t;

typedef struct {
    heavy_job_type_t type;
    uint16_t conn;
    uint16_t rid;
    uint8_t  entry_id[8];
    uint8_t  target8;           /* TARGET_HANDLE low byte, 0xFF = none */
    uint16_t hid_conn;          /* picked HID link (PWD_TYPE) */
    bool     via_usb;           /* PWD_TYPE 走 USB 通道，而非 BLE */
    uint32_t timeout_ms;
    uint8_t  tlv[512];
    uint16_t tlv_len;
} heavy_job_t;

static QueueHandle_t s_rx_q;
static QueueHandle_t s_heavy_q;
static reasm_t s_reasm;

static uint32_t s_last_resp_len;
static uint8_t  s_last_resp[512];

static SemaphoreHandle_t s_type_done_sem;
static volatile esp_err_t s_type_done_result;

static volatile bool s_confirm_pending;
static volatile bool s_heavy_busy;

static uint16_t s_rid_ctr;

typedef struct { bool used; uint16_t conn; uint32_t id; } sessid_t;
static sessid_t s_sessid[CFG_MAX_LINKS];

typedef struct {
    bool     active;
    uint16_t conn;
    uint8_t  salt[16];
    int64_t  t0;
} authnew_pending_t;
static authnew_pending_t s_authnew;

typedef struct {
    bool     valid;
    uint16_t conn;
    uint8_t  token[4];
    int64_t  t0;
} factory_token_t;
static factory_token_t s_factory_token;

/* ---------------- small helpers ---------------- */

static int64_t now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

static uint16_t rid_next(void)
{
    return ++s_rid_ctr;
}

static uint32_t sessid_get(uint16_t conn)
{
    for (int i = 0; i < CFG_MAX_LINKS; i++) {
        if (s_sessid[i].used && s_sessid[i].conn == conn) {
            return s_sessid[i].id;
        }
    }
    return 0;
}

static void sessid_set(uint16_t conn, uint32_t id)
{
    for (int i = 0; i < CFG_MAX_LINKS; i++) {
        if (s_sessid[i].used && s_sessid[i].conn == conn) {
            s_sessid[i].id = id;
            return;
        }
    }
    for (int i = 0; i < CFG_MAX_LINKS; i++) {
        if (!s_sessid[i].used) {
            s_sessid[i].used = true;
            s_sessid[i].conn = conn;
            s_sessid[i].id = id;
            return;
        }
    }
}

static void sessid_clear(uint16_t conn)
{
    for (int i = 0; i < CFG_MAX_LINKS; i++) {
        if (s_sessid[i].used && s_sessid[i].conn == conn) {
            s_sessid[i].used = false;
        }
    }
}

/* drop id slots whose session vanished (expiry / lock / disconnect) */
static void sessid_cleanup(void)
{
    for (int i = 0; i < CFG_MAX_LINKS; i++) {
        if (s_sessid[i].used && !session_valid(s_sessid[i].conn)) {
            s_sessid[i].used = false;
        }
    }
}

static uint16_t state_for_conn(uint16_t conn)
{
    uint16_t b = 0;
    if (conn != 0xFFFF && session_valid(conn)) {
        b |= 0x0001;
    }
    if (conn != 0xFFFF) {
        struct ble_gap_conn_desc d;
        if (ble_gap_conn_find(conn, &d) == 0 && d.sec_state.bonded) {
            b |= 0x0002;
        }
    }
    if (s_confirm_pending) {
        b |= 0x0004;
    }
    uint8_t ls = sys_lock_state();
    if (ls == 1) {
        b |= 0x0008;
    } else if (ls == 2) {
        b |= 0x0010;
    }
    uint8_t hc = gap_mgr_hid_link_count();
    if (hc == 1) {
        b |= 0x0020;
    } else if (hc >= 2) {
        b |= 0x0040;
    }
    if (gap_mgr_get_mode() == GAP_MODE_S2) {
        b |= 0x0080;
    }
    if (cred_exists()) {
        b |= 0x0100;
    }
    return b;
}

uint16_t mgmt_state_bitmap(void)
{
    return state_for_conn(0xFFFF);
}

/* ---------------- TLV helpers ---------------- */

static int tlv_put(uint8_t *buf, uint16_t cap, uint16_t *off,
                   uint8_t tag, const void *val, uint16_t vlen)
{
    if (*off + 3u + vlen > cap) {
        return -1;
    }
    buf[(*off)++] = tag;
    buf[(*off)++] = (uint8_t)(vlen & 0xFF);
    buf[(*off)++] = (uint8_t)(vlen >> 8);
    if (vlen) {
        memcpy(buf + *off, val, vlen);
        *off += vlen;
    }
    return 0;
}

static int tlv_put_u8(uint8_t *buf, uint16_t cap, uint16_t *off, uint8_t tag, uint8_t v)
{
    return tlv_put(buf, cap, off, tag, &v, 1);
}

static int tlv_put_u16(uint8_t *buf, uint16_t cap, uint16_t *off, uint8_t tag, uint16_t v)
{
    uint8_t b[2] = { (uint8_t)(v & 0xFF), (uint8_t)(v >> 8) };
    return tlv_put(buf, cap, off, tag, b, 2);
}

static int tlv_put_u32(uint8_t *buf, uint16_t cap, uint16_t *off, uint8_t tag, uint32_t v)
{
    uint8_t b[4] = { (uint8_t)(v & 0xFF), (uint8_t)((v >> 8) & 0xFF),
                     (uint8_t)((v >> 16) & 0xFF), (uint8_t)((v >> 24) & 0xFF) };
    return tlv_put(buf, cap, off, tag, b, 4);
}

static bool tlv_get(const uint8_t *buf, uint16_t len, uint8_t tag,
                    const uint8_t **out, uint16_t *out_len)
{
    uint16_t i = 0;
    while (i + 3 <= len) {
        uint8_t t = buf[i];
        uint16_t l = (uint16_t)buf[i + 1] | ((uint16_t)buf[i + 2] << 8);
        if (i + 3u + l > len) {
            return false;       /* malformed */
        }
        if (t == tag) {
            *out = buf + i + 3;
            *out_len = l;
            return true;
        }
        i += 3 + l;             /* skip unknown tags */
    }
    return false;
}

static uint16_t rid_of(uint16_t conn, const uint8_t *tlv, uint16_t len)
{
    (void)conn;
    const uint8_t *v;
    uint16_t vl;
    if (tlv_get(tlv, len, T_REQUEST_ID, &v, &vl) && vl == 2) {
        return (uint16_t)(v[0] | (v[1] << 8));
    }
    return rid_next();
}

/* ---------------- response sending ---------------- */

esp_err_t mgmt_send_response(uint16_t conn_handle, uint8_t opcode,
                             const uint8_t *tlv, uint16_t tlv_len)
{
    if (tlv_len > sizeof(s_last_resp) - 6) {
        return ESP_ERR_INVALID_SIZE;
    }
    if (!gap_mgr_conn_alive(conn_handle)) {
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t frame[sizeof(s_last_resp)];
    frame[0] = 0xA5;
    frame[1] = CFG_PROTO_VER;
    frame[2] = opcode;
    frame[3] = F_RESP | F_LAST;
    frame[4] = (uint8_t)(tlv_len & 0xFF);
    frame[5] = (uint8_t)(tlv_len >> 8);
    memcpy(frame + 6, tlv, tlv_len);

    /* cache the most recent response (readable via 0xFFF4) */
    memcpy(s_last_resp, frame, 6u + tlv_len);
    s_last_resp_len = 6u + tlv_len;

    struct os_mbuf *om = ble_hs_mbuf_from_flat(frame, 6u + tlv_len);
    if (om == NULL) {
        return ESP_ERR_NO_MEM;
    }
    int rc = ble_gatts_notify_custom(conn_handle, s_h_resp, om);
    return rc == 0 ? ESP_OK : ESP_FAIL;
}

/* result-only ASYNC with STATE (common shape) */
static void send_result(uint16_t conn, uint8_t opcode, uint16_t rid, uint16_t rc)
{
    uint8_t tlv[16];
    uint16_t off = 0;
    tlv_put_u16(tlv, sizeof(tlv), &off, T_REQUEST_ID, rid);
    tlv_put_u16(tlv, sizeof(tlv), &off, T_RESULT_CODE, rc);
    tlv_put_u16(tlv, sizeof(tlv), &off, T_STATE, state_for_conn(conn));
    mgmt_send_response(conn, opcode, tlv, off);
}

/* HALF-SYNC: "waiting for physical confirmation" (STATE bit2). Sent immediately
 * for slow operations, before the ASYNC result follows (spec 4.6). */
static void send_halfsync_wait(uint16_t conn, uint8_t opcode, uint16_t rid)
{
    uint8_t tlv[16];
    uint16_t off = 0;
    tlv_put_u16(tlv, sizeof(tlv), &off, T_REQUEST_ID, rid);
    tlv_put_u16(tlv, sizeof(tlv), &off, T_STATE,
                (uint16_t)(state_for_conn(conn) | 0x0004));
    mgmt_send_response(conn, opcode, tlv, off);
}

/* C34: 0x3002 now carries the candidate *identity addresses* (stable across
 * reconnects) instead of the volatile conn_handle bytes that C33 used. The App
 * resolves each one to its name and re-sends with T_HOST_ADDR. */
static void send_hid_ambiguous(uint16_t conn, uint8_t opcode, uint16_t rid)
{
    uint8_t buf[256];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    tlv_put_u16(buf, sizeof(buf), &off, T_RESULT_CODE, E_HID_AMBIG);
    uint8_t n = gap_mgr_hid_link_count();
    for (uint8_t i = 0; i < n && i < 8; i++) {
        uint8_t addr[6];
        if (!gap_mgr_hid_addr_at(i, addr, NULL)) {
            continue;               /* unresolved RPA - offer nothing for it */
        }
        const host_rec_t *r = host_reg_find(addr);
        const char *nm = (r != NULL) ? r->name : NULL;
        if (tlv_put(buf, sizeof(buf), &off, T_HOST_ADDR, addr, 6) != 0) {
            break;
        }
        /* name is included so the picker reads "书房台式机" instead of a raw
         * MAC, even if the App never fetched HOST_LIST itself */
        if (nm != NULL) {
            tlv_put(buf, sizeof(buf), &off, T_HOST_NAME, nm, strlen(nm));
        }
        tlv_put_u8(buf, sizeof(buf), &off, T_HOST_FLAGS,
                   (uint8_t)(HOST_FLAG_ONLINE | HOST_FLAG_HID_NOW |
                             ((r != NULL) ? (r->flags & HOST_FLAG_USER_NAMED) : 0)));
    }

    /* USB 通道也作为一个可选目标（地址全 0，插上即在线） */
    if (usb_hid_mounted()) {
        static const uint8_t usb_addr[6] = { 0 };
        const host_rec_t *ur = host_reg_find(usb_addr);
        const char *un = (ur != NULL) ? ur->name : "USB \xE7\x9B\xB4\xE8\xBF\x9E";
        if (tlv_put(buf, sizeof(buf), &off, T_HOST_ADDR, usb_addr, 6) == 0) {
            tlv_put(buf, sizeof(buf), &off, T_HOST_NAME, un, strlen(un));
            tlv_put_u8(buf, sizeof(buf), &off, T_HOST_FLAGS,
                       (uint8_t)(HOST_FLAG_ONLINE | HOST_FLAG_HID_NOW | HOST_FLAG_IS_USB));
        }
    }
    mgmt_send_response(conn, opcode, buf, off);
}

void mgmt_notify_status(void)
{
    uint8_t st[6];
    uint8_t n = gap_mgr_mgmt_link_count();
    for (uint8_t i = 0; i < n; i++) {
        uint16_t conn = gap_mgr_mgmt_link_at(i);
        if (!gap_mgr_conn_alive(conn)) {
            continue;
        }
        uint16_t b = state_for_conn(conn);
        uint32_t lsec = sys_lock_remaining_s();
        st[0] = (uint8_t)(b & 0xFF);
        st[1] = (uint8_t)(b >> 8);
        st[2] = (uint8_t)(lsec & 0xFF);
        st[3] = (uint8_t)((lsec >> 8) & 0xFF);
        st[4] = (uint8_t)((lsec >> 16) & 0xFF);
        st[5] = (uint8_t)((lsec >> 24) & 0xFF);
        struct os_mbuf *om = ble_hs_mbuf_from_flat(st, sizeof(st));
        if (om != NULL) {
            ble_gatts_notify_custom(conn, s_h_status, om);
        }
    }
}

bool mgmt_is_notify_char(uint16_t attr_handle)
{
    return attr_handle == s_h_resp || attr_handle == s_h_status;
}

/* ---------------- GATT access ---------------- */

static int mgmt_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                          struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)arg;
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        if (attr_handle == s_h_chal) {
            /* 36 bytes = NONCE(32) || SESSION_SEQ(4, LE)  (spec P-2) */
            uint8_t blob[36];
            uint32_t seq;
            if (nonce_issue(conn_handle, blob, &seq) != ESP_OK) {
                return BLE_ATT_ERR_UNLIKELY;
            }
            blob[32] = (uint8_t)(seq & 0xFF);
            blob[33] = (uint8_t)((seq >> 8) & 0xFF);
            blob[34] = (uint8_t)((seq >> 16) & 0xFF);
            blob[35] = (uint8_t)((seq >> 24) & 0xFF);
            return os_mbuf_append(ctxt->om, blob, sizeof(blob)) ?
                   BLE_ATT_ERR_INSUFFICIENT_RES : 0;
        }
        if (attr_handle == s_h_resp) {
            return os_mbuf_append(ctxt->om, s_last_resp, (uint16_t)s_last_resp_len) ?
                   BLE_ATT_ERR_INSUFFICIENT_RES : 0;
        }
        if (attr_handle == s_h_status) {
            uint8_t st[6];
            uint16_t b = state_for_conn(conn_handle);
            uint32_t lsec = sys_lock_remaining_s();
            st[0] = (uint8_t)(b & 0xFF);
            st[1] = (uint8_t)(b >> 8);
            st[2] = (uint8_t)(lsec & 0xFF);
            st[3] = (uint8_t)((lsec >> 8) & 0xFF);
            st[4] = (uint8_t)((lsec >> 16) & 0xFF);
            st[5] = (uint8_t)((lsec >> 24) & 0xFF);
            return os_mbuf_append(ctxt->om, st, sizeof(st)) ?
                   BLE_ATT_ERR_INSUFFICIENT_RES : 0;
        }
        return BLE_ATT_ERR_UNLIKELY;
    }

    if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
        uint8_t buf[260];
        uint16_t len = 0;
        int rc = ble_hs_mbuf_to_flat(ctxt->om, buf, sizeof(buf), &len);
        if (rc != 0) {
            /* C8: truncated copy + BLE_HS_EMSGSIZE -> drop, never parse half data */
            ESP_LOGW(TAG, "mgmt write too long, rc=%d, dropped", rc);
            return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
        }
        if (attr_handle == s_h_cmd) {
            rx_item_t item;
            item.conn = conn_handle;
            item.len = len;
            memcpy(item.data, buf, len);
            if (xQueueSend(s_rx_q, &item, 0) != pdTRUE) {
                ESP_LOGW(TAG, "rx queue full, dropped");
                return BLE_ATT_ERR_INSUFFICIENT_RES;
            }
            return 0;   /* GATT-level ACK first, business on the worker task */
        }
        if (attr_handle == s_h_authrsp) {
            return 0;   /* reserved channel, ignored */
        }
        return BLE_ATT_ERR_UNLIKELY;
    }
    return BLE_ATT_ERR_UNLIKELY;
}

/* ---------------- forward decls ---------------- */

static void process_frame(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len);
static void heavy_task(void *arg);

/* ---------------- rx handling (frame reassembly) ---------------- */

static void send_err(uint16_t conn, uint8_t opcode, uint16_t rc)
{
    uint16_t rid = rid_next();
    uint8_t tlv[16];
    uint16_t off = 0;
    tlv_put_u16(tlv, sizeof(tlv), &off, T_REQUEST_ID, rid);
    tlv_put_u16(tlv, sizeof(tlv), &off, T_RESULT_CODE, rc);
    tlv_put_u16(tlv, sizeof(tlv), &off, T_STATE, state_for_conn(conn));
    mgmt_send_response(conn, opcode, tlv, off);
}

static void reasm_reset(void)
{
    s_reasm.active = false;
    s_reasm.recv = 0;
}

static void handle_rx(uint16_t conn, const uint8_t *buf, uint16_t len)
{
    if (len < 6) {
        return;     /* can't even parse a header; no opcode to answer with */
    }
    uint8_t magic = buf[0];
    uint8_t ver = buf[1];
    uint8_t opcode = buf[2];
    uint8_t flags = buf[3];
    uint16_t total = (uint16_t)(buf[4] | (buf[5] << 8));

    if (magic != 0xA5) {
        send_err(conn, opcode, E_BAD_MAGIC);
        return;
    }
    if (ver > CFG_PROTO_VER) {
        if (flags & F_CRITICAL) {
            send_err(conn, opcode, E_VERSION);
            return;
        }
        /* best-effort parse otherwise */
    }

    /* assembly timeout check (5s) */
    if (s_reasm.active && (now_ms() - s_reasm.last_ms) > 5000) {
        uint8_t old_op = s_reasm.opcode;
        reasm_reset();
        send_err(conn, old_op, E_ASM_TIMEOUT);
    }

    uint16_t plen = (uint16_t)(len - 6);
    bool more = (flags & F_MORE) != 0;

    if (total > CFG_TLV_VALUE_MAX) {
        send_err(conn, opcode, E_FRAME_LARGE);
        reasm_reset();
        return;
    }

    if (!more) {
        /* single frame or final fragment */
        if (s_reasm.active) {
            /* finishing a multi-fragment sequence */
            if (s_reasm.conn != conn || s_reasm.opcode != opcode ||
                s_reasm.total_len != total) {
                reasm_reset();
                send_err(conn, opcode, E_SEQUENCE);
                return;
            }
            if (s_reasm.recv + plen > total) {
                reasm_reset();
                send_err(conn, opcode, E_MALFORMED);
                return;
            }
            memcpy(s_reasm.buf + s_reasm.recv, buf + 6, plen);
            s_reasm.recv += plen;
            if (s_reasm.recv != total) {
                reasm_reset();
                send_err(conn, opcode, E_MALFORMED);
                return;
            }
            process_frame(conn, opcode, s_reasm.buf, total);
            reasm_reset();
        } else {
            /* standalone single frame */
            if (plen != total) {
                send_err(conn, opcode, E_MALFORMED);
                return;
            }
            process_frame(conn, opcode, buf + 6, plen);
        }
        return;
    }

    /* MORE set: first or intermediate fragment */
    if (!s_reasm.active) {
        s_reasm.active = true;
        s_reasm.conn = conn;
        s_reasm.opcode = opcode;
        s_reasm.total_len = total;
        s_reasm.recv = 0;
    } else if (s_reasm.conn != conn || s_reasm.opcode != opcode ||
               s_reasm.total_len != total) {
        reasm_reset();
        send_err(conn, opcode, E_SEQUENCE);
        return;
    }
    if (s_reasm.recv + plen > total) {
        reasm_reset();
        send_err(conn, opcode, E_MALFORMED);
        return;
    }
    memcpy(s_reasm.buf + s_reasm.recv, buf + 6, plen);
    s_reasm.recv += plen;
    s_reasm.last_ms = now_ms();
}

/* ---------------- job submission helpers ---------------- */

static bool heavy_submit(const heavy_job_t *job)
{
    if (s_heavy_busy) {
        return false;
    }
    return xQueueSend(s_heavy_q, job, 0) == pdTRUE;
}

/* ---------------- fast command handlers ---------------- */

static void h_device_info(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    uint8_t buf[128];
    uint16_t off = 0;
    uint8_t fwv[3] = { FW_MAJOR, FW_MINOR, FW_PATCH };

    uint8_t salt[16];
    if (cred_get_salt(salt) != ESP_OK) {
        cred_gen_salt(salt);    /* lazy init: factory state salt */
    }
    uint32_t iter = CFG_DEFAULT_KDF_ITER;
    cred_get_iter(&iter);

    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    tlv_put(buf, sizeof(buf), &off, T_FW_VERSION, fwv, 3);
    tlv_put_u16(buf, sizeof(buf), &off, T_ENTRY_COUNT, store_entry_count());
    tlv_put_u16(buf, sizeof(buf), &off, T_STATE, state_for_conn(conn));
    tlv_put_u32(buf, sizeof(buf), &off, T_LOCK_SECONDS, sys_lock_remaining_s());
    if (session_valid(conn)) {
        tlv_put_u32(buf, sizeof(buf), &off, T_SESSION_ID, sessid_get(conn));
    }
    tlv_put(buf, sizeof(buf), &off, T_SALT, salt, 16);
    tlv_put_u32(buf, sizeof(buf), &off, T_KDF_ITER, iter);
    tlv_put_u8(buf, sizeof(buf), &off, T_LAYOUT, 0);
    mgmt_send_response(conn, opcode, buf, off);
}

static void h_auth_start(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    uint8_t nonce[32];
    uint32_t seq;
    if (nonce_issue(conn, nonce, &seq) != ESP_OK) {
        send_result(conn, opcode, rid, E_INTERNAL);
        return;
    }
    uint8_t buf[64];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    tlv_put(buf, sizeof(buf), &off, T_NONCE, nonce, 32);
    tlv_put_u32(buf, sizeof(buf), &off, T_SESSION_SEQ, seq);
    mgmt_send_response(conn, opcode, buf, off);
}

static void h_auth_verify(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);

    /* lock gate (device level) */
    uint8_t ls = sys_lock_state();
    if (ls == 2) {
        send_result(conn, opcode, rid, E_LOCKED_PERM);
        return;
    }
    if (ls == 1) {
        uint8_t buf[24];
        uint16_t off = 0;
        tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
        tlv_put_u16(buf, sizeof(buf), &off, T_RESULT_CODE, E_LOCKED_TEMP);
        tlv_put_u32(buf, sizeof(buf), &off, T_LOCK_SECONDS, sys_lock_remaining_s());
        mgmt_send_response(conn, opcode, buf, off);
        return;
    }

    const uint8_t *nonce, *proof, *kek;
    uint16_t nl, pl, kl;
    if (!tlv_get(tlv, len, T_NONCE, &nonce, &nl) || nl != 32 ||
        !tlv_get(tlv, len, T_PROOF, &proof, &pl) || pl != 32) {
        send_err(conn, opcode, E_MISSING);
        return;
    }
    if (!tlv_get(tlv, len, T_KEK_BLOB, &kek, &kl) || kl != 32) {
        send_err(conn, opcode, E_KEK_MISSING);
        return;
    }

    /* consume nonce (one-shot) */
    uint32_t seq;
    if (nonce_pending_seq(conn, &seq) != ESP_OK ||
        !nonce_consume(conn, nonce, seq)) {
        send_err(conn, opcode, E_NONCE);
        return;
    }

    /* PROOF = HMAC(VERIFIER, NONCE || SEQ_LE) */
    uint8_t verifier[32];
    if (cred_get_verifier(verifier) != ESP_OK) {
        send_err(conn, opcode, E_INTERNAL);
        return;
    }
    uint8_t msg[36], expected[32];
    memcpy(msg, nonce, 32);
    msg[32] = (uint8_t)(seq & 0xFF);
    msg[33] = (uint8_t)((seq >> 8) & 0xFF);
    msg[34] = (uint8_t)((seq >> 16) & 0xFF);
    msg[35] = (uint8_t)((seq >> 24) & 0xFF);
    kdf_hmac_sha256(verifier, 32, msg, sizeof(msg), expected);

    if (!ct_mem_equal(expected, proof, 32)) {
        sys_fail_bump();
        audit_append(0x07, conn, NULL, E_AUTH_FAILED);
        uint8_t ls2 = sys_lock_state();
        uint16_t rc = (ls2 == 2) ? E_LOCKED_PERM :
                      (ls2 == 1) ? E_LOCKED_TEMP : E_AUTH_FAILED;
        uint8_t buf[24];
        uint16_t off = 0;
        tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
        tlv_put_u16(buf, sizeof(buf), &off, T_RESULT_CODE, rc);
        tlv_put_u32(buf, sizeof(buf), &off, T_LOCK_SECONDS, sys_lock_remaining_s());
        mgmt_send_response(conn, opcode, buf, off);
        memset(verifier, 0, sizeof(verifier));
        memset(expected, 0, sizeof(expected));
        return;
    }

    /* success: create session with the supplied KEK (RAM only) */
    session_create(conn, kek);
    sys_fail_clear();
    sessid_set(conn, esp_random());
    audit_append(0x06, conn, NULL, E_OK);
    ESP_LOGI(TAG, "AUTH_VERIFY ok, conn=%u", conn);

    uint8_t buf[32];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    tlv_put_u16(buf, sizeof(buf), &off, T_RESULT_CODE, E_OK);
    tlv_put_u32(buf, sizeof(buf), &off, T_SESSION_ID, sessid_get(conn));
    tlv_put_u16(buf, sizeof(buf), &off, T_STATE, state_for_conn(conn));
    mgmt_send_response(conn, opcode, buf, off);

    memset(verifier, 0, sizeof(verifier));
    memset(expected, 0, sizeof(expected));
    mgmt_notify_status();
}

static void h_auth_lock(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!session_valid(conn)) {
        send_result(conn, opcode, rid, E_NOT_AUTH);
        return;
    }
    session_lock(conn);
    sessid_clear(conn);
    send_result(conn, opcode, rid, E_OK);
    mgmt_notify_status();
}

static void h_auth_status(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    uint8_t buf[24];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    tlv_put_u16(buf, sizeof(buf), &off, T_STATE, state_for_conn(conn));
    if (session_valid(conn)) {
        tlv_put_u32(buf, sizeof(buf), &off, T_SESSION_ID, sessid_get(conn));
    }
    tlv_put_u32(buf, sizeof(buf), &off, T_LOCK_SECONDS, sys_lock_remaining_s());
    mgmt_send_response(conn, opcode, buf, off);
}

/* --- entry ops --- */

static bool require_auth(uint16_t conn, uint8_t opcode, uint16_t rid)
{
    if (session_valid(conn)) {
        return true;
    }
    send_result(conn, opcode, rid, E_NOT_AUTH);
    return false;
}

static void h_pwd_list(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!require_auth(conn, opcode, rid)) {
        return;
    }
    const uint8_t *pv;
    uint16_t pvl;
    uint8_t page = 0;
    if (tlv_get(tlv, len, T_PAGE_INDEX, &pv, &pvl) && pvl == 1) {
        page = pv[0];
    }

    uint8_t (*all)[8] = calloc(CFG_ENTRY_MAX, 8);
    if (all == NULL) {
        send_result(conn, opcode, rid, E_INTERNAL);
        return;
    }
    uint16_t all_n = 0;
    store_list_ids(all, CFG_ENTRY_MAX, &all_n);
    uint16_t total = store_entry_count();

    uint8_t buf[128];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    uint16_t start = (uint16_t)page * 8;
    uint16_t n = 0;
    for (uint16_t i = start; i < all_n && n < 8; i++, n++) {
        tlv_put(buf, sizeof(buf), &off, T_ENTRY_ID, all[i], 8);
    }
    tlv_put_u16(buf, sizeof(buf), &off, T_ENTRY_COUNT, total);
    tlv_put_u8(buf, sizeof(buf), &off, T_PAGE_INDEX, page);
    mgmt_send_response(conn, opcode, buf, off);
    free(all);
}

static void h_pwd_add(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!require_auth(conn, opcode, rid)) {
        return;
    }
    const uint8_t *sec, *nm, *eid;
    uint16_t sl, nl, el;
    if (!tlv_get(tlv, len, T_SECRET, &sec, &sl) || sl == 0) {
        send_err(conn, opcode, E_MISSING);
        return;
    }
    if (sl > CFG_SECRET_MAX) {
        send_err(conn, opcode, E_SECRET_LONG);
        return;
    }
    /* client-side charset gate: reject non-ASCII outright */
    for (uint16_t i = 0; i < sl; i++) {
        uint8_t c = sec[i];
        bool ok = (c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\n' || c == '\r' || c == '\b';
        if (!ok) {
            uint8_t buf[24];
            uint16_t off = 0;
            tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
            tlv_put_u16(buf, sizeof(buf), &off, T_RESULT_CODE, E_CHARSET);
            tlv_put_u8(buf, sizeof(buf), &off, T_ERR_DETAIL, c);
            mgmt_send_response(conn, opcode, buf, off);
            return;
        }
    }
    bool has_name = tlv_get(tlv, len, T_NAME, &nm, &nl);
    if (has_name && nl > CFG_NAME_MAX) {
        send_err(conn, opcode, E_NAME_LONG);
        return;
    }
    bool has_id = tlv_get(tlv, len, T_ENTRY_ID, &eid, &el) && el == 8;

    const uint8_t *kek = session_kek(conn);
    if (kek == NULL) {
        send_result(conn, opcode, rid, E_NOT_AUTH);
        return;
    }
    uint8_t new_id[8];
    esp_err_t err = store_add_entry_opt(kek, has_id ? eid : NULL,
                                        (const char *)sec, (uint8_t)sl,
                                        has_name ? (const char *)nm : "", (uint8_t)(has_name ? nl : 0),
                                        new_id);
    uint16_t rc = E_OK;
    switch (err) {
    case ESP_OK: rc = E_OK; break;
    case ESP_ERR_NO_MEM: rc = E_STORAGE_FULL; break;
    case ESP_ERR_INVALID_ARG: rc = E_CHARSET; break;
    case ESP_ERR_INVALID_STATE: rc = E_ID_CONFLICT; break;
    default: rc = E_STORAGE_IO; break;
    }
    if (rc == E_OK) {
        audit_append(0x03, conn, new_id, E_OK);
    }
    uint8_t buf[32];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    tlv_put_u16(buf, sizeof(buf), &off, T_RESULT_CODE, rc);
    if (rc == E_OK) {
        tlv_put(buf, sizeof(buf), &off, T_ENTRY_ID, new_id, 8);
    }
    mgmt_send_response(conn, opcode, buf, off);
}

static void h_pwd_update(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!require_auth(conn, opcode, rid)) {
        return;
    }
    const uint8_t *eid, *sec, *nm;
    uint16_t el, sl, nl;
    if (!tlv_get(tlv, len, T_ENTRY_ID, &eid, &el) || el != 8) {
        send_err(conn, opcode, E_MISSING);
        return;
    }
    bool has_sec = tlv_get(tlv, len, T_SECRET, &sec, &sl) && sl > 0;
    bool has_name = tlv_get(tlv, len, T_NAME, &nm, &nl);
    if (!has_sec && !has_name) {
        send_err(conn, opcode, E_MALFORMED);
        return;
    }
    if (has_sec && sl > CFG_SECRET_MAX) {
        send_err(conn, opcode, E_SECRET_LONG);
        return;
    }
    if (has_name && nl > CFG_NAME_MAX) {
        send_err(conn, opcode, E_NAME_LONG);
        return;
    }
    if (has_sec) {
        for (uint16_t i = 0; i < sl; i++) {
            uint8_t c = sec[i];
            bool ok = (c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\n' || c == '\r' || c == '\b';
            if (!ok) {
                send_err(conn, opcode, E_CHARSET);
                return;
            }
        }
    }
    const uint8_t *kek = session_kek(conn);
    if (kek == NULL) {
        send_result(conn, opcode, rid, E_NOT_AUTH);
        return;
    }
    esp_err_t err = store_update_entry(kek, eid,
                                       has_sec ? (const char *)sec : NULL, (uint8_t)sl,
                                       has_name ? (const char *)nm : NULL, (uint8_t)(has_name ? nl : 0));
    uint16_t rc = (err == ESP_OK) ? E_OK :
                  (err == ESP_ERR_NOT_FOUND || err == ESP_ERR_NVS_NOT_FOUND) ? E_NOT_FOUND :
                  E_STORAGE_IO;
    if (rc == E_OK) {
        audit_append(0x04, conn, eid, E_OK);
    }
    send_result(conn, opcode, rid, rc);
}

static void h_pwd_delete(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!require_auth(conn, opcode, rid)) {
        return;
    }
    const uint8_t *eid;
    uint16_t el;
    if (!tlv_get(tlv, len, T_ENTRY_ID, &eid, &el) || el != 8) {
        send_err(conn, opcode, E_MISSING);
        return;
    }
    esp_err_t err = store_delete_entry(eid);
    uint16_t rc = (err == ESP_OK) ? E_OK :
                  (err == ESP_ERR_NOT_FOUND || err == ESP_ERR_NVS_NOT_FOUND) ? E_NOT_FOUND :
                  E_STORAGE_IO;
    if (rc == E_OK) {
        audit_append(0x05, conn, eid, E_OK);
    }
    send_result(conn, opcode, rid, rc);
}

static void h_attr_get(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!require_auth(conn, opcode, rid)) {
        return;
    }
    const uint8_t *eid;
    uint16_t el;
    if (!tlv_get(tlv, len, T_ENTRY_ID, &eid, &el) || el != 8) {
        send_err(conn, opcode, E_MISSING);
        return;
    }
    const uint8_t *kek = session_kek(conn);
    if (kek == NULL) {
        send_result(conn, opcode, rid, E_NOT_AUTH);
        return;
    }
    char name[CFG_NAME_MAX];
    uint8_t nlen = sizeof(name);
    esp_err_t err = store_read_entry(kek, eid, NULL, NULL, name, &nlen);
    uint16_t rc = (err == ESP_OK) ? E_OK :
                  (err == ESP_ERR_NVS_NOT_FOUND) ? E_NOT_FOUND : E_STORAGE_IO;
    uint8_t buf[128];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    tlv_put_u16(buf, sizeof(buf), &off, T_RESULT_CODE, rc);
    if (rc == E_OK && nlen > 0) {
        tlv_put(buf, sizeof(buf), &off, T_NAME, name, nlen);
    }
    mgmt_send_response(conn, opcode, buf, off);
    memset(name, 0, sizeof(name));
}

static void h_audit_read(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!require_auth(conn, opcode, rid)) {
        return;
    }
    const uint8_t *ov;
    uint16_t ol;
    uint32_t offset = 0;
    if (tlv_get(tlv, len, T_AUDIT_OFFSET, &ov, &ol) && ol == 4) {
        offset = (uint32_t)ov[0] | ((uint32_t)ov[1] << 8) |
                 ((uint32_t)ov[2] << 16) | ((uint32_t)ov[3] << 24);
    }

    uint8_t recs[128];
    uint16_t rlen = 0;
    uint32_t next = offset;
    audit_read(offset, recs, sizeof(recs), &rlen, &next);

    uint8_t buf[160];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    for (uint16_t i = 0; i + 16 <= rlen; i += 16) {
        if (tlv_put(buf, sizeof(buf), &off, T_AUDIT_RECORD, recs + i, 16) != 0) {
            break;
        }
    }
    tlv_put_u32(buf, sizeof(buf), &off, T_AUDIT_OFFSET, next);
    mgmt_send_response(conn, opcode, buf, off);
}

/* ---------------- named hosts (the PCs this device is/was a keyboard for) ----------
 *
 * Hosts are keyed on the peer identity address, so a name the user assigns
 * survives reconnects, reboots and even swapping phones. Online state is
 * derived from the live link list at query time and never persisted, so an
 * unclean disconnect can't leave a stale "online" flag behind.
 */

#define HOST_PAGE_SIZE  2       /* 2 records fit comfortably inside any MTU */

static bool addr_has_hid(const uint8_t addr[6])
{
    uint8_t hc = gap_mgr_hid_link_count();
    for (uint8_t i = 0; i < hc; i++) {
        uint8_t ha[6];
        if (gap_mgr_hid_addr_at(i, ha, NULL) && memcmp(ha, addr, 6) == 0) {
            return true;
        }
    }
    return false;
}

static void h_host_list(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!require_auth(conn, opcode, rid)) {
        return;
    }
    const uint8_t *pv;
    uint16_t pvl;
    uint8_t page = 0;
    if (tlv_get(tlv, len, T_PAGE_INDEX, &pv, &pvl) && pvl == 1) {
        page = pv[0];
    }

    host_rec_t recs[HOST_REG_MAX];
    int total = host_reg_all(recs, HOST_REG_MAX);

    uint8_t buf[160];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    uint16_t start = (uint16_t)page * HOST_PAGE_SIZE;
    uint16_t n = 0;
    for (uint16_t i = start; i < (uint16_t)total && n < HOST_PAGE_SIZE; i++, n++) {
        uint8_t flags = recs[i].flags &
                        (HOST_FLAG_USER_NAMED | HOST_FLAG_IS_HID | HOST_FLAG_IS_USB);
        if (recs[i].flags & HOST_FLAG_IS_USB) {
            /* USB 通道：在线与否看主机有没有枚举我们。
             * 插上即"可直接输出"，不存在配对/订阅这一步。 */
            if (usb_hid_mounted()) {
                flags |= HOST_FLAG_ONLINE | HOST_FLAG_HID_NOW;
            }
        } else {
            if (gap_mgr_addr_is_online(recs[i].addr)) {
                flags |= HOST_FLAG_ONLINE;
            }
            if (addr_has_hid(recs[i].addr)) {
                flags |= HOST_FLAG_HID_NOW;
            }
        }
        if (tlv_put(buf, sizeof(buf), &off, T_HOST_ADDR, recs[i].addr, 6) != 0 ||
            tlv_put(buf, sizeof(buf), &off, T_HOST_NAME,
                    recs[i].name, strlen(recs[i].name)) != 0) {
            break;                   /* frame full - App will fetch the next page */
        }
        tlv_put_u8(buf, sizeof(buf), &off, T_HOST_FLAGS, flags);
    }
    tlv_put_u8(buf, sizeof(buf), &off, T_HOST_COUNT, (uint8_t)total);
    tlv_put_u8(buf, sizeof(buf), &off, T_PAGE_INDEX, page);
    mgmt_send_response(conn, opcode, buf, off);
}

static void h_host_rename(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!require_auth(conn, opcode, rid)) {
        return;
    }
    const uint8_t *av, *nv;
    uint16_t al, nl;
    if (!tlv_get(tlv, len, T_HOST_ADDR, &av, &al) || al != 6) {
        send_err(conn, opcode, E_MISSING);
        return;
    }
    /* Renaming is only allowed for hosts we actually know - otherwise a typo
     * would silently create junk records. */
    if (host_reg_find(av) == NULL && !gap_mgr_addr_is_online(av)) {
        send_result(conn, opcode, rid, E_NOT_FOUND);
        return;
    }
    bool has = tlv_get(tlv, len, T_HOST_NAME, &nv, &nl) && nl > 0;
    if (has && nl > HOST_NAME_MAX - 1) {
        nl = HOST_NAME_MAX - 1;
    }
    esp_err_t err = host_reg_set_name(av, has ? (const char *)nv : NULL,
                                      has ? nl : 0, true);
    if (err != ESP_OK) {
        send_result(conn, opcode, rid, E_STORAGE_IO);
        return;
    }
    send_result(conn, opcode, rid, E_OK);
}

static void h_host_disconnect(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!require_auth(conn, opcode, rid)) {
        return;
    }
    const uint8_t *av;
    uint16_t al;
    if (!tlv_get(tlv, len, T_HOST_ADDR, &av, &al) || al != 6) {
        send_err(conn, opcode, E_MISSING);
        return;
    }
    /* USB 通道是物理连接，软件断不开（强行断开也会中断正在进行的输出） */
    if (HOST_ADDR_IS_USB(av)) {
        send_result(conn, opcode, rid, E_UNSUPPORTED);
        return;
    }
    uint16_t target = gap_mgr_conn_by_addr(av);
    if (target == 0xFFFF) {
        send_result(conn, opcode, rid, E_NOT_FOUND);
        return;
    }
    if (target == conn) {
        /* killing the link that carried this request would lose the reply */
        send_result(conn, opcode, rid, E_NOT_ALLOWED);
        return;
    }
    int rc = ble_gap_terminate(target, BLE_ERR_REM_USER_CONN_TERM);
    send_result(conn, opcode, rid, rc == 0 ? E_OK : E_INTERNAL);
}

/* ---------------- slow command dispatch ---------------- */

static void h_pwd_type(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!require_auth(conn, opcode, rid)) {
        return;
    }
    /* C23: freshness - auth must be no older than 30s */
    if (session_age_ms(conn) > CFG_PWD_TYPE_MAX_AUTH_AGE_MS) {
        send_result(conn, opcode, rid, E_AUTH_STALE);
        return;
    }
    const uint8_t *eid, *tv;
    uint16_t el, tvl;
    if (!tlv_get(tlv, len, T_ENTRY_ID, &eid, &el) || el != 8) {
        send_err(conn, opcode, E_MISSING);
        return;
    }

    /* ---- 目标通道判定 ----
     * T_HOST_ADDR 全 0 → USB 通道（约定，见《PwdKey_协议v1.3_输出通道设计》）
     * 未指定地址 → 只在"在线通道数 == 1"时自动选；多条时让 App 选
     */
    uint8_t hc = gap_mgr_hid_link_count();
    bool usb_ok = usb_hid_mounted();
    uint16_t hid_conn = 0xFFFF;
    bool via_usb = false;
    bool has_addr = tlv_get(tlv, len, T_HOST_ADDR, &tv, &tvl) && tvl == 6;

    if (has_addr && HOST_ADDR_IS_USB(tv)) {
        via_usb = true;                       /* App 明确指定了有线 */
    } else if (!has_addr) {
        uint8_t chans = (uint8_t)(hc + (usb_ok ? 1 : 0));
        if (chans == 0) {
            send_result(conn, opcode, rid, E_NO_HID);
            return;
        }
        if (chans > 1) {
            send_hid_ambiguous(conn, opcode, rid);
            return;
        }
        via_usb = (hc == 0);                  /* 唯一在线通道是有线 */
    }

    if (via_usb) {
        if (!usb_ok) {
            send_result(conn, opcode, rid, E_NO_HID);
            return;
        }
        if (usb_hid_busy()) {
            send_result(conn, opcode, rid, E_HID_BUSY);
            return;
        }
    } else {
        /* ---- 以下为原有 BLE 路径，行为保持不变 ---- */
        if (hc == 0) {
            send_result(conn, opcode, rid, E_NO_HID);
            return;
        }
        if (has_addr) {
            hid_conn = gap_mgr_conn_by_addr(tv);
            bool is_hid = false;
            for (uint8_t i = 0; i < hc; i++) {
                if (gap_mgr_hid_link_at(i) == hid_conn) {
                    is_hid = true;
                    break;
                }
            }
            if (hid_conn == 0xFFFF || !is_hid) {
                /* peer vanished / never had HID - give the App a fresh candidate list */
                send_hid_ambiguous(conn, opcode, rid);
                return;
            }
        } else {
            if (hc != 1) {
                send_hid_ambiguous(conn, opcode, rid);
                return;
            }
            hid_conn = gap_mgr_hid_link_at(0);
        }
        if (hid_kbd_busy()) {
            send_result(conn, opcode, rid, E_HID_BUSY);
            return;
        }
    }

    /* entry must exist */
    {
        uint8_t all[CFG_ENTRY_MAX][8];
        uint16_t n = 0;
        store_list_ids(all, CFG_ENTRY_MAX, &n);
        bool found = false;
        for (uint16_t i = 0; i < n; i++) {
            if (memcmp(all[i], eid, 8) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            send_result(conn, opcode, rid, E_NOT_FOUND);
            return;
        }
    }

    /* confirm window (clamped by device) */
    uint32_t tmo = CFG_CONFIRM_DEFAULT_MS;
    if (tlv_get(tlv, len, T_TIMEOUT_MS, &tv, &tvl) && tvl == 2) {
        tmo = (uint32_t)(tv[0] | (tv[1] << 8));
    }
    if (tmo < CFG_CONFIRM_MIN_MS) {
        tmo = CFG_CONFIRM_MIN_MS;
    }
    if (tmo > CFG_CONFIRM_MAX_MS) {
        tmo = CFG_CONFIRM_MAX_MS;
    }

    heavy_job_t job = {0};
    job.type = JOB_PWD_TYPE;
    job.conn = conn;
    job.rid = rid;
    memcpy(job.entry_id, eid, 8);
    job.timeout_ms = tmo;
    job.target8 = 0xFF;
    job.hid_conn = hid_conn;
    job.via_usb = via_usb;
    if (!heavy_submit(&job)) {
        send_result(conn, opcode, rid, E_BUSY);
        return;
    }

    /* HALF-SYNC: waiting for physical confirm (+ real window + entry id) */
    uint8_t buf[32];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    tlv_put_u16(buf, sizeof(buf), &off, T_STATE,
                (uint16_t)(state_for_conn(conn) | 0x0004));
    tlv_put(buf, sizeof(buf), &off, T_ENTRY_ID, eid, 8);
    tlv_put_u16(buf, sizeof(buf), &off, T_TIMEOUT_MS, (uint16_t)tmo);
    mgmt_send_response(conn, opcode, buf, off);
}

static void h_auth_new(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    const uint8_t *v;
    uint16_t vl;
    bool has_kek = tlv_get(tlv, len, T_KEK_BLOB, &v, &vl) && vl == 32;
    bool has_rec = tlv_get(tlv, len, T_RECOVERY_CODE, &v, &vl) && vl > 0;
    bool authed = session_valid(conn);
    bool s0 = !cred_exists();

    heavy_job_t job = {0};
    job.conn = conn;
    job.rid = rid;
    if (len > sizeof(job.tlv)) {
        send_err(conn, opcode, E_FRAME_LARGE);
        return;
    }
    job.tlv_len = len;
    memcpy(job.tlv, tlv, job.tlv_len);

    if (has_rec) {
        /* recovery-code reset: needs both RECOVERY_CODE and new KEK */
        if (!tlv_get(tlv, len, T_KEK_BLOB, &v, &vl) || vl != 32) {
            send_err(conn, opcode, E_KEK_MISSING);
            return;
        }
        job.type = JOB_AUTHNEW_RECOVERY;
        if (!heavy_submit(&job)) {
            send_result(conn, opcode, rid, E_BUSY);
        } else {
            send_halfsync_wait(conn, opcode, rid);
        }
        return;
    }

    if (has_kek) {
        if (s0 && !authed) {
            job.type = JOB_AUTHNEW_SETUP;
            if (!heavy_submit(&job)) {
                send_result(conn, opcode, rid, E_BUSY);
            } else {
                send_halfsync_wait(conn, opcode, rid);
            }
            return;
        }
        if (authed) {
            /* change flow, step 2 */
            job.type = JOB_AUTHNEW_STEP2;
            if (!heavy_submit(&job)) {
                send_result(conn, opcode, rid, E_BUSY);
            }
            return;
        }
        send_result(conn, opcode, rid, E_NOT_AUTH);
        return;
    }

    /* no KEK: step 1 of the change flow (requires a session) */
    if (!authed) {
        send_err(conn, opcode, E_MISSING);
        return;
    }
    job.type = JOB_AUTHNEW_STEP1;
    if (!heavy_submit(&job)) {
        send_result(conn, opcode, rid, E_BUSY);
    } else {
        send_halfsync_wait(conn, opcode, rid);
    }
}

static void h_factory_reset(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!require_auth(conn, opcode, rid)) {
        return;
    }
    const uint8_t *tv;
    uint16_t tvl;
    if (!tlv_get(tlv, len, T_CONFIRM_TOKEN, &tv, &tvl) || tvl != 4) {
        /* step 1: issue a token */
        s_factory_token.valid = true;
        s_factory_token.conn = conn;
        esp_fill_random(s_factory_token.token, 4);
        s_factory_token.t0 = now_ms();
        uint8_t buf[16];
        uint16_t off = 0;
        tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
        tlv_put(buf, sizeof(buf), &off, T_CONFIRM_TOKEN, s_factory_token.token, 4);
        mgmt_send_response(conn, opcode, buf, off);
        return;
    }
    /* step 2: validate token (device-generated, 30s, one-shot) */
    if (!s_factory_token.valid || s_factory_token.conn != conn ||
        (now_ms() - s_factory_token.t0) > 30000 ||
        !ct_mem_equal(s_factory_token.token, tv, 4)) {
        uint8_t buf[16];
        uint16_t off = 0;
        tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
        tlv_put_u16(buf, sizeof(buf), &off, T_RESULT_CODE, E_MISSING);
        tlv_put_u8(buf, sizeof(buf), &off, T_ERR_DETAIL, T_CONFIRM_TOKEN);
        mgmt_send_response(conn, opcode, buf, off);
        return;
    }
    s_factory_token.valid = false;

    heavy_job_t job = {0};
    job.type = JOB_FACTORY_EXEC;
    job.conn = conn;
    job.rid = rid;
    if (!heavy_submit(&job)) {
        send_result(conn, opcode, rid, E_BUSY);
        return;
    }
    /* HALF-SYNC: waiting for the physical confirm */
    uint8_t buf[16];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    tlv_put_u16(buf, sizeof(buf), &off, T_STATE,
                (uint16_t)(state_for_conn(conn) | 0x0004));
    mgmt_send_response(conn, opcode, buf, off);
}

static void h_enter_pairing(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!require_auth(conn, opcode, rid)) {
        return;
    }
    heavy_job_t job = {0};
    job.type = JOB_ENTER_PAIRING;
    job.conn = conn;
    job.rid = rid;
    if (!heavy_submit(&job)) {
        send_result(conn, opcode, rid, E_BUSY);
        return;
    }
    uint8_t buf[16];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    tlv_put_u16(buf, sizeof(buf), &off, T_STATE,
                (uint16_t)(state_for_conn(conn) | 0x0004));
    mgmt_send_response(conn, opcode, buf, off);
}

/* ---------------- frame dispatch ---------------- */

static void process_frame(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    switch (opcode) {
    case OP_DEVICE_INFO:    h_device_info(conn, opcode, tlv, len); break;
    case OP_AUTH_START:     h_auth_start(conn, opcode, tlv, len); break;
    case OP_AUTH_VERIFY:    h_auth_verify(conn, opcode, tlv, len); break;
    case OP_AUTH_LOCK:      h_auth_lock(conn, opcode, tlv, len); break;
    case OP_AUTH_STATUS:    h_auth_status(conn, opcode, tlv, len); break;
    case OP_AUTH_NEW:       h_auth_new(conn, opcode, tlv, len); break;
    case OP_FACTORY_RESET:  h_factory_reset(conn, opcode, tlv, len); break;
    case OP_PWD_LIST:       h_pwd_list(conn, opcode, tlv, len); break;
    case OP_PWD_ADD:        h_pwd_add(conn, opcode, tlv, len); break;
    case OP_PWD_UPDATE:     h_pwd_update(conn, opcode, tlv, len); break;
    case OP_PWD_DELETE:     h_pwd_delete(conn, opcode, tlv, len); break;
    case OP_PWD_TYPE:       h_pwd_type(conn, opcode, tlv, len); break;
    case OP_PWD_EXPORT_BEGIN: h_pwd_export_begin(conn, opcode, tlv, len); break;
    case OP_PWD_EXPORT_CHUNK: h_pwd_export_chunk(conn, opcode, tlv, len); break;
    case OP_RECOVERY_SETUP:   h_recovery_setup(conn, opcode, tlv, len); break;
    case OP_RECOVERY_RESTORE: h_recovery_restore(conn, opcode, tlv, len); break;
    case OP_ATTR_GET:       h_attr_get(conn, opcode, tlv, len); break;
    case OP_ENTER_PAIRING:  h_enter_pairing(conn, opcode, tlv, len); break;
    case OP_AUDIT_READ:     h_audit_read(conn, opcode, tlv, len); break;
    case OP_HOST_LIST:      h_host_list(conn, opcode, tlv, len); break;
    case OP_HOST_RENAME:    h_host_rename(conn, opcode, tlv, len); break;
    case OP_HOST_DISCONNECT: h_host_disconnect(conn, opcode, tlv, len); break;
    default:
        send_err(conn, opcode, E_UNSUPPORTED);
        break;
    }
}

/* ---------------- heavy worker ---------------- */

static void on_kbd_done(uint16_t conn, esp_err_t result)
{
    (void)conn;
    s_type_done_result = result;
    xSemaphoreGive(s_type_done_sem);
}

/* USB 通道的完成回调（签名少一个 conn 参数），复用同一个信号量。
 * 两条通道不会并发输出：进入前已做 busy 检查。 */
static void on_usb_done(esp_err_t result)
{
    s_type_done_result = result;
    xSemaphoreGive(s_type_done_sem);
}

/* ask for a physical confirm; returns E_OK / E_CONF_TIMEOUT / E_CONF_DENIED */
static uint16_t confirm_request(uint16_t conn, btn_req_type_t type, uint32_t timeout_ms)
{
    btn_req_t req = { .type = type, .conn_handle = conn, .arg = 0 };
    if (btn_confirm_post(&req) != ESP_OK) {
        return E_BUSY;
    }
    s_confirm_pending = true;
    mgmt_notify_status();
    int r = btn_wait_result(type, timeout_ms);
    s_confirm_pending = false;
    mgmt_notify_status();
    if (r == 1) {
        return E_OK;
    }
    return (btn_last_outcome() == 2) ? E_CONF_DENIED : E_CONF_TIMEOUT;
}

static void gen_recovery_code(char out[25])
{
    static const char B32[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    uint8_t rnd[15];    /* 120 bits -> 24 x 5b */
    esp_fill_random(rnd, sizeof(rnd));
    uint64_t acc = 0;
    int bits = 0;
    int oi = 0;
    for (int i = 0; i < 15 && oi < 24; i++) {
        acc = (acc << 8) | rnd[i];
        bits += 8;
        while (bits >= 5 && oi < 24) {
            bits -= 5;
            out[oi++] = B32[(acc >> bits) & 0x1F];
        }
    }
    out[24] = '\0';
}

static void run_pwd_type(heavy_job_t *job)
{
    uint16_t conn = job->conn;
    uint16_t hid_conn = job->hid_conn;

    session_touch(conn);    /* keep the session alive while confirming */

    uint16_t rc = confirm_request(conn, BTN_REQ_PWD_TYPE, job->timeout_ms);
    if (rc != E_OK) {
        audit_append(0x02, conn, job->entry_id, rc);
        send_result(conn, 0x24, job->rid, rc);
        return;
    }

    const uint8_t *kek = session_kek(conn);
    if (kek == NULL) {
        send_result(conn, 0x24, job->rid, E_NOT_AUTH);
        return;
    }
    char pwd[CFG_SECRET_MAX];
    uint8_t plen = sizeof(pwd);
    esp_err_t err = store_read_entry(kek, job->entry_id, pwd, &plen, NULL, NULL);
    if (err != ESP_OK) {
        memset(pwd, 0, sizeof(pwd));
        send_result(conn, 0x24, job->rid, E_NOT_FOUND);
        return;
    }

    /* drain any stale completion */
    xSemaphoreTake(s_type_done_sem, 0);
    if (job->via_usb) {
        err = usb_hid_type_string(pwd, plen);
    } else {
        err = hid_kbd_type_string(hid_conn, pwd, plen);
    }
    memset(pwd, 0, sizeof(pwd));    /* hid layer holds its own copy */
    if (err != ESP_OK) {
        uint16_t rc2 = (err == ESP_ERR_INVALID_ARG) ? E_LAYOUT : E_HID_BUSY;
        audit_append(0x02, conn, job->entry_id, rc2);
        send_result(conn, 0x24, job->rid, rc2);
        return;
    }

    /* wait for typing completion (generous bound: 2x char time + 2s) */
    uint32_t bound = (uint32_t)plen * 2 * CFG_INTER_CHAR_MS + 2000;
    if (xSemaphoreTake(s_type_done_sem, pdMS_TO_TICKS(bound)) != pdTRUE) {
        rc = E_INTERNAL;
    } else {
        rc = (s_type_done_result == ESP_OK) ? E_OK : E_HID_DISC;
    }

    audit_append(rc == E_OK ? 0x01 : 0x02, conn, job->entry_id, rc);
    send_result(conn, 0x24, job->rid, rc);
}

static void run_authnew_setup(heavy_job_t *job)
{
    uint16_t conn = job->conn;
    const uint8_t *kek;
    uint16_t kl;
    if (!tlv_get(job->tlv, job->tlv_len, T_KEK_BLOB, &kek, &kl) || kl != 32) {
        send_result(conn, 0x06, job->rid, E_KEK_MISSING);
        return;
    }

    uint16_t rc = confirm_request(conn, BTN_REQ_AUTH_NEW, CFG_CONFIRM_DEFAULT_MS);
    if (rc != E_OK) {
        send_result(conn, 0x06, job->rid, rc);
        return;
    }

    /* IMPORTANT (bugfix): do NOT regenerate the salt here. The App derived its
     * KEK with the salt served by DEVICE_INFO; the device must keep that exact
     * salt so the stored verifier matches the App's KEK. (Only create one as a
     * fallback - normally DEVICE_INFO already lazily created it.) */
    uint8_t salt[16], verifier[32], hint[32];
    char code[25];
    if (cred_get_salt(salt) != ESP_OK) {
        esp_fill_random(salt, 16);
        cred_set_salt(salt);
    }
    /* iteration count: keep as-is (App used the DEVICE_INFO value; default matches) */
    sec_store_compute_verifier(kek, verifier);
    cred_set_verifier(verifier);
    gen_recovery_code(code);
    sec_store_compute_rec_hint(code, 24, hint);
    cred_set_rec_hint(hint);
    audit_append(0x0C, conn, NULL, E_OK);
    ESP_LOGI(TAG, "primary password set (S0 -> configured)");

    uint8_t buf[64];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, job->rid);
    tlv_put_u16(buf, sizeof(buf), &off, T_RESULT_CODE, E_OK);
    tlv_put_u16(buf, sizeof(buf), &off, T_STATE, state_for_conn(conn));
    tlv_put(buf, sizeof(buf), &off, T_RECOVERY_CODE, code, 24);
    mgmt_send_response(conn, 0x06, buf, off);
    memset(code, 0, sizeof(code));
    memset(verifier, 0, sizeof(verifier));
    memset(hint, 0, sizeof(hint));

    /* leave factory state: stop advertising, normal mode */
    gap_mgr_set_mode(GAP_MODE_S1);
}

static void run_authnew_step1(heavy_job_t *job)
{
    uint16_t conn = job->conn;
    uint16_t rc = confirm_request(conn, BTN_REQ_AUTH_NEW, CFG_CONFIRM_DEFAULT_MS);
    if (rc != E_OK) {
        send_result(conn, 0x06, job->rid, rc);
        return;
    }
    esp_fill_random(s_authnew.salt, 16);
    s_authnew.active = true;
    s_authnew.conn = conn;
    s_authnew.t0 = now_ms();

    uint32_t iter = CFG_DEFAULT_KDF_ITER;
    cred_get_iter(&iter);

    uint8_t buf[48];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, job->rid);
    tlv_put_u16(buf, sizeof(buf), &off, T_RESULT_CODE, E_OK);   /* step 1 done */
    tlv_put(buf, sizeof(buf), &off, T_NEW_SALT, s_authnew.salt, 16);
    tlv_put_u32(buf, sizeof(buf), &off, T_KDF_ITER, iter);
    mgmt_send_response(conn, 0x06, buf, off);
}

static void run_authnew_step2(heavy_job_t *job)
{
    uint16_t conn = job->conn;
    uint16_t rid = job->rid;
    const uint8_t *nonce, *proof, *kek_new;
    uint16_t nl, pl, kl;

    if (!s_authnew.active || s_authnew.conn != conn ||
        (now_ms() - s_authnew.t0) > 120000) {
        send_result(conn, 0x06, rid, E_NONCE);
        return;
    }
    if (!tlv_get(job->tlv, job->tlv_len, T_NONCE, &nonce, &nl) || nl != 32 ||
        !tlv_get(job->tlv, job->tlv_len, T_PROOF, &proof, &pl) || pl != 32) {
        send_err(conn, 0x06, E_MISSING);
        return;
    }
    if (!tlv_get(job->tlv, job->tlv_len, T_KEK_BLOB, &kek_new, &kl) || kl != 32) {
        send_err(conn, 0x06, E_KEK_MISSING);
        return;
    }

    /* C25: PROOF2 is computed with the OLD verifier */
    uint32_t seq;
    if (nonce_pending_seq(conn, &seq) != ESP_OK ||
        !nonce_consume(conn, nonce, seq)) {
        send_err(conn, 0x06, E_NONCE);
        return;
    }
    uint8_t verifier_old[32], msg[36], expected[32];
    if (cred_get_verifier(verifier_old) != ESP_OK) {
        send_err(conn, 0x06, E_INTERNAL);
        return;
    }
    memcpy(msg, nonce, 32);
    msg[32] = (uint8_t)(seq & 0xFF);
    msg[33] = (uint8_t)((seq >> 8) & 0xFF);
    msg[34] = (uint8_t)((seq >> 16) & 0xFF);
    msg[35] = (uint8_t)((seq >> 24) & 0xFF);
    kdf_hmac_sha256(verifier_old, 32, msg, sizeof(msg), expected);
    if (!ct_mem_equal(expected, proof, 32)) {
        sys_fail_bump();
        audit_append(0x07, conn, NULL, E_AUTH_FAILED);
        send_err(conn, 0x06, E_AUTH_FAILED);
        memset(verifier_old, 0, sizeof(verifier_old));
        memset(expected, 0, sizeof(expected));
        return;
    }
    memset(verifier_old, 0, sizeof(verifier_old));
    memset(expected, 0, sizeof(expected));

    /* snapshot old KEK (session may be destroyed mid-rekey on disconnect) */
    uint8_t kek_old[32];
    const uint8_t *k = session_kek(conn);
    if (k == NULL) {
        send_result(conn, 0x06, rid, E_NOT_AUTH);
        return;
    }
    memcpy(kek_old, k, 32);

    /* build new credentials */
    uint8_t verifier_new[32], hint_new[32];
    char code[25];
    uint32_t iter = CFG_DEFAULT_KDF_ITER;
    cred_get_iter(&iter);
    sec_store_compute_verifier(kek_new, verifier_new);
    gen_recovery_code(code);
    sec_store_compute_rec_hint(code, 24, hint_new);

    esp_err_t err = store_rekey_begin();
    if (err == ESP_OK) {
        err = store_rekey_apply(kek_old, kek_new, s_authnew.salt, iter,
                                verifier_new, hint_new);
    }
    memset(kek_old, 0, sizeof(kek_old));
    s_authnew.active = false;

    uint16_t rc = (err == ESP_OK) ? E_OK : E_STORAGE_IO;
    uint8_t buf[64];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    tlv_put_u16(buf, sizeof(buf), &off, T_RESULT_CODE, rc);
    if (rc == E_OK) {
        /* refresh session with the new KEK */
        session_create(conn, kek_new);
        audit_append(0x0C, conn, NULL, E_OK);
        tlv_put(buf, sizeof(buf), &off, T_RECOVERY_CODE, code, 24);
        ESP_LOGI(TAG, "primary password changed, %u entries re-encrypted",
                 (unsigned)store_entry_count());
    } else {
        audit_append(0x0C, conn, NULL, E_STORAGE_IO);
    }
    tlv_put_u16(buf, sizeof(buf), &off, T_STATE, state_for_conn(conn));
    mgmt_send_response(conn, 0x06, buf, off);
    memset(code, 0, sizeof(code));
    memset(verifier_new, 0, sizeof(verifier_new));
    memset(hint_new, 0, sizeof(hint_new));
}

static void run_authnew_recovery(heavy_job_t *job)
{
    uint16_t conn = job->conn;
    uint16_t rid = job->rid;
    const uint8_t *code_p, *kek_new;
    uint16_t cl, kl;

    if (!tlv_get(job->tlv, job->tlv_len, T_RECOVERY_CODE, &code_p, &cl) ||
        cl == 0 || cl > 32) {
        send_err(conn, 0x06, E_MISSING);
        return;
    }
    if (!tlv_get(job->tlv, job->tlv_len, T_KEK_BLOB, &kek_new, &kl) || kl != 32) {
        send_err(conn, 0x06, E_KEK_MISSING);
        return;
    }

    /* verify code against the stored hint (no KEK needed) */
    uint8_t hint[32];
    sec_store_compute_rec_hint((const char *)code_p, cl, hint);
    esp_err_t err = cred_check_rec_hint(hint);
    memset(hint, 0, sizeof(hint));
    if (err != ESP_OK) {
        sys_fail_bump();
        audit_append(0x07, conn, NULL, E_RECOVERY_BAD);
        uint8_t ls = sys_lock_state();
        uint16_t rc = (ls == 2) ? E_LOCKED_PERM :
                      (ls == 1) ? E_LOCKED_TEMP : E_RECOVERY_BAD;
        send_result(conn, 0x06, rid, rc);
        return;
    }

    uint16_t rc = confirm_request(conn, BTN_REQ_AUTH_NEW, CFG_CONFIRM_DEFAULT_MS);
    if (rc != E_OK) {
        send_result(conn, 0x06, rid, rc);
        return;
    }

    /* full reset: wipe entries, install fresh credentials, clear recovery hint */
    /* Same rule as SETUP: keep the current salt/iter (the App computed the new
     * KEK with the values served by DEVICE_INFO). */
    uint8_t salt[16], verifier[32];
    uint32_t cur_iter = CFG_DEFAULT_KDF_ITER;
    if (cred_get_salt(salt) != ESP_OK) {
        esp_fill_random(salt, 16);
    }
    cred_get_iter(&cur_iter);
    sec_store_compute_verifier(kek_new, verifier);
    err = store_recovery_reset(salt, cur_iter, verifier, NULL);
    memset(verifier, 0, sizeof(verifier));

    /* destroy the session (data changed, KEK invalidated) */
    session_lock(conn);
    sessid_clear(conn);

    rc = (err == ESP_OK) ? E_OK : E_STORAGE_IO;
    audit_append(0x0C, conn, NULL, rc);
    ESP_LOGW(TAG, "recovery reset executed, all entries wiped");
    send_result(conn, 0x06, rid, rc);
    mgmt_notify_status();
}

static void run_factory_exec(heavy_job_t *job)
{
    uint16_t conn = job->conn;
    uint16_t rc = confirm_request(conn, BTN_REQ_FACTORY_RESET, CFG_CONFIRM_DEFAULT_MS);
    if (rc != E_OK) {
        send_result(conn, 0x07, job->rid, rc);
        return;
    }
    audit_append(0x0B, conn, NULL, E_OK);
    send_result(conn, 0x07, job->rid, E_OK);
    /* give the notify a moment to flush, then wipe everything and reboot */
    vTaskDelay(pdMS_TO_TICKS(300));
    nvs_flash_erase();
    esp_restart();
}

static void run_enter_pairing(heavy_job_t *job)
{
    uint16_t conn = job->conn;
    uint16_t rc = confirm_request(conn, BTN_REQ_ENTER_PAIRING, CFG_CONFIRM_DEFAULT_MS);
    if (rc == E_OK) {
        rc = (gap_mgr_set_mode(GAP_MODE_S2) == ESP_OK) ? E_OK : E_INTERNAL;
        audit_append(0x0A, conn, NULL, rc);
    }
    send_result(conn, 0x40, job->rid, rc);
    mgmt_notify_status();
}

static void heavy_task(void *arg)
{
    (void)arg;
    heavy_job_t job;
    for (;;) {
        if (xQueueReceive(s_heavy_q, &job, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        s_heavy_busy = true;
        switch (job.type) {
        case JOB_PWD_TYPE:         run_pwd_type(&job); break;
        case JOB_AUTHNEW_SETUP:    run_authnew_setup(&job); break;
        case JOB_AUTHNEW_STEP1:    run_authnew_step1(&job); break;
        case JOB_AUTHNEW_STEP2:    run_authnew_step2(&job); break;
        case JOB_AUTHNEW_RECOVERY: run_authnew_recovery(&job); break;
        case JOB_FACTORY_EXEC:     run_factory_exec(&job); break;
        case JOB_ENTER_PAIRING:    run_enter_pairing(&job); break;
        default: break;
        }
        memset(&job, 0, sizeof(job));
        s_heavy_busy = false;
    }
}

/* ---------------- command task ---------------- */

static void mgmt_cmd_task(void *arg)
{
    (void)arg;
    rx_item_t item;
    for (;;) {
        if (xQueueReceive(s_rx_q, &item, pdMS_TO_TICKS(1000)) == pdTRUE) {
            handle_rx(item.conn, item.data, item.len);
        } else {
            /* periodic maintenance */
            if (sec_session_expire_check()) {
                mgmt_notify_status();
            }
            sessid_cleanup();
            if (s_reasm.active && (now_ms() - s_reasm.last_ms) > 5000) {
                uint8_t op = s_reasm.opcode;
                uint16_t c = s_reasm.conn;
                reasm_reset();
                send_err(c, op, E_ASM_TIMEOUT);
            }
        }
    }
}

/* ---------------- init ---------------- */

esp_err_t mgmt_svc_init(void)
{
    int rc = ble_gatts_count_cfg(s_mgmt_svc);
    if (rc != 0) {
        return ESP_FAIL;
    }
    rc = ble_gatts_add_svcs(s_mgmt_svc);
    if (rc != 0) {
        return ESP_FAIL;
    }

    s_rx_q = xQueueCreate(4, sizeof(rx_item_t));
    s_heavy_q = xQueueCreate(2, sizeof(heavy_job_t));
    s_type_done_sem = xSemaphoreCreateBinary();
    if (s_rx_q == NULL || s_heavy_q == NULL || s_type_done_sem == NULL) {
        return ESP_ERR_NO_MEM;
    }
    if (xTaskCreate(mgmt_cmd_task, "mgmt_cmd", 6144, NULL, 5, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    if (xTaskCreate(heavy_task, "mgmt_heavy", 8192, NULL, 5, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    hid_kbd_set_done_cb(on_kbd_done);
    usb_hid_set_done_cb(on_usb_done);
    export_cooldown_boot();       /* 上次导出的冷却若没走完，从本次上电重新计时 */
    ESP_LOGI(TAG, "management service ready");
    return ESP_OK;
}

/* ---------------- 加密导出（明文永不出设备）----------------
 *
 * 流程：BEGIN（BOOT 确认一次）→ 拿到 wrapped/nonce/total → 反复 CHUNK 取密文。
 * 设备侧只有密文，App 侧只接触 32 字节的 K_export，条目明文全程不出芯片。
 */

#define EXPORT_COOLDOWN_MS  (30u * 60u * 1000u)   /* 30 分钟，两次导出之间的最小间隔 */
static uint32_t s_cool_start_ms;                  /* 冷却起算点（本次上电的时间轴） */

/* 若上次导出后冷却没走完就重启了，从本次上电时刻重新计时。
 * 设备没有 RTC，算不出真实间隔，所以宁可让用户多等，也不给重启绕过留口子。 */
static void export_cooldown_boot(void)
{
    if (store_export_cooldown_get()) {
        s_cool_start_ms = 0;
    }
}

static void h_pwd_export_begin(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!require_auth(conn, opcode, rid)) {
        return;
    }
    /* 导出是高危操作，认证必须足够新鲜 */
    if (session_age_ms(conn) > CFG_PWD_TYPE_MAX_AUTH_AGE_MS) {
        send_result(conn, opcode, rid, E_AUTH_STALE);
        return;
    }
    const uint8_t *kek = session_kek(conn);
    if (kek == NULL) {
        send_result(conn, opcode, rid, E_NOT_AUTH);
        return;
    }

    /* 限速 30 分钟，且冷却标记持久化 —— 拔电重启也要重新等满 */
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
    if (store_export_cooldown_get()) {
        uint32_t elapsed = now - s_cool_start_ms;
        if (elapsed < EXPORT_COOLDOWN_MS) {
            uint16_t wait_s = (uint16_t)((EXPORT_COOLDOWN_MS - elapsed + 999) / 1000);
            uint8_t buf[32];
            uint16_t off = 0;
            tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
            tlv_put_u16(buf, sizeof(buf), &off, T_RESULT_CODE, E_BUSY);
            tlv_put_u16(buf, sizeof(buf), &off, T_ERR_DETAIL, wait_s);
            mgmt_send_response(conn, opcode, buf, off);
            return;
        }
        (void)store_export_cooldown_set(false);      /* 冷却结束 */
    }

    uint16_t rc = confirm_request(conn, BTN_REQ_EXPORT, CFG_CONFIRM_DEFAULT_MS);
    if (rc != E_OK) {
        audit_append(0x08, conn, NULL, rc);
        send_result(conn, opcode, rid, rc);
        return;
    }

    uint8_t wrapped[60];
    uint8_t dnonce[12];
    size_t total = 0;
    esp_err_t err = store_export_build(kek, wrapped, dnonce, &total);
    if (err != ESP_OK) {
        send_result(conn, opcode, rid,
                    (err == ESP_ERR_NOT_FOUND) ? E_NOT_FOUND : E_INTERNAL);
        return;
    }
    s_cool_start_ms = now;
    (void)store_export_cooldown_set(true);

    uint8_t buf[128];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    tlv_put(buf, sizeof(buf), &off, T_EXPORT_WRAPPED, wrapped, 60);
    tlv_put(buf, sizeof(buf), &off, T_EXPORT_NONCE, dnonce, 12);
    tlv_put_u32(buf, sizeof(buf), &off, T_EXPORT_TOTAL, (uint32_t)total);
    mgmt_send_response(conn, opcode, buf, off);

    audit_append(0x08, conn, NULL, E_OK);
}

static void h_pwd_export_chunk(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!require_auth(conn, opcode, rid)) {
        return;
    }
    const uint8_t *ov;
    uint16_t ol;
    if (!tlv_get(tlv, len, T_EXPORT_OFFSET, &ov, &ol) || ol != 4) {
        send_err(conn, opcode, E_MISSING);
        return;
    }
    uint32_t offset = (uint32_t)ov[0] | ((uint32_t)ov[1] << 8) |
                      ((uint32_t)ov[2] << 16) | ((uint32_t)ov[3] << 24);

    uint8_t data[512];
    uint16_t got = 0;
    esp_err_t err = store_export_chunk((uint16_t)offset, data, sizeof(data), &got);
    if (err != ESP_OK) {
        send_result(conn, opcode, rid,
                    (err == ESP_ERR_INVALID_STATE) ? E_NOT_FOUND : E_INTERNAL);
        return;
    }

    uint8_t buf[560];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    tlv_put_u32(buf, sizeof(buf), &off, T_EXPORT_OFFSET, offset);
    tlv_put(buf, sizeof(buf), &off, T_EXPORT_DATA, data, got);
    mgmt_send_response(conn, opcode, buf, off);
}

/* ---------------- 恢复码（3-of-5）----------------
 *
 * SETUP：会话解锁 + BOOT 确认 → 生成 5 份，返回给 App 显示
 * RESTORE：**不需要会话**（主密码忘了就没有会话），凭 3 份码 + 新 KEK 重设
 *
 * 安全边界：任意 3 份恢复码即可重建 DEK，不需要主密码。
 * 这是 Shamir 的数学必然，所以 5 张纸必须分开保管。
 */

static void h_recovery_setup(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);
    if (!require_auth(conn, opcode, rid)) {
        return;
    }
    const uint8_t *kek = session_kek(conn);
    if (kek == NULL) {
        send_result(conn, opcode, rid, E_NOT_AUTH);
        return;
    }
    if (session_age_ms(conn) > CFG_PWD_TYPE_MAX_AUTH_AGE_MS) {
        send_result(conn, opcode, rid, E_AUTH_STALE);
        return;
    }

    /* 生成恢复码会触发 DEK 迁移（首次），属于高危操作，必须物理确认 */
    uint16_t rc = confirm_request(conn, BTN_REQ_EXPORT, CFG_CONFIRM_DEFAULT_MS);
    if (rc != E_OK) {
        audit_append(0x09, conn, NULL, rc);
        send_result(conn, opcode, rid, rc);
        return;
    }

    uint8_t shares[5 * 16];
    esp_err_t err = store_recovery_setup(kek, shares);
    if (err != ESP_OK) {
        memset(shares, 0, sizeof(shares));
        send_result(conn, opcode, rid, E_INTERNAL);
        return;
    }

    uint8_t buf[256];
    uint16_t off = 0;
    tlv_put_u16(buf, sizeof(buf), &off, T_REQUEST_ID, rid);
    for (uint8_t i = 0; i < 5; i++) {
        tlv_put_u8(buf, sizeof(buf), &off, T_REC_IDX, (uint8_t)(i + 1));
        tlv_put(buf, sizeof(buf), &off, T_REC_DATA, shares + (size_t)i * 16, 16);
    }
    mgmt_send_response(conn, opcode, buf, off);

    memset(shares, 0, sizeof(shares));
    audit_append(0x09, conn, NULL, E_OK);
}

static void h_recovery_restore(uint16_t conn, uint8_t opcode, const uint8_t *tlv, uint16_t len)
{
    uint16_t rid = rid_of(conn, tlv, len);

    /* 这里刻意不调 require_auth：用户正是因为忘了主密码才走这条路 */

    uint8_t xs[3];
    uint8_t datas[3 * 16];
    uint8_t n = 0;
    uint8_t pending_idx = 0;
    const uint8_t *p = tlv;
    const uint8_t *end = tlv + len;

    /* 遍历 TLV，收集 (idx, share) 对。
     * 注意：TLV 的长度字段是 **2 字节小端**（见 App 侧 proto.js 的 tlv()：
     * concatBytes([tag], u16le(len), value)）。一开始按 1 字节写，整个流错位，
     * 一组都读不出来，设备只好回 E_MISSING。 */
    while ((size_t)(end - p) >= 3 && n < 3) {
        uint8_t tag = p[0];
        uint16_t l = (uint16_t)(p[1] | ((uint16_t)p[2] << 8));
        const uint8_t *v = p + 3;
        if ((size_t)(end - v) < (size_t)l) {
            break;
        }
        if (tag == T_REC_IDX && l == 1) {
            pending_idx = v[0];
        } else if (tag == T_REC_DATA && l == 16 && pending_idx >= 1 && pending_idx <= 5) {
            xs[n] = pending_idx;
            memcpy(datas + (size_t)n * 16, v, 16);
            n++;
            pending_idx = 0;
        }
        p += 3 + l;
    }

    if (n < 3) {
        send_result(conn, opcode, rid, E_MISSING);
        return;
    }

    const uint8_t *kek_new;
    uint16_t kl;
    if (!tlv_get(tlv, len, T_KEK_BLOB, &kek_new, &kl) || kl != 32) {
        send_result(conn, opcode, rid, E_KEK_MISSING);
        return;
    }

    /* 物理确认：防止有人拿偷来的 3 张纸远程恢复 */
    uint16_t rc = confirm_request(conn, BTN_REQ_AUTH_NEW, CFG_CONFIRM_DEFAULT_MS);
    if (rc != E_OK) {
        audit_append(0x0A, conn, NULL, rc);
        send_result(conn, opcode, rid, rc);
        return;
    }

    esp_err_t err = store_recovery_restore(xs, datas, n, kek_new);
    memset(datas, 0, sizeof(datas));
    if (err != ESP_OK) {
        sys_fail_bump();
        audit_append(0x0A, conn, NULL, E_RECOVERY_BAD);
        uint8_t ls = sys_lock_state();
        send_result(conn, opcode, rid,
                    (ls == 2) ? E_LOCKED_PERM :
                    (ls == 1) ? E_LOCKED_TEMP : E_RECOVERY_BAD);
        return;
    }

    /* 新主密码的校验值必须一起更新，否则下次解锁会判定密码错误 */
    uint8_t verifier[32];
    sec_store_compute_verifier(kek_new, verifier);
    (void)cred_set_verifier(verifier);
    memset(verifier, 0, sizeof(verifier));

    audit_append(0x0A, conn, NULL, E_OK);
    send_result(conn, opcode, rid, E_OK);
}
