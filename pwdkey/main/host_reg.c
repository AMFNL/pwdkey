/* host_reg.c - registry of HID hosts (PCs / phones) keyed by BLE MAC.
 *
 * Why this exists: a peripheral cannot learn the central's advertising name
 * from the air - the name is inside the *central's* GATT server, not its
 * advertising data. So we keep our own table, addressed by the peer identity
 * address, which is stable across reconnects and across phones.
 *
 * Name precedence:
 *   1. user-defined name  (set via OP_HOST_RENAME, survives everything)
 *   2. auto-probed name   (read from the peer's GAP 0x2A00, best effort)
 *   3. fallback "电脑 A1B2" (last 2 MAC bytes, uppercase hex)
 *
 * Storage: single blob in namespace "pkey_host", key "hosts".
 */
#include "host_reg.h"

#include <assert.h>
#include <string.h>

#include "esp_log.h"
#include "app_cfg.h"          /* VAULT_NVS_OPEN：用户数据必须放 vault 分区 */
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"

#define NS_HOST  "pkey_host"
#define KEY_HOSTS "hosts"

/* persisted record layout (must stay <= HOST_REG_MAX * HOST_REC_SIZE bytes) */
#define HOST_REC_SIZE  40   /* addr[6] + addr_type + flags + name[32] */

static const char *TAG = "host_reg";
static nvs_handle_t s_h;
static host_rec_t s_rec[HOST_REG_MAX];
static uint8_t s_cnt;

/* ---------------- default name ---------------- */

void host_reg_default_name(const uint8_t addr[6], char *out, size_t cap)
{
    if (cap < 16) {
        if (cap > 0) {
            out[0] = '\0';
        }
        return;
    }
    /* USB 通道（全 0 地址）：固定名字，不参与 MAC 派生 */
    if (HOST_ADDR_IS_USB(addr)) {
        snprintf(out, cap, "\x55\x53\x42 \xE7\x9B\xB4\xE8\xBF\x9E");  /* "USB 直连" */
        return;
    }
    /* "电脑 " (6 bytes) + 4 hex chars + NUL  -> 11 bytes, fits in 16 */
    const char hex[] = "0123456789ABCDEF";
    char tmp[16];
    char *p = tmp;
    memcpy(p, "\xE7\x94\xB5\xE8\x84\x91 ", 7);   /* UTF-8 "电脑 " incl. space */
    p += 7;
    uint8_t b1 = addr[4];
    uint8_t b0 = addr[5];
    *p++ = hex[(b1 >> 4) & 0x0F];
    *p++ = hex[b1 & 0x0F];
    *p++ = hex[(b0 >> 4) & 0x0F];
    *p++ = hex[b0 & 0x0F];
    *p = '\0';
    snprintf(out, cap, "%s", tmp);
}

/* ---------------- persistence ---------------- */

static void blob_pack(uint8_t *buf)
{
    memset(buf, 0, HOST_REC_SIZE * HOST_REG_MAX);
    for (uint8_t i = 0; i < s_cnt; i++) {
        uint8_t *p = buf + (size_t)i * HOST_REC_SIZE;
        memcpy(p, s_rec[i].addr, 6);
        p[6] = s_rec[i].addr_type;
        p[7] = s_rec[i].flags;
        memcpy(p + 8, s_rec[i].name, HOST_NAME_MAX);
    }
}

static void blob_unpack(const uint8_t *buf, size_t len)
{
    size_t n = len / HOST_REC_SIZE;
    if (n > HOST_REG_MAX) {
        n = HOST_REG_MAX;
    }
    s_cnt = 0;
    for (size_t i = 0; i < n; i++) {
        const uint8_t *p = buf + i * HOST_REC_SIZE;
        /* an all-zero addr marks an empty slot */
        bool empty = true;
        for (int k = 0; k < 6; k++) {
            if (p[k] != 0) {
                empty = false;
                break;
            }
        }
        if (empty) {
            continue;
        }
        memcpy(s_rec[s_cnt].addr, p, 6);
        s_rec[s_cnt].addr_type = p[6];
        s_rec[s_cnt].flags = p[7];
        memcpy(s_rec[s_cnt].name, p + 8, HOST_NAME_MAX);
        s_rec[s_cnt].name[HOST_NAME_MAX - 1] = '\0';
        s_rec[s_cnt].last_seen_ms = 0;
        s_rec[s_cnt].online = false;
        s_cnt++;
    }
}

static esp_err_t flush(void)
{
    static uint8_t buf[HOST_REC_SIZE * HOST_REG_MAX];
    static_assert(sizeof(buf) <= 512, "host blob too large for a single NVS blob");
    blob_pack(buf);
    esp_err_t err = nvs_set_blob(s_h, KEY_HOSTS, buf, sizeof(buf));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "persist failed: %s", esp_err_to_name(err));
        return err;
    }
    return nvs_commit(s_h);
}

esp_err_t host_reg_init(void)
{
    memset(s_rec, 0, sizeof(s_rec));
    s_cnt = 0;
    esp_err_t err = VAULT_NVS_OPEN(NS_HOST, NVS_READWRITE, &s_h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        return err;
    }
    size_t sz = 0;
    if (nvs_get_blob(s_h, KEY_HOSTS, NULL, &sz) == ESP_OK && sz > 0) {
        static uint8_t buf[HOST_REC_SIZE * HOST_REG_MAX];
        if (sz <= sizeof(buf)) {
            size_t rd = sz;
            if (nvs_get_blob(s_h, KEY_HOSTS, buf, &rd) == ESP_OK) {
                blob_unpack(buf, rd);
            }
        }
    }
    /* 确保 USB 通道记录存在（地址全 0）。
     * USB HID 协议里设备无法得知主机身份，所以有线永远只有这一条记录，
     * 换电脑插也是它；用户给它改的名字会保留。 */
    {
        static const uint8_t usb_addr[6] = { 0 };
        host_rec_t *ur = host_reg_upsert(usb_addr, 0);
        if (ur != NULL && !(ur->flags & HOST_FLAG_IS_USB)) {
            ur->flags |= HOST_FLAG_IS_USB;
            (void)flush();
        }
    }

    ESP_LOGI(TAG, "host registry ready, %u known hosts", (unsigned)s_cnt);
    return ESP_OK;
}

/* ---------------- lookup ---------------- */

host_rec_t *host_reg_find(const uint8_t addr[6])
{
    if (addr == NULL) {
        return NULL;
    }
    for (uint8_t i = 0; i < s_cnt; i++) {
        if (memcmp(s_rec[i].addr, addr, 6) == 0) {
            return &s_rec[i];
        }
    }
    return NULL;
}

const host_rec_t *host_reg_find_c(const uint8_t addr[6])
{
    return host_reg_find(addr);
}

int host_reg_all(host_rec_t *out, int cap)
{
    int n = s_cnt < cap ? s_cnt : cap;
    memcpy(out, s_rec, (size_t)n * sizeof(host_rec_t));
    return n;
}

uint8_t host_reg_count(void)
{
    return s_cnt;
}

/* Oldest-first eviction: keeps at least one slot free for a new host.
 * A user-named record is never evicted while unnamed ones exist. */
static void evict_if_full(void)
{
    if (s_cnt < HOST_REG_MAX) {
        return;
    }
    int victim = -1;
    for (int i = 0; i < s_cnt; i++) {
        if (!(s_rec[i].flags & HOST_FLAG_USER_NAMED)) {
            victim = i;
            break;
        }
    }
    if (victim < 0) {
        victim = 0;
    }
    for (int i = victim; i < s_cnt - 1; i++) {
        s_rec[i] = s_rec[i + 1];
    }
    s_cnt--;
}

host_rec_t *host_reg_upsert(const uint8_t addr[6], uint8_t addr_type)
{
    host_rec_t *r = host_reg_find(addr);
    if (r != NULL) {
        r->addr_type = addr_type;
        return r;
    }
    evict_if_full();
    host_rec_t *slot = &s_rec[s_cnt++];
    memset(slot, 0, sizeof(*slot));
    memcpy(slot->addr, addr, 6);
    slot->addr_type = addr_type;
    slot->flags = 0;
    host_reg_default_name(addr, slot->name, HOST_NAME_MAX);
    /* persist the new record; failure is not fatal (RAM copy stays usable) */
    (void)flush();
    return slot;
}

/* ---------------- naming ---------------- */

esp_err_t host_reg_set_name(const uint8_t addr[6], const char *name, size_t len,
                            bool user_named)
{
    host_rec_t *r = host_reg_upsert(addr, 0);
    if (r == NULL) {
        return ESP_ERR_NO_MEM;
    }
    if (name == NULL || len == 0) {
        /* clearing a custom name -> fall back to the MAC-derived default */
        host_reg_default_name(addr, r->name, HOST_NAME_MAX);
        r->flags &= (uint8_t)~HOST_FLAG_USER_NAMED;
        return flush();
    }
    if (len > HOST_NAME_MAX - 1) {
        len = HOST_NAME_MAX - 1;
    }
    memcpy(r->name, name, len);
    r->name[len] = '\0';
    if (user_named) {
        r->flags |= HOST_FLAG_USER_NAMED;
    }
    return flush();
}

/* Auto-probed names must never clobber something the user typed. */
esp_err_t host_reg_set_autoname(const uint8_t addr[6], uint8_t addr_type,
                                const char *name, size_t len)
{
    if (name == NULL || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    /* reject anything with control chars - some peers return garbage */
    for (size_t i = 0; i < len; i++) {
        if ((uint8_t)name[i] < 0x20 || (uint8_t)name[i] == 0x7F) {
            return ESP_ERR_INVALID_ARG;
        }
    }
    if (len > HOST_NAME_MAX - 1) {
        len = HOST_NAME_MAX - 1;
    }
    host_rec_t *r = host_reg_upsert(addr, addr_type);
    if (r == NULL) {
        return ESP_ERR_NO_MEM;
    }
    if (r->flags & HOST_FLAG_USER_NAMED) {
        host_reg_touch(addr);       /* still record the sighting */
        return ESP_OK;
    }
    if (strlen(r->name) == len && memcmp(r->name, name, len) == 0) {
        host_reg_touch(addr);
        return ESP_OK;             /* unchanged, avoid an NVS write */
    }
    memcpy(r->name, name, len);
    r->name[len] = '\0';
    host_reg_touch(addr);
    ESP_LOGI(TAG, "probed name for %02X:%02X:%02X:%02X:%02X:%02X = \"%s\"",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], r->name);
    return flush();
}

esp_err_t host_reg_touch(const uint8_t addr[6])
{
    host_rec_t *r = host_reg_find(addr);
    if (r == NULL) {
        return ESP_ERR_NOT_FOUND;
    }
    r->last_seen_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);
    return ESP_OK;
}

esp_err_t host_reg_del(const uint8_t addr[6])
{
    for (uint8_t i = 0; i < s_cnt; i++) {
        if (memcmp(s_rec[i].addr, addr, 6) == 0) {
            for (uint8_t j = i; j + 1 < s_cnt; j++) {
                s_rec[j] = s_rec[j + 1];
            }
            s_cnt--;
            memset(&s_rec[s_cnt], 0, sizeof(s_rec[s_cnt]));
            return flush();
        }
    }
    return ESP_ERR_NOT_FOUND;
}

/* NOTE: online state is intentionally not stored here - see host_reg.h. */
