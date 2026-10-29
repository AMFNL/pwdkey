/* host_reg.h - registry of HID hosts (PCs / phones) keyed by BLE MAC address.
 *
 * The peer identity address (not the volatile conn_handle) is the key, so a
 * user-assigned name survives reconnects, reboots and phone switches.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#define HOST_REG_MAX     8        /* maximum remembered hosts */
#define HOST_NAME_MAX    32       /* including NUL */

/* flags (persisted) */
#define HOST_FLAG_USER_NAMED  0x01   /* name typed by the user - never auto-overwritten */
#define HOST_FLAG_IS_HID      0x02   /* was seen holding an HID (keyboard) link */
#define HOST_FLAG_IS_USB      0x04   /* USB 通道（有线），不是真实 BLE 主机 */

/* flags reported in T_HOST_FLAGS - runtime only, never persisted */
#define HOST_FLAG_ONLINE      0x40   /* currently connected */
#define HOST_FLAG_HID_NOW     0x80   /* currently an active HID link */

/* USB 通道的哨兵地址：全 0。
 * USB HID 协议里设备无法得知主机身份，所以有线永远只有这一条记录。 */
#define HOST_ADDR_IS_USB(a) \
    ((a)[0] == 0 && (a)[1] == 0 && (a)[2] == 0 && \
     (a)[3] == 0 && (a)[4] == 0 && (a)[5] == 0)

typedef struct {
    uint8_t  addr[6];
    uint8_t  addr_type;
    uint8_t  flags;
    char     name[HOST_NAME_MAX];
    uint32_t last_seen_ms;           /* uptime-based, volatile */
    bool     online;                 /* volatile: currently connected */
} host_rec_t;

esp_err_t host_reg_init(void);

/* --- queries --- */
host_rec_t       *host_reg_find(const uint8_t addr[6]);          /* NULL if unknown */
const host_rec_t *host_reg_find_c(const uint8_t addr[6]);
uint8_t           host_reg_count(void);
int               host_reg_all(host_rec_t *out, int cap);        /* returns count written */

/* --- mutation --- */
/* Create-or-fetch. New records get the MAC-derived fallback name. */
host_rec_t *host_reg_upsert(const uint8_t addr[6], uint8_t addr_type);

/* user_named=true sets HOST_FLAG_USER_NAMED (immune to auto-probe).
 * name==NULL or len==0 restores the fallback name and clears the flag. */
esp_err_t   host_reg_set_name(const uint8_t addr[6], const char *name, size_t len,
                              bool user_named);

/* Best-effort name learned from the peer's GAP 0x2A00. Silently ignored when
 * the user already named this host, or when the value looks like garbage. */
esp_err_t   host_reg_set_autoname(const uint8_t addr[6], uint8_t addr_type,
                                  const char *name, size_t len);

esp_err_t   host_reg_touch(const uint8_t addr[6]);                /* update last_seen */
esp_err_t   host_reg_del(const uint8_t addr[6]);

/* Online state is NOT persisted: it is computed on demand from the connection
 * tracker (gap_mgr_addr_is_online / hid link list) at query time, so it can
 * never go stale after an unclean disconnect. */

/* --- helpers --- */
void        host_reg_default_name(const uint8_t addr[6], char *out, size_t cap);
