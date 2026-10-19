/* app_cfg.h - PwdKey centralized configuration
 * Per project spec (3rd edition firmware manual, v2.1 / C16-C28 applied).
 */
#pragma once

/* --- Identity --- */
#define CFG_DEV_NAME_FALLBACK   "PwdKey-0000"    /* real name comes from NVS sys.dev_name */

/* --- Protocol / scale limits --- */
#define CFG_ENTRY_ID_LEN        8                /* base32 chars (NVS key = 'p'+8 = 9 chars) */
#define CFG_SECRET_MAX          128              /* password <= 128 chars */
#define CFG_NAME_MAX            64               /* name <= 64 chars */
#define CFG_ENTRY_MAX           100              /* capacity limit */
#define CFG_TLV_VALUE_MAX       1024             /* single TLV value limit */
#define CFG_FRAME_BUF_MAX       (6 + 1024)       /* 6B header + max TLV stream + margin */

/* --- Session / security --- */
#define CFG_SESSION_IDLE_MS     60000            /* session idle 60s */
#define CFG_PWD_TYPE_MAX_AUTH_AGE_MS 30000       /* C23: PWD_TYPE requires auth fresher than 30s */
#define CFG_CONFIRM_DEFAULT_MS  30000            /* physical confirm default window */
#define CFG_CONFIRM_MIN_MS      5000
#define CFG_CONFIRM_MAX_MS      60000
#define CFG_FAIL_TEMP1          3                /* 3 fails -> lock 30s */
#define CFG_FAIL_TEMP2          6                /* 6 fails -> lock 5min */
#define CFG_FAIL_PERMANENT      10               /* 10 fails -> permanent lock */

/* --- Pairing / advertising --- */
#define CFG_S0_WINDOW_MS        120000           /* factory-state adv window */
#define CFG_S2_WINDOW_MS        60000            /* HID pairing mode window */
#define CFG_MAX_LINKS           3                /* C18: connection tracking limit */

/* --- Typing --- */
#define CFG_INTER_CHAR_MS       8                /* inter-char delay default 8ms */

/* --- Protocol version --- */
#define CFG_PROTO_VER           0x01
#define CFG_DATA_VER            1                /* NVS sys.ver */

/* --- BOOT button --- */
#define CFG_BTN_SHORT_MAX_MS    2000             /* short press < 2s = confirm */
#define CFG_BTN_FACTORY_MS      5000             /* power-on hold >= 5s = factory reset */
