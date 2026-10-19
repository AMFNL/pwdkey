/* sec_session.c - session / nonce / lock state.
 *
 * Locking algorithm (spec C9, firmware manual 6.4):
 *   persisted: sys.fail_cnt, sys.lock_state (0/1/2)
 *   RAM only : s_lock_until_ms (unlock instant of this boot), s_permanent
 *   On boot  : re-arm a FULL penalty window based on fail_cnt
 *              (reboot can only extend, never shorten the wait)
 */
#include "sec_session.h"

#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"

#include "app_cfg.h"
#include "kdf.h"

static const char *TAG = "session";

#define NS_SYS       "sys"
#define KEY_FAIL     "fail_cnt"
#define KEY_LSTATE   "lock_state"

typedef struct {
    bool     used;
    uint16_t conn_handle;
    uint8_t  kek[32];
    int64_t  auth_ms;        /* time of last successful AUTH_VERIFY */
    int64_t  last_act_ms;    /* time of last authenticated command */
} session_t;

typedef struct {
    bool     used;
    uint16_t conn_handle;
    bool     pending;        /* nonce issued and not yet consumed */
    uint8_t  nonce[32];
    uint32_t seq;
} nonce_slot_t;

static session_t s_sess[CFG_MAX_LINKS];
static nonce_slot_t s_nonce[CFG_MAX_LINKS];
static SemaphoreHandle_t s_mtx;
static nvs_handle_t s_h_sys;

static uint32_t s_seq_ctr;

/* lock state */
static int64_t s_lock_until_ms;
static bool    s_permanent;

static int64_t now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

/* ---------------- failure count / lock ---------------- */

static void persist_fail(uint32_t cnt, uint8_t state)
{
    nvs_set_u32(s_h_sys, KEY_FAIL, cnt);
    nvs_set_u8(s_h_sys, KEY_LSTATE, state);
    nvs_commit(s_h_sys);
}

static uint32_t load_fail(void)
{
    uint32_t v = 0;
    nvs_get_u32(s_h_sys, KEY_FAIL, &v);
    return v;
}

static void arm_penalty(uint32_t fail_cnt)
{
    if (fail_cnt >= CFG_FAIL_TEMP2) {
        s_lock_until_ms = now_ms() + 300000;
    } else if (fail_cnt >= CFG_FAIL_TEMP1) {
        s_lock_until_ms = now_ms() + 30000;
    }
}

void sec_session_init(void)
{
    if (s_mtx == NULL) {
        s_mtx = xSemaphoreCreateMutex();
    }
    esp_err_t err = nvs_open(NS_SYS, NVS_READWRITE, &s_h_sys);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open sys failed: %s", esp_err_to_name(err));
        return;
    }

    uint8_t lstate = 0;
    nvs_get_u8(s_h_sys, KEY_LSTATE, &lstate);
    uint32_t fail_cnt = load_fail();

    if (lstate == 2) {
        s_permanent = true;
        ESP_LOGW(TAG, "device is permanently locked");
    } else if (fail_cnt >= CFG_FAIL_TEMP1) {
        /* re-arm full penalty window on every cold boot */
        arm_penalty(fail_cnt);
        ESP_LOGW(TAG, "temp lock re-armed on boot (fail_cnt=%u)", (unsigned)fail_cnt);
    }
    s_seq_ctr = esp_random();
}

uint8_t sys_fail_count(void)
{
    return (uint8_t)load_fail();
}

void sys_fail_bump(void)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    uint32_t cnt = load_fail() + 1;
    uint8_t state = 1;
    if (cnt >= CFG_FAIL_PERMANENT) {
        state = 2;
        s_permanent = true;
        ESP_LOGW(TAG, "permanent lock engaged (fail_cnt=%u)", (unsigned)cnt);
    } else if (cnt >= CFG_FAIL_TEMP1) {
        arm_penalty(cnt);
    }
    persist_fail(cnt, state);
    xSemaphoreGive(s_mtx);
}

void sys_fail_clear(void)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    s_lock_until_ms = 0;
    s_permanent = false;
    persist_fail(0, 0);
    xSemaphoreGive(s_mtx);
}

uint8_t sys_lock_state(void)
{
    if (s_permanent) {
        return 2;
    }
    if (s_lock_until_ms > now_ms()) {
        return 1;
    }
    return 0;
}

uint32_t sys_lock_remaining_s(void)
{
    int64_t left = s_lock_until_ms - now_ms();
    if (left <= 0) {
        return 0;
    }
    return (uint32_t)((left + 999) / 1000);
}

/* ---------------- sessions ---------------- */

static session_t *sess_find(uint16_t conn_handle)
{
    for (int i = 0; i < CFG_MAX_LINKS; i++) {
        if (s_sess[i].used && s_sess[i].conn_handle == conn_handle) {
            return &s_sess[i];
        }
    }
    return NULL;
}

bool session_create(uint16_t conn_handle, const uint8_t kek[32])
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    session_t *s = sess_find(conn_handle);
    bool existed = (s != NULL);
    if (s == NULL) {
        for (int i = 0; i < CFG_MAX_LINKS; i++) {
            if (!s_sess[i].used) {
                s = &s_sess[i];
                break;
            }
        }
    }
    bool ok = (s != NULL);
    if (ok) {
        s->used = true;
        s->conn_handle = conn_handle;
        memcpy(s->kek, kek, 32);
        s->auth_ms = now_ms();
        s->last_act_ms = s->auth_ms;
    }
    xSemaphoreGive(s_mtx);
    return !existed && ok;      /* false = session already existed (refreshed) */
}

bool session_valid(uint16_t conn_handle)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    session_t *s = sess_find(conn_handle);
    bool ok = (s != NULL);
    xSemaphoreGive(s_mtx);
    return ok;
}

uint32_t session_age_ms(uint16_t conn_handle)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    session_t *s = sess_find(conn_handle);
    uint32_t age = 0;
    if (s != NULL) {
        int64_t d = now_ms() - s->auth_ms;
        age = d > 0 ? (uint32_t)d : 0;
    } else {
        age = UINT32_MAX;   /* no session: treat as stale */
    }
    xSemaphoreGive(s_mtx);
    return age;
}

void session_touch(uint16_t conn_handle)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    session_t *s = sess_find(conn_handle);
    if (s != NULL) {
        s->last_act_ms = now_ms();
    }
    xSemaphoreGive(s_mtx);
}

static void sess_destroy(session_t *s)
{
    memset(s->kek, 0, sizeof(s->kek));
    memset(s, 0, sizeof(*s));
}

void session_lock(uint16_t conn_handle)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    session_t *s = sess_find(conn_handle);
    if (s != NULL) {
        sess_destroy(s);
    }
    xSemaphoreGive(s_mtx);
}

void session_on_disconnect(uint16_t conn_handle)
{
    session_lock(conn_handle);

    xSemaphoreTake(s_mtx, portMAX_DELAY);
    for (int i = 0; i < CFG_MAX_LINKS; i++) {
        if (s_nonce[i].used && s_nonce[i].conn_handle == conn_handle) {
            memset(&s_nonce[i], 0, sizeof(s_nonce[i]));
        }
    }
    xSemaphoreGive(s_mtx);
}

const uint8_t *session_kek(uint16_t conn_handle)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    session_t *s = sess_find(conn_handle);
    const uint8_t *k = (s != NULL) ? s->kek : NULL;
    xSemaphoreGive(s_mtx);
    return k;
}

bool sec_session_expire_check(void)
{
    bool any = false;
    int64_t now = now_ms();
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    for (int i = 0; i < CFG_MAX_LINKS; i++) {
        if (s_sess[i].used && (now - s_sess[i].last_act_ms) >= CFG_SESSION_IDLE_MS) {
            ESP_LOGI(TAG, "session conn=%u expired after %us idle",
                     s_sess[i].conn_handle, (unsigned)CFG_SESSION_IDLE_MS / 1000);
            sess_destroy(&s_sess[i]);
            any = true;
        }
    }
    xSemaphoreGive(s_mtx);
    return any;
}

/* ---------------- nonces ---------------- */

static nonce_slot_t *nonce_find_used(uint16_t conn_handle)
{
    for (int i = 0; i < CFG_MAX_LINKS; i++) {
        if (s_nonce[i].used && s_nonce[i].conn_handle == conn_handle) {
            return &s_nonce[i];
        }
    }
    return NULL;
}

esp_err_t nonce_issue(uint16_t conn_handle, uint8_t out_nonce[32], uint32_t *out_seq)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    nonce_slot_t *slot = nonce_find_used(conn_handle);
    if (slot == NULL) {
        for (int i = 0; i < CFG_MAX_LINKS; i++) {
            if (!s_nonce[i].used) {
                slot = &s_nonce[i];
                break;
            }
        }
    }
    esp_err_t err = ESP_OK;
    if (slot == NULL) {
        err = ESP_ERR_NO_MEM;
    } else {
        /* C26: re-issuing invalidates the previous pending nonce */
        slot->used = true;
        slot->conn_handle = conn_handle;
        slot->pending = true;
        esp_fill_random(slot->nonce, 32);
        slot->seq = ++s_seq_ctr;
        memcpy(out_nonce, slot->nonce, 32);
        if (out_seq != NULL) {
            *out_seq = slot->seq;
        }
    }
    xSemaphoreGive(s_mtx);
    return err;
}

bool nonce_consume(uint16_t conn_handle, const uint8_t nonce[32], uint32_t seq)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    nonce_slot_t *slot = nonce_find_used(conn_handle);
    bool ok = false;
    if (slot != NULL && slot->pending &&
        slot->seq == seq && ct_mem_equal(slot->nonce, nonce, 32)) {
        ok = true;
    }
    if (slot != NULL) {
        /* one-shot: invalid immediately, success or not */
        slot->pending = false;
        memset(slot->nonce, 0, sizeof(slot->nonce));
    }
    xSemaphoreGive(s_mtx);
    return ok;
}

esp_err_t nonce_pending_seq(uint16_t conn_handle, uint32_t *out_seq)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    nonce_slot_t *slot = nonce_find_used(conn_handle);
    esp_err_t err = ESP_ERR_NOT_FOUND;
    if (slot != NULL && slot->pending && out_seq != NULL) {
        *out_seq = slot->seq;
        err = ESP_OK;
    }
    xSemaphoreGive(s_mtx);
    return err;
}
