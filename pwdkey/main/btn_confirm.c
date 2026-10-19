/* btn_confirm.c - BOOT button driver (poll-based state machine, 10ms tick).
 *
 * Timing: short press (< 2s, on release) = confirm; holding past 2s fires
 * cancel immediately. Press events while nobody is waiting are discarded.
 */
#include "btn_confirm.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "driver/gpio.h"

#include "app_cfg.h"

static const char *TAG = "btn";

#define BTN_GPIO            GPIO_NUM_0
#define BTN_POLL_MS         10
#define BTN_DEBOUNCE_TICKS  2      /* 2 x 10ms stable samples */

/* request slot (single consumer) */
static SemaphoreHandle_t s_mtx;
static bool              s_req_pending;
static btn_req_type_t    s_req_type;
static uint16_t          s_req_conn;

/* waiter */
static bool              s_waiting;
static btn_req_type_t    s_wait_type;

/* press events */
static int               s_press_seq;      /* increments on each decided press */
static int               s_last_press;     /* 1 = short/confirm, 0 = long/cancel */
static uint8_t           s_last_outcome;   /* 0 = timeout, 1 = short, 2 = long */

static int64_t now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

static void btn_task(void *arg)
{
    (void)arg;
    bool stable = false, raw_last = false;
    int deb = 0;
    bool long_fired = false;
    int64_t press_t0 = 0;

    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(BTN_POLL_MS));
        bool raw = (gpio_get_level(BTN_GPIO) == 0);   /* active low */

        if (raw == raw_last) {
            if (deb < BTN_DEBOUNCE_TICKS) {
                deb++;
            }
        } else {
            raw_last = raw;
            deb = 0;
        }
        if (deb < BTN_DEBOUNCE_TICKS || stable == raw) {
            /* still bouncing or no state change: check long-press progress below */
            if (stable && !long_fired && raw &&
                (now_ms() - press_t0) >= CFG_BTN_SHORT_MAX_MS) {
                long_fired = true;
                xSemaphoreTake(s_mtx, portMAX_DELAY);
                if (s_waiting) {
                    s_last_press = 0;       /* long press = cancel */
                    s_press_seq++;
                }
                xSemaphoreGive(s_mtx);
            }
            continue;
        }

        /* stable state change */
        stable = raw;
        if (stable) {
            press_t0 = now_ms();
            long_fired = false;
        } else {
            if (!long_fired) {
                xSemaphoreTake(s_mtx, portMAX_DELAY);
                if (s_waiting) {
                    s_last_press = 1;       /* short press = confirm */
                    s_press_seq++;
                }
                xSemaphoreGive(s_mtx);
            }
        }
    }
}

esp_err_t btn_confirm_init(void)
{
    gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << BTN_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,     /* polled state machine (documented choice) */
    };
    esp_err_t err = gpio_config(&cfg);
    if (err != ESP_OK) {
        return err;
    }
    s_mtx = xSemaphoreCreateMutex();
    if (s_mtx == NULL) {
        return ESP_ERR_NO_MEM;
    }
    BaseType_t ok = xTaskCreate(btn_task, "btn_task", 3072, NULL, 6, NULL);
    if (ok != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "BOOT button ready (GPIO%d)", BTN_GPIO);
    return ESP_OK;
}

bool btn_is_pressed(void)
{
    return gpio_get_level(BTN_GPIO) == 0;
}

esp_err_t btn_confirm_post(const btn_req_t *req)
{
    if (req == NULL || req->type == BTN_REQ_NONE) {
        return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    esp_err_t err = ESP_OK;
    if (s_req_pending || s_waiting) {
        err = ESP_ERR_INVALID_STATE;    /* busy -> immediate reject on caller side */
    } else {
        s_req_pending = true;
        s_req_type = req->type;
        s_req_conn = req->conn_handle;
    }
    xSemaphoreGive(s_mtx);
    return err;
}

int btn_wait_result(btn_req_type_t type, uint32_t timeout_ms)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    if (!s_req_pending || s_req_type != type) {
        xSemaphoreGive(s_mtx);
        return 0;       /* no matching request: treat as denied */
    }
    s_req_pending = false;
    s_waiting = true;
    s_wait_type = type;
    int base = s_press_seq;
    xSemaphoreGive(s_mtx);

    int result = 0;
    int64_t deadline = now_ms() + timeout_ms;
    while (now_ms() < deadline) {
        xSemaphoreTake(s_mtx, portMAX_DELAY);
        bool fired = (s_press_seq != base);
        if (fired) {
            result = s_last_press;
        }
        xSemaphoreGive(s_mtx);
        if (fired) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(BTN_POLL_MS));
    }

    xSemaphoreTake(s_mtx, portMAX_DELAY);
    s_waiting = false;
    s_last_outcome = (s_press_seq != base)
                     ? (uint8_t)(result ? 1 : 2)    /* short / long */
                     : 0;                           /* timeout */
    xSemaphoreGive(s_mtx);
    return result;
}

uint8_t btn_last_outcome(void)
{
    return s_last_outcome;
}

bool btn_boot_factory_reset_check(void)
{
    if (!btn_is_pressed()) {
        return false;
    }
    int64_t t0 = now_ms();
    ESP_LOGW(TAG, "BOOT held at boot, watching for factory reset...");
    while ((now_ms() - t0) < CFG_BTN_FACTORY_MS) {
        if (!btn_is_pressed()) {
            return false;       /* released early */
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    return true;
}

void btn_confirm_cancel_pairing(void)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    if (s_req_pending && s_req_type == BTN_REQ_PAIRING) {
        s_req_pending = false;
    }
    if (s_waiting && s_wait_type == BTN_REQ_PAIRING) {
        s_last_press = 0;       /* inject cancel result */
        s_press_seq++;
    }
    xSemaphoreGive(s_mtx);
}
