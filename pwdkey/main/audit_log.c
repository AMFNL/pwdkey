/* audit_log.c - append-only ring buffer over the "audit" data partition.
 * Record layout (16 bytes, matches spec v1.2 section 6.3):
 *   0..3   timestamp (seconds since boot, LE)
 *   4      event type
 *   5      conn_handle
 *   6..13  entry id (zeroed if N/A)
 *   14..15 result code (LE)
 */
#include "audit_log.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_partition.h"

static const char *TAG = "audit";

#define AUDIT_REC_SIZE   16
#define AUDIT_ERASED_TS  0xFFFFFFFFu

static const esp_partition_t *s_part;
static SemaphoreHandle_t s_mtx;
static uint32_t s_size;      /* partition size in bytes */
static uint32_t s_next;      /* physical offset of the next slot to write (== oldest) */

static bool slot_is_erased(const uint8_t *rec)
{
    for (int i = 0; i < AUDIT_REC_SIZE; i++) {
        if (rec[i] != 0xFF) {
            return false;
        }
    }
    return true;
}

esp_err_t audit_log_init(void)
{
    s_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                      ESP_PARTITION_SUBTYPE_ANY, "audit");
    if (s_part == NULL) {
        ESP_LOGE(TAG, "audit partition not found");
        return ESP_ERR_NOT_FOUND;
    }
    s_size = s_part->size & ~(uint32_t)(AUDIT_REC_SIZE - 1);
    s_mtx = xSemaphoreCreateMutex();
    if (s_mtx == NULL) {
        return ESP_ERR_NO_MEM;
    }

    /* Locate the first erased slot. If the partition is entirely written,
     * find the slot holding the smallest timestamp and resume there. */
    uint8_t rec[AUDIT_REC_SIZE];
    uint32_t first_erased = UINT32_MAX;
    uint32_t oldest_off = 0;
    uint32_t oldest_ts = UINT32_MAX;

    for (uint32_t off = 0; off < s_size; off += AUDIT_REC_SIZE) {
        esp_err_t err = esp_partition_read(s_part, off, rec, AUDIT_REC_SIZE);
        if (err != ESP_OK) {
            return err;
        }
        if (slot_is_erased(rec)) {
            if (first_erased == UINT32_MAX) {
                first_erased = off;
            }
            continue;
        }
        uint32_t ts;
        memcpy(&ts, rec, 4);
        if (ts < oldest_ts) {
            oldest_ts = ts;
            oldest_off = off;
        }
    }

    s_next = (first_erased != UINT32_MAX) ? first_erased : oldest_off;
    ESP_LOGI(TAG, "audit partition %u bytes, next=%u (erased=%d)",
             (unsigned)s_size, (unsigned)s_next, first_erased != UINT32_MAX);
    return ESP_OK;
}

esp_err_t audit_append(uint8_t evt_type, uint16_t conn_handle,
                       const uint8_t entry_id[8], uint16_t result_code)
{
    if (s_part == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t rec[AUDIT_REC_SIZE];
    uint32_t ts = (uint32_t)(esp_timer_get_time() / 1000000);

    memcpy(rec, &ts, 4);
    rec[4] = evt_type;
    rec[5] = (uint8_t)(conn_handle & 0xFF);
    if (entry_id != NULL) {
        memcpy(rec + 6, entry_id, 8);
    } else {
        memset(rec + 6, 0, 8);
    }
    rec[14] = (uint8_t)(result_code & 0xFF);
    rec[15] = (uint8_t)(result_code >> 8);

    xSemaphoreTake(s_mtx, portMAX_DELAY);
    esp_err_t err = esp_partition_write(s_part, s_next, rec, AUDIT_REC_SIZE);
    if (err == ESP_OK) {
        s_next += AUDIT_REC_SIZE;
        if (s_next >= s_size) {
            s_next = 0;
        }
    }
    xSemaphoreGive(s_mtx);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "append failed: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t audit_read(uint32_t offset, uint8_t *out, uint16_t max_len,
                     uint16_t *out_len, uint32_t *next_offset)
{
    if (s_part == NULL || out == NULL || out_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_len = 0;
    if (next_offset != NULL) {
        *next_offset = offset;
    }
    if (offset >= s_size || max_len < AUDIT_REC_SIZE) {
        return ESP_OK;      /* nothing more to read */
    }

    uint32_t want = max_len < (s_size - offset) ? max_len : (s_size - offset);
    uint32_t copied = 0;
    uint8_t rec[AUDIT_REC_SIZE];

    /* Walk the ring starting at the oldest record (s_next), skipping 'offset'
     * bytes of the logical sequence. */
    uint32_t pos = s_next;
    uint32_t skip = offset;
    uint32_t produced = 0;   /* bytes of the logical sequence already consumed */

    while (produced < s_size) {
        if (skip >= AUDIT_REC_SIZE) {
            skip -= AUDIT_REC_SIZE;
            pos = (pos + AUDIT_REC_SIZE) % s_size;
            produced += AUDIT_REC_SIZE;
            continue;
        }
        if (skip > 0) {
            /* partial record offset: not supported, align down */
            skip = 0;
        }
        if (copied + AUDIT_REC_SIZE > want) {
            break;
        }
        esp_err_t err = esp_partition_read(s_part, pos, rec, AUDIT_REC_SIZE);
        if (err != ESP_OK) {
            return err;
        }
        if (slot_is_erased(rec)) {
            break;      /* hit unwritten area: no more records */
        }
        memcpy(out + copied, rec, AUDIT_REC_SIZE);
        copied += AUDIT_REC_SIZE;
        produced += AUDIT_REC_SIZE;
        pos = (pos + AUDIT_REC_SIZE) % s_size;
    }

    *out_len = (uint16_t)copied;
    if (next_offset != NULL) {
        *next_offset = offset + copied;
        if (*next_offset >= s_size) {
            *next_offset = s_size;      /* end marker: caller sees short read */
        }
    }
    return ESP_OK;
}
