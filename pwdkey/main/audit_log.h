/* audit_log.h - audit log on a dedicated partition (ring buffer, 16B records) */
#pragma once
#include <stdint.h>
#include "esp_err.h"

esp_err_t audit_log_init(void);

/* Append one record. entry_id may be NULL (all-zero). Records never contain secrets. */
esp_err_t audit_append(uint8_t evt_type, uint16_t conn_handle,
                       const uint8_t entry_id[8], uint16_t result_code);

/* Read records into out (raw 16B records). offset is a byte cursor over the
 * logical oldest-to-newest sequence. next_offset returns the cursor for the
 * following page. */
esp_err_t audit_read(uint32_t offset, uint8_t *out, uint16_t max_len,
                     uint16_t *out_len, uint32_t *next_offset);
