/* host_name_probe.h - best-effort lookup of the connected central's name.
 *
 * Reads the peer's GAP Device Name (0x2A00) over GATT. Must be called from
 * NimBLE host-task context (GAP event callback). See host_name_probe.c for
 * the platform caveats.
 */
#pragma once
#include <stdint.h>

/* Start a probe for `conn`. No-op if the address is unknown, the user already
 * named this host, or the peer's GATT server cannot be reached. */
void name_probe_request(uint16_t conn);

/* Cancel an in-flight probe (call on disconnect). */
void name_probe_abort(uint16_t conn);
