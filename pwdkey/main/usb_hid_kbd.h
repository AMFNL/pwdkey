/* usb_hid_kbd.h - USB HID 键盘后端（TinyUSB）
 *
 * 定位：给"没有蓝牙、或不想配对"的电脑用。插上数据线即枚举为标准键盘，
 *       免驱、跨平台，输出路径与 BLE HID 完全等价（都是 HID report）。
 *
 * 与 ble_hid_kbd 的关系：两者是并列的"输出后端"，语义一致：
 *   都是把一段 ASCII 逐字符敲出去，都支持中途 abort。
 *   上层（将来的 hid_out 分发层）按通道选择调用其中一个。
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

/** 输出完成回调（在 USB 任务上下文调用，不要做耗时操作） */
typedef void (*usb_hid_done_cb_t)(esp_err_t result);

/** 初始化 TinyUSB。必须在 console 已切到 UART 之后调用（否则等宽 19/20 引脚冲突）。 */
esp_err_t usb_hid_init(void);

/** 主机是否已枚举完成（插好线、驱动装好） */
bool usb_hid_mounted(void);

/** 是否正在输出 */
bool usb_hid_busy(void);

/**
 * 异步输出一段 ASCII（仅支持 0x20-0x7E）。
 * 立即返回；实际打字在内部任务里做。
 * 忙碌时返回 ESP_ERR_INVALID_STATE。
 */
esp_err_t usb_hid_type_string(const char *ascii, uint8_t len);

/** 中止当前输出（会尽力松开所有键） */
void usb_hid_abort(void);

/** 设置完成回调 */
void usb_hid_set_done_cb(usb_hid_done_cb_t cb);

/**
 * 空闲时补发"全松开"。
 * 上层应在主循环里定期调用（比如每 300ms），
 * 防止任何意外残留导致主机 typematic 无限重复。
 */
void usb_hid_keepalive(void);
