# PwdKey 固件操作部署手册 v1.0

> **适用对象**：拿到本固件源码的开发者 / 测试人员。
> **配套文档**：《ESP32-S3 BLE密码输入器_项目开发总纲 v1.1》（设计依据、协议规范）。
> **固件版本**：pwdkey v0.1.0（协议文档 v1.2 / `sys.ver = 1`）
> **硬件**：ESP32-S3-N16R8 开发板（16MB Flash / 8MB Octal PSRAM）

---

## 目录

1. [交付物与目录结构](#1-交付物与目录结构)
2. [环境准备](#2-环境准备)
3. [编译](#3-编译)
4. [烧录](#4-烧录)
5. [首次上电与初始化（S0 出厂流程）](#5-首次上电与初始化s0-出厂流程)
6. [电脑配对键盘（HID）](#6-电脑配对键盘hid)
7. [日常使用流程](#7-日常使用流程)
8. [测试验证清单（阶段 0）](#8-测试验证清单阶段-0)
9. [故障排查速查表](#9-故障排查速查表)
10. [生产 / 批量检查清单](#10-生产--批量检查清单)
11. [实现说明与规范偏差记录](#11-实现说明与规范偏差记录)
12. [附录 A：nRF Connect 手工调试指南（App 开发前的验证路径）](#附录-anrf-connect-手工调试指南)
13. [附录 B：常用命令速查](#附录-b常用命令速查)

---

## 1. 交付物与目录结构

固件工程位于 `<项目根>\pwdkey\`：

```
pwdkey/
├── CMakeLists.txt                # 工程根（project(pwdkey)）
├── partitions.csv                # 分区表 v2：nvs 16K / factory 11.9M / vault 1M@0xC00000 / audit 256K@0xD00000
├── sdkconfig.defaults            # 关键配置（含 HKDF/SM_LVL/NVS_PERSIST 等）
└── main/
    ├── CMakeLists.txt
    ├── app_cfg.h                 # 集中配置宏
    ├── main.c                    # 初始化序列编排
    ├── kdf.c / kdf.h             # PBKDF2 / HKDF / HMAC / 常数时间比较 / benchmark
    ├── sec_store.c / sec_store.h # NVS + AES-256-GCM 存储（含重加密事务）
    ├── sec_session.c / sec_session.h  # 会话 / nonce / 失败计数与锁定
    ├── btn_confirm.c / btn_confirm.h  # BOOT 键驱动（短按确认 / 长按取消）
    ├── ble_hid_kbd.c / ble_hid_kbd.h  # HID 键盘（Report Map / 字符映射 / 打字引擎）
    ├── ble_mgmt_svc.c / ble_mgmt_svc.h # 管理服务（0xFFF0，15 条指令）
    ├── ble_gap_mgr.c / ble_gap_mgr.h  # GAP（S0/S1/S2 广播、配对、连接跟踪）
    └── audit_log.c / audit_log.h      # 审计日志（环形缓冲）
```

9 个模块与总纲 §5 冻结接口一一对应；额外补充的少量辅助接口（如打字完成回调、nonce 查询等）在 §11 有清单。

---

## 2. 环境准备

### 2.1 硬件

| 项 | 要求 |
|---|---|
| 开发板 | ESP32-S3-N16R8（必须是 **R8** = Octal PSRAM 版本，sdkconfig 已按此配置） |
| 数据线 | USB-C **数据线**（注意：部分线缆只有充电功能，无法识别串口） |
| 电脑 | Windows（本手册以 Windows 为准）；蓝牙 4.0+（用于 HID 配对测试） |
| 手机 | Android / iOS（安装 nRF Connect，用于 S0 初始化与协议调试） |

### 2.2 软件（ESP-IDF v5.5.5）

本工程已在本机验证：`<IDF_PATH>`（离线安装器安装）。

**标准激活方式（推荐）**：
- 开始菜单 → 「ESP-IDF 5.5 CMD」或「ESP-IDF 5.5 PowerShell」→ 在打开的窗口里操作。

**⚠️ 本机踩坑记录（重要）**：

1. **不要在 Git Bash / MSYS 里编译**——IDF 的 `idf_tools.py` 会直接拒绝（"MSys/Mingw is not supported"）。
2. **如果命令行直接 `idf.py` 提示找不到 venv**（例如 `idf5.5_py3.13_env not found`）：说明探测到了系统里其它版本的 Python。先用 `venv` 的 python 顶到 PATH 最前再激活（本机验证过的 PowerShell 序列）：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
$env:IDF_TOOLS_PATH = "<IDF_TOOLS_PATH>"
$env:PATH = "<IDF_TOOLS_PATH>\python_env\idf5.5_py3.11_env\Scripts;" + $env:PATH
. "<IDF_PATH>\export.ps1"
cd <项目根>\pwdkey
```

激活成功的标志：输出结尾出现 `ESP-IDF v5.5.5`。

---

## 3. 编译

在已激活 IDF 环境的终端中：

```bash
cd <项目根>\pwdkey

# 1) 设置目标芯片（首次执行一次；会读取 sdkconfig.defaults 生成 sdkconfig）
idf.py set-target esp32s3

# 2) 编译
idf.py build
```

**成功标志**（输出末尾）：

```
Project build complete. To flash, run:
 idf.py flash
or
 idf.py -p (PORT) flash
```

**产物**（`build/` 目录）：

| 文件 | 说明 |
|---|---|
| `pwdkey.bin` | 应用程序 |
| `bootloader/bootloader.bin` | 引导器 |
| `partition_table/partition-table.bin` | 分区表（应与 §3.4 文档一致） |
| `flash_args` / `flasher_args.json` | 烧录参数 |

**校验分区表**（可选）：

```bash
idf.py partition-table
```
预期与 `partitions.csv` 一致：nvs 0x9000(16K) / phy_init 0xD000(4K) / factory 0x10000(11.9M) / **vault 0xC00000(1M)** / audit 0xD00000(256K)。
> `vault` 是独立的数据分区，固定在 12 MB 处；固件区最大 11.9 MB，两者物理隔离，
> 因此**烧录任何固件都不可能覆盖密码库**。

#### 分区布局（v2，2026-10-27 起）

| 分区 | 偏移 | 大小 | 内容 | 烧固件会碰吗 |
|---|---|---|---|---|
| bootloader | `0x000000` | 32 K | 引导器 | ✅ 每次都写 |
| 分区表 | `0x008000` | 4 K | 本表 | ✅ 每次都写 |
| nvs | `0x009000` | 16 K | BLE 绑定/配对（丢了只需重配） | ⚠️ 仅改分区表时 |
| phy_init | `0x00D000` | 4 K | 射频校准 | ✅ 每次都写 |
| factory | `0x010000` | 11.9 M | 固件本体（当前 578 K） | ✅ 每次都写 |
| **vault** | **`0xC00000`** | **1 M** | **密码库** | ❌ **永不触碰** |
| audit | `0xD00000` | 256 K | 审计日志 | ❌ 永不触碰 |

**为什么这样排**：容量小的数据区放到 flash 尾部，代码区只占前 11.9 MB。
`idf.py flash` 只写 `0x0 / 0x8000 / 0x10000` 三个地址，物理上到不了 `0xC00000`。
即使以后固件涨到 11 MB、或改成双 OTA 槽（`ota_0` + `ota_1`），`vault` 依然原地不动。

**已实测**：连续两次完整烧录固件，读取 `0xC00000` 起 1 KB 与烧录前逐字节比对，完全一致。

**v1 → v2 的变化**：

| | v1（旧） | v2（当前） |
|---|---|---|
| nvs | 48 K @`0x9000` | 16 K @`0x9000` |
| factory | 2 M @`0x20000` | 11.9 M @`0x10000` |
| vault | —— | **1 M @`0xC00000`** |
| audit | 128 K @`0x220000` | 256 K @`0xD00000` |

所有用户数据（主密码验证值/盐/条目/主机名/系统配置）从 `nvs` 迁到 `vault`，
代码里统一走 `app_cfg.h` 的 `VAULT_NVS_OPEN()` 宏。

> ⚠️ **从 v1 分区表跨到 v2 时，旧 `nvs` 里的数据不会自动迁移**（位置和大小都变了）。
> 设备里已有密码的，必须先用旧固件导出，再在新固件里重新录入。

**数据版本保护**：`vault` 内有 `sys.ver` 记录数据格式版本。

- 旧数据 + 新固件 → 记录日志并继续（迁移钩子已预留）
- 新数据 + 旧固件（降级）→ **拒绝启动**，宁可打不开也不冒险写坏

**绝对不要做**：

- `idf.py erase_flash` / `esptool erase_flash` —— 全片擦除，密码库一起没
- 用**不同布局**的 `partitions.csv` 烧任何测试固件 —— app 起点一变就可能盖住数据区
  （2026-10-27 曾因此覆盖过旧 NVS 后半段）

**确认关键配置已生效**（可选，防 C3 类问题）：

```bash
# 确认下列值应为 y / 对应数值
python -c "import re;c=open('sdkconfig',encoding='utf-8').read();[print(k,re.search(k+r'=(\S+)',c).group(1) if re.search(k+r'=(\S+)',c) else 'MISSING') for k in ['CONFIG_MBEDTLS_HKDF_C','CONFIG_BT_NIMBLE_SM_LVL','CONFIG_BT_NIMBLE_NVS_PERSIST','CONFIG_NVS_ENCRYPTION']]"
```
预期：`CONFIG_MBEDTLS_HKDF_C=y`、`CONFIG_BT_NIMBLE_SM_LVL=2`、`CONFIG_BT_NIMBLE_NVS_PERSIST=y`、`CONFIG_NVS_ENCRYPTION` 不存在或为 n。

**首次编译时间**：全量编译约 12 分钟（本机实测，含 bootloader）；后续增量编译约 2 分钟。

### 3.1 本机实测编译验证结果（✅ 已通过）

> 本节为 2026-10-16 在本机（ESP-IDF v5.5.5 / Windows）的实际编译验证记录：

| 项 | 结果 |
|---|---|
| 工具链 | xtensa-esp32s3-elf GCC 14.2.0（esp-14.2.0_20260121） |
| 主程序编译 | ✅ 通过，**0 警告**（-Wall -Wextra） |
| `build/pwdkey.bin` | **574,688 字节**（Total image ≈ 574.6 KB，占 2MB app 分区约 28%，余量充足） |
| `build/bootloader/bootloader.bin` | 20,832 字节 |
| `build/partition_table/partition-table.bin` | 3,072 字节；**解析验证**：nvs 16K / phy_init 4K / factory 11.9M / vault 1M@0xC00000 / audit 256K@0xD00000 —— 与 `partitions.csv` 完全一致 |
| sdkconfig 关键项 | ✅ 全部生效：`MBEDTLS_HKDF_C=y`、`SM_LVL=2`、`NVS_PERSIST=y`、`MAX_CCCDS=16`、`SVC_HID_MAX_RPTS=2`、`SPIRAM_MODE_OCT=y`、**`NVS_ENCRYPTION` 未设置（零 eFuse 红线守住）** |
| 过程中修复的编译问题 | 仅 1 处（`ble_mgmt_svc.h` 缺 `<stdbool.h>`，已修复） |

**注意**：编译通过 ≠ 功能通过。**功能验证请按 §8 测试清单在真机执行**（尤其是双连接 0.2、句柄自检 0.3 两项）。

### 3.2 真机部署与协议验证结果（2026-10-16 实测 ✅）

> 本节记录在真实硬件上完成的部署与端到端协议验证（验证工具：Python `bleak`，本机蓝牙）：

**部署环境**

| 项 | 值 |
|---|---|
| 开发板 | ESP32-S3-N16R8；蓝牙 MAC `AA:BB:CC:DD:EE:FF`（示例）；广播名 `PwdKey-XXXX`（随芯片地址生成，工厂恢复后重新生成） |
| 串口 | Windows 下通常为 `COMx`；板载 **USB-Serial-JTAG**（VID 303A / PID 1001），一根 USB 线即可烧录 + 看日志 |
| 烧录 | `idf.py -p COMx flash`（建议首次做一次"全片擦除 → 重烧"演练） |

**已通过验证项**

| # | 验证项 | 结果 |
|---|---|---|
| 1 | 启动自检 | ✅ `report handles: in=46 out=50`（C2 句柄捕获正确，非 0 且不等）；PSRAM 8MB@80MHz |
| 2 | eFuse 安全基线 | ✅ `SPI_BOOT_CRYPT_CNT=0`、`SECURE_BOOT_EN=False`、JTAG 未禁（零 eFuse 承诺落实） |
| 3 | BLE 广播 | ✅ 扫描到 `PwdKey-XXXX`（RSSI≈-33），名称/MAC 与设计一致（实测广播名已脱敏） |
| 4 | GATT 服务表 | ✅ 管理服务 0xFFF0（0xFFF1~FFF5 全部正确）+ BAS + DIS + GAP |
| 5 | 配对与加密 | ✅ Just Works 配对成功；`enc_change status=0` 加密链路建立 |
| 6 | **Auth Challenge** | ✅ 读 0xFFF1 返回 **36 字节** = NONCE(32) + SEQ(4 LE)，与协议 P-2 完全一致 |
| 7 | **DEVICE_INFO 往返** | ✅ 响应帧（`A5 01 01 0C 3A 00...`）全部 TLV 解析正确：FW 0.1.0 / STATE=0x0022 / SALT(16B) / **KDF_ITER=200000** / LAYOUT=0 |
| 8 | Status 特征 | ✅ 读 0xFFF5 返回 STATE(2B)+LOCK_SECONDS(4B) |
| 9 | S0 窗口超时 | ✅ `W gap_mgr: S0 window expired` → RTC_SW_CPU_RST 自动重启回 S0 |
| 10 | 完整业务闭环（用户实机） | ✅ `info` 回报 STATE=`0x0142` = 已绑定 + **HID 链路 ≥2** + 主密码已设置；`store ready, 1 entries`；audit `next=240`（设置成功 + 后续操作均已落审计） |
| 11 | S1 低频持续广播（C29 回归） | ✅ 启动日志 `advertise; adv_itvl_min=1600 adv_itvl_max=2400`，且在已连接状态下仍继续广播 |

**联调阶段发现并已修复的问题（C29–C34，均已重编重烧）**

| 编号 | 问题 | 影响 | 修复 |
|---|---|---|---|
| **C29** | S1 常态不广播 | 设置主密码后设备无法再被连接（ENTER_PAIRING 也发不出去） | S1 改为**低频持续广播**（1–1.5s 间隔，可连接） |
| **C30** | AUTH_NEW 缺先行 HALF-SYNC | App 在用户按键前无任何反馈 | 三个分支立即回 HALF-SYNC；改密第一步 `NEW_SALT` 帧补 `RESULT_CODE` |
| **C31** | **AUTH_NEW(SETUP) 重新生成 salt** | **🔴 设置主密码后永远无法登录**——App 用 DEVICE_INFO 下发的 salt 计算 KEK，而设备把 verifier 绑定到了新生成的 salt 上 | SETUP 改为沿用现有 salt（仅缺失时兜底生成） |
| **C32** | 恢复码重置同样重新生成 salt/iter | 重置后无法用新密码登录 | 沿用现有 salt/iter |
| **C33** | `PWD_TYPE` 遇多条 HID 链路时只回裸 `0x3002` | App 拿不到候选目标，**多电脑场景下完全无法输出**（用户报 bug） | 新增 `send_hid_ambiguous()`：`0x3002` 附带 **N 个 `TARGET_HANDLE` TLV**（候选 HID `conn_handle` 低 1 字节，最多 8 个）；App 让用户选一台后带 `TARGET_HANDLE` 重发 |
| **C34** | 上述候选用 **conn_handle** 标识 | conn_handle 每次重连都变 → App 侧无法把"第 2 台"稳定地对应到某台电脑，**命名功能无从落地** | 目标寻址整体改为 **6 字节 peer MAC**（`T_HOST_ADDR=0x20`）；`0x3002` 候选改为携带 MAC（并附带已知名称），重发时带 MAC。旧的单字节 `TARGET_HANDLE` 语义作废 |

> C31/C32 由"小程序 × mock 设备"端到端测试发现（真实硬件联调前拦截）。
> 小程序侧的配套修复（RESULT_CODE 判定语义、连接脏状态防护）见《小程序使用指南》第 7 节。
> **C33 需与小程序的「输出到第 N 台电脑」选择框配套使用**，两侧任一未升级都无法工作
> ——详见《小程序使用指南》§8 v1.0.2。

**已完成的实机验证（用户实操）**：主密码设置（AUTH_NEW）→ 认证解锁（AUTH_VERIFY）→
密码条目增删 → 电脑键盘配对（ENTER_PAIRING，且同时建立了 ≥2 条 HID 链路）。
密码输出（PWD_TYPE）需本机按键配合，由用户在手机端复验。

**`PWD_TYPE` 目标解析规则（v1.2 协议补充，C34 后）**

| 条件 | 设备行为 |
|---|---|
| HID 链路数 = 0 | `0x3001 无 HID 链路` |
| HID 链路数 = 1 | 直接输出到该链路（无需指定目标） |
| HID 链路数 ≥2 且未带 `T_HOST_ADDR` | `0x3002` + 候选列表（每台一个 `T_HOST_ADDR` + `T_HOST_NAME`） |
| 带了 `T_HOST_ADDR` 且匹配成功 | 输出到指定链路 |
| 带了 `T_HOST_ADDR` 但该 MAC 不在线 / 不是 HID 链路 | `0x3002` + 最新候选列表（App 应重新让用户选） |

**主机命名（新增，v1.2 协议扩展）**

设备为每个连接过的 HID 主机维护一条记录，键为 **peer identity address**（不是会变的 conn_handle），
保存在独立 NVS 命名空间 `pkey_host`（单 blob，最多 8 条 × 40 B）。

| Opcode | 名称 | 认证 | 说明 |
|---|---|---|---|
| `0x42` | `HOST_LIST` | 需要 | 分页返回已登记主机（每页 2 条）。每条含 `T_HOST_ADDR`(6B) + `T_HOST_NAME` + `T_HOST_FLAGS`；附 `T_HOST_COUNT` 总数与 `T_PAGE_INDEX` |
| `0x43` | `HOST_RENAME` | 需要 | 按 MAC 设置自定义名；不带 `T_HOST_NAME` 或空值 = 清除自定义名并恢复 MAC 兜底名 |
| `0x44` | `HOST_DISCONNECT` | 需要 | 断开指定 MAC 的连接；目标是承载管理连接的那一台时返回 `0x4006` |

新增 TLV：`T_HOST_ADDR=0x20`、`T_HOST_NAME=0x21`、`T_HOST_FLAGS=0x22`、`T_HOST_COUNT=0x23`。
其中 `HOST_FLAGS` 低两位持久化（`0x01` 用户已命名 / `0x02` 曾是 HID），
高两位实时计算（`0x40` 在线 / `0x80` 当前是 HID 链路）——在线状态**从不落盘**，避免异常掉电留下脏标记。

**名字的三层优先级**：用户自定义 > 自动探测的蓝牙名 > `电脑 XXXX`（MAC 末两位大写十六进制）。

> ⚠️ **构建配置变更**：反向读取对方蓝牙名需要 NimBLE 的 GATT Client，即必须打开
> `CONFIG_BT_NIMBLE_ROLE_CENTRAL=y`（见 `sdkconfig.defaults` / `sdkconfig`）。
> 若关闭此开关，`host_name_probe.c` 会在链接期报 `undefined reference to ble_gattc_*`。
> 注意：仅改 `sdkconfig.defaults` 对**已存在** `sdkconfig` 的工程不生效，需同时改 `sdkconfig` 或删掉它重建。

> 平台差异实测预期：Android / iOS / Linux BlueZ 通常能读到名字；**Windows 读不到**（无可读 Device Name）
> ——属预期行为，用户在小程序里手动命名即可。

**开发期注意事项（实测发现）**

1. **Windows 蓝牙会自动重连已配对设备**——设备每次重启/广播后 Windows 可能自动连接
   （串口可见 `connected` → `enc_change` → `mtu=256`）。自动化测试时应注意此行为带来的干扰（会产生"意外的"连接事件与 HID 订阅）。
2. **console 已配置为 USB-Serial-JTAG primary**（见 `sdkconfig.defaults`）：一根 USB 线即可完成
   烧录 + 看日志。如改用板载 UART 口看日志，把 defaults 改回 `CONFIG_ESP_CONSOLE_UART_DEFAULT=y` 并重编。
3. 验证用辅助脚本位于工作区 `.workbuddy/`（read_serial / scan_ble / protocol_smoke_test 等），可复用。

---

## 4. 烧录

### 4.1 连接与识别串口

1. USB 线连接开发板与电脑；
2. 查看串口号：设备管理器 → 端口（COM 和 LPT）→ 找到 `USB-SERIAL CH340` / `CP210x` / `USB JTAG/serial debug unit` 对应的 `COMx`。

### 4.2 烧录并监视

```bash
idf.py -p COM5 flash monitor
```
（把 `COM5` 换成实际串口）

- **不要按住 BOOT 上电**（GPIO0 是 strapping 引脚，按住会进下载模式而不是运行固件）；
- 退出监视：`Ctrl+]`。

### 4.3 全局擦除（零 eFuse 方案任意阶段可用）

```bash
idf.py -p COM5 erase-flash
```
用途：清空全部数据（密码、绑定、审计）回到出厂态；开发期改 GATT 布局后**必须**擦除并重新配对（C10，对端服务缓存问题）。

### 4.4 预期启动日志（首次烧录、空 NVS）

```
I (xxx) btn: BOOT button ready (GPIO0)
I (xxx) sec_store: store ready, 0 entries
I (xxx) audit: audit partition 131072 bytes, next=0 (erased=1)
I (xxx) hid_kbd: HID keyboard ready (map 65 bytes)
I (xxx) mgmt: management service ready
I (xxx) main: init done
I (xxx) hid_kbd: report handles: in=XX out=YY (in!=0 && in!=out == capture OK)
```
> **关键自检**：`in` 与 `out` 两个句柄必须是**非 0 且不相等**（C2 验收）。若 in==out==0，说明 DSC 捕获失败，检查启动顺序。
> 若 NVS 中已有主密码，还会看到广播为静默（S1）而非 S0。

---

## 5. 首次上电与初始化（S0 出厂流程）

> 出厂首次上电后设备进入 **S0 态**：广播 120 秒，只接受 `DEVICE_INFO` / `AUTH_NEW` / `AUTH_VERIFY` 三条指令。
> ⚠️ **S0 是产品最弱时刻**：请在私密环境完成首次设置。120 秒超时未完成会重启回到 S0。

### 5.1 用 nRF Connect 连接（App 就绪前的标准调试路径）

1. 打开 nRF Connect → SCANNER → 找到 `PwdKey-XXXX`（XXXX 为随机 4 位 hex）→ CONNECT；
2. 展开服务 `0xFFF0`，应看到 5 个特征：`0xFFF1`(Read) `0xFFF2`(Write) `0xFFF3`(Write) `0xFFF4`(Read,Notify) `0xFFF5`(Read,Notify)；
3. 订阅 `0xFFF4` 的 **Notify**（点右侧三个箭头图标）；
4. 向 `0xFFF3` 写一帧 `DEVICE_INFO` 请求：
   ```
   A5 01 01 04 00 00
   （MAGIC A5 | VERSION 01 | OPCODE 01 | FLAGS 04(LAST) | TOTAL_LEN 0000）
   ```
5. `0xFFF4` 会收到响应，可解析出：`salt`(0x19)、`KDF_ITER`(0x1A)、`STATE`(0x09，位 8 = 0 表示未设置主密码)。

### 5.2 设置主密码（AUTH_NEW，需在 App 中完成）

> 设备端不接收主密码明文。完整流程（协议规范 §5.5 / §6.1）：
> App 端执行 PBKDF2(主密码, salt, iter, 32) → 得 KEK → 提交 `KEK_BLOB`。
> **当前无正式 App**，推荐先用 nRF Connect **手工**按附录 A 流程走通；在 App 开发完成后此步骤完全由 App 完成。

设置成功后：
- `0xFFF4` 收到 `RECOVERY_CODE`（24 字符）——⚠️ **只显示一次，必须抄写保存**；
- 设备**自动按键确认**要求：设置过程中**在设备上短按 BOOT 键**（等待期间 App/nRF 会先收到 HALF-SYNC 的 STATE 位 2）；
- 完成后设备退出 S0（停止广播），进入常态 S1。

### 5.3 常见初始问题

| 现象 | 处理 |
|---|---|
| 扫描不到设备 | 确认上电后 120s 内扫描；超时设备重启发 S0 广播，等它重启后再扫 |
| 写 0xFFF3 无响应 | 确认已订阅 0xFFF4 Notify；确认帧头 6 字节格式正确 |
| AUTH_NEW 返回 0x400A | 请求里缺 `KEK_BLOB`(0x1C)，见规范 §6.1 |
| 按键后仍失败 | 确认按的是 BOOT（GPIO0），短按 < 2 秒 |

---

## 6. 电脑配对键盘（HID）

BLE HID 的"键盘配对"需要设备进入 **S2 配对模式**（广播含 HID 服务 UUID + Keyboard 外观）。

### 6.1 进入 S2 模式

两种方式：

**方式 A（标准路径，需 App/调试端已认证）**：
1. 认证（AUTH_VERIFY）；
2. 发送 `ENTER_PAIRING`（opcode `0x40`）；
3. **在设备上短按 BOOT** 确认；
4. 设备进入 S2：广播 60 秒，App 会收到 STATE 位 7（配对模式）。

**方式 B（开发调试）**：S2 窗口到期或未进入时，可临时用烧录后第一件事——通过 nRF Connect 完成方式 A 的前两步 + 按键。

### 6.2 在电脑上配对

**Windows 10/11**：
1. 设置 → 蓝牙和其他设备 → 添加设备 → 蓝牙；
2. 找到 `PwdKey-XXXX` → 点击 → 等待配对完成；
3. 完成信号：设备列表出现键盘图标；**立刻测试**：打开记事本，App 发一条 `PWD_TYPE`，按设备 BOOT 键，应逐字符打出。

**Android**：设置 → 蓝牙 → 扫描 → 配对（可能弹出数字确认框，按设备 BOOT 确认）。

### 6.3 HID 目标验证（`PWD_TYPE` 全流程）

前置：设备已认证 + 电脑已配对（HID 链路在线，STATE 位 5 = 1）+ 至少存了一条密码。

```
① App/nRF → 0xFFF3 写 PWD_TYPE 帧：
   A5 01 24 04 <TL 2B> | 01 08 00 <8B 条目ID> | 07 02 00 <2B 请求ID>
② 0xFFF4 收到 HALF-SYNC：STATE 位 2 = 1（等待确认）+ ENTRY_ID + TIMEOUT_MS
③ 在设备上【短按 BOOT】
④ 电脑记事本应自动逐字符打出该条密码
⑤ 0xFFF4 收到 ASYNC：RESULT_CODE = 0x0000
```

---

## 7. 日常使用流程

1. **存密码**：App `PWD_ADD`（纯 ASCII；中文/emoji 会被设备拒绝 0x2007）；
2. **用密码**：电脑点入输入框 → App 点"输入" → 设备短按 BOOT → 自动打出；
3. **安全提醒**：
   - 每次输出都要按 BOOT（物理确认，防手机沦陷）；
   - 认证后 30 秒内才可执行输出（超时回 0x400B，重新验证即可）；
   - 目标电脑必须是 **US QWERTY** 布局，否则含符号的密码会输错；
4. **锁定与恢复**：
   - 3 次认证失败 → 锁 30 秒；6 次 → 锁 5 分钟；10 次 → **永久锁定**（重启不清零）；
   - 恢复码重置会**清空全部密码**；修改主密码保留数据；
   - 上电后立刻长按 BOOT ≥5 秒 = **工厂重置**（全部擦除）。

---

## 8. 测试验证清单（阶段 0）

按总纲 §7 顺序执行（前 3 项为最高优先级）：

| # | 测试项 | 操作 | 通过标准 |
|---|---|---|---|
| 0.1 | 编译 | `idf.py build` | 编译通过；`CONFIG_MBEDTLS_HKDF_C=y` |
| **0.2** | **双连接** | 手机（nRF Connect）连上后，按 §6 让电脑也连上（或反之） | 两条链路同时在线 ≥10 分钟；串口无资源错误 |
| 0.3 | HID 基础 | 见 §6.3 | 电脑正确打出字符；串口 `rpt in/out` 非 0 且不等 |
| 0.3b | BOOT 键 | 串口观察按键日志；正常上电 ×10 | 短/长按区分正确；10/10 正常启动 |
| 0.4a | 平台兼容 A | Windows/Android 配对 + 打混合字符 | 均正确 |
| 0.4b | 平台兼容 B | macOS/iOS；**记录是否弹配对确认框** | 记录矩阵表（R18） |
| 0.5 | 全字符 | 打一遍 95 字符测试串（总纲 §8.5） | 逐字符正确 |
| 0.6 | 管理服务 | nRF Connect 全指令遍历 | 每条指令响应正确 |
| 0.7 | 持久化 | 存 3 条 → 断电重启 | 数据保留 |
| 0.8 | KDF benchmark | 代码中调用 `kdf_bench_iterations(2500)` | 迭代数写入 `cred.iter` 目标 2–3 秒 |
| 0.9 | S0/S2 窗口 | 观察 120s/60s 超时行为 | S0 超时重启；S2 超时回 S1 |
| 0.10 | 配对物理确认 | Win/Android 配对时按 BOOT | 确认后配对成功 |
| 0.11 | SM_LVL=3（阶段 1） | 改 sdkconfig + `sm_mitm=1` + 重编译 | 配对与打字仍正常 |

**安全检查**（建议一并执行）：

| 测试 | 操作 | 通过标准 |
|---|---|---|
| 失败锁定 | 故意输错主密码 3/6/10 次 | 分别触发 30s / 5min / 永久锁定 |
| 重启不清锁定 | 锁定中断电重启 | 仍处于锁定 |
| 恢复码重置 | 用恢复码重置 | 成功；全部条目清空 |
| 断电恢复 | 重加密中断电（可暴力测试） | 重启后数据完好（前滚/回滚） |
| 无明文 | `esptool read_flash` 搜测试密码 | 搜不到 |
| eFuse 未动 | `espefuse.py summary` | 全 0，未烧 |

---

## 9. 故障排查速查表

（与总纲 §10 + 附录一对应，为实际固件行为）

| 现象 | 最可能原因 | 处理 |
|---|---|---|
| 能配对但打字无反应 | 句柄捕获失败 / 未加密 | 看串口 `rpt in/out` 自检行；清 bond 重配对 |
| 个别字符打错 | 映射表 off-by-one | 跑 §8.5 断言（42 项）；不要肉眼看屏幕 |
| 打字丢字符 | 延迟/主机节奏 | 调大 `CFG_INTER_CHAR_MS`（8→15/25ms）；检查释放报告 |
| 每次重启要重新配对 | `NVS_PERSIST` 未生效 | 确认 sdkconfig；清 bond 重配 |
| 改了固件但行为还是旧的 | 对端服务缓存 | `idf.py erase-flash` + 电脑/手机侧删除设备 → 重配 |
| SM_LVL=3 后完全不出字 | 主机不弹框/sm_mitm 未同步 | 退回 `SM_LVL=2`，按附录一两段式升级 |
| 上电直接进下载模式 | 上电时按住了 BOOT | 属预期；上电时勿按 BOOT |
| `ble_gap_adv_start` 失败 | 地址未初始化（已被固件修复） | 确认固件为 v2.1+（`ensure_addr` 已内置） |
| 重启后数据丢失 | 重加密事务未完成 | 检查串口 rekey 恢复日志；必要时 erase 重来 |
| 手机换 RPA 后认不出 | IRK 未分发 | 确认 `key_dist` 配置（已内置）；清 bond 重配 |

---

## 10. 生产 / 批量检查清单

逐台出厂检查（与总纲附二.2 一致）：

| # | 检查项 | 方法 | 判据 |
|---|---|---|---|
| 1 | 固件可启动 | 上电看串口 | 无 panic；`init done` |
| 2 | **eFuse 未被触碰** | `espefuse.py summary` | `SPI_BOOT_CRYPT_CNT` 全 0 |
| 3 | 无 NVS 加密 | 检查 sdkconfig | `CONFIG_NVS_ENCRYPTION` 未设 |
| 4 | 分区表正确 | `idf.py partition-table` | 与标准一致；nvs 无 encrypted 标志 |
| 5 | 双连接可用 | 电脑 + 手机同时连 | 见阶段 0.2 |
| 6 | HID 出字正确 | 全字符测试串 | 逐字符一致 |
| 7 | BOOT 键短/长按 | 手动 | 短按确认、长按取消 |
| 8 | 上电不误进下载模式 | 不按键上电 ×10 | 10/10 正常 |
| 9 | 四平台配对 | Win/mac/Android/iOS | 均识别为键盘 |
| 10 | 配对物理确认 | 观察主机弹框 | 记录平台矩阵 |
| 11 | 闪存无明文 | 读 flash 搜索 | 搜不到 |
| 12 | 认证与锁定 | 3/6/10 次错误 | 触发对应锁定 |
| 13 | 重启不清锁定 | 断电重启 | 仍锁定 |
| 14 | 恢复码可用 | 恢复码重置 | 成功；数据清空 |
| 15 | 长按 BOOT 工厂重置 | 上电后立即长按 5s | 数据清空回 S0 |

---

## 11. 实现说明与规范偏差记录

> 开发过程中对总纲 v1.1 / 协议 v1.2 中**留白或存在实现歧义**的少数点做了工程定版，全部透明记录如下（未改变任何安全性质）：

| # | 位置 | 规范原文/留白 | 实现定版 | 理由 |
|---|---|---|---|---|
| D1 | 恢复码校验 | 附录四写 `rec_hint = HMAC(K_recovery, ·)`，`K_recovery = HKDF(KEK)` | **`rec_hint = HMAC-SHA256(recovery_code, "PWD_MGR_RECOVERY_V1")`**（以恢复码本身为 HMAC key） | 原文方式需要旧 KEK 才能验证，而"重置"场景恰恰没有旧 KEK（主密码已忘），流程不可用。定版方案：120-bit 恢复码空间不可暴力、不可反推、验证不依赖任何密钥；安全强度不变 |
| D2 | 按键驱动 | 总纲 §6.2 写"输入+上拉+**中断**" | **10ms 轮询状态机**（去抖 2 拍） | 实现细节（§5 允许自定）；轮询方案无 ISR 复杂性、响应 ≤20ms，对按键语义无影响 |
| D3 | `PWD_TYPE` 会话语义 | 未明确等待按键期间会话是否保活 | 等待按键期间 `session_touch()` 保活；解密前再验证会话 | 避免"用户正在确认时恰好空闲锁超时"的边缘失败 |
| D4 | `AUTH_NEW` 修改流程 | 未明确第二步 PROOF 的密钥（C25 已修订为旧 VERIFIER） | 按 C25 执行；且第一步物理确认、第二步不再重复按键 | 按键集中在"操作开始"，避免双按键体验 |
| D5 | `FACTORY_RESET` 令牌错误 | 未定义无效令牌的错误码 | 回 `0x1001`（含 `ERR_DETAIL = 0x11`） | 复用现有错误码，语义"参数缺失/无效" |
| D6 | 分区/审计 | "audit 分区环形缓冲"未定实现 | 扫描式初始化（无需头部元数据）；记录 16B 原样 | 简化实现、掉电安全 |
| D7 | `DEVICE_INFO` 的 salt | 未明确 S0 时 salt 何时生成 | 首次 `DEVICE_INFO` 时懒惰生成并持久化 | 与附二.1"首次上电生成"等价 |
| D8 | 重加密期间会话 | §6.7 ⑧"断线不中断" | 快照旧 KEK 到工作栈；完成后刷新会话 KEK | 防止重加密中会话销毁导致悬垂引用 |

固件内所有相关代码均带 `Dx`/`Cxx` 注释可追溯。

---

## 附录 A：nRF Connect 手工调试指南

> 目标：在无正式 App 时手工完成"设置主密码 → 认证 → 存取密码 → 触发输出"全流程。
> 需要工具：nRF Connect（手机）；记号笔/记事本（抄恢复码）。

### A.1 帧格式速记

```
请求帧： A5 01 <OPCODE> 04 <TOTAL_LEN lo hi> <TLV...>      （单帧；FLAGS=04=LAST）
响应帧： A5 01 <OPCODE> 0C <TOTAL_LEN lo hi> <TLV...>      （FLAGS=0C=RESP|LAST）
TLV：    <Tag 1B> <Len 2B 小端> <Value>
```

常用 Tag：`01`条目ID(8B) `02`名称 `03`密码(明文,仅上行) `04`NONCE(32B) `05`PROOF(32B) `07`请求ID(2B) `08`结果码(2B) `09`STATE(2B) `0A`版本 `0B`条目数 `0C`锁定秒数 `10`恢复码(24B) `11`确认令牌(4B) `12`目标句柄(1B) `14`超时ms(2B) `17`页码(1B) `19`salt(16B) `1A`迭代数(4B) `1B`SEQ(4B) `1C`KEK(32B) `1D`新salt(16B)

### A.2 完整手工流程

> PBKDF2 计算建议用电脑（Python）：

```python
# Python 参考片段（设置主密码时生成 KEK / PROOF）
import hmac, hashlib
pwd = b'MyMasterPwd2026'          # 主密码（自己定，纯 ASCII）
salt = bytes.fromhex('<0x19 的16字节hex，从 DEVICE_INFO 响应抄>')
iter = <0x1A 的数值>
kek = hashlib.pbkdf2_hmac('sha256', pwd, salt, iter, 32)
verifier = hmac.new(kek, b'PWD_MGR_VERIFIER_V1', hashlib.sha256).digest()
# PROOF：读 0xFFF1 得 36 字节（nonce+seq），或 AUTH_START 响应
nonce = bytes.fromhex('<32字节hex>'); seq = <4字节整数>
proof = hmac.new(verifier, nonce + seq.to_bytes(4,'little'), hashlib.sha256).digest()
print('KEK  =', kek.hex())
print('PROOF=', proof.hex())
# 修改主密码的第二阶段 PROOF2：用【旧】KEK 派生的 verifier 对新 nonce 计算
```

**Step 1 — DEVICE_INFO**：写 `A5 01 01 04 00 00` → 读响应，抄 `0x19 salt`、`0x1A iter`。

**Step 2 — 设置主密码（S0）**：算好 KEK（见上）→ 写：
```
A5 01 06 04 <len> 00 | 1C 20 00 <KEK 32B> | 07 02 00 <rid>
```
→ 收到 STATE 位 2（等待确认）→ **短按 BOOT** → 收到 `0x10 RECOVERY_CODE`（24 字符，立即抄写！）。

**Step 3 — 认证**：读 `0xFFF1`（36B：nonce+seq）→ 算 PROOF → 写：
```
A5 01 03 04 <len> 00 | 04 20 00 <nonce> | 05 20 00 <PROOF> | 1C 20 00 <KEK> | 07 02 00 <rid>
```
→ 响应 `0x08 = 0000`（OK）+ `0x06 SESSION_ID`。

**Step 4 — 加密码**：写 PWD_ADD：
```
A5 01 21 04 <len> 00 | 03 <n> 00 "<密码ASCII>" | 02 <m> 00 "<名称>" | 07 02 00 <rid>
```
→ 响应含新条目 ID（`0x01`）。

**Step 5 — 配对电脑**：见 §6.1/6.2（ENTER_PAIRING + 按键 + 电脑蓝牙配对）。

**Step 6 — 输出**：写 PWD_TYPE：
```
A5 01 24 04 <len> 00 | 01 08 00 <条目ID> | 07 02 00 <rid>
```
→ HALF-SYNC（STATE 位 2）→ **短按 BOOT** → 电脑上自动出字 → ASYNC OK。

**Step 7 — 审计**：写 `A5 01 41 04 <len> 00 | 07 02 00 <rid>` 读审计记录。

### A.3 新增错误码速查（v1.2）

| 码 | 含义 | 处理 |
|---|---|---|
| `0x400B` | PWD_TYPE 认证时效过期（>30s） | 重新 AUTH_VERIFY 后重发 |
| `0x400A` | 缺 KEK_BLOB | 检查请求 TLV |
| `0x3005` | 打字中途 HID 断开 | **电脑上可能已有半截密码**，检查输入框 |
| `0x0002` | 设备正忙（有耗时操作进行中） | 稍后重试 |

---

## 附录 B：常用命令速查

```bash
# 激活环境（本机）
#   开始菜单 → ESP-IDF 5.5 PowerShell；或按 §2.2 的 PowerShell 序列。

cd <项目根>\pwdkey

idf.py set-target esp32s3      # 首次
idf.py build                   # 编译
idf.py -p COM5 flash monitor   # 烧录 + 串口监视
idf.py -p COM5 erase-flash     # 全擦除（回出厂）
idf.py partition-table         # 查看分区表
idf.py size                    # 查看固件尺寸
idf.py fullclean               # 彻底清理（改 sdkconfig 后建议）
```

**备份三件套**（与固件版本一起归档）：`sdkconfig` + `sdkconfig.defaults` + `partitions.csv`。

---

*手册结束。如有与《项目开发总纲 v1.1》不一致处，以总纲为准并反馈修订。*
