# PwdKey 安卓 App · 使用与构建手册 v1.1

> 面向对象：使用者（安装即可）+ 后续维护者（改代码重新打包）
> 对应固件：PwdKey 0.1.0 / 管理协议 v1.2
>
> **v1.1 变更**：新增「指纹 / 面容 + 6 位 PIN」解锁、修改主密码入口。
> 固件与微信小程序**零改动**，小程序仍只支持主密码。

---

## 1. 这是什么

一个**可以独立安装的 Android 应用**，功能与微信小程序版完全一致（连接设备、设主密码、存密码、输出密码、管理已连接电脑），但摆脱了小程序的三条硬限制：

| 限制（小程序） | 安卓 App |
|---|---|
| 必须先打开微信、登录账号 | 点桌面图标直接用 |
| 真机调试/预览要联网 | **完全离线**（APK 里连 `INTERNET` 权限都没有） |
| 需企业主体 + 微信审核才能正式发布 | 自己签名自己装，无审核 |
| 纯 JS 算 PBKDF2，解锁要等 6–10 秒 | 走系统原生 PBKDF2，**解锁基本秒开** |

---

## 2. 安装

1. 把 `PwdKey-v1.0.0.apk` 传到手机（微信文件传输 / 数据线 / 网盘均可）；
2. 在手机上点开 APK，如提示"不允许安装未知来源应用"，按提示**允许当前文件管理器安装**；
3. 安装完成后桌面会出现 **PwdKey** 图标（蓝色钥匙）。

> 应用信息：包名 `com.pwdkey.app`，版本 1.0.0，release 签名，已 zipalign。
> 目标系统：Android 8.0 (API 26) 及以上；推荐 Android 12+。

---

## 3. 首次打开：给蓝牙权限

第一次点「扫描附近设备」时，系统会弹出权限请求：

| 系统版本 | 弹窗内容 | 请选择 |
|---|---|---|
| Android 12+ | "允许 PwdKey 查找附近的设备并与其连接" | **允许** |
| Android 11 及以下 | 蓝牙权限 + 位置信息权限 | **允许**（旧系统扫 BLE 必须有定位权限） |

若误点了拒绝：**设置 → 应用 → PwdKey → 权限 → 附近的设备 → 允许**，然后重开 App。

---

## 4. 使用流程（与小程序一致）

### 4.1 连接设备

```
打开 App → 扫描附近设备 → 点列表里的 PwdKey-XXXX → 连接
```

连过一次之后，**下次打开会自动重连**，不用再扫码。设备不在附近时静默失败，可手动扫描。

### 4.2 首次设置主密码（新设备）

```
连接成功 → 首次设置主密码 → 输入两遍 → 开始设置
→ 等待密钥计算 → 在设备上短按 BOOT → 抄下恢复码
```

> 恢复码**只显示这一次**，忘记主密码时全靠它。请抄到纸上。

### 4.3 存密码 / 输出密码

```
密码库 → ＋添加密码 → 名称（可中文）+ 密码（纯 ASCII）
密码库 → 点条目 → 输出到电脑 → 短按 BOOT → 电脑自动打出
```

多台电脑在线时会先弹「输出到 XXX」（按你起的名字选）。

### 4.4 给电脑改名

```
密码库 → 🖥️（右上角）→ 点某台 → 改名 / 恢复默认名 / 断开
```

名字存在**设备**里，换手机也不丢。Windows 电脑通常读不到蓝牙名，会显示「电脑 XXXX」，手动改一下即可。

### 4.5 开启生物解锁（指纹 / 面容 + 6 位 PIN）

```
密码库 → ⚙️ → 开启生物解锁 → 设置 6 位 PIN（输两遍）→ 验证指纹/面容
```

开启后解锁流程变成两步，**缺一不可**：

```
系统弹窗验证指纹/面容  →  输入 6 位 PIN  →  进入密码库
```

- **为什么要 PIN**：指纹是"你是谁"，PIN 是"你知道什么"。别人趁你睡着拿你手指按一下能过第一关，但过不了第二关。
- **为什么 PIN 键盘每次换位置**：防止被旁边的人看一次就永久记住。
- **PIN 错 5 次**：本次保存的密钥会被丢弃，需要重新验证指纹/面容。
- **主密码永远保留**：换手机、新增指纹导致密钥失效、指纹模块坏了，都靠它。**不要因为开了指纹就忘记主密码。**

关闭：`⚙️ → 关闭生物解锁`。关闭后立即删除手机上保存的密钥。

### 4.6 修改主密码（只在需要时做）

```
⚙️ → 修改主密码 → 输入当前密码 + 新密码 → 设备上短按 BOOT
→ 抄下【新的】恢复码
```

改完设备会用新密码**重新加密全部条目**，并生成**新的恢复码**，旧恢复码立即作废。

> ⚠️ 本 App **不做定期强制更换**。主密码在离线环境里不会被在线撞库，强度够时"换得勤"并不更安全，反而每次都要重新抄恢复码。建议只在**怀疑泄露**或**想提升强度**时修改。
> 修改后指纹解锁会自动关闭（旧密钥已失效），需要重新开启。

---

## 5. 为什么能"没网也能用"

这不是宣传话术，是可验证的事实：

1. **APK 没有申请 `INTERNET` 权限** —— 系统层面就不可能建立任何网络连接。
   自查：`设置 → 应用 → PwdKey → 权限`，看不到任何网络相关项。
2. 界面文件（HTML/CSS/JS）全部打包在 APK 内部，由 WebView 从本地 assets 加载，不走网络。
3. 密码**只存在硬件设备里**（加密后写进 NVS），手机上不留任何副本。

---

## 6. 权限清单（每个都解释清楚）

| 权限 | 用途 | 备注 |
|---|---|---|
| `BLUETOOTH_SCAN` | 扫描 PwdKey 设备 | 带 `neverForLocation`，**不需要定位权限** |
| `BLUETOOTH_CONNECT` | 连接设备、读写特征 | Android 12+ |
| `BLUETOOTH` / `BLUETOOTH_ADMIN` | 同上 | 仅 Android 11 及以下（`maxSdkVersion=30`） |
| `ACCESS_FINE_LOCATION` | 旧系统扫 BLE 的系统强制要求 | 仅 Android 11 及以下 |
| `VIBRATE` | 按键确认时的轻震动 | 可忽略 |
| `USE_BIOMETRIC` | v1.1 指纹 / 面容解锁 | 普通权限，**不联网**；没有生物硬件的机型自动回落到主密码 |
| `USE_FINGERPRINT` | 同上，Android 9 及以下的旧名字 | 由 `androidx.biometric` 自动合并进来，普通权限，不会联网 |
| ~~`INTERNET`~~ | —— | **已移除** |

---

## 7. 与微信小程序的功能对照

| 功能 | 小程序 | 安卓 App |
|---|---|---|
| 扫描 / 连接 / 自动重连 | ✅ | ✅ |
| 设置主密码 + 恢复码 | ✅ | ✅ |
| 解锁、锁定、切后台自动锁定 | ✅ | ✅ |
| 密码库增删、输出密码（按键确认） | ✅ | ✅ |
| 多电脑按名字选目标 | ✅ | ✅ |
| 已连接设备管理（改名/断开） | ✅ | ✅ |
| 会话过期（30 秒）提示 | ✅ | ✅ |
| 恢复码重置流程 | ❌（仅文档说明） | ❌（同） |
| 需要联网 | ✅ 需要 | ❌ 完全不需要 |
| 解锁耗时（20 万次 PBKDF2） | 6–10 秒 | **< 0.3 秒** |

---

## 8. 重新构建（维护者看这里）

### 8.1 环境

| 项 | 位置 / 版本 |
|---|---|
| JDK | JDK 17（AGP 8.2 要求，`JAVA_HOME` 指向它） |
| Android SDK | 任意路径，需含 `platform-tools` / `android-34` / `build-tools;34.0.0` |
| Node | 22.x |
| Gradle | 8.2.1（wrapper 自动下载，已配腾讯镜像） |

> SDK 路径写在 `android/local.properties`（注意 Windows 下反斜杠要转义）：
>
> ```properties
> sdk.dir=C\:\\Android\\Sdk
> ```
>
> 上面只是示例，换成你自己的路径。该文件已被 `.gitignore` 排除，换机器时改这一行即可。
> `local.properties` 里出现真实路径是正常的，**它永远不会被提交**。
>
> **首次构建前必须执行一次 `npm run sync`**（内部是 `cap sync android`，不是 `cap copy`）：
> 它会生成 `android/capacitor-cordova-android-plugins/` 目录，缺了它 Gradle 会在
> `capacitor.build.gradle` 处直接报 "could not read cordova.variables.gradle"。

**这套流程已在 Windows 上实测跑通**（2026-10-20 验证）：

| 检查项 | 结果 |
|---|---|
| platforms | `android-34`（compileSdk 34 / targetSdk 34） |
| build-tools | `34.0.0`（`aapt2`、`apksigner` 可用） |
| platform-tools | 含 `adb` |
| cmdline-tools | `latest`，`licenses` 已接受 |
| Gradle | 8.2.1，JVM 17.0.12 |
| 构建结果 | `BUILD SUCCESSFUL`，151 tasks，增量约 1 分 10 秒 |

> 若用离线安装包，目录里可能还留着 `cmdtools.zip` 之类的原始包，**构建不需要它们**；
> 但**不要删 `Sdk` 目录本身**。

### 8.2 目录结构

```
pwdkey_android/
├── www/                       # 前端（打包进 APK 的资源）
│   ├── index.html
│   ├── css/app.css            # 由小程序 wxss 逐条换算（1rem = 20rpx）
│   ├── js/app.bundle.js       # esbuild 产物（自动生成，不要手改）
│   └── src/
│       ├── main.js            # 入口：路由注册 / 断线兜底 / 切后台锁定
│       ├── router.js          # 页面栈（对应 navigateTo/redirectTo/navigateBack）
│       ├── ui.js              # toast/modal/actionSheet/loading/storage
│       ├── components/
│       │   └── pinpad.js      # ★ v1.1：6 位 PIN 键盘（按键位置随机）
│       ├── utils/
│       │   ├── ble.js         # ★ 新写：Capacitor 原生 BLE 适配器
│       │   ├── crypto.js      # 小程序原版 + WebCrypto 加速
│       │   ├── pwdkey.js      # 小程序原版 + v1.1 新增 unlockWithKek/changePassword
│       │   ├── biowrap.js     # ★ v1.1：生物认证包裹层门面
│       │   └── bioenroll.js   # ★ v1.1：开启/关闭生物解锁的交互流程
│       ├── libs/
│       │   ├── proto.js       # 小程序原版，**一行未改**
│       │   └── crypto-js/     # 同上
│       └── pages/             # index / setup / unlock / vault / hosts
│                              # + security / change-pwd（v1.1 新增）
├── tests/
│   ├── test_crypto_equiv.js   # WebCrypto 与纯 JS 的 KEK 对拍
│   ├── test_change_pwd.js     # ★ v1.1：改密码协议对拍（rekey / salt 轮换）
│   ├── test_dom_smoke.js      # jsdom 全链路 UI 冒烟（含生物 + PIN 路径）
│   └── verify_bundle.js       # ★ v1.1：确认 bundle 里真的含新版代码（防"改了没打包"）
└── android/
    └── app/src/main/java/com/pwdkey/app/
        ├── MainActivity.java          # v1.1：注册自定义插件
        └── BiometricWrapPlugin.java   # ★ v1.1：Keystore + BiometricPrompt
```

**关键点**：`proto.js` / `crypto.js` / `pwdkey.js` 三个核心文件是从小程序**原样复制**的
（目录结构保持一致，`require` 的相对路径不用改）。只有 `ble.js` 因为平台 API 不同而重写，
但它保持了与小程序版**完全相同的公开接口**，所以上层逻辑零改动。

### 8.3 改完代码怎么出包

```bash
cd pwdkey_android

# 1) 重新打包前端 + 复制到 Android 工程
npm run sync

# 2) 构建 APK（增量，约 20 秒）
cd android && gradlew.bat assembleRelease

# 产物：android/app/build/outputs/apk/release/app-release.apk
```

一条命令跑完：`npm run apk`

> 首次构建约 2–3 分钟（要下载 AGP / androidx.biometric 等依赖），之后增量约 20–40 秒。
> 没配 `android/keystore.properties` 时会自动退回 debug 签名（能装能测，但不能覆盖正式签名版）。

**⚠️ 最容易踩的坑**：`www/index.html` 加载的是 `www/js/app.bundle.js`（esbuild 产物），
不是 `www/src/*.js` 源码。只改源码不跑 `npm run build:web`（或 `npm run sync`），
APK 里跑的还是旧逻辑——页面看起来"没变化"，但也不会报错，极难排查。
所以 `npm test` 里加了 `verify_bundle.js` 专门盯这件事。

出包后建议核对（本机已验证通过）：

```bash
cd android/app/build/outputs/apk/release
"<SDK 路径>/build-tools/34.0.0/aapt2.exe" dump badging app-release.apk | head -3
# 期望：versionCode='2'  versionName='1.1.0'  sdkVersion:'26'  targetSdkVersion:'34'

"<SDK 路径>/build-tools/34.0.0/aapt2.exe" dump permissions app-release.apk
# 期望：有 USE_BIOMETRIC / USE_FINGERPRINT，**没有 INTERNET**
```

### 8.4 跑测试

```bash
cd pwdkey_android
npm test
```

- `test_crypto_equiv.js`：验证"WebCrypto 加速版"与"纯 JS 版"的 KEK / VERIFIER / PROOF
  **逐字节一致**（含 200000 次真实迭代），并与 Node 原生 `pbkdf2Sync` 三方对拍。
- `test_dom_smoke.js`：在 jsdom 里加载**真实的页面与协议代码**，用一个会正确应答协议的
  假设备，跑通「首屏 → 扫描 → 连接 → 解锁页 → 密码库 → 设备管理 → 弹层 → 切后台锁定」。
  其中包含 3 组 v1.1 专项断言：**salt 不匹配必须拒绝**（且不发 `AUTH_VERIFY`、
  不消耗设备失败计数）、PIN 错误计数、正确 PIN 走通生物解锁全链路。
- `verify_bundle.js`：把 `app.bundle.js` 里的 `\uXXXX` 还原后，逐条核验 v1.1 新增文案与
  关键标识（`BiometricWrap` / `PIN_INVALID` / `changePassword` / `deviceSalt` 等）都在包内。

当前基线：**61 条断言全过 + bundle 完整性通过**。

### 8.5 已产出的包（2026-10-20 实测）

| 项 | 值 |
|---|---|
| 路径 | `pwdkey_android/dist/PwdKey-1.1.0-release.apk`（原始产物在 `android/app/build/outputs/apk/release/`） |
| 大小 | 3,171,849 字节（约 3.1 MB） |
| SHA-256 | `52e7b90460991cf98e90d00d8845cfe03aaa05270f9586237328fcd097825a4a` |
| versionName / Code | `1.1.0` / `2` |
| minSdk / targetSdk | 26 / 34 |
| 权限 | Bluetooth 一组、`USE_BIOMETRIC`、`USE_FINGERPRINT`、`VIBRATE`；**无 INTERNET** |
| 签名 | `CN=Android Debug`（未配 keystore，自动退化） |

`dist/` 里的副本只是方便你拷到手机；`*.apk` 已在 `.gitignore` 中，不会被提交。

**装上手机后请按这个顺序验一遍**（本机无真机，这步必须你来做）：

1. 连设备 → 用主密码解锁 → 进「安全设置」→ 开启生物解锁 → 录指纹 + 设 6 位 PIN；
2. 杀掉 App 重开 → 应先弹指纹，再弹 PIN 键盘（**键盘数字位置每次随机**）；
3. 故意输错 PIN → 提示剩余次数；错满 5 次应回到指纹并提示"为防止他人反复猜 PIN…"；
4. **去系统设置里新加一枚指纹，再回来解锁** → 应提示"系统里的指纹或面容发生了变化"
   并回退到主密码（这一步验证 `setInvalidatedByBiometricEnrollment` 真的生效，
   是整个方案最关键的防线，务必测）；
5. 用主密码解锁 → 改主密码 → 重启 App → 旧密码应失效、生物解锁需重新开启；
6. 解锁后 30 秒内输出一次密码，确认设备端行为未变。

---

## 9. 签名与升级（务必先读）

APK 必须用你自己的证书签名。**本仓库不包含任何签名密钥**（`.jks`、
`keystore.properties` 都已在 `.gitignore` 里排除）。

自己生成一份：

```bash
cd pwdkey_android/android/app
keytool -genkeypair -v -keystore pwdkey-release.jks -alias pwdkey \
  -keyalg RSA -keysize 2048 -validity 10000
```

然后新建 `pwdkey_android/android/keystore.properties`：

```properties
storeFile=pwdkey-release.jks
storePassword=<你设的密码>
keyAlias=pwdkey
keyPassword=<你设的密码>
```

| 项 | 说明 |
|---|---|
| keystore | `android/app/pwdkey-release.jks`（自己生成） |
| 别名 | `pwdkey` |
| 密码 | 自己设定，**不要提交** |
| 有效期 | 建议 10000 天 |

> ⚠️ **升级必须用同一个 keystore**。换了签名，手机会拒绝覆盖安装，必须先卸载旧版
> （卸载会丢 App 内的"上次设备"记录，但设备里的密码不受影响）。

> 该文件缺失时构建不会失败 —— `app/build.gradle` 会自动退化为 debug 签名，
> 方便别人 clone 后直接编译试玩。

---

## 10. 故障排查

| 现象 | 处理 |
|---|---|
| 点扫描没反应 / 列表一直空 | 检查「附近的设备」权限；确认手机蓝牙已开；靠近设备 1 米内 |
| 提示"未发现任何蓝牙设备" | 权限问题。设置 → 应用 → PwdKey → 权限，把「附近的设备」设为允许 |
| 提示"共发现 N 个设备但没有 PwdKey" | 权限正常，是设备不在附近或正处于 120 秒重启间隙，再扫一次 |
| 连接超时 | 设备可能已被别处连满（最多 3 条链路），稍等重试 |
| 连接后立刻断开 | 设备刚重启；重连一次即可 |
| 解锁很慢（>3 秒） | 说明 WebCrypto 没生效（异常回退到纯 JS）。功能正常，只是慢。可在 `chrome://inspect` 看控制台确认 |
| 输出时提示"认证已过期" | 解锁后 30 秒内才能输出，重新解锁 |
| 输出中断（电脑上有半截） | 清除电脑输入框内容后重试 |
| 改名提示"未在设备上找到" | 只能改**连过**的设备；先在电脑上完成配对 |
| 想彻底重来 | 卸载 App 重装（设备端数据不受影响）；设备端工厂重置见《使用手册》 |

**万一白屏**：说明本机 WebView 对无网络权限的场景处理特殊。把
`android/app/src/main/AndroidManifest.xml` 末尾的
`android.permission.INTERNET` + `tools:node="remove"` 那一段删掉，重新 `npm run apk` 即可。

---

## 11. 安全说明

- App 本身**不存任何密码**：条目全部加密存放在设备 NVS；
- 主密码只在内存里存在到派生完成，KEK 用完即弃；
- 切到后台 800ms 后自动销毁会话（与小程序一致）；
- 没有网络权限，物理上无法外传数据；
- 但请注意：**主密码弱 = 全部失守**（拆机可离线暴力破解），这条和以前一样。

### 11.1 开启生物解锁后，手机上多存了什么

只多存一个 **信封**：`AES-GCM(KEK, 6 位 PIN)` 再用 Android Keystore 里的一把
**不可导出**的 AES-256 密钥整体加密。这把 Keystore 密钥要求每次使用都现场通过
强生物认证（指纹 / 3D 面容），并且**新增或删除指纹后自动永久失效**。

由此带来三个结果：

| 情况 | 结果 |
|---|---|
| 手机被捡到、没有你的指纹 | 连信封都解不开，**无从爆破 PIN** |
| 有人拿你的手指按了一下 | 还需要 6 位 PIN，第二关过不去 |
| 你在系统里新加了一枚指纹 | Keystore 密钥失效 → App 自动要求用主密码，并关闭生物解锁 |

需要清楚的两条边界：

1. **PIN 只有 6 位，本轮不靠它抗爆破**。真正的硬屏障是 TEE 里的 Keystore 密钥；
   PIN 的作用是"生物特征被强制时的第二道门"，以及让人无法靠偷看记住。
2. **手机被 root / 内存被 hook 时，任何手机端方案都挡不住**（KEK 在解封瞬间必然是明文）。
   本方案不改变这条上限，但也没有降低它 —— 因为设备侧仍然要求每次输出都按物理 BOOT 键。

最后：**主密码不能忘**。它仍是设备密钥的唯一来源；指纹只是"取密钥更方便的方式"，
而不是"另一种密钥"。

---

*配套文档：《PwdKey 使用手册》（设备操作全解）／《PwdKey 固件操作部署手册》（烧录与生产）／
《PwdKey 小程序使用指南》（微信版）／《项目开发总纲 v1.1》（设计依据）。*
