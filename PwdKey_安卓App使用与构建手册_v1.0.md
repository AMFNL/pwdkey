# PwdKey 安卓 App · 使用与构建手册 v1.0

> 面向对象：使用者（安装即可）+ 后续维护者（改代码重新打包）
> 对应固件：PwdKey 0.1.0 / 管理协议 v1.2

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

### 8.1 环境（本机已配好）

| 项 | 位置 / 版本 |
|---|---|
| JDK | `<JDK 17 安装目录>`（AGP 8.2 要求 JDK 17） |
| Android SDK | `<SDK 路径>`（platform-tools / android-34 / build-tools 34.0.0） |
| Node | 22.x |
| Gradle | 8.2.1（wrapper 自动下载，已配腾讯镜像） |

> SDK 路径写在 `android/local.properties`（`sdk.dir=<SDK 路径>`）。
> 换机器时改这一行即可。

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
│       ├── utils/
│       │   ├── ble.js         # ★ 新写：Capacitor 原生 BLE 适配器
│       │   ├── crypto.js      # 小程序原版 + WebCrypto 加速
│       │   └── pwdkey.js      # 小程序原版，**一行未改**
│       ├── libs/
│       │   ├── proto.js       # 小程序原版，**一行未改**
│       │   └── crypto-js/     # 同上
│       └── pages/             # index / setup / unlock / vault / hosts
├── tests/
│   ├── test_crypto_equiv.js   # WebCrypto 与纯 JS 的 KEK 对拍
│   └── test_dom_smoke.js      # jsdom 全链路 UI 冒烟（23 条断言）
└── android/                   # Capacitor 生成的 Android 工程
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

### 8.4 跑测试

```bash
cd pwdkey_android
npm test
```

- `test_crypto_equiv.js`：验证"WebCrypto 加速版"与"纯 JS 版"的 KEK / VERIFIER / PROOF
  **逐字节一致**（含 200000 次真实迭代），并与 Node 原生 `pbkdf2Sync` 三方对拍。
- `test_dom_smoke.js`：在 jsdom 里加载**真实的页面与协议代码**，用一个会正确应答协议的
  假设备，跑通「首屏 → 扫描 → 连接 → 解锁页 → 密码库 → 设备管理 → 弹层 → 切后台锁定」。

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

---

*配套文档：《PwdKey 使用手册》（设备操作全解）／《PwdKey 固件操作部署手册》（烧录与生产）／
《PwdKey 小程序使用指南》（微信版）／《项目开发总纲 v1.1》（设计依据）。*
