# 测试

三组测试，**全部不需要真实硬件**。核心思路是用"协议级假设备"：
一个实现了帧重组与命令响应的 JS 对象，让连接、加密、UI 逻辑可以完整跑一遍。

## 1. 协议 / 加密 / 业务流程（Node）

无外部依赖（`crypto-js` 已内置在 `pwdkey_app/miniprogram/libs/` 里）。

```bash
cd tests/miniprogram

node test_crypto.js    # PBKDF2 RFC 向量 + 与 Node 原生 crypto 对拍
node test_proto.js     # TLV / 分帧 / PROOF，与 Python 参考实现对拍
node test_flow.js      # 全流程集成测试（30 条断言）
```

`test_flow.js` 覆盖：

| 分组 | 验证点 |
|---|---|
| 连接 | `DEVICE_INFO` 成功响应**不带** `RESULT_CODE` 的回归用例 |
| 认证 | 设主密码（HALF-SYNC → 异步完成）、错误密码 → `0x4001`、解锁成功 |
| 条目 | 增 / 删 / 查 / 名称读取（UTF-8） |
| 输出 | `PWD_TYPE` 的等待确认 → 完成；30 秒认证时效 |
| 多机 | `0x3002` 候选列表、按名字选择、重发带 MAC |
| 主机管理 | `HOST_LIST` 分页与排序、改名、清除恢复默认名、断开、离线报错 |
| 会话 | 锁定后 KEK 清零 |

## 2. 安卓 App（Node + jsdom）

```bash
cd pwdkey_android
npm install
npm test
```

| 测试 | 作用 |
|---|---|
| `test_crypto_equiv.js` | **WebCrypto 加速版**与**纯 JS 版**的 KEK / VERIFIER / PROOF 逐字节一致；并与 Node 原生 `pbkdf2Sync` 三方对拍（含 200000 次真实迭代） |
| `test_dom_smoke.js` | 在 jsdom 里加载**真实的页面代码与协议栈**，走通首屏 → 扫描 → 连接 → 解锁页 → 密码库 → 设备管理 → 弹层 → 切后台锁定（23 条断言） |

> 安卓版把 PBKDF2 换成了系统原生实现（解锁从 6–10 秒降到 <0.3 秒），
> 这属于密码学路径的改动，所以必须有上面这份等价性证据。

## 3. 参考实现

`ref_python_calc.py` 是 PROOF / KEK 计算的独立 Python 实现，供交叉验证用：

```bash
python ref_python_calc.py
```

---

### 为什么用假设备而不是真机

协议层的 bug（分片丢失、TLV 顺序、状态机错位）用真机复现成本极高，而且不可自动化。
假设备把硬件抽象掉之后，可以精确构造边界条件（比如"第 2 片丢了"、"响应缺 RESULT_CODE"），
并且能在 CI 里跑。真机验证仍然是必要的最后一关，但不该是唯一一关。
