#!/usr/bin/env python3
"""pwdkey_cli.py - local command-line tool for the PwdKey device.

Temporary stand-in for the mobile App: talks to the device over BLE from this
PC. The master password is entered locally via getpass and never logged.

Requirements (already installed in the ESP-IDF python env; otherwise):
    pip install bleak

Usage:
    python pwdkey_cli.py info                  # show device info (no password)
    python pwdkey_cli.py set-password          # FIRST-TIME setup (S0 state)
    python pwdkey_cli.py ls                    # list entries
    python pwdkey_cli.py add "NAME"            # add an entry
    python pwdkey_cli.py typepwd ENTRY_ID      # type entry on the paired PC
    python pwdkey_cli.py pair                  # enter pairing mode (for a PC)
    python pwdkey_cli.py change-password       # change master password

Deployment note: the device confirms with the BOOT button; the tool prints a
prompt and waits up to the given window.
"""
import argparse
import asyncio
import getpass
import hashlib
import hmac
import secrets
import sys
import time

from bleak import BleakClient, BleakScanner

NAME_PREFIX = "PwdKey"
UUID_CMD = "0000fff3-0000-1000-8000-00805f9b34fb"
UUID_RESP = "0000fff4-0000-1000-8000-00805f9b34fb"

# TLV tags
T_ENTRY_ID = 0x01
T_NAME = 0x02
T_SECRET = 0x03
T_NONCE = 0x04
T_PROOF = 0x05
T_SESSION_ID = 0x06
T_REQUEST_ID = 0x07
T_RESULT_CODE = 0x08
T_STATE = 0x09
T_FW_VERSION = 0x0A
T_ENTRY_COUNT = 0x0B
T_LOCK_SECONDS = 0x0C
T_RECOVERY_CODE = 0x10
T_CONFIRM_TOKEN = 0x11
T_TARGET = 0x12
T_TIMEOUT_MS = 0x14
T_ERR_DETAIL = 0x16
T_PAGE_INDEX = 0x17
T_SALT = 0x19
T_KDF_ITER = 0x1A
T_SESSION_SEQ = 0x1B
T_KEK_BLOB = 0x1C
T_NEW_SALT = 0x1D

# opcodes
OP_DEVICE_INFO = 0x01
OP_AUTH_START = 0x02
OP_AUTH_VERIFY = 0x03
OP_AUTH_NEW = 0x06
OP_PWD_LIST = 0x20
OP_PWD_ADD = 0x21
OP_PWD_TYPE = 0x24
OP_ENTER_PAIRING = 0x40

ERR = {
    0x0000: "OK", 0x0001: "内部错误", 0x0002: "设备忙(有耗时操作进行中)",
    0x1001: "缺少字段", 0x2001: "存储已满", 0x2002: "名称过长",
    0x2003: "ID 冲突", 0x2004: "密码过长", 0x2005: "条目不存在",
    0x2007: "密码含非 ASCII 字符", 0x3001: "无 HID 链路(先在电脑配对键盘)",
    0x3002: "多条 HID 链路(需指定目标)", 0x3003: "按键超时",
    0x3004: "操作被取消", 0x3005: "输出中断(电脑上可能有半截密码!)",
    0x3006: "正在输出中", 0x4001: "主密码错误", 0x4002: "未认证",
    0x4003: "临时锁定", 0x4004: "永久锁定(需恢复码)", 0x4005: "nonce 失效",
    0x4009: "恢复码错误", 0x400A: "缺少 KEK", 0x400B: "认证时效过期(重新验证)",
}


def frame(opcode: int, tlv: bytes = b"", rid: int = 0) -> bytes:
    body = tlv + tlv_put(T_REQUEST_ID, rid.to_bytes(2, "little")) if rid else tlv
    return bytes([0xA5, 0x01, opcode, 0x04]) + len(body).to_bytes(2, "little") + body


def tlv_put(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + len(value).to_bytes(2, "little") + value


def parse_tlvs(payload: bytes) -> dict:
    out = {}
    i = 0
    while i + 3 <= len(payload):
        t = payload[i]
        ln = int.from_bytes(payload[i + 1:i + 3], "little")
        out.setdefault(t, []).append(payload[i + 3:i + 3 + ln])
        i += 3 + ln
    return out


class Dev:
    def __init__(self, client: BleakClient):
        self.client = client
        self.q: asyncio.Queue = asyncio.Queue()
        self._loop = None

    def _on_notify(self, _char, data: bytearray):
        # bleak callbacks fire from a system thread -> hop to the loop
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self.q.put_nowait, bytes(data))

    async def open(self):
        self._loop = asyncio.get_running_loop()
        await self.client.start_notify(UUID_RESP, self._on_notify)

    async def write(self, opcode: int, tlv: bytes = b""):
        # drain stale frames
        while not self.q.empty():
            self.q.get_nowait()
        await self.client.write_gatt_char(UUID_CMD, frame(opcode, tlv), response=True)

    async def wait_frame(self, opcode: int, timeout: float, want_result: bool = None) -> dict:
        """Wait for a response frame of the given opcode.

        want_result=True  -> wait for a frame carrying RESULT_CODE (final ASYNC reply)
        want_result=False -> wait for a frame WITHOUT RESULT_CODE (HALF-SYNC)
        want_result=None  -> first frame of this opcode
        """
        deadline = time.time() + timeout
        while True:
            remain = deadline - time.time()
            if remain <= 0:
                raise TimeoutError("等待设备响应超时")
            data = await asyncio.wait_for(self.q.get(), timeout=remain)
            if len(data) < 6 or data[0] != 0xA5:
                continue
            if data[2] != opcode:
                continue
            t = parse_tlvs(data[6:])
            has_res = T_RESULT_CODE in t
            if want_result is None or has_res == want_result:
                return t

    async def device_info(self) -> dict:
        await self.write(OP_DEVICE_INFO)
        # success reply has no RESULT_CODE; error replies do
        t = await self.wait_frame(OP_DEVICE_INFO, 10, want_result=None)
        if T_RESULT_CODE in t and result_of(t) != 0:
            raise SystemExit(f"DEVICE_INFO 失败: {rc_str(result_of(t))}")
        return t


def result_of(t: dict) -> int:
    v = t.get(T_RESULT_CODE)
    return int.from_bytes(v[-1], "little") if v else 0xFFFF


def rc_str(rc: int) -> str:
    return f"0x{rc:04X} {ERR.get(rc, '未知')}"


async def find_device(timeout=12.0):
    print(f"扫描 {NAME_PREFIX}-* ...")
    for _ in range(3):
        results = await BleakScanner.discover(timeout=timeout, return_adv=True)
        for addr, (d, adv) in results.items():
            name = d.name or adv.local_name or ""
            if name.startswith(NAME_PREFIX):
                print(f"找到设备: {name} @ {addr} (RSSI {adv.rssi})")
                return addr
        print("未找到，重试...")
    raise SystemExit("错误：未扫描到 PwdKey 设备（确认设备已上电且在广播）")


async def connect(addr=None) -> Dev:
    if addr is None:
        addr = await find_device()
    client = BleakClient(addr, timeout=25)
    await client.connect()
    # Management characteristics are _ENC: the link must be encrypted before
    # subscribing/reading. Pairing (Just Works) establishes encryption.
    try:
        await client.pair(protection_level=2)
    except Exception as e:
        print(f"注: 配对调用返回 {e.__class__.__name__}，继续尝试")
    dev = Dev(client)
    try:
        await dev.open()
    except Exception as e:
        print()
        print("!! 订阅通知失败，Windows 侧可能尚未完成与本设备的系统级配对。")
        print("!! 请在 Windows 里执行一次手动配对，之后本工具即可稳定使用：")
        print("!!   设置 → 蓝牙和其他设备 → 添加设备 → 蓝牙 → 选择 PwdKey-XXXX")
        print("!!   （设备需处于广播状态：出厂态下开机自动广播 120 秒）")
        print(f"!! 原始错误: {type(e).__name__}: {e}")
        raise SystemExit(2)
    return dev


def derive(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, 32)


async def authenticate(dev: Dev, password: str):
    """Full AUTH_VERIFY. Returns session tlv."""
    info = await dev.device_info()
    salt = info[T_SALT][-1]
    it = int.from_bytes(info[T_KDF_ITER][-1], "little")
    kek = derive(password, salt, it)
    verifier = hmac.new(kek, b"PWD_MGR_VERIFIER_V1", hashlib.sha256).digest()

    await dev.write(OP_AUTH_START)
    t = await dev.wait_frame(OP_AUTH_START, 10, want_result=None)
    if T_RESULT_CODE in t and result_of(t) != 0:
        sys.exit(f"AUTH_START 失败: {rc_str(result_of(t))}")
    nonce = t[T_NONCE][-1]
    seq = int.from_bytes(t[T_SESSION_SEQ][-1], "little")
    proof = hmac.new(verifier, nonce + seq.to_bytes(4, "little"), hashlib.sha256).digest()

    body = tlv_put(T_NONCE, nonce) + tlv_put(T_PROOF, proof) + tlv_put(T_KEK_BLOB, kek)
    await dev.write(OP_AUTH_VERIFY, body)
    t = await dev.wait_frame(OP_AUTH_VERIFY, 10, want_result=True)
    rc = result_of(t)
    if rc != 0:
        print(f"认证失败: {rc_str(rc)}")
        if rc == 0x4003:
            lsec = int.from_bytes(t.get(T_LOCK_SECONDS, [b"\x00" * 4])[-1], "little")
            print(f"  剩余锁定时间: {lsec} 秒")
        sys.exit(1)
    print("认证成功 ✓")
    return t


# ---------------- commands ----------------

async def cmd_info(dev: Dev):
    t = await dev.device_info()
    state = int.from_bytes(t[T_STATE][-1], "little")
    print(f"固件版本      : {'.'.join(str(b) for b in t[T_FW_VERSION][-1])}")
    print(f"条目数        : {int.from_bytes(t[T_ENTRY_COUNT][-1], 'little')}")
    print(f"STATE         : 0x{state:04X}")
    print(f"  主密码已设置: {'是' if state & 0x100 else '否 (S0 出厂态)'}")
    print(f"  已绑定      : {'是' if state & 0x02 else '否'}")
    print(f"  HID 链路    : {'≥2' if state & 0x40 else ('1 条' if state & 0x20 else '0 条')}")
    print(f"  等待按键    : {'是' if state & 0x04 else '否'}")
    print(f"锁定剩余      : {int.from_bytes(t[T_LOCK_SECONDS][-1], 'little')} 秒")
    print(f"salt          : {t[T_SALT][-1].hex()}")
    print(f"KDF 迭代数    : {int.from_bytes(t[T_KDF_ITER][-1], 'little')}")


async def cmd_set_password(dev: Dev):
    t = await dev.device_info()
    state = int.from_bytes(t[T_STATE][-1], "little")
    if state & 0x100:
        print("设备已设置主密码。如需修改请用 change-password；忘记密码请用恢复码重置。")
        return
    salt = t[T_SALT][-1]
    it = int.from_bytes(t[T_KDF_ITER][-1], "little")

    print("== 设置主密码（纯 ASCII，建议 ≥12 位混合字符）==")
    pwd = getpass.getpass("输入主密码: ")
    pwd2 = getpass.getpass("再输入一遍: ")
    if pwd != pwd2:
        sys.exit("两次输入不一致，退出。")
    if not all(0x20 <= ord(c) <= 0x7E for c in pwd):
        sys.exit("主密码含非 ASCII 字符，请改用纯 ASCII。")

    print("计算密钥中 (PBKDF2, 约 1 秒)...")
    kek = derive(pwd, salt, it)

    await dev.write(OP_AUTH_NEW, tlv_put(T_KEK_BLOB, kek))
    await dev.wait_frame(OP_AUTH_NEW, 10, want_result=False)   # HALF-SYNC
    print()
    print(">>> 请在设备上【短按 BOOT 键】确认设置（60 秒内）<<<")
    t = await dev.wait_frame(OP_AUTH_NEW, 65, want_result=True)
    rc = result_of(t)
    if rc != 0:
        sys.exit(f"设置失败: {rc_str(rc)}")
    code = t[T_RECOVERY_CODE][-1].decode()
    print()
    print("=" * 56)
    print("  设置成功！恢复码（只显示这一次！请立刻抄写保存）：")
    print()
    print(f"      {code}")
    print()
    print("  ⚠️ 忘记主密码时只有它能重置设备（会清空所有密码）")
    print("  ⚠️ 请抄写到纸上，不要只存在手机里")
    print("=" * 56)


async def cmd_ls(dev: Dev):
    pwd = getpass.getpass("主密码: ")
    await authenticate(dev, pwd)
    await dev.write(OP_PWD_LIST)
    t = await dev.wait_frame(OP_PWD_LIST, 10, want_result=None)   # success reply has no RESULT_CODE
    rc = result_of(t) if T_RESULT_CODE in t else 0
    if rc != 0:
        sys.exit(f"失败: {rc_str(rc)}")
    ids = [v.decode() for v in t.get(T_ENTRY_ID, [])]
    count = int.from_bytes(t.get(T_ENTRY_COUNT, [b"\x00\x00"])[-1], "little")
    print(f"条目数: {count}")
    for i, e in enumerate(ids):
        print(f"  [{i}] {e}")


async def cmd_add(dev: Dev, name: str):
    pwd = getpass.getpass("主密码: ")
    await authenticate(dev, pwd)
    secret = getpass.getpass(f"新条目密码 (纯 ASCII): ")
    if not all(0x20 <= ord(c) <= 0x7E for c in secret):
        sys.exit("密码含非 ASCII 字符（中文/emoji 无法通过键盘输入）。")
    body = tlv_put(T_SECRET, secret.encode()) + tlv_put(T_NAME, name.encode())
    await dev.write(OP_PWD_ADD, body)
    t = await dev.wait_frame(OP_PWD_ADD, 10, want_result=True)
    rc = result_of(t)
    if rc != 0:
        sys.exit(f"添加失败: {rc_str(rc)}")
    eid = t[T_ENTRY_ID][-1].decode()
    print(f"添加成功 ✓  条目 ID: {eid}")


async def cmd_typepwd(dev: Dev, entry_id: str):
    pwd = getpass.getpass("主密码: ")
    await authenticate(dev, pwd)
    body = tlv_put(T_ENTRY_ID, entry_id.encode())
    await dev.write(OP_PWD_TYPE, body)
    t = await dev.wait_frame(OP_PWD_TYPE, 10, want_result=False)   # HALF-SYNC
    tmo = int.from_bytes(t.get(T_TIMEOUT_MS, [b"\x1e\x00"])[-1], "little") // 1000
    print()
    print(f">>> 请在设备上【短按 BOOT 键】确认输出（{tmo} 秒内）<<<")
    print(">>> 确认电脑上的光标已在正确的输入框中 <<<")
    t = await dev.wait_frame(OP_PWD_TYPE, tmo + 20, want_result=True)
    rc = result_of(t)
    if rc == 0:
        print("输出完成 ✓")
    elif rc == 0x3005:
        print("⚠️ 输出中断！电脑上可能已打出半截密码，请检查并清除输入框。")
    else:
        print(f"输出失败: {rc_str(rc)}")


async def cmd_pair(dev: Dev):
    pwd = getpass.getpass("主密码: ")
    await authenticate(dev, pwd)
    await dev.write(OP_ENTER_PAIRING)
    await dev.wait_frame(OP_ENTER_PAIRING, 10, want_result=False)
    print()
    print(">>> 请在设备上【短按 BOOT 键】确认进入配对模式 <<<")
    t = await dev.wait_frame(OP_ENTER_PAIRING, 70, want_result=True)
    rc = result_of(t)
    if rc != 0:
        sys.exit(f"失败: {rc_str(rc)}")
    print()
    print("设备已进入配对模式（60 秒）。现在去电脑/手机上操作：")
    print("  Windows: 设置 → 蓝牙和其他设备 → 添加设备 → 蓝牙 → 选择 PwdKey-XXXX")
    print("  macOS  : 系统设置 → 蓝牙 → 连接 PwdKey-XXXX")
    print("  Android: 设置 → 蓝牙 → 配对 PwdKey-XXXX")


async def cmd_change_password(dev: Dev):
    old = getpass.getpass("当前主密码: ")
    await authenticate(dev, old)

    # step 1: request new salt (HALF-SYNC -> press BOOT -> ASYNC with NEW_SALT)
    await dev.write(OP_AUTH_NEW)
    await dev.wait_frame(OP_AUTH_NEW, 10, want_result=False)      # HALF-SYNC
    print()
    print(">>> 请在设备上【短按 BOOT 键】确认修改操作 <<<")
    t = await dev.wait_frame(OP_AUTH_NEW, 70, want_result=True)   # ASYNC (step 1 done)
    rc = result_of(t)
    if rc != 0:
        sys.exit(f"修改请求被拒绝: {rc_str(rc)}")
    new_salt = t[T_NEW_SALT][-1]
    it = int.from_bytes(t[T_KDF_ITER][-1], "little")

    print("== 修改主密码（数据保留）==")
    new = getpass.getpass("新主密码: ")
    new2 = getpass.getpass("再输入一遍: ")
    if new != new2 or not new:
        sys.exit("两次输入不一致，退出。")
    if not all(0x20 <= ord(c) <= 0x7E for c in new):
        sys.exit("新主密码含非 ASCII 字符。")

    print("计算新密钥中 ...")
    new_kek = derive(new, new_salt, it)

    # step 2: challenge + PROOF with OLD verifier + new KEK blob
    info = await dev.device_info()
    salt = info[T_SALT][-1]
    old_kek = derive(old, salt, it)
    verifier_old = hmac.new(old_kek, b"PWD_MGR_VERIFIER_V1", hashlib.sha256).digest()

    await dev.write(OP_AUTH_START)
    t = await dev.wait_frame(OP_AUTH_START, 10, want_result=None)
    if T_RESULT_CODE in t and result_of(t) != 0:
        sys.exit(f"AUTH_START 失败: {rc_str(result_of(t))}")
    nonce = t[T_NONCE][-1]
    seq = int.from_bytes(t[T_SESSION_SEQ][-1], "little")
    proof2 = hmac.new(verifier_old, nonce + seq.to_bytes(4, "little"), hashlib.sha256).digest()

    body = (tlv_put(T_NONCE, nonce) + tlv_put(T_PROOF, proof2) + tlv_put(T_KEK_BLOB, new_kek))
    await dev.write(OP_AUTH_NEW, body)
    print()
    print(">>> 重加密进行中，请稍候 <<<")
    t = await dev.wait_frame(OP_AUTH_NEW, 30, want_result=True)
    rc = result_of(t)
    if rc != 0:
        sys.exit(f"修改失败: {rc_str(rc)}")
    code = t[T_RECOVERY_CODE][-1].decode()
    print()
    print("=" * 56)
    print("  修改成功！新的恢复码（旧的已作废，请抄写）：")
    print(f"      {code}")
    print("=" * 56)


async def dispatch(args):
    if args.command == "info":
        dev = await connect(args.addr)
        try:
            await cmd_info(dev)
        finally:
            await dev.client.disconnect()
        return

    dev = await connect(args.addr)
    try:
        if args.command == "set-password":
            await cmd_set_password(dev)
        elif args.command == "ls":
            await cmd_ls(dev)
        elif args.command == "add":
            await cmd_add(dev, args.name)
        elif args.command == "typepwd":
            await cmd_typepwd(dev, args.entry_id)
        elif args.command == "pair":
            await cmd_pair(dev)
        elif args.command == "change-password":
            await cmd_change_password(dev)
    finally:
        await dev.client.disconnect()


def main():
    ap = argparse.ArgumentParser(description="PwdKey local CLI (BLE)")
    ap.add_argument("--addr", help="BLE address (default: auto-scan PwdKey-*)")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("info", help="显示设备信息")
    sub.add_parser("set-password", help="首次设置主密码 (S0)")
    sub.add_parser("ls", help="列出条目")
    p_add = sub.add_parser("add", help="添加条目")
    p_add.add_argument("name", help="条目名称")
    p_type = sub.add_parser("typepwd", help="输出条目到已配对电脑")
    p_type.add_argument("entry_id", help="条目 ID（8 字符）")
    sub.add_parser("pair", help="进入键盘配对模式")
    sub.add_parser("change-password", help="修改主密码（保留数据）")
    args = ap.parse_args()
    try:
        asyncio.run(dispatch(args))
    except TimeoutError as e:
        sys.exit(f"超时: {e}")
    except KeyboardInterrupt:
        print("\n已取消")


if __name__ == "__main__":
    main()
