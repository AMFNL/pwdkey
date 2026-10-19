/* End-to-end flow test: mock WeChat BLE APIs + mock PwdKey device (firmware
 * behaviour), run the real miniprogram pwdkey.js through the full lifecycle.
 * Regression target: refreshInfo must NOT misjudge DEVICE_INFO (its success
 * reply carries no RESULT_CODE field).
 */
const nodeCrypto = require("crypto");

/* ---------------- mock wx BLE environment ---------------- */
let notifyCb = null;
let writeHandler = null;

const UUID_SVC = "0000FFF0-0000-1000-8000-00805F9B34FB";

global.wx = {
  openBluetoothAdapter: (o) => o.success && o.success({}),
  closeBluetoothAdapter: (o) => o.success && o.success({}),
  startBluetoothDevicesDiscovery: (o) => o.success && o.success({}),
  stopBluetoothDevicesDiscovery: (o) => o.success && o.success({}),
  onBluetoothDeviceFound: () => {},
  offBluetoothDeviceFound: () => {},
  createBLEConnection: (o) => o.success && o.success({}),
  setBLEMTU: (o) => o.success && o.success({ mtu: 256 }),
  getBLEDeviceServices: (o) => o.success && o.success({ services: [{ uuid: UUID_SVC }] }),
  getBLEDeviceCharacteristics: (o) => o.success && o.success({
    characteristics: [{ uuid: "0000FFF3-0000-1000-8000-00805F9B34FB" },
                      { uuid: "0000FFF4-0000-1000-8000-00805F9B34FB" }],
  }),
  notifyBLECharacteristicValueChange: (o) => o.success && o.success({}),
  onBLECharacteristicValueChange: (cb) => { notifyCb = cb; },
  writeBLECharacteristicValue: (o) => {
    const data = new Uint8Array(o.value);
    setImmediate(() => writeHandler && writeHandler(data));
    o.success && o.success({});
  },
  closeBLEConnection: (o) => o.success && o.success({}),
  vibrateShort: () => {},
  setStorageSync: () => {},
  getStorageSync: () => "",
  showToast: () => {},
  showModal: () => {},
  showLoading: () => {},
  hideLoading: () => {},
};

/* ---------------- mock device (firmware behaviour) ---------------- */
const proto = require("../../pwdkey_app/miniprogram/libs/proto.js");
const { OP, TAG, tlv } = proto;

function hmac(key, msg) {
  return nodeCrypto.createHmac("sha256", key).update(msg).digest();
}

const B32 = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/* --- helpers mirroring the firmware's host naming rules --- */
function hexUpper(b) {
  return Array.from(b).map((x) => (x + 0x100).toString(16).slice(1).toUpperCase()).join("");
}
function addrText(addr) {
  return Array.from(addr).map((x) => (x + 0x100).toString(16).slice(1).toUpperCase()).join(":");
}
/* firmware fallback: "电脑 " + last two MAC bytes in uppercase hex */
function defaultName(addr) {
  return "电脑 " + hexUpper(addr.slice(4));
}
function sameAddr(a, b) {
  return !!a && !!b && a.length === b.length && Array.from(a).every((x, i) => x === b[i]);
}

function createMockDevice() {
  const dev = {
    passwordSet: false,
    salt: nodeCrypto.randomBytes(16),
    iter: 200000,
    verifier: null,
    entries: [],
    session: null,
    pendingNonce: null,
    reasm: null,
    autoConfirmMs: 60,           // simulate user pressing BOOT quickly

    /* 模拟设备上已登记的主机（MAC 即身份，名称由固件侧维护） */
    hosts: [
      { addr: new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
        name: defaultName(new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])),
        flags: 0, online: true, hid: true },
      { addr: new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
        name: "书房台式机", flags: proto.HOST_FLAG.USER_NAMED,
        online: true, hid: true },
      { addr: new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
        name: defaultName(new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])),
        flags: 0, online: false, hid: false },
    ],
  };

  dev._send = (opcode, tlvs) => {
    // build ONE response frame, deliver in ATT-sized (20B) chunks
    const frame = proto.buildFrames(opcode, tlvs, 9999)[0];
    for (let off = 0; off < frame.length; off += 20) {
      const chunk = frame.subarray(off, off + 20);
      const copy = chunk.slice();
      setTimeout(() => {
        if (notifyCb) {
          notifyCb({ deviceId: "MOCK", value: copy.buffer.slice(0) });
        }
      }, 4 + off);
    }
  };

  dev._sendResult = (opcode, rid, rc, extraTlvs) => {
    let t = proto.concatBytes(tlv(TAG.REQUEST_ID, proto.u16le(rid)),
                              tlv(TAG.RESULT_CODE, proto.u16le(rc)));
    if (extraTlvs) { t = proto.concatBytes(t, extraTlvs); }
    dev._send(opcode, t);
  };

  dev._stateBits = () => {
    let s = 0;
    if (dev.passwordSet) { s |= 0x0100; }
    return s;
  };

  dev._halfSync = (opcode, rid) => {
    dev._send(opcode, proto.concatBytes(
      tlv(TAG.REQUEST_ID, proto.u16le(rid)),
      tlv(TAG.STATE, proto.u16le(dev._stateBits() | 0x0004))));
  };

  dev.onWrite = (u8) => {
    // request-side fragments: every chunk carries a 6B header (MORE/LAST)
    if (u8[0] !== 0xA5) { return; }
    const opcode = u8[2];
    const flags = u8[3];
    const total = proto.readU16le(u8, 4);
    const payload = u8.subarray(6);

    if (!dev.reasm) {
      dev.reasm = { opcode, total, buf: payload.slice() };
    } else {
      dev.reasm.buf = proto.concatBytes(dev.reasm.buf, payload);
    }
    if (!(flags & proto.FLAG_LAST)) { return; }
    const body = dev.reasm.buf;
    dev.reasm = null;
    if (body.length !== total) { throw new Error("mock: length mismatch"); }
    dev._handle(opcode, body);
  };

  dev._handle = (opcode, body) => {
    const t = proto.parseTLVs(body);
    const rid = proto.tlvLast(t, TAG.REQUEST_ID);
    const ridNum = rid ? proto.readU16le(rid, 0) : 0;

    switch (opcode) {
      case OP.DEVICE_INFO: {
        // NOTE: success reply carries NO RESULT_CODE (firmware behaviour!)
        const fwv = new Uint8Array([0, 1, 0]);
        dev._send(opcode, proto.concatBytes(
          tlv(TAG.REQUEST_ID, proto.u16le(ridNum)),
          tlv(TAG.FW_VERSION, fwv),
          tlv(TAG.ENTRY_COUNT, proto.u16le(dev.entries.length)),
          tlv(TAG.STATE, proto.u16le(dev._stateBits())),
          tlv(TAG.LOCK_SECONDS, proto.u32le(0)),
          tlv(TAG.SALT, dev.salt),
          tlv(TAG.KDF_ITER, proto.u32le(dev.iter)),
          tlv(TAG.LAYOUT, new Uint8Array([0]))));
        break;
      }
      case OP.AUTH_NEW: {
        const kek = proto.tlvLast(t, TAG.KEK_BLOB);
        if (!kek || kek.length !== 32) { dev._sendResult(opcode, ridNum, 0x400A); return; }
        if (!dev.passwordSet) {
          // 首设：HALF-SYNC -> (auto BOOT press) -> ASYNC
          dev._halfSync(opcode, ridNum);
          setTimeout(() => {
            let code = "";
            for (let i = 0; i < 24; i++) {
              code += B32[nodeCrypto.randomBytes(1)[0] % 32];
            }
            dev.passwordSet = true;
            // salt unchanged: App derived its KEK with the salt served by
            // DEVICE_INFO; the device must keep that same salt (fixed firmware)
            dev.verifier = hmac(kek, Buffer.from("PWD_MGR_VERIFIER_V1"));
            dev._sendResult(opcode, ridNum, 0x0000, proto.concatBytes(
              tlv(TAG.STATE, proto.u16le(dev._stateBits())),
              tlv(TAG.RECOVERY_CODE, Buffer.from(code))));
          }, dev.autoConfirmMs);
        } else {
          dev._sendResult(opcode, ridNum, 0x4006);
        }
        break;
      }
      case OP.AUTH_START: {
        dev.pendingNonce = nodeCrypto.randomBytes(32);
        const seq = nodeCrypto.randomBytes(4);
        dev.session = null;
        dev._send(opcode, proto.concatBytes(
          tlv(TAG.REQUEST_ID, proto.u16le(ridNum)),
          tlv(TAG.NONCE, dev.pendingNonce),
          tlv(TAG.SESSION_SEQ, seq)));
        dev.pendingSeq = proto.readU32le(seq, 0);
        break;
      }
      case OP.AUTH_VERIFY: {
        const nonce = proto.tlvLast(t, TAG.NONCE);
        const proof = proto.tlvLast(t, TAG.PROOF);
        const kek = proto.tlvLast(t, TAG.KEK_BLOB);
        if (!dev.verifier || !dev.pendingNonce) { dev._sendResult(opcode, ridNum, 0x4005); return; }
        // verify KEK blob matches (device recomputes verifier)
        const v2 = hmac(kek, Buffer.from("PWD_MGR_VERIFIER_V1"));
        if (!v2.equals(dev.verifier)) { dev._sendResult(opcode, ridNum, 0x4001); return; }
        // verify PROOF
        const expect = hmac(dev.verifier, proto.concatBytes(nonce, proto.u32le(dev.pendingSeq)));
        if (!Buffer.from(expect).equals(Buffer.from(proof))) {
          dev._sendResult(opcode, ridNum, 0x4001); return;
        }
        dev.pendingNonce = null;
        dev.session = { kek: Buffer.from(kek) };
        dev._sendResult(opcode, ridNum, 0x0000, proto.concatBytes(
          tlv(TAG.SESSION_ID, proto.u32le(12345)),
          tlv(TAG.STATE, proto.u16le(dev._stateBits() | 0x01))));
        break;
      }
      case OP.AUTH_LOCK: {
        dev.session = null;
        dev._sendResult(opcode, ridNum, 0x0000);
        break;
      }
      case OP.PWD_LIST: {
        if (!dev.session) { dev._sendResult(opcode, ridNum, 0x4002); return; }
        let extra = new Uint8Array(0);
        for (const e of dev.entries) {
          extra = proto.concatBytes(extra, tlv(TAG.ENTRY_ID, Buffer.from(e.id)));
        }
        extra = proto.concatBytes(extra, tlv(TAG.ENTRY_COUNT, proto.u16le(dev.entries.length)));
        dev._send(opcode, proto.concatBytes(tlv(TAG.REQUEST_ID, proto.u16le(ridNum)), extra));
        break;
      }
      case OP.PWD_ADD: {
        if (!dev.session) { dev._sendResult(opcode, ridNum, 0x4002); return; }
        const secret = proto.tlvLast(t, TAG.SECRET);
        const name = proto.tlvLast(t, TAG.NAME);
        let id = "";
        for (let i = 0; i < 8; i++) { id += B32[nodeCrypto.randomBytes(1)[0] % 32]; }
        dev.entries.push({ id, pwd: Buffer.from(secret).toString(), name: Buffer.from(name).toString() });
        dev._sendResult(opcode, ridNum, 0x0000, tlv(TAG.ENTRY_ID, Buffer.from(id)));
        break;
      }
      case OP.PWD_DELETE: {
        if (!dev.session) { dev._sendResult(opcode, ridNum, 0x4002); return; }
        const id = Buffer.from(proto.tlvLast(t, TAG.ENTRY_ID)).toString();
        const before = dev.entries.length;
        dev.entries = dev.entries.filter((e) => e.id !== id);
        dev._sendResult(opcode, ridNum, before === dev.entries.length ? 0x2005 : 0x0000);
        break;
      }
      case OP.ATTR_GET: {
        if (!dev.session) { dev._sendResult(opcode, ridNum, 0x4002); return; }
        const id = Buffer.from(proto.tlvLast(t, TAG.ENTRY_ID)).toString();
        const e = dev.entries.find((x) => x.id === id);
        if (!e) { dev._sendResult(opcode, ridNum, 0x2005); return; }
        dev._sendResult(opcode, ridNum, 0x0000, tlv(TAG.NAME, Buffer.from(e.name)));
        break;
      }
      case OP.PWD_TYPE: {
        if (!dev.session) { dev._sendResult(opcode, ridNum, 0x4002); return; }
        if (dev.multiHid) {
          /* firmware v2: targets are addressed by identity address, and the
           * ambiguous reply carries both the MAC and the known name. */
          const tgt = proto.tlvLast(t, TAG.HOST_ADDR);
          const wanted = dev.hosts[1].addr;
          if (!tgt || !sameAddr(tgt, wanted)) {
            dev._send(opcode, proto.concatBytes(
              tlv(TAG.REQUEST_ID, proto.u16le(ridNum)),
              tlv(TAG.RESULT_CODE, proto.u16le(0x3002)),
              tlv(TAG.HOST_ADDR, dev.hosts[0].addr),
              tlv(TAG.HOST_NAME, Buffer.from(dev.hosts[0].name, "utf8")),
              tlv(TAG.HOST_ADDR, dev.hosts[1].addr),
              tlv(TAG.HOST_NAME, Buffer.from(dev.hosts[1].name, "utf8"))));
            return;
          }
          dev.lastTargetUsed = addrText(tgt);
        }
        dev._halfSync(opcode, ridNum);   // NOTE: half-sync has no TIMEOUT_MS in mock (client defaults)
        setTimeout(() => { dev._sendResult(opcode, ridNum, 0x0000); }, dev.autoConfirmMs);
        break;
      }
      case OP.HOST_LIST: {
        if (!dev.session) { dev._sendResult(opcode, ridNum, 0x4002); return; }
        const pi = proto.tlvLast(t, TAG.PAGE_INDEX);
        const page = pi ? pi[0] : 0;
        const PAGE = 2;                       // same as firmware HOST_PAGE_SIZE
        const slice = dev.hosts.slice(page * PAGE, page * PAGE + PAGE);
        let body = tlv(TAG.REQUEST_ID, proto.u16le(ridNum));
        for (const h of slice) {
          const fl = (h.online ? proto.HOST_FLAG.ONLINE : 0) |
                     (h.hid ? proto.HOST_FLAG.HID_NOW : 0) |
                     (h.flags & proto.HOST_FLAG.USER_NAMED);
          body = proto.concatBytes(body,
            tlv(TAG.HOST_ADDR, h.addr),
            tlv(TAG.HOST_NAME, Buffer.from(h.name, "utf8")),
            tlv(TAG.HOST_FLAGS, new Uint8Array([fl])));
        }
        body = proto.concatBytes(body,
          tlv(TAG.HOST_COUNT, new Uint8Array([dev.hosts.length])),
          tlv(TAG.PAGE_INDEX, new Uint8Array([page])));
        dev._send(opcode, body);
        break;
      }
      case OP.HOST_RENAME: {
        if (!dev.session) { dev._sendResult(opcode, ridNum, 0x4002); return; }
        const a = proto.tlvLast(t, TAG.HOST_ADDR);
        const h = dev.hosts.find((x) => sameAddr(x.addr, a));
        if (!h) { dev._sendResult(opcode, ridNum, 0x2005); return; }
        const n = proto.tlvLast(t, TAG.HOST_NAME);
        if (!n || n.length === 0) {           // clear -> MAC fallback name
          h.name = defaultName(h.addr);
          h.flags &= ~proto.HOST_FLAG.USER_NAMED;
        } else {
          h.name = Buffer.from(n).toString("utf8");
          h.flags |= proto.HOST_FLAG.USER_NAMED;
        }
        dev._sendResult(opcode, ridNum, 0x0000);
        break;
      }
      case OP.HOST_DISCONNECT: {
        if (!dev.session) { dev._sendResult(opcode, ridNum, 0x4002); return; }
        const a = proto.tlvLast(t, TAG.HOST_ADDR);
        const h = dev.hosts.find((x) => sameAddr(x.addr, a));
        if (!h || !h.online) { dev._sendResult(opcode, ridNum, 0x2005); return; }
        h.online = false;
        h.hid = false;
        dev._sendResult(opcode, ridNum, 0x0000);
        break;
      }
      case OP.ENTER_PAIRING: {
        if (!dev.session) { dev._sendResult(opcode, ridNum, 0x4002); return; }
        dev._halfSync(opcode, ridNum);
        setTimeout(() => { dev._sendResult(opcode, ridNum, 0x0000); }, dev.autoConfirmMs);
        break;
      }
      default:
        dev._sendResult(opcode, ridNum, 0x1000);
    }
  };

  return dev;
}

/* ---------------- run the test ---------------- */
const dev = createMockDevice();
writeHandler = (u8) => dev.onWrite(u8);

const { pwdkey, PwdKeyError } = require("../../pwdkey_app/miniprogram/utils/pwdkey.js");

let failures = 0;
function assert(cond, name) {
  if (cond) { console.log(`  PASS: ${name}`); }
  else { console.log(`  FAIL: ${name}`); failures++; }
}

async function main() {
  console.log("== connect (regression: DEVICE_INFO has no RESULT_CODE) ==");
  const info = await pwdkey.connect("MOCK");
  assert(info && info.salt && info.salt.length === 16, "connect returns info with salt");
  assert(info.passwordSet === false, "passwordSet=false before setup");
  assert(pwdkey.connected === true, "connected flag true after full success");

  console.log("== setPassword (HALF-SYNC -> ASYNC) ==");
  let waited = false, progress = 0;
  const code = await pwdkey.setPassword("TestPwd-2026!", {
    onProgress: (f) => { progress = f; },
    onWaiting: () => { waited = true; },
  });
  assert(waited, "onWaiting (press BOOT prompt) fired");
  assert(typeof code === "string" && code.length === 24, "recovery code is 24 chars");
  assert(progress > 0.9, "PBKDF2 progress reached ~1.0");
  assert(pwdkey.info.passwordSet === true, "info refreshed: passwordSet=true");

  console.log("== wrong password rejected ==");
  await pwdkey.lock();
  let wrongRejected = false;
  try { await pwdkey.unlock("WrongPwd!"); } catch (e) {
    wrongRejected = (e.code === 0x4001);
  }
  assert(wrongRejected, "wrong password -> 0x4001");

  console.log("== unlock (correct) ==");
  await pwdkey.unlock("TestPwd-2026!");
  assert(pwdkey.isUnlocked(), "session established");

  console.log("== entries lifecycle ==");
  let list = await pwdkey.listEntries();
  assert(list.ids.length === 0, "empty vault");

  const id = await pwdkey.addEntry("P@ssw0rd!#2026", "测试名称");
  assert(typeof id === "string" && id.length === 8, "addEntry returns 8-char id");

  list = await pwdkey.listEntries();
  assert(list.ids.length === 1 && list.ids[0] === id, "entry listed");

  const name = await pwdkey.getEntryName(id);
  assert(name === "测试名称", "getEntryName utf-8 decode");

  console.log("== typeEntry (HALF-SYNC -> ASYNC) ==");
  let waited2 = false;
  await pwdkey.typeEntry(id, { onWaiting: () => { waited2 = true; } });
  assert(waited2, "typeEntry waiting prompt fired");

  console.log("== host registry: list (paged) / rename / disconnect ==");
  {
    const hosts = await pwdkey.listHosts();
    assert(hosts.length === 3, "listHosts returns all 3 hosts (paged)");
    assert(hosts[0].online === true && hosts[2].online === false,
           "online hosts sorted first");
    const custom = hosts.find((h) => h.userNamed);
    assert(custom && custom.name === "书房台式机", "user-named host keeps its name");
    const fallback = hosts.find((h) => !h.userNamed && h.online);
    assert(fallback && fallback.name === "电脑 5566",
           "unnamed host falls back to 电脑 5566");
    assert(fallback && fallback.mac === addrText(dev.hosts[0].addr),
           "MAC formatted as A1:B2:…");
  }
  {
    /* rename -> then clear -> back to the MAC-derived default */
    const target = dev.hosts[2].addr;
    await pwdkey.renameHost(target, "公司笔记本");
    let h = (await pwdkey.listHosts()).find((x) => x.mac === addrText(target));
    assert(h && h.name === "公司笔记本" && h.userNamed, "rename persists");
    await pwdkey.renameHost(target, "");
    h = (await pwdkey.listHosts()).find((x) => x.mac === addrText(target));
    assert(h && h.name === "电脑 0506" && !h.userNamed,
           "clearing a name restores the MAC fallback");
  }
  {
    await pwdkey.disconnectHost(dev.hosts[0].addr);
    const h = (await pwdkey.listHosts()).find((x) => x.mac === addrText(dev.hosts[0].addr));
    assert(h && h.online === false, "disconnectHost takes the link offline");
    let rejected = false;
    try { await pwdkey.disconnectHost(dev.hosts[2].addr); } catch (e) {
      rejected = (e.code === 0x2005);
    }
    assert(rejected, "disconnecting an offline host -> 0x2005");
  }

  console.log("== multi-HID target picking (by host name) ==");
  {
    dev.multiHid = true;                       // two PCs online
    let candidates = null;
    await pwdkey.typeEntry(id, {
      onPickTarget: async (list) => {
        candidates = list;
        return list[1].addr;                   // user picks "书房台式机"
      },
    });
    assert(candidates && candidates.length === 2, "received 2 candidate targets");
    assert(candidates[1].name === "书房台式机",
           "candidates carry their display names");
    assert(dev.lastTargetUsed === addrText(dev.hosts[1].addr),
           "retry carried the chosen MAC");
    dev.multiHid = false;
  }

  console.log("== user cancels target picking ==");
  {
    dev.multiHid = true;
    let cancelled = false;
    try {
      await pwdkey.typeEntry(id, { onPickTarget: async () => null });
    } catch (e) {
      cancelled = (e.code === 0x3004);
    }
    assert(cancelled, "cancel surfaces as 0x3004");
    dev.multiHid = false;
  }

  console.log("== enterPairing ==");
  await pwdkey.enterPairing({ onWaiting: () => {} });

  console.log("== delete + lock ==");
  await pwdkey.deleteEntry(id);
  list = await pwdkey.listEntries();
  assert(list.ids.length === 0, "entry deleted");

  await pwdkey.lock();
  assert(!pwdkey.isUnlocked(), "lock clears session");

  console.log(failures === 0 ? "\nALL FLOW TESTS PASSED" : `\n${failures} FAILURES`);
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.error("FATAL:", e);
  process.exit(1);
});
