/**
 * test_change_pwd.js - 修改主密码的协议级对拍（不需要硬件）
 *
 * 假设备严格照固件 v1.2 的行为实现：
 *   AUTH_NEW（无 KEK）   -> HALF-SYNC（等按键） + 带 NEW_SALT/KDF_ITER 的结果
 *   AUTH_NEW（有 KEK）   -> 用【旧】verifier 校验 PROOF2，通过后 rekey 全库：
 *                           salt / verifier 换新，并生成新的 24 位恢复码
 *
 * 验证四件事：
 *   1. 用错旧密码时，本地就拦下，一个字节都不发给设备（保护失败计数）
 *   2. 正确旧密码可以完成改密，并拿到新的恢复码
 *   3. 改密后设备 salt 变了（旧 salt 派生的 KEK 再也进不去）
 *   4. 新密码能解锁、旧密码不能解锁
 *
 * 运行：node tests/test_change_pwd.js
 */
const path = require('path');

const SRC = path.join(__dirname, '..', 'www', 'src');
const proto = require(path.join(SRC, 'libs', 'proto.js'));
const crypto = require(path.join(SRC, 'utils', 'crypto.js'));
const { TAG, OP } = proto;

const PWD_OLD = 'old-password-123';
const PWD_NEW = 'new-password-456';

/* ------------------------------------------------------------------
 * 假设备
 * ------------------------------------------------------------------ */

const dev = {
  salt: new Uint8Array(16).fill(0x21),
  iter: 200000,
  verifier: null,          // 32 字节
  entryCount: 0,
  recoveryCode: '',

  /* 统计：用来断言"错的旧密码不会发到设备" */
  authNewFrames: 0,
  authVerifyOk: 0,
  authVerifyFail: 0,
  rekeyCount: 0,
};

const fakeBle = {
  _notify: null,
  _asm: null,

  async initialize() {},
  async connect() {},
  async disconnect() {},
  async requestMtu() { return 256; },
  async getServices() {
    return [{
      uuid: '0000fff0-0000-1000-8000-00805f9b34fb',
      characteristics: [
        { uuid: '0000fff3-0000-1000-8000-00805f9b34fb' },
        { uuid: '0000fff4-0000-1000-8000-00805f9b34fb' },
      ],
    }];
  },
  async startNotifications(devId, svc, chr, cb) { fakeBle._notify = cb; },
  async stopNotifications() {},
  async write(devId, svc, chr, dv) {
    fakeBle._onWrite(new Uint8Array(dv.buffer, dv.byteOffset, dv.byteLength));
  },

  _onWrite(u8) {
    const opcode = u8[2];
    const flags = u8[3];
    const payload = u8.slice(6);
    if (!fakeBle._asm) {
      fakeBle._asm = { buf: payload };
    } else {
      fakeBle._asm.buf = proto.concatBytes(fakeBle._asm.buf, payload);
    }
    if (!(flags & proto.FLAG_LAST)) { return; }
    const body = fakeBle._asm.buf;
    fakeBle._asm = null;
    fakeBle._handle(opcode, body);
  },

  _send(opcode, tlvs) {
    const frame = proto.buildFrames(opcode, tlvs, 9999)[0];
    setTimeout(() => {
      if (fakeBle._notify) {
        fakeBle._notify(new DataView(frame.buffer, frame.byteOffset, frame.byteLength));
      }
    }, 2);
  },

  _result(opcode, rid, rc, extra) {
    const parts = [
      proto.tlv(TAG.REQUEST_ID, proto.u16le(rid)),
      proto.tlv(TAG.RESULT_CODE, proto.u16le(rc)),
    ];
    if (extra) { parts.push(extra); }
    fakeBle._send(opcode, proto.concatBytes(...parts));
  },

  _halfSync(opcode, rid) {
    fakeBle._send(opcode, proto.concatBytes(
      proto.tlv(TAG.REQUEST_ID, proto.u16le(rid)),
      proto.tlv(TAG.STATE, proto.u16le(0x0001 | 0x0004))));
  },

  _handle(opcode, body) {
    const tlvs = proto.parseTLVs(body);
    const ridRaw = proto.tlvLast(tlvs, TAG.REQUEST_ID);
    const rid = ridRaw ? proto.readU16le(ridRaw, 0) : 0;

    if (opcode === OP.DEVICE_INFO) {
      fakeBle._send(opcode, proto.concatBytes(
        proto.tlv(TAG.REQUEST_ID, proto.u16le(rid)),
        proto.tlv(TAG.FW_VERSION, new Uint8Array([0, 1, 2])),
        proto.tlv(TAG.ENTRY_COUNT, proto.u16le(dev.entryCount)),
        proto.tlv(TAG.STATE, proto.u16le(0x0100 | 0x0001)),
        proto.tlv(TAG.LOCK_SECONDS, proto.u32le(0)),
        proto.tlv(TAG.SALT, dev.salt),
        proto.tlv(TAG.KDF_ITER, proto.u32le(dev.iter))));
      return;
    }

    if (opcode === OP.AUTH_START) {
      fakeBle._send(opcode, proto.concatBytes(
        proto.tlv(TAG.REQUEST_ID, proto.u16le(rid)),
        proto.tlv(TAG.NONCE, new Uint8Array(32).fill(0x33)),
        proto.tlv(TAG.SESSION_SEQ, proto.u32le(7))));
      return;
    }

    if (opcode === OP.AUTH_VERIFY) {
      const nonce = proto.tlvLast(tlvs, TAG.NONCE);
      const proof = proto.tlvLast(tlvs, TAG.PROOF);
      const kek = proto.tlvLast(tlvs, TAG.KEK_BLOB);
      const expect = crypto.computeProof(dev.verifier, nonce, 7);
      const ok = kek && proof && bytesEq(proof, expect)
        && bytesEq(crypto.computeVerifier(kek), dev.verifier);
      if (ok) { dev.authVerifyOk++; } else { dev.authVerifyFail++; }
      fakeBle._result(opcode, rid, ok ? 0 : 0x4001);
      return;
    }

    if (opcode === OP.AUTH_NEW) {
      dev.authNewFrames++;
      const kek = proto.tlvLast(tlvs, TAG.KEK_BLOB);

      if (!kek) {
        /* step 1：等按键 -> 生成新 salt */
        const newSalt = new Uint8Array(16);
        for (let i = 0; i < 16; i++) { newSalt[i] = (i * 7 + 3) & 0xFF; }
        dev.pendingSalt = newSalt;

        fakeBle._halfSync(opcode, rid);
        setTimeout(() => {
          fakeBle._send(opcode, proto.concatBytes(
            proto.tlv(TAG.REQUEST_ID, proto.u16le(rid)),
            proto.tlv(TAG.RESULT_CODE, proto.u16le(0)),
            proto.tlv(TAG.NEW_SALT, newSalt),
            proto.tlv(TAG.KDF_ITER, proto.u32le(dev.iter))));
        }, 30);
        return;
      }

      /* step 2：PROOF2 用【旧】verifier */
      const nonce = proto.tlvLast(tlvs, TAG.NONCE);
      const proof = proto.tlvLast(tlvs, TAG.PROOF);
      const expect = crypto.computeProof(dev.verifier, nonce, 7);
      if (!proof || !bytesEq(proof, expect)) {
        fakeBle._result(opcode, rid, 0x4001);
        return;
      }

      /* rekey：salt 与 verifier 一起换新 */
      dev.salt = dev.pendingSalt;
      dev.verifier = crypto.computeVerifier(kek);
      dev.pendingSalt = null;
      dev.rekeyCount++;

      const code = new Uint8Array(24);
      for (let i = 0; i < 24; i++) { code[i] = 0x41 + (i % 26); }
      dev.recoveryCode = proto.bytesToAscii(code);

      fakeBle._result(opcode, rid, 0, proto.concatBytes(
        proto.tlv(TAG.RECOVERY_CODE, code),
        proto.tlv(TAG.STATE, proto.u16le(0x0100 | 0x0001))));
      return;
    }

    if (opcode === OP.PWD_LIST) {
      fakeBle._send(opcode, proto.concatBytes(
        proto.tlv(TAG.REQUEST_ID, proto.u16le(rid)),
        proto.tlv(TAG.ENTRY_COUNT, proto.u16le(0))));
      return;
    }

    fakeBle._result(opcode, rid, 0x4002);
  },
};

function bytesEq(a, b) {
  if (!a || !b || a.length !== b.length) { return false; }
  for (let i = 0; i < a.length; i++) { if (a[i] !== b[i]) { return false; } }
  return true;
}

/* 注入假 BLE */
const blePluginPath = require.resolve('@capacitor-community/bluetooth-le');
require.cache[blePluginPath] = {
  id: blePluginPath,
  filename: blePluginPath,
  loaded: true,
  exports: { BleClient: fakeBle },
  children: [],
  paths: [],
};

const { pwdkey } = require(path.join(SRC, 'utils', 'pwdkey.js'));

/* ------------------------------------------------------------------
 * 断言
 * ------------------------------------------------------------------ */

let failures = 0;
function assert(cond, name, extra) {
  if (cond) {
    console.log('  PASS: ' + name);
  } else {
    failures++;
    console.log('  FAIL: ' + name + (extra ? '  -> ' + extra : ''));
  }
}

async function main() {
  console.log('== 初始化：设备已设置主密码 ==');
  const kekOld = await crypto.deriveKekAsync(
    crypto.utf8ToBytes(PWD_OLD), dev.salt, dev.iter);
  dev.verifier = crypto.computeVerifier(kekOld);

  await pwdkey.connect('FAKE-DEV');
  assert(pwdkey.connected === true, '连接成功');

  console.log('== 用旧密码解锁 ==');
  await pwdkey.unlock(PWD_OLD);
  assert(pwdkey.isUnlocked() === true, '旧密码可以解锁');
  assert(dev.authVerifyOk === 1, '设备侧 AUTH_VERIFY 通过一次');

  console.log('== 旧密码输错时必须在本地拦下 ==');
  const before = dev.authNewFrames;
  let blocked = false;
  try {
    await pwdkey.changePassword('wrong-password-999', PWD_NEW);
  } catch (e) {
    blocked = (e.code === 0x4001);
  }
  assert(blocked === true, '旧密码错误时抛出 0x4001');
  assert(dev.authNewFrames === before, '没有向设备发送 AUTH_NEW（不消耗失败计数）',
    `before=${before} now=${dev.authNewFrames}`);

  console.log('== 修改主密码 ==');
  const saltBefore = dev.salt.slice();
  const res = await pwdkey.changePassword(PWD_OLD, PWD_NEW);
  assert(dev.rekeyCount === 1, '设备执行了一次 rekey');
  assert(!!res.recoveryCode && res.recoveryCode.length === 24,
    '拿到 24 位新恢复码', res.recoveryCode);
  assert(!bytesEq(dev.salt, saltBefore), '设备 salt 已更换（旧 KEK 失效）');
  assert(bytesEq(pwdkey.info.salt, dev.salt), 'App 侧 info.salt 已同步为新 salt');

  console.log('== 改密后的解锁行为 ==');
  pwdkey.kek = null;
  pwdkey.verifier = null;

  let oldRejected = false;
  try {
    await pwdkey.unlock(PWD_OLD);
  } catch (e) {
    oldRejected = (e.code === 0x4001);
  }
  assert(oldRejected === true, '旧密码已经无法解锁');

  await pwdkey.unlock(PWD_NEW);
  assert(pwdkey.isUnlocked() === true, '新密码可以解锁');

  console.log(failures === 0 ? '\nALL CHANGE-PASSWORD TESTS PASSED'
                             : `\n${failures} FAILURES`);
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.error('FATAL:', e);
  process.exit(1);
});
