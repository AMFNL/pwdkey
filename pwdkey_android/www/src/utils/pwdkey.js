/**
 * pwdkey.js - PwdKey 设备操作层（协议 v1.2）
 *
 * 对外接口（页面调用）:
 *   connect(deviceId)        连接并读取设备信息
 *   refreshInfo()            刷新设备信息
 *   setPassword(pwd, cb)     首次设置主密码 → 返回恢复码
 *   unlock(pwd, cb)          认证（主密码）
 *   lock()                   锁定（销毁会话）
 *   listEntries()            条目 ID 列表
 *   addEntry(pwd, name)      添加条目 → 返回条目 ID
 *   deleteEntry(id)          删除条目
 *   getEntryName(id)         读取条目名称
 *   typeEntry(id, cb)        输出条目到电脑（等待按键）
 *                            cb.onPickTarget 支持多台电脑在线时选目标
 *   enterPairing(cb)         进入配对模式（等待按键）
 *
 * 会话安全: KEK 只保存在本模块内存中，lock()/断开时立即清除。
 */
const ble = require('./ble.js');
const proto = require('../libs/proto.js');
const crypto = require('./crypto.js');
const exp = require('./export.js');

const { OP, TAG, tlv, buildFrames } = proto;

class PwdKeyError extends Error {
  constructor(code, message) {
    super(message || proto.errText(code));
    this.code = code;
  }
}

/* ---------------- 恢复码的 Base32 编解码 ----------------
 * 字母表与固件 gen_recovery_code 完全一致：去掉易混的 I / O / 0 / 1。
 * 16 字节 → 26 字符（128 bit = 25.6 个 5 位组，向上取整，末位补 0）。
 */
const B32_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function b32Encode(bytes) {
  let acc = 0;
  let bits = 0;
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    acc = (acc << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32_ALPHABET[(acc >> bits) & 0x1F];
    }
  }
  if (bits > 0) {
    out += B32_ALPHABET[(acc << (5 - bits)) & 0x1F];
  }
  return out;
}

function b32Decode(str, byteLen) {
  const s = String(str || '').toUpperCase().replace(/[^A-Z2-9]/g, '');
  const out = new Uint8Array(byteLen);
  let acc = 0;
  let bits = 0;
  let oi = 0;
  for (let i = 0; i < s.length && oi < byteLen; i++) {
    const v = B32_ALPHABET.indexOf(s[i]);
    if (v < 0) {
      throw new Error('恢复码里有非法字符：' + s[i]);
    }
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[oi++] = (acc >> bits) & 0xFF;
    }
  }
  if (oi !== byteLen) {
    throw new Error(`恢复码长度不对（应为 26 个字符，实际有效 ${s.length} 个）`);
  }
  return out;
}

class PwdKey {
  constructor() {
    this.connected = false;
    this.deviceId = null;
    this.info = null;          // { fw, entryCount, state, lockSeconds, salt, iter, sessionId }
    this.kek = null;           // Uint8Array | null（仅内存）
    this.verifier = null;
    this._rid = 0;
    this._waiters = [];        // { opcode, wantResult, resolve, reject }
    this._orphan = [];         // 早到的帧缓存 { ts, opcode, tlvs, hasResult }
    this._asm = new proto.RecvAssembler();
  }

  /* ---------------- 底层收发 ---------------- */

  async connect(deviceId) {
    try {
      await ble.connect(deviceId);
      this.deviceId = deviceId;
      this._asm = new proto.RecvAssembler();
      ble.onNotify((data) => this._onData(data));
      await this.refreshInfo();
      // 全部成功后才置为已连接，避免"半连接"脏状态
      this.connected = true;
      return this.info;
    } catch (e) {
      this.connected = false;
      await ble.disconnect().catch(() => {});
      throw e;
    }
  }

  async disconnect() {
    this.lock().catch(() => {});
    this.kek = null;
    this.verifier = null;
    this.connected = false;
    this.deviceId = null;
    await ble.disconnect();
  }

  _onData(data) {
    const frames = this._asm.push(data);
    for (const f of frames) {
      const p = proto.parseFrame(f);
      if (p) { this._dispatch(p); }
    }
  }

  _dispatch(f) {
    const hasRes = proto.hasResult(f.tlvs);
    // 先给等待者
    for (let i = 0; i < this._waiters.length; i++) {
      const w = this._waiters[i];
      if (w.opcode !== f.opcode) { continue; }
      if (w.wantResult !== undefined && w.wantResult !== hasRes) { continue; }
      this._waiters.splice(i, 1);
      w.resolve(f);
      return;
    }
    // 无等待者：暂存（10 秒内有效）
    this._orphan.push({ ts: Date.now(), frame: f, hasResult: hasRes });
    if (this._orphan.length > 8) { this._orphan.shift(); }
  }

  _nextRid() {
    this._rid = (this._rid % 0xFFFF) + 1;
    return this._rid;
  }

  /** 发送请求（自动分片） */
  async _send(opcode, tlvs) {
    const all = proto.concatBytes(tlvs, tlv(TAG.REQUEST_ID, proto.u16le(this._nextRid())));
    const frames = buildFrames(opcode, all, 14);
    await ble.writeChunks(frames);
  }

  /**
   * 等待一帧响应。
   * @param {number} opcode
   * @param {{wantResult?:boolean, timeout?:number}} opts
   */
  _waitFrame(opcode, opts) {
    const { wantResult, timeout = 10000 } = opts || {};
    // 先查早到缓存
    const now = Date.now();
    this._orphan = this._orphan.filter((o) => now - o.ts < 10000);
    for (let i = 0; i < this._orphan.length; i++) {
      const o = this._orphan[i];
      if (o.frame.opcode !== opcode) { continue; }
      if (wantResult !== undefined && wantResult !== o.hasResult) { continue; }
      this._orphan.splice(i, 1);
      return Promise.resolve(o.frame);
    }
    return new Promise((resolve, reject) => {
      const w = { opcode, wantResult, resolve, reject };
      w.timer = setTimeout(() => {
        const i = this._waiters.indexOf(w);
        if (i >= 0) { this._waiters.splice(i, 1); }
        reject(new PwdKeyError(0xFFFF, '等待设备响应超时'));
      }, timeout);
      const wrappedResolve = (f) => { clearTimeout(w.timer); resolve(f); };
      w.resolve = wrappedResolve;
      this._waiters.push(w);
    });
  }

  _checkResult(frame) {
    // 语义：无 RESULT_CODE 的帧视为成功响应（设备的部分成功响应不含该字段，
    // 例如 DEVICE_INFO）；带 RESULT_CODE 的帧按码校验。
    if (!proto.hasResult(frame.tlvs)) { return frame; }
    const rc = proto.resultCode(frame.tlvs);
    if (rc !== 0) {
      let msg = proto.errText(rc);
      /* 两种"等一会儿"的提示，固件用的 TLV 不同，长度也不同：
       *   0x4003 临时锁定 → T_LOCK_SECONDS(0x0C)，u32
       *   0x0002 设备忙   → T_ERR_DETAIL(0x16)，u16（导出 30 分钟限速走这里）
       * 之前只处理了前者，所以导出被限速时只显示"设备正忙"，看不出要等多久。 */
      if (rc === 0x4003) {
        const lv = proto.tlvLast(frame.tlvs, TAG.LOCK_SECONDS);
        if (lv) {
          msg += `（剩余 ${proto.readU32le(lv, 0)} 秒）`;
        }
      } else if (rc === 0x0002) {
        const dv = proto.tlvLast(frame.tlvs, TAG.ERR_DETAIL);
        if (dv && dv.length >= 2) {
          msg += `（还需等待 ${proto.readU16le(dv, 0)} 秒）`;
        }
      }
      throw new PwdKeyError(rc, msg);
    }
    return frame;
  }

  /* ---------------- 设备信息 ---------------- */

  async refreshInfo() {
    await this._send(OP.DEVICE_INFO, new Uint8Array(0));
    const f = await this._waitFrame(OP.DEVICE_INFO, { timeout: 10000 });
    this._checkResult(f);   // 成功响应无 RESULT_CODE -> 直接通过
    const t = f.tlvs;
    const fwv = proto.tlvLast(t, TAG.FW_VERSION);
    const salt = proto.tlvLast(t, TAG.SALT);
    const iter = proto.tlvLast(t, TAG.KDF_ITER);
    const state = proto.tlvLast(t, TAG.STATE);
    const cnt = proto.tlvLast(t, TAG.ENTRY_COUNT);
    const lock = proto.tlvLast(t, TAG.LOCK_SECONDS);
    this.info = {
      fw: fwv ? `${fwv[0]}.${fwv[1]}.${fwv[2]}` : '?',
      entryCount: cnt ? proto.readU16le(cnt, 0) : 0,
      state: state ? proto.readU16le(state, 0) : 0,
      lockSeconds: lock ? proto.readU32le(lock, 0) : 0,
      salt: salt ? salt.slice() : null,
      iter: iter ? proto.readU32le(iter, 0) : 0,
      passwordSet: state ? !!(proto.readU16le(state, 0) & 0x0100) : false,
    };
    return this.info;
  }

  isUnlocked() {
    return !!this.kek;
  }

  /* ---------------- 首次设置主密码（S0） ---------------- */

  /**
   * @param {string} pwd 主密码（纯 ASCII）
   * @param {{onProgress?:(f:number)=>void, onWaiting?:()=>void}} cb
   * @returns {Promise<string>} 恢复码（24 字符）
   */
  async setPassword(pwd, cb) {
    const { onProgress, onWaiting } = cb || {};
    if (!this.info || !this.info.salt) {
      await this.refreshInfo();     // 尝试补一次设备信息
    }
    if (!this.info || !this.info.salt) {
      throw new PwdKeyError(0xFFFF, '未获取到设备信息，请返回首页重新连接设备');
    }
    const pwdBytes = crypto.utf8ToBytes(pwd);
    const kek = await crypto.deriveKekAsync(pwdBytes, this.info.salt,
                                            this.info.iter, onProgress);
    await this._send(OP.AUTH_NEW, tlv(TAG.KEK_BLOB, kek));
    // 等第一帧：正常为 HALF-SYNC（无 RESULT_CODE）；错误帧则立即中止
    const half = await this._waitFrame(OP.AUTH_NEW, { timeout: 10000 });
    if (proto.hasResult(half.tlvs)) { this._checkResult(half); }
    if (onWaiting) { onWaiting(); }
    // ASYNC：用户按键后
    const fin = await this._waitFrame(OP.AUTH_NEW, { wantResult: true, timeout: 65000 });
    this._checkResult(fin);
    const code = proto.tlvLast(fin.tlvs, TAG.RECOVERY_CODE);
    this.kek = kek;
    this.verifier = crypto.computeVerifier(kek);
    await this.refreshInfo();
    return code ? proto.bytesToAscii(code) : '';
  }

  /* ---------------- 认证 ---------------- */

  /**
   * 用已持有的 KEK 完成一次 AUTH_VERIFY（不涉及密码派生）。
   * 主密码路径与生物认证路径最终都汇到这里，保证两条路径的 PROOF 完全一致。
   * @param {Uint8Array} kek 32 字节
   */
  async _verifyKek(kek) {
    if (!this.info || !this.info.salt) { await this.refreshInfo(); }

    await this._send(OP.AUTH_START, new Uint8Array(0));
    const sf = await this._waitFrame(OP.AUTH_START, { timeout: 10000 });
    if (proto.hasResult(sf.tlvs) && proto.resultCode(sf.tlvs) !== 0) {
      this._checkResult(sf);
    }
    const nonce = proto.tlvLast(sf.tlvs, TAG.NONCE);
    const seqb = proto.tlvLast(sf.tlvs, TAG.SESSION_SEQ);
    if (!nonce || !seqb) { throw new PwdKeyError(0xFFFF, 'AUTH_START 响应异常'); }
    const seq = proto.readU32le(seqb, 0);

    const verifier = crypto.computeVerifier(kek);
    const proof = crypto.computeProof(verifier, nonce, seq);

    await this._send(OP.AUTH_VERIFY, proto.concatBytes(
      tlv(TAG.NONCE, nonce),
      tlv(TAG.PROOF, proof),
      tlv(TAG.KEK_BLOB, kek)));
    const fin = await this._waitFrame(OP.AUTH_VERIFY, { wantResult: true, timeout: 15000 });
    this._checkResult(fin);

    this.kek = kek;
    this.verifier = verifier;
    await this.refreshInfo();
  }

  /**
   * @param {string} pwd
   * @param {{onProgress?:(f:number)=>void}} cb
   */
  async unlock(pwd, cb) {
    const { onProgress } = cb || {};
    if (!this.info || !this.info.salt) { await this.refreshInfo(); }

    const pwdBytes = crypto.utf8ToBytes(pwd);
    const kek = await crypto.deriveKekAsync(pwdBytes, this.info.salt,
                                            this.info.iter, onProgress);
    await this._verifyKek(kek);
  }

  /**
   * 生物认证路径：KEK 已由「生物解封 + PIN 解封」得到，跳过 PBKDF2。
   * @param {Uint8Array} kek 32 字节
   */
  async unlockWithKek(kek) {
    if (!kek || kek.length !== 32) {
      throw new PwdKeyError(0xFFFF, 'KEK 长度不正确');
    }
    await this._verifyKek(kek);
  }

  /* ---------------- 修改主密码（v1.1） ---------------- */

  /**
   * 修改主密码：设备重加密全库，并生成【新的恢复码】（旧恢复码立即作废）。
   *
   * 协议（固件 v1.2，无需改固件）：
   *   1) AUTH_NEW（空 TLV）          -> 设备等 BOOT 确认
   *   2) 设备返回 NEW_SALT + KDF_ITER
   *   3) 用新 salt 派生 newKek
   *   4) AUTH_START                  -> nonce / seq
   *   5) AUTH_NEW(NONCE, PROOF2, KEK_BLOB)  其中 PROOF2 = HMAC(旧 verifier, nonce||seq)
   *
   * 注意：PROOF2 用的是【旧】verifier，这是固件 C25 的约定。
   *
   * @param {string} oldPwd 仅用于本地校验（不会发给设备），防止误改
   * @param {string} newPwd
   * @param {{onProgress?:(f:number)=>void, onWaiting?:()=>void}} cb
   * @returns {Promise<{recoveryCode:string, salt:Uint8Array, iter:number}>}
   */
  async changePassword(oldPwd, newPwd, cb) {
    const { onProgress, onWaiting } = cb || {};
    this._requireUnlocked();
    if (!this.verifier) { throw new PwdKeyError(0x4002, '请先解锁设备'); }
    if (!this.info || !this.info.salt) { await this.refreshInfo(); }

    /* 先在本地确认旧密码确实是当前 KEK 的来源：算错的密码绝不会发到设备，
       避免消耗设备的失败计数（10 次即永久锁定）。 */
    const oldKek = await crypto.deriveKekAsync(
      crypto.utf8ToBytes(oldPwd), this.info.salt, this.info.iter);
    const same = oldKek.length === this.kek.length &&
                 oldKek.every((b, i) => b === this.kek[i]);
    if (!same) {
      throw new PwdKeyError(0x4001, '当前主密码不正确');
    }

    /* --- 步骤 1：请求设备进入改密流程并生成新 salt --- */
    await this._send(OP.AUTH_NEW, new Uint8Array(0));
    const half = await this._waitFrame(OP.AUTH_NEW, { timeout: 10000 });
    if (proto.hasResult(half.tlvs)) { this._checkResult(half); }
    if (onWaiting) { onWaiting(); }

    const s1 = await this._waitFrame(OP.AUTH_NEW, { wantResult: true, timeout: 65000 });
    this._checkResult(s1);
    const saltB = proto.tlvLast(s1.tlvs, TAG.NEW_SALT);
    const iterB = proto.tlvLast(s1.tlvs, TAG.KDF_ITER);
    if (!saltB || saltB.length !== 16) {
      throw new PwdKeyError(0xFFFF, '设备未返回新 salt');
    }
    const newSalt = saltB.slice();
    const iter = iterB ? proto.readU32le(iterB, 0) : this.info.iter;

    /* --- 步骤 2：用新 salt 派生新 KEK --- */
    const newKek = await crypto.deriveKekAsync(
      crypto.utf8ToBytes(newPwd), newSalt, iter, onProgress);

    /* --- 步骤 3：取 nonce，用旧 verifier 算 PROOF2 --- */
    await this._send(OP.AUTH_START, new Uint8Array(0));
    const sf = await this._waitFrame(OP.AUTH_START, { timeout: 10000 });
    if (proto.hasResult(sf.tlvs) && proto.resultCode(sf.tlvs) !== 0) {
      this._checkResult(sf);
    }
    const nonce = proto.tlvLast(sf.tlvs, TAG.NONCE);
    const seqb = proto.tlvLast(sf.tlvs, TAG.SESSION_SEQ);
    if (!nonce || !seqb) { throw new PwdKeyError(0xFFFF, 'AUTH_START 响应异常'); }
    const proof2 = crypto.computeProof(this.verifier, nonce, proto.readU32le(seqb, 0));

    await this._send(OP.AUTH_NEW, proto.concatBytes(
      tlv(TAG.NONCE, nonce),
      tlv(TAG.PROOF, proof2),
      tlv(TAG.KEK_BLOB, newKek)));

    const fin = await this._waitFrame(OP.AUTH_NEW, { wantResult: true, timeout: 60000 });
    this._checkResult(fin);

    this.kek = newKek;
    this.verifier = crypto.computeVerifier(newKek);
    const code = proto.tlvLast(fin.tlvs, TAG.RECOVERY_CODE);
    await this.refreshInfo();      // 这会把 info.salt 更新为设备的新 salt

    return {
      recoveryCode: code ? proto.bytesToAscii(code) : '',
      salt: newSalt,
      iter: iter,
    };
  }

  async lock() {
    if (!this.connected) {
      this.kek = null; this.verifier = null;
      return;
    }
    try {
      await this._send(OP.AUTH_LOCK, new Uint8Array(0));
      await this._waitFrame(OP.AUTH_LOCK, { timeout: 5000 });
    } catch (e) { /* 忽略 */ }
    this.kek = null;
    this.verifier = null;
  }

  _requireUnlocked() {
    if (!this.kek) { throw new PwdKeyError(0x4002, '请先解锁设备'); }
  }

  /* ---------------- 条目操作 ---------------- */

  async listEntries() {
    this._requireUnlocked();
    await this._send(OP.PWD_LIST, new Uint8Array(0));
    const f = await this._waitFrame(OP.PWD_LIST, { timeout: 10000 });
    if (proto.hasResult(f.tlvs) && proto.resultCode(f.tlvs) !== 0) {
      this._checkResult(f);
    }
    const ids = (f.tlvs[TAG.ENTRY_ID] || []).map((b) => proto.bytesToAscii(b));
    return { ids, count: ids.length };
  }

  async addEntry(pwd, name) {
    this._requireUnlocked();
    const tlvs = proto.concatBytes(
      tlv(TAG.SECRET, crypto.utf8ToBytes(pwd)),
      tlv(TAG.NAME, crypto.utf8ToBytes(name || '')));
    await this._send(OP.PWD_ADD, tlvs);
    const f = await this._waitFrame(OP.PWD_ADD, { timeout: 10000 });
    this._checkResult(f);
    const id = proto.tlvLast(f.tlvs, TAG.ENTRY_ID);
    await this.refreshInfo();
    return id ? proto.bytesToAscii(id) : '';
  }

  /**
   * 只改条目名称，密码不动。
   * 固件 PWD_UPDATE 的 has_name / has_sec 是独立判断的，只带 NAME
   * 就是纯改名，不会重新加密条目内容。
   */
  async renameEntry(id, name) {
    this._requireUnlocked();
    const nm = String(name || '').trim();
    if (!nm) { throw new PwdKeyError(0x1003, '名称不能为空'); }
    const tlvs = proto.concatBytes(
      tlv(TAG.ENTRY_ID, proto.asciiToBytes(id)),
      tlv(TAG.NAME, crypto.utf8ToBytes(nm)));
    await this._send(OP.PWD_UPDATE, tlvs);
    const f = await this._waitFrame(OP.PWD_UPDATE, { timeout: 10000 });
    this._checkResult(f);
    await this.refreshInfo();
  }

  /**
   * 加密导出：**设备内加密**，BLE 上只跑密文，App 全程不接触条目明文。
   *
   *   1. BEGIN  → 设备生成导出包（需在设备上按 BOOT 确认），返回 wrapped/nonce/总长
   *   2. CHUNK  → 分块取密文
   *   3. 换锁   → 用 KEK 解出 K_export，再用主密码派生的密钥重新包裹
   *   4. 存文件 → 写缓存 + 系统分享 + 删除缓存副本
   *
   * @param {string} masterPwd
   * @param {{onProgress?:(done:number,total:number)=>void}} cb
   * @returns {Promise<string>} 备份文件内容（保存由调用方负责）
   */
  async exportVault(masterPwd, cb) {
    this._requireUnlocked();
    const onProgress = cb && cb.onProgress;
    if (!this.kek) {
      throw new PwdKeyError(0x4002, '会话已失效，请重新解锁');
    }

    /* 1. BEGIN —— 这一步会触发设备上的 BOOT 确认窗口 */
    await this._send(OP.PWD_EXPORT_BEGIN, proto.concatBytes());
    const head = await this._waitFrame(OP.PWD_EXPORT_BEGIN, { timeout: 45000 });
    this._checkResult(head);

    const wrapped = proto.tlvLast(head.tlvs, TAG.EXPORT_WRAPPED);
    const dnonce = proto.tlvLast(head.tlvs, TAG.EXPORT_NONCE);
    const totalB = proto.tlvLast(head.tlvs, TAG.EXPORT_TOTAL);
    if (!wrapped || wrapped.length !== 60 || !dnonce || dnonce.length !== 12 || !totalB) {
      throw new PwdKeyError(0x0001, '设备返回的导出头不完整');
    }
    const total = proto.readU32le(totalB, 0);
    if (!total || total > 65536) {
      throw new PwdKeyError(0x0001, '导出长度异常');
    }

    /* 2. 分块取密文 */
    const parts = [];
    let offset = 0;
    while (offset < total) {
      await this._send(OP.PWD_EXPORT_CHUNK, tlv(TAG.EXPORT_OFFSET, proto.u32le(offset)));
      const f = await this._waitFrame(OP.PWD_EXPORT_CHUNK, { timeout: 10000 });
      this._checkResult(f);
      const blk = proto.tlvLast(f.tlvs, TAG.EXPORT_DATA);
      if (!blk || !blk.length) {
        throw new PwdKeyError(0x0001, '导出中断（设备无更多数据）');
      }
      parts.push(blk);
      offset += blk.length;
      if (onProgress) { onProgress(offset, total); }
      if (parts.length > 256) { break; }
    }
    if (offset < total) {
      throw new PwdKeyError(0x0001, `导出不完整（${offset}/${total} 字节）`);
    }
    const cipher = proto.concatBytes.apply(null, parts);

    /* 3. 换锁：只经手 32 字节的 K_export，不碰条目明文 */
    const content = await exp.fromDevice(wrapped, dnonce, cipher, this.kek, masterPwd);

    /* 4. 只返回内容，保存/分享交给 UI 层。
     *    原因：Share.share() 在某些 ROM 上可能长时间不回调，
     *    如果把它放在这里，调用方的"等待确认"浮层会一直关不掉。 */
    return content;
  }

  /* ---------------- 恢复码（3-of-5） ---------------- */

  /**
   * 生成 5 份恢复码。**首次调用会触发 DEK 迁移**（把所有条目重新加密一次）。
   * 需要在设备上按 BOOT 确认。
   *
   * @returns {Promise<Array<{idx:number, code:string}>>} 按序号排好的 5 份
   */
  async recoverySetup() {
    this._requireUnlocked();
    if (!this.kek) {
      throw new PwdKeyError(0x4002, '会话已失效，请重新解锁');
    }

    await this._send(OP.RECOVERY_SETUP, proto.concatBytes());
    const f = await this._waitFrame(OP.RECOVERY_SETUP, { timeout: 60000 });
    this._checkResult(f);

    const idxs = f.tlvs[TAG.REC_IDX] || [];
    const datas = f.tlvs[TAG.REC_DATA] || [];
    const out = [];
    for (let i = 0; i < idxs.length && i < datas.length; i++) {
      out.push({ idx: idxs[i][0], code: b32Encode(datas[i]) });
    }
    if (out.length !== 5) {
      throw new PwdKeyError(0x0001, '设备返回的恢复码数量不对：' + out.length);
    }
    return out.sort((a, b) => a.idx - b.idx);
  }

  /**
   * 用 3 份恢复码重设主密码。**不需要旧主密码**，但需要在设备上按 BOOT。
   * 数据不会被清除 —— 设备只是用新 KEK 重新包裹 DEK。
   *
   * @param {Array<{idx:number, code:string}>} codes
   * @param {string} newPwd 新主密码
   */
  async recoveryRestore(codes, newPwd) {
    if (!this.info || !this.info.salt || !this.info.iter) {
      throw new PwdKeyError(0x0001, '请先连接设备并读取设备信息');
    }
    if (!Array.isArray(codes) || codes.length < 3) {
      throw new PwdKeyError(0x0001, '至少需要 3 份恢复码');
    }

    const parts = [];
    for (const c of codes) {
      const data = b32Decode(c.code, 16);
      parts.push(tlv(TAG.REC_IDX, new Uint8Array([c.idx & 0xFF])));
      parts.push(tlv(TAG.REC_DATA, data));
    }

    /* 新主密码 → 新 KEK（salt/iter 沿用设备当前值） */
    const pwdBytes = crypto.utf8ToBytes(String(newPwd));
    const kek = await crypto.deriveKekAsync(pwdBytes, this.info.salt, this.info.iter);
    parts.push(tlv(TAG.KEK_BLOB, kek));

    try {
      await this._send(OP.RECOVERY_RESTORE, proto.concatBytes.apply(null, parts));
      const f = await this._waitFrame(OP.RECOVERY_RESTORE, { timeout: 90000 });
      this._checkResult(f);
    } finally {
      if (kek && kek.fill) { kek.fill(0); }
    }
    return true;
  }

  async deleteEntry(id) {
    this._requireUnlocked();
    await this._send(OP.PWD_DELETE, tlv(TAG.ENTRY_ID, proto.asciiToBytes(id)));
    const f = await this._waitFrame(OP.PWD_DELETE, { timeout: 10000 });
    this._checkResult(f);
    await this.refreshInfo();
  }

  async getEntryName(id) {
    this._requireUnlocked();
    await this._send(OP.ATTR_GET, tlv(TAG.ENTRY_ID, proto.asciiToBytes(id)));
    const f = await this._waitFrame(OP.ATTR_GET, { timeout: 10000 });
    this._checkResult(f);
    const nm = proto.tlvLast(f.tlvs, TAG.NAME);
    return nm ? utf8Decode(nm) : '';
  }

  /* ---------------- 已连接的电脑（命名与管理） ---------------- */

  /** 6 字节 MAC -> "A1:B2:C3:D4:E5:F6" */
  static macText(bytes) {
    return proto.bytesToHex(bytes).toUpperCase().replace(/(.{2})(?=.)/g, '$1:');
  }

  /** 按 UTF-8 字节数截断，避免在 3 字节汉字中间断开产生乱码 */
  static fitUtf8(str, maxBytes) {
    const b = crypto.utf8ToBytes(str || '');
    if (b.length <= maxBytes) { return String(str || ''); }
    let cut = maxBytes;
    /* 回退到完整字符边界：0x10xxxxxx/0x0xxxxxxx 是首字节，其余为续字节 */
    while (cut > 0 && (b[cut] & 0xC0) === 0x80) { cut--; }
    return utf8Decode(b.subarray(0, cut));
  }

  /**
   * 读取设备的主机登记表（自动翻页）。
   * 返回 [{ addr, mac, name, flags, online, hid, userNamed }]，在线的排前面。
   */
  async listHosts() {
    this._requireUnlocked();
    const out = [];
    let total = 0;
    for (let page = 0; page < 16; page++) {
      const body = page === 0
        ? new Uint8Array(0)
        : tlv(TAG.PAGE_INDEX, new Uint8Array([page]));
      await this._send(OP.HOST_LIST, body);
      const f = await this._waitFrame(OP.HOST_LIST, { timeout: 10000 });
      if (proto.hasResult(f.tlvs)) { this._checkResult(f); }

      const addrs = f.tlvs[TAG.HOST_ADDR] || [];
      const names = f.tlvs[TAG.HOST_NAME] || [];
      const flags = f.tlvs[TAG.HOST_FLAGS] || [];
      const cnt = f.tlvs[TAG.HOST_COUNT];
      if (cnt && cnt.length) { total = cnt[cnt.length - 1][0]; }

      for (let i = 0; i < addrs.length; i++) {
        const fl = flags[i] ? flags[i][0] : 0;
        out.push({
          addr: addrs[i],
          mac: PwdKey.macText(addrs[i]),
          name: names[i] ? utf8Decode(names[i]) : PwdKey.macText(addrs[i]),
          flags: fl,
          online: !!(fl & proto.HOST_FLAG.ONLINE),
          hid: !!(fl & proto.HOST_FLAG.HID_NOW),
          userNamed: !!(fl & proto.HOST_FLAG.USER_NAMED),
          isUsb: !!(fl & proto.HOST_FLAG.IS_USB),
        });
      }
      if (addrs.length === 0 || out.length >= total) { break; }
    }
    return out.sort((a, b) => (b.online - a.online) || a.name.localeCompare(b.name));
  }

  /** 给某台电脑起名。name 为空字符串 = 清除自定义名，恢复 MAC 兜底名。 */
  async renameHost(addrBytes, name) {
    this._requireUnlocked();
    const nm = PwdKey.fitUtf8(String(name || '').trim(), 31);
    const parts = [tlv(TAG.HOST_ADDR, addrBytes)];
    if (nm) { parts.push(tlv(TAG.HOST_NAME, crypto.utf8ToBytes(nm))); }
    await this._send(OP.HOST_RENAME, proto.concatBytes(...parts));
    const f = await this._waitFrame(OP.HOST_RENAME, { timeout: 10000 });
    this._checkResult(f);
  }

  /** 断开某一台连接（不能断开承载本管理连接的那一台）。 */
  async disconnectHost(addrBytes) {
    this._requireUnlocked();
    await this._send(OP.HOST_DISCONNECT, tlv(TAG.HOST_ADDR, addrBytes));
    const f = await this._waitFrame(OP.HOST_DISCONNECT, { timeout: 10000 });
    this._checkResult(f);
  }

  /* ---------------- 输出密码（核心） ---------------- */

  /**
   * 输出条目到电脑。
   * @param {string} id 条目 ID
   * @param {{onWaiting?:(timeoutMs:number)=>void,
   *          onPickTarget?:(cands:Array<{addr:Uint8Array,mac:string,name:string}>)
   *                        =>Promise<Uint8Array|null>}} cb
   *   onPickTarget: 设备存在多条 HID 链路（多台电脑在线）时回调，入参为候选列表
   *   （已带设备已知的名称）；返回选中的 MAC，或 null 表示取消。
   * @returns {Promise<void>} 失败时抛出 PwdKeyError（含 0x3005 等特殊上下文）
   */
  async typeEntry(id, cb) {
    this._requireUnlocked();
    const { onWaiting, onPickTarget } = cb || {};
    let targetAddr = null;   // 用户选择的输出目标（peer identity address）
    let pickedOnce = false;  // 已选过一次但仍失败 -> 不再重复弹窗

    for (let attempt = 0; attempt < 3; attempt++) {
      const parts = [
        tlv(TAG.ENTRY_ID, proto.asciiToBytes(id)),
        tlv(TAG.TIMEOUT_MS, proto.u16le(30000)),
      ];
      if (targetAddr) {
        parts.push(tlv(TAG.HOST_ADDR, targetAddr));
      }
      await this._send(OP.PWD_TYPE, proto.concatBytes(...parts));

      const half = await this._waitFrame(OP.PWD_TYPE, { timeout: 10000 });

      if (proto.hasResult(half.tlvs)) {
        const rc = proto.resultCode(half.tlvs);
        if (rc === 0x3002 && onPickTarget && !pickedOnce) {
          /* 设备回报"目标不明确"，并附上候选 MAC（连同它已知的名称与通道标记） */
          const addrs = half.tlvs[TAG.HOST_ADDR] || [];
          const names = half.tlvs[TAG.HOST_NAME] || [];
          const hflags = half.tlvs[TAG.HOST_FLAGS] || [];
          if (!addrs.length) { this._checkResult(half); }
          const cands = addrs.map((a, i) => {
            const fl = hflags[i] ? hflags[i][0] : 0;
            return {
              addr: a,
              mac: PwdKey.macText(a),
              name: names[i] ? utf8Decode(names[i]) : PwdKey.macText(a),
              isUsb: !!(fl & proto.HOST_FLAG.IS_USB),
              online: !!(fl & proto.HOST_FLAG.ONLINE),
            };
          });
          const chosen = await onPickTarget(cands);
          if (!chosen) {
            throw new PwdKeyError(0x3004, '已取消选择目标');
          }
          targetAddr = chosen;
          pickedOnce = true;
          continue;   // 带目标重发
        }
        this._checkResult(half);
      }

      const tmo = proto.tlvLast(half.tlvs, TAG.TIMEOUT_MS);
      const timeoutMs = tmo ? proto.readU16le(tmo, 0) : 30000;
      if (onWaiting) { onWaiting(timeoutMs); }
      const fin = await this._waitFrame(OP.PWD_TYPE, {
        wantResult: true, timeout: timeoutMs + 20000,
      });
      this._checkResult(fin);
      return;
    }
    throw new PwdKeyError(0x3002, '选择目标后仍无法输出，请稍后重试');
  }

  /* ---------------- 配对模式 ---------------- */

  async enterPairing(cb) {
    this._requireUnlocked();
    const { onWaiting } = cb || {};
    await this._send(OP.ENTER_PAIRING, new Uint8Array(0));
    const half = await this._waitFrame(OP.ENTER_PAIRING, { timeout: 10000 });
    if (proto.hasResult(half.tlvs)) { this._checkResult(half); }
    if (onWaiting) { onWaiting(); }
    const fin = await this._waitFrame(OP.ENTER_PAIRING, { wantResult: true, timeout: 65000 });
    this._checkResult(fin);
  }
}

/* 设备名（UTF-8 解码） */
function utf8Decode(bytes) {
  let s = '';
  let i = 0;
  while (i < bytes.length) {
    const b = bytes[i];
    if (b < 0x80) { s += String.fromCharCode(b); i += 1; }
    else if (b < 0xE0) {
      s += String.fromCharCode(((b & 0x1F) << 6) | (bytes[i + 1] & 0x3F)); i += 2;
    } else if (b < 0xF0) {
      s += String.fromCharCode(((b & 0x0F) << 12) | ((bytes[i + 1] & 0x3F) << 6) |
                               (bytes[i + 2] & 0x3F)); i += 3;
    } else {
      const cp = ((b & 0x07) << 18) | ((bytes[i + 1] & 0x3F) << 12) |
                 ((bytes[i + 2] & 0x3F) << 6) | (bytes[i + 3] & 0x3F);
      const c = cp - 0x10000;
      s += String.fromCharCode(0xD800 + (c >> 10), 0xDC00 + (c & 0x3FF));
      i += 4;
    }
  }
  return s;
}

module.exports = {
  pwdkey: new PwdKey(),
  PwdKeyError,
  macText: PwdKey.macText,
  fitUtf8: PwdKey.fitUtf8,
};
