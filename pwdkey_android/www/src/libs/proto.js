/**
 * proto.js - PwdKey 管理协议帧/TLV 编解码（协议 v1.2）
 *
 * 帧格式: MAGIC(A5) | VER(01) | OPCODE | FLAGS | TOTAL_LEN(LE16) | TLV 数据...
 * 分片规则: 每片都带 6 字节帧头，末片 FLAGS 置 LAST(0x04)，中间片置 MORE(0x02)。
 *           默认每片 ≤ 14 字节数据（配合微信小程序单次写入 ≤20 字节的限制）。
 * 接收侧: 提供 RecvAssembler 按帧头重组（兼容任意 MTU 下的通知分片）。
 */

/* ---------------- 字节工具 ---------------- */

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += (bytes[i] + 0x100).toString(16).substr(1);
  }
  return s;
}

function concatBytes(...arrs) {
  let len = 0;
  for (const a of arrs) { len += a.length; }
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

function u16le(v) {
  return new Uint8Array([v & 0xFF, (v >> 8) & 0xFF]);
}

function u32le(v) {
  return new Uint8Array([v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF]);
}

function readU16le(b, off) {
  return b[off] | (b[off + 1] << 8);
}

function readU32le(b, off) {
  return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
}

function asciiToBytes(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) { out[i] = s.charCodeAt(i) & 0xFF; }
  return out;
}

function bytesToAscii(b) {
  let s = '';
  for (let i = 0; i < b.length; i++) { s += String.fromCharCode(b[i]); }
  return s;
}

/* ---------------- 协议常量 ---------------- */

const MAGIC = 0xA5;
const VERSION = 0x01;

const FLAG_CRITICAL = 0x01;
const FLAG_MORE = 0x02;
const FLAG_LAST = 0x04;
const FLAG_RESP = 0x08;

const OP = {
  DEVICE_INFO: 0x01,
  AUTH_START: 0x02,
  AUTH_VERIFY: 0x03,
  AUTH_LOCK: 0x04,
  AUTH_STATUS: 0x05,
  AUTH_NEW: 0x06,
  FACTORY_RESET: 0x07,
  PWD_LIST: 0x20,
  PWD_ADD: 0x21,
  PWD_UPDATE: 0x22,
  PWD_DELETE: 0x23,
  PWD_TYPE: 0x24,
  ATTR_GET: 0x25,
  PWD_EXPORT_BEGIN: 0x26,   // 开始加密导出（设备内加密，需 BOOT 确认）
  PWD_EXPORT_CHUNK: 0x27,   // 按偏移取密文块
  RECOVERY_SETUP: 0x28,     // 生成 5 份恢复码（需 BOOT 确认）
  RECOVERY_RESTORE: 0x29,   // 用 3 份恢复码重设主密码
  ENTER_PAIRING: 0x40,
  AUDIT_READ: 0x41,
  HOST_LIST: 0x42,          // 已配对/已连接的电脑列表
  HOST_RENAME: 0x43,        // 给某个 MAC 设自定义名称
  HOST_DISCONNECT: 0x44,    // 断开某一台
};

const TAG = {
  ENTRY_ID: 0x01,
  NAME: 0x02,
  SECRET: 0x03,
  NONCE: 0x04,
  PROOF: 0x05,
  SESSION_ID: 0x06,
  REQUEST_ID: 0x07,
  RESULT_CODE: 0x08,
  STATE: 0x09,
  FW_VERSION: 0x0A,
  ENTRY_COUNT: 0x0B,
  LOCK_SECONDS: 0x0C,
  AUDIT_RECORD: 0x0D,
  AUDIT_OFFSET: 0x0E,
  RECOVERY_CODE: 0x10,
  CONFIRM_TOKEN: 0x11,
  TARGET_HANDLE: 0x12,
  LAYOUT: 0x13,
  TIMEOUT_MS: 0x14,
  ERR_DETAIL: 0x16,
  PAGE_INDEX: 0x17,
  PART_INDEX: 0x18,
  SALT: 0x19,
  KDF_ITER: 0x1A,
  SESSION_SEQ: 0x1B,
  KEK_BLOB: 0x1C,
  NEW_SALT: 0x1D,
  HOST_ADDR: 0x20,          // 6 字节 BLE MAC（主机身份）
  HOST_NAME: 0x21,          // UTF-8 名称
  HOST_FLAGS: 0x22,         // 位标记
  HOST_COUNT: 0x23,         // 记录总数（分页用）
  // 加密导出
  EXPORT_WRAPPED: 0x30,     // 60B: wrap_nonce(12)+ct(32)+tag(16)
  EXPORT_NONCE: 0x31,       // 12B: data 的 GCM nonce
  EXPORT_TOTAL: 0x32,       // 4B LE: 密文总长
  EXPORT_OFFSET: 0x33,      // 4B LE: 块偏移
  EXPORT_DATA: 0x34,        // 密文块
  // 恢复码
  REC_IDX: 0x35,            // 1B: 第几份（1..5）
  REC_DATA: 0x36,           // 16B: 该份内容
};

/* HOST_FLAGS 位定义：
 * 低 3 位是持久标记，高 2 位是查询时实时状态 */
const HOST_FLAG = {
  USER_NAMED: 0x01,         // 用户自定义过名字（自动探测不得覆盖）
  IS_HID: 0x02,             // 曾作为 HID 键盘链路
  IS_USB: 0x04,             // USB 通道（有线），addr 恒为全 0
  ONLINE: 0x40,             // 当前在线
  HID_NOW: 0x80,            // 当前是活跃的 HID 链路
};

const ERR = {
  0x0000: '成功',
  0x0001: '设备内部错误',
  0x0002: '设备正忙，请稍后重试',
  0x1000: '不支持的操作',
  0x1001: '缺少字段',
  0x1002: '协议版本不符',
  0x1003: '数据格式错误',
  0x1004: '帧标识错误',
  0x1005: '分片序列错误',
  0x1006: '分片超时',
  0x1007: '数据过长',
  0x2001: '存储已满（最多 100 条）',
  0x2002: '名称过长',
  0x2003: '条目 ID 冲突',
  0x2004: '密码过长（最多 128 字符）',
  0x2005: '条目不存在',
  0x2006: '存储写入失败',
  0x2007: '密码含非 ASCII 字符',
  0x3001: '没有已配对的电脑（请先配对键盘）',
  0x3002: '检测到多台电脑在线，请只保留一台后重试',
  0x3003: '按键确认超时',
  0x3004: '操作已被取消',
  0x3005: '输出中断：电脑上可能已打出半截密码，请检查并清除',
  0x3006: '设备正在输出中',
  0x3007: '按键类型不支持',
  0x4001: '主密码错误',
  0x4002: '未认证，请先解锁',
  0x4003: '设备临时锁定中',
  0x4004: '设备已永久锁定（需恢复码重置）',
  0x4005: '会话已失效，请重新解锁',
  0x4006: '当前状态不允许此操作',
  0x4008: '主密码强度不足',
  0x4009: '恢复码错误',
  0x400A: '密钥数据缺失',
  0x400B: '认证已过期（超过 30 秒），请重新解锁',
};

function errText(code) {
  return ERR[code] || ('未知错误 0x' + code.toString(16).toUpperCase());
}

/* ---------------- 帧构建 ---------------- */

/** 单个 TLV：tag(1) | len(2, LE) | value */
function tlv(tag, value) {
  const v = value || new Uint8Array(0);
  return concatBytes(new Uint8Array([tag]), u16le(v.length), v);
}

/**
 * 将 opcode + TLV 流的分片帧序列。
 * @param {number} opcode
 * @param {Uint8Array} tlvs      完整 TLV 数据
 * @param {number} maxDataPerFrame 每片最大数据字节数（默认 14 = 20-6）
 * @returns {Uint8Array[]} 每个元素为一片（含 6 字节头）
 */
function buildFrames(opcode, tlvs, maxDataPerFrame) {
  const cap = maxDataPerFrame || 14;
  const total = tlvs.length;
  const frames = [];
  if (total <= cap) {
    const f = new Uint8Array(6 + total);
    f[0] = MAGIC; f[1] = VERSION; f[2] = opcode;
    f[3] = FLAG_LAST;
    f[4] = total & 0xFF; f[5] = (total >> 8) & 0xFF;
    f.set(tlvs, 6);
    frames.push(f);
    return frames;
  }
  let off = 0;
  while (off < total) {
    const n = Math.min(cap, total - off);
    const last = (off + n >= total);
    const f = new Uint8Array(6 + n);
    f[0] = MAGIC; f[1] = VERSION; f[2] = opcode;
    f[3] = last ? FLAG_LAST : FLAG_MORE;
    f[4] = total & 0xFF; f[5] = (total >> 8) & 0xFF;
    f.set(tlvs.subarray(off, off + n), 6);
    frames.push(f);
    off += n;
  }
  return frames;
}

/* ---------------- 帧解析 ---------------- */

/**
 * 解析完整帧 → { ver, opcode, flags, totalLen, tlvs: {tag: [Uint8Array]} }
 */
function parseFrame(buf) {
  if (!buf || buf.length < 6 || buf[0] !== MAGIC) { return null; }
  const opcode = buf[2];
  const flags = buf[3];
  const totalLen = readU16le(buf, 4);
  const payload = buf.subarray(6, 6 + totalLen);
  return { ver: buf[1], opcode, flags, totalLen, tlvs: parseTLVs(payload) };
}

function parseTLVs(payload) {
  const out = {};
  let i = 0;
  while (i + 3 <= payload.length) {
    const tag = payload[i];
    const len = readU16le(payload, i + 1);
    if (i + 3 + len > payload.length) { break; }
    const val = payload.subarray(i + 3, i + 3 + len);
    if (!out[tag]) { out[tag] = []; }
    out[tag].push(val);
    i += 3 + len;
  }
  return out;
}

/** 取 TLV 最后一个值（辅助） */
function tlvLast(tlvs, tag) {
  const arr = tlvs[tag];
  return (arr && arr.length) ? arr[arr.length - 1] : null;
}

function hasResult(tlvs) {
  return !!tlvs[TAG.RESULT_CODE];
}

function resultCode(tlvs) {
  const v = tlvLast(tlvs, TAG.RESULT_CODE);
  return v ? readU16le(v, 0) : 0xFFFF;
}

/* ---------------- 接收重组器 ---------------- */

class RecvAssembler {
  constructor() {
    this.buf = new Uint8Array(0);
  }

  /**
   * 推入一段接收数据，返回本次能拼出的所有完整帧（Uint8Array[]）。
   * 数据流语义：设备的一个响应帧（6 字节头 + payload）可能被 ATT 层分成
   * 多个 ≤MTU-3 的块到达——小块推入，本类按帧头重组。
   */
  push(data) {
    this.buf = concatBytes(this.buf, data);
    const frames = [];
    for (;;) {
      // 丢弃帧头之前的垃圾字节
      let start = -1;
      for (let i = 0; i < this.buf.length; i++) {
        if (this.buf[i] === MAGIC) { start = i; break; }
      }
      if (start < 0) { this.buf = new Uint8Array(0); break; }
      if (start > 0) { this.buf = this.buf.subarray(start); }

      if (this.buf.length < 6) { break; }
      const totalLen = readU16le(this.buf, 4);
      if (totalLen > 1024) {
        // 数据中出现的伪帧头：跳过本字节重新同步
        this.buf = this.buf.subarray(1);
        continue;
      }
      const frameLen = 6 + totalLen;
      if (this.buf.length < frameLen) { break; }
      frames.push(this.buf.subarray(0, frameLen));
      this.buf = this.buf.subarray(frameLen);
    }
    return frames;
  }
}

module.exports = {
  // 工具
  hexToBytes, bytesToHex, concatBytes, u16le, u32le, readU16le, readU32le,
  asciiToBytes, bytesToAscii,
  // 常量
  MAGIC, VERSION, FLAG_CRITICAL, FLAG_MORE, FLAG_LAST, FLAG_RESP, OP, TAG, ERR,
  HOST_FLAG, errText,
  // 协议
  tlv, buildFrames, parseFrame, parseTLVs, tlvLast, hasResult, resultCode,
  RecvAssembler,
};
