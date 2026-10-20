/**
 * biowrap.js - 生物认证包裹层（JS 侧门面）
 *
 * 与原生插件 BiometricWrap 一一对应，负责：
 *   - 字节 / Base64 转换
 *   - 把原生的错误码归一成 BioError(code)
 *   - 给测试留一个注入点（setMock）
 *
 * 安全链路（两层，缺一不可）：
 *
 *   指纹/面容  ──[K_bio, TEE 内不可导出]──▶  envelope（含 salt + PIN 密文）
 *                                              │
 *                          6 位 PIN ──[PBKDF2]─┘
 *                                              ▼
 *                                             KEK ──▶ 设备 AUTH_VERIFY
 *
 * 关键点：envelope 必须"先过生物认证"才能拿到，所以没指纹时攻击者连
 * 可以离线爆破 PIN 的那段密文都没有。反过来，PIN 只错时不需要重按指纹，
 * 但试错次数用尽会丢弃 envelope、强制重新生物认证。
 *
 * 注意：PIN 只有 20 bit 熵，本身撑不住离线爆破。本层真正的硬屏障是 TEE
 * 内的 K_bio，PIN 是过了这道门之后的减速带 + 抗胁迫（生物特征可被强制，
 * 秘密不能）。
 */

const PIN_ITER = 600000;          // PBKDF2-HMAC-SHA256，OWASP 2023 建议值
const MAX_PIN_TRIES = 5;

let mockPlugin = null;

/* 系统生物弹窗正在显示时 +1：main.js 用它抑制"切后台自动锁定"，
   避免某些 ROM 在指纹浮层出现时让 Activity 短暂 onStop，把自己刚解锁的会话锁掉。 */
let prompting = 0;

function isPrompting() {
  return prompting > 0;
}

class BioError extends Error {
  constructor(code, message) {
    super(message || code);
    this.code = code || 'BIO_ERROR';
  }
}

function plugin() {
  if (mockPlugin) { return mockPlugin; }
  const cap = typeof window !== 'undefined' ? window.Capacitor : null;
  if (cap && cap.Plugins && cap.Plugins.BiometricWrap) {
    return cap.Plugins.BiometricWrap;
  }
  return null;
}

/** 仅用于测试：注入假的原生插件 */
function setMock(p) {
  mockPlugin = p;
}

function available() {
  return !!plugin();
}

/* ---------------- Base64 ---------------- */

function b64encode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) { s += String.fromCharCode(bytes[i]); }
  return btoa(s);
}

function b64decode(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
  return out;
}

/* ---------------- 调用封装 ---------------- */

function wrapError(e) {
  if (e instanceof BioError) { return e; }
  const code = (e && e.code) || 'BIO_ERROR';
  const msg = (e && e.message) || String(e);
  return new BioError(code, msg);
}

async function call(method, args) {
  const p = plugin();
  if (!p) { throw new BioError('UNAVAILABLE', '当前环境不支持生物认证'); }
  try {
    return await p[method](args || {});
  } catch (e) {
    throw wrapError(e);
  }
}

/* ---------------- 对外接口 ---------------- */

/**
 * @returns {Promise<{available:boolean, reason:number, reasonText:string,
 *                    hasEnroll:boolean, supported:boolean}>}
 */
async function status() {
  const p = plugin();
  if (!p) {
    return {
      available: false, reason: -1, reasonText: '当前环境不支持生物认证',
      hasEnroll: false, supported: false,
    };
  }
  try {
    const r = await p.status();
    return {
      available: !!r.available,
      reason: r.reason,
      reasonText: r.reasonText || '',
      hasEnroll: !!r.hasEnroll,
      supported: true,
    };
  } catch (e) {
    return {
      available: false, reason: -2, reasonText: (e && e.message) || '状态读取失败',
      hasEnroll: false, supported: true,
    };
  }
}

/**
 * 开启生物解锁：把当前 KEK 用 PIN 包一层，再交给原生用生物密钥包外层。
 * 会弹一次系统生物认证框。
 *
 * @param {{kek:Uint8Array, pin:string, deviceSalt:Uint8Array}} opts
 */
async function enroll(opts) {
  const o = opts || {};
  if (!o.kek || o.kek.length !== 32) { throw new BioError('BAD_ARGS', 'KEK 长度不对'); }
  if (!o.deviceSalt || o.deviceSalt.length !== 16) {
    throw new BioError('BAD_ARGS', '设备 salt 缺失');
  }
  if (!/^\d{6}$/.test(o.pin || '')) { throw new BioError('BAD_ARGS', 'PIN 必须是 6 位数字'); }

  prompting++;
  try {
    await call('enroll', {
      kekB64: b64encode(o.kek),
      pin: o.pin,
      pinIter: o.pinIter || PIN_ITER,
      deviceSaltB64: b64encode(o.deviceSalt),
    });
  } finally {
    prompting--;
  }
  return true;
}

/** 只做生物认证，拿回内层信封（还没解 PIN）。不弹 UI 之外的任何东西。 */
async function unwrap() {
  prompting++;
  try {
    const r = await call('unwrap');
    return b64decode(r.envelopeB64);
  } finally {
    prompting--;
  }
}

/**
 * 用 PIN 解信封 → KEK。
 * 纯计算，不触发认证；PIN 错误抛 BioError('PIN_INVALID')。
 *
 * @returns {Promise<{kek:Uint8Array, deviceSalt:Uint8Array, pinIter:number}>}
 */
async function open(envelope, pin) {
  const r = await call('open', {
    envelopeB64: b64encode(envelope),
    pin: pin,
  });
  return {
    kek: b64decode(r.kekB64),
    deviceSalt: b64decode(r.deviceSaltB64),
    pinIter: r.pinIter,
  };
}

async function hasEnroll() {
  const st = await status();
  return !!st.hasEnroll;
}

async function clear() {
  try {
    await call('clear');
  } catch (e) {
    /* 原生不可用时也要允许"关闭"，本地标记交给调用方处理 */
    if (e.code === 'UNAVAILABLE') { return; }
    throw e;
  }
}

module.exports = {
  PIN_ITER,
  MAX_PIN_TRIES,
  BioError,
  setMock,
  available,
  isPrompting,
  status,
  enroll,
  unwrap,
  open,
  hasEnroll,
  clear,
  b64encode,
  b64decode,
};
