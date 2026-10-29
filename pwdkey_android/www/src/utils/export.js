/**
 * export.js - 加密导出 / 导入（.amfnl，格式 v2）
 *
 * **核心原则：条目明文永不出设备。**
 *
 * 设备侧（固件 store_export_build）：
 *   K_export = 随机 32B（一次性）
 *   data     = AES-GCM(K_export, 条目明文)     ← 明文只存在于芯片内部
 *   wrapped  = AES-GCM(KEK, K_export)          ← 用当前会话的 KEK 锁住它
 *
 * App 侧（本文件）：
 *   K_export = 解(wrapped, KEK)                 ← 只接触这 32 字节
 *   K_new    = PBKDF2(主密码, 新 salt, 200k)
 *   wrapped2 = AES-GCM(K_new, K_export)         ← 换个锁重新锁上
 *   写文件：{ salt, wrapped2, dataNonce, data }  ← data 原样带走，一个字节都不解
 *
 * 所以 BLE 上跑的全是密文，App 内存里也没有任何密码。
 *
 * 关于后缀 .amfnl：它只是身份标识 + 防误双击，**不能防暴力破解**
 * （攻击者改后缀或直接读字节即可）。真正的防护是 AES-256-GCM + 200k 次 PBKDF2。
 */

const { deriveKekAsync, utf8ToBytes } = require('./crypto.js');

const MAGIC = 'AMFNL1';
const FORMAT_VERSION = 2;
const EXPORT_ITER = 200000;      /* OWASP 2023 对 PBKDF2-HMAC-SHA256 的建议下限 */
const SALT_LEN = 16;
const MIN_PWD_LEN = 12;          /* 导出包可被离线爆破，弱密码等于没加密 */

/* 必须与固件 store_export_build 里的 aad[] 完全一致，否则解不开 */
const AAD = utf8ToBytes('PWDKEY-EXPORT-V1');

/* ---------------- 编解码 ---------------- */

function b64(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += String.fromCharCode(bytes[i]);
  }
  return btoa(s);
}

function unb64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    out[i] = s.charCodeAt(i);
  }
  return out;
}

function utf8Decode(bytes) {
  if (typeof TextDecoder !== 'undefined') {
    return new TextDecoder('utf-8').decode(bytes);
  }
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += String.fromCharCode(bytes[i]);
  }
  return s;
}

function subtle() {
  const c = typeof crypto !== 'undefined' ? crypto : null;
  if (!c || !c.subtle || typeof c.subtle.importKey !== 'function') {
    return null;
  }
  return c.subtle;
}

function randomBytes(n) {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

/** 主密码强度：导出包可离线爆破，太弱等于没加密 */
function checkPasswordStrength(pwd) {
  const s = String(pwd || '');
  if (s.length < MIN_PWD_LEN) {
    return { ok: false, reason: `主密码至少 ${MIN_PWD_LEN} 位才能导出（当前 ${s.length} 位）` };
  }
  if (!/[A-Za-z]/.test(s) || !/[0-9]/.test(s)) {
    return { ok: false, reason: '主密码需同时包含字母和数字' };
  }
  return { ok: true };
}

/** 比较两个 Uint8Array 是否相同（用于校验 AAD 之外的一致性） */
function sameBytes(a, b) {
  if (!a || !b || a.length !== b.length) { return false; }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) { return false; }
  }
  return true;
}

/* ---------------- 设备密文 → 文件内容 ---------------- */

/**
 * 把设备传来的三段密文换成"主密码可解"的文件内容。
 * **全程不接触条目明文。**
 *
 * @param {Uint8Array} wrapped    60B = nonce(12) + ct(32) + tag(16)
 * @param {Uint8Array} dataNonce  12B
 * @param {Uint8Array} dataCipher 密文 + tag（固件已在末尾拼好）
 * @param {Uint8Array} kek        当前会话 KEK（32B）
 * @param {string}     masterPwd
 * @returns {Promise<string>}
 */
async function fromDevice(wrapped, dataNonce, dataCipher, kek, masterPwd) {
  const st = subtle();
  if (!st) {
    throw new Error('当前环境不支持 WebCrypto，无法安全导出');
  }
  const strength = checkPasswordStrength(masterPwd);
  if (!strength.ok) {
    throw new Error(strength.reason);
  }
  if (!wrapped || wrapped.length !== 60) {
    throw new Error('设备返回的导出头长度异常');
  }
  if (!kek || kek.length !== 32) {
    throw new Error('会话密钥无效，请重新解锁');
  }

  /* 1. 用 KEK 解出一次性数据密钥 K_export */
  const wrapNonce = wrapped.slice(0, 12);
  const wrapData = wrapped.slice(12);          /* ct(32) + tag(16) */
  const kekKey = await st.importKey('raw', kek, 'AES-GCM', false, ['decrypt']);
  let kexp;
  try {
    kexp = await st.decrypt(
      { name: 'AES-GCM', iv: wrapNonce, tagLength: 128, additionalData: AAD },
      kekKey, wrapData
    );
  } catch (e) {
    throw new Error('无法解开设备给出的导出密钥（会话可能已失效，请重新解锁后重试）');
  }

  /* 2. 主密码 + 全新 salt → K_new（跨设备可解的关键：不依赖 device_salt） */
  const salt = randomBytes(SALT_LEN);
  const knew = await deriveKekAsync(utf8ToBytes(String(masterPwd)), salt, EXPORT_ITER);
  const knewKey = await st.importKey('raw', knew, 'AES-GCM', false, ['encrypt']);

  /* 3. 换个锁重新锁上 K_export */
  const newWrapNonce = randomBytes(12);
  const wrappedNew = await st.encrypt(
    { name: 'AES-GCM', iv: newWrapNonce, tagLength: 128, additionalData: AAD },
    knewKey, kexp
  );

  if (knew && knew.fill) { knew.fill(0); }
  if (kexp && kexp.fill) { kexp.fill(0); }

  return JSON.stringify({
    magic: MAGIC,
    v: FORMAT_VERSION,
    kdf: 'PBKDF2-HMAC-SHA256',
    iter: EXPORT_ITER,
    salt: b64(salt),
    wrapNonce: b64(newWrapNonce),
    wrapped: b64(new Uint8Array(wrappedNew)),
    dataNonce: b64(dataNonce),
    data: b64(dataCipher),
    exportedAt: new Date().toISOString(),
  });
}

/* ---------------- 文件内容 → 条目列表（仅导入用）---------------- */

/**
 * 解开 .amfnl，返回条目明文。**只有导入时才需要**，导出链路不调用它。
 * @returns {Promise<{entries:Array<{name,secret}>, exportedAt:string}>}
 */
async function openPackage(content, masterPwd) {
  const st = subtle();
  if (!st) {
    throw new Error('当前环境不支持 WebCrypto，无法解密');
  }

  let obj;
  try {
    obj = JSON.parse(content);
  } catch (e) {
    throw new Error('文件格式无法识别（不是 PwdKey 备份）');
  }
  if (!obj || obj.magic !== MAGIC) {
    throw new Error('不是 PwdKey 备份文件（魔数不匹配）');
  }
  if (obj.v !== FORMAT_VERSION) {
    throw new Error('备份文件版本不支持：' + obj.v);
  }

  const salt = unb64(obj.salt);
  const knew = await deriveKekAsync(utf8ToBytes(String(masterPwd)), salt, obj.iter || EXPORT_ITER);
  const key = await st.importKey('raw', knew, 'AES-GCM', false, ['decrypt']);

  let kexp;
  try {
    kexp = await st.decrypt(
      { name: 'AES-GCM', iv: unb64(obj.wrapNonce), tagLength: 128, additionalData: AAD },
      key, unb64(obj.wrapped)
    );
  } catch (e) {
    if (knew && knew.fill) { knew.fill(0); }
    throw new Error('密码错误，或文件已损坏');
  }
  if (knew && knew.fill) { knew.fill(0); }

  const kexpKey = await st.importKey('raw', kexp, 'AES-GCM', false, ['decrypt']);
  let plainBuf;
  try {
    plainBuf = await st.decrypt(
      { name: 'AES-GCM', iv: unb64(obj.dataNonce), tagLength: 128, additionalData: AAD },
      kexpKey, unb64(obj.data)
    );
  } catch (e) {
    throw new Error('数据解密失败，文件可能被篡改');
  }
  if (kexp && kexp.fill) { kexp.fill(0); }

  /* 二进制格式：count(2 LE) + [nameLen(1) name pwdLen(1) pwd]... */
  const bytes = new Uint8Array(plainBuf);
  const count = bytes[0] | (bytes[1] << 8);
  let off = 2;
  const entries = [];
  for (let i = 0; i < count; i++) {
    if (off >= bytes.length) { break; }
    const nl = bytes[off++];
    const name = utf8Decode(bytes.slice(off, off + nl));
    off += nl;
    if (off >= bytes.length) { break; }
    const pl = bytes[off++];
    const secret = utf8Decode(bytes.slice(off, off + pl));
    off += pl;
    entries.push({ name, secret });
  }
  return { entries, exportedAt: obj.exportedAt || '' };
}

/* ---------------- 文件读写 ---------------- */

function timestamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
}

/** 给可能卡住的系统调用套一个超时，避免整个流程挂死 */
function withTimeout(promise, ms, what) {
  return new Promise((resolve, reject) => {
    let done = false;
    const t = setTimeout(() => {
      if (done) { return; }
      done = true;
      reject(new Error(`${what}（超过 ${Math.round(ms / 1000)} 秒无响应）`));
    }, ms);
    promise.then(
      (v) => { if (!done) { done = true; clearTimeout(t); resolve(v); } },
      (e) => { if (!done) { done = true; clearTimeout(t); reject(e); } }
    );
  });
}

/**
 * 写入缓存目录并唤起系统分享，由用户决定存到哪。
 *
 * 两个超时保护（都是实测踩出来的）：
 *   写文件 —— 个别 ROM 的 Cache 目录会卡住
 *   分享面板 —— 用户切走 / 系统无响应时可能永远不回调
 * 分享超时不当作失败：文件已经生成，只是没送出去，提示用户手动处理即可。
 */
async function saveAndShare(content) {
  const { Filesystem, Directory, Encoding } = require('@capacitor/filesystem');
  const { Share } = require('@capacitor/share');

  const filename = `PwdKey-backup-${timestamp()}.amfnl`;
  await withTimeout(
    Filesystem.writeFile({
      path: filename,
      data: content,
      directory: Directory.Cache,
      encoding: Encoding.UTF8,
    }),
    15000,
    '写入备份文件失败'
  );

  const got = await Filesystem.getUri({ path: filename, directory: Directory.Cache });

  let shared = true;
  try {
    await withTimeout(
      Share.share({
        title: 'PwdKey 加密备份',
        text: '这是加密备份。只有配合你的主密码才能解开，请当作钥匙保管。',
        url: got.uri,
        dialogTitle: '保存备份文件',
      }),
      20000,
      '分享面板无响应'
    );
  } catch (e) {
    /* 分享没成功不算导出失败 —— 文件已经在缓存里了。
     * 不删缓存，让用户有机会从文件管理器再取一次。 */
    shared = false;
  }

  if (shared) {
    try {
      await Filesystem.deleteFile({ path: filename, directory: Directory.Cache });
    } catch (e) { /* 删不掉也无妨，Cache 会被系统回收 */ }
  }

  return shared ? filename : `${filename}（已生成，但分享未完成，可从文件管理器取）`;
}

module.exports = {
  MAGIC,
  FORMAT_VERSION,
  EXPORT_ITER,
  fromDevice,
  openPackage,
  saveAndShare,
  checkPasswordStrength,
  sameBytes,
};
