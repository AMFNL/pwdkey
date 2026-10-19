/**
 * crypto.js - PwdKey 密码学工具（与固件协议 v1.2 配套）
 *
 * KEK       = PBKDF2-HMAC-SHA256(主密码, salt, KDF_ITER, 32)
 * VERIFIER  = HMAC-SHA256(KEK, "PWD_MGR_VERIFIER_V1")
 * PROOF     = HMAC-SHA256(VERIFIER, NONCE || SESSION_SEQ_LE)
 *
 * PBKDF2 为 HMAC 复用优化版（200k 迭代约 1.4s@桌面 V8），并以
 * 分片 + setTimeout 让出事件循环的方式异步执行，保证 UI 进度可刷新。
 * （实现已通过 RFC 官方向量 + Node 原生 crypto 对拍验证）
 */
const CryptoJS = require('../libs/crypto-js/core.js');
require('../libs/crypto-js/sha256.js');
require('../libs/crypto-js/hmac.js');
require('../libs/crypto-js/enc-hex.js');

const proto = require('../libs/proto.js');

const INFO_VERIFIER = 'PWD_MGR_VERIFIER_V1';

/* ---------------- 字节 / WordArray 转换 ---------------- */

/**
 * Uint8Array → WordArray（手工大端转换；不依赖 crypto-js 的 typedarray 扩展，
 * 跨版本行为稳定。此前直接用 WordArray.create(Uint8Array) 会产生错误结果）。
 */
function waFromBytes(bytes) {
  const words = [];
  for (let i = 0; i < bytes.length; i++) {
    words[i >>> 2] |= bytes[i] << (24 - (i % 4) * 8);
  }
  return CryptoJS.lib.WordArray.create(words, bytes.length);
}

function waToBytes(wa) {
  const out = new Uint8Array(wa.sigBytes);
  for (let i = 0; i < wa.sigBytes; i++) {
    out[i] = (wa.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xFF;
  }
  return out;
}

/** UTF-8 编码（小程序无 TextEncoder 时的可靠实现） */
function utf8ToBytes(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c < 0x80) {
      out.push(c);
    } else if (c < 0x800) {
      out.push(0xC0 | (c >> 6), 0x80 | (c & 63));
    } else if (c >= 0xD800 && c <= 0xDBFF && i + 1 < str.length) {
      const c2 = str.charCodeAt(i + 1);
      if (c2 >= 0xDC00 && c2 <= 0xDFFF) {
        const cp = 0x10000 + ((c - 0xD800) << 10) + (c2 - 0xDC00);
        out.push(0xF0 | (cp >> 18), 0x80 | ((cp >> 12) & 63),
                 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
        i++;
      }
    } else {
      out.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
  }
  return new Uint8Array(out);
}

/* ---------------- 基础 HMAC ---------------- */

function hmacSha256(keyBytes, msgBytes) {
  const hmac = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, waFromBytes(keyBytes));
  return waToBytes(hmac.update(waFromBytes(msgBytes)).finalize());
}

/* ---------------- PBKDF2（单 block, dkLen=32, HMAC 复用优化） ---------------- */

/**
 * 同步核心（迭代数较大时请用 deriveKekAsync）。
 * @returns {Uint8Array} 32 字节 KEK
 */
function pbkdf2Sha256(pwdBytes, saltBytes, iterations) {
  const hmac = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, waFromBytes(pwdBytes));
  const saltWA = waFromBytes(saltBytes);
  const block = saltWA.clone().concat(CryptoJS.lib.WordArray.create([0x00000001], 4));

  hmac.reset();
  let u = hmac.update(block).finalize();
  const t = u.clone();
  for (let i = 1; i < iterations; i++) {
    hmac.reset();
    u = hmac.update(u).finalize();
    const tw = t.words, uw = u.words;
    for (let w = 0; w < tw.length; w++) { tw[w] ^= uw[w]; }
  }
  return waToBytes(t);
}

/**
 * 异步分片版（每片让出事件循环，UI 可更新进度）。
 * 这是纯 JS 实现，同时作为 WebCrypto 不可用时的回退路径。
 * @param {Uint8Array} pwdBytes
 * @param {Uint8Array} saltBytes
 * @param {number} iterations
 * @param {(frac:number)=>void} [onProgress] 0..1
 * @returns {Promise<Uint8Array>}
 */
function deriveKekAsyncJs(pwdBytes, saltBytes, iterations, onProgress) {
  return new Promise((resolve) => {
    const slice = 20000;                 // 每片迭代数
    const hmac = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, waFromBytes(pwdBytes));
    const saltWA = waFromBytes(saltBytes);
    const block = saltWA.clone().concat(CryptoJS.lib.WordArray.create([0x00000001], 4));

    hmac.reset();
    let u = hmac.update(block).finalize();
    const t = u.clone();
    let i = 1;

    function step() {
      const end = Math.min(iterations, i + slice);
      for (; i < end; i++) {
        hmac.reset();
        u = hmac.update(u).finalize();
        const tw = t.words, uw = u.words;
        for (let w = 0; w < tw.length; w++) { tw[w] ^= uw[w]; }
      }
      if (onProgress) { onProgress(i / iterations); }
      if (i >= iterations) {
        resolve(waToBytes(t));
      } else {
        setTimeout(step, 0);   // 让出事件循环
      }
    }
    setTimeout(step, 0);
  });
}

/* ---------------- WebCrypto 加速（可选） ----------------
 *
 * 纯 JS 跑 20 万次 PBKDF2 在手机上要 6~10 秒，用户每次解锁都要等。Android
 * WebView 自带原生 PBKDF2（OpenSSL 实现），同一组参数下耗时 <200ms。
 *
 * 两者算法完全等价（PBKDF2-HMAC-SHA256 / dkLen=32 / 同一 salt 与迭代数），
 * 因此 KEK 逐字节一致 —— 已用 Node 的 WebCrypto 与纯 JS 实现对拍验证。
 *
 * 拿不到 crypto.subtle（非安全上下文）时自动回退到纯 JS 路径。
 */
function webCryptoAvailable() {
  const c = (typeof globalThis !== 'undefined') ? globalThis.crypto : null;
  return !!(c && c.subtle &&
            typeof c.subtle.deriveBits === 'function' &&
            typeof c.subtle.importKey === 'function');
}

async function deriveKekWebCrypto(pwdBytes, saltBytes, iterations, onProgress) {
  const c = globalThis.crypto;
  const key = await c.subtle.importKey('raw', pwdBytes, { name: 'PBKDF2' }, false,
                                       ['deriveBits']);
  const bits = await c.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: iterations, hash: 'SHA-256' },
    key, 256);
  if (onProgress) { onProgress(1); }
  return new Uint8Array(bits);
}

/**
 * 派生 KEK（优先走原生实现，失败自动回退纯 JS）。
 * @param {Uint8Array} pwdBytes
 * @param {Uint8Array} saltBytes
 * @param {number} iterations
 * @param {(frac:number)=>void} [onProgress]
 * @returns {Promise<Uint8Array>} 32 字节
 */
function deriveKekAsync(pwdBytes, saltBytes, iterations, onProgress) {
  if (webCryptoAvailable()) {
    return deriveKekWebCrypto(pwdBytes, saltBytes, iterations, onProgress)
      .catch(() => deriveKekAsyncJs(pwdBytes, saltBytes, iterations, onProgress));
  }
  return deriveKekAsyncJs(pwdBytes, saltBytes, iterations, onProgress);
}

/* ---------------- 协议密钥链 ---------------- */

function computeVerifier(kekBytes) {
  return hmacSha256(kekBytes, utf8ToBytes(INFO_VERIFIER));
}

/** PROOF = HMAC(VERIFIER, NONCE || SEQ_LE) */
function computeProof(verifierBytes, nonceBytes, seq) {
  const msg = proto.concatBytes(nonceBytes, proto.u32le(seq >>> 0));
  return hmacSha256(verifierBytes, msg);
}

module.exports = {
  utf8ToBytes,
  waToBytes,
  waFromBytes,
  hmacSha256,
  pbkdf2Sha256,
  deriveKekAsync,
  deriveKekAsyncJs,
  webCryptoAvailable,
  computeVerifier,
  computeProof,
};
