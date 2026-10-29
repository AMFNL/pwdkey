/* test_export.js - 加密导出 v2 的端到端测试
 *
 * 模拟设备侧（固件 store_export_build）：
 *   K_export = 随机 32B
 *   data     = AES-GCM(K_export, 二进制条目)
 *   wrapped  = AES-GCM(KEK, K_export)
 * 再用 App 的 fromDevice 换锁，最后用 openPackage 解回，验证条目一致。
 *
 * 这条链路验证了除固件实现之外的全部逻辑。
 */
globalThis.crypto = require('node:crypto').webcrypto;
if (typeof globalThis.btoa === 'undefined') {
  globalThis.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
  globalThis.atob = (s) => Buffer.from(s, 'base64').toString('binary');
}

const exp = require('../www/src/utils/export.js');

const AAD = Buffer.from('PWDKEY-EXPORT-V1');

let pass = 0, fail = 0;
function ok(n) { console.log('  PASS: ' + n); pass++; }
function bad(n, w) { console.log('  FAIL: ' + n + (w ? ' — ' + w : '')); fail++; }

function rnd(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

async function aesEnc(keyBytes, nonce, plain) {
  const k = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const out = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128, additionalData: AAD }, k, plain);
  return new Uint8Array(out);
}

/* 构造设备侧二进制：count(2 LE) + [nameLen(1) name pwdLen(1) pwd] */
function packBinary(entries) {
  const parts = [];
  const cnt = new Uint8Array(2);
  cnt[0] = entries.length & 0xFF;
  cnt[1] = (entries.length >> 8) & 0xFF;
  parts.push(cnt);
  for (const e of entries) {
    const nb = Buffer.from(e.name, 'utf8');
    const pb = Buffer.from(e.secret, 'utf8');
    parts.push(new Uint8Array([nb.length]), new Uint8Array(nb));
    parts.push(new Uint8Array([pb.length]), new Uint8Array(pb));
  }
  const total = parts.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

(async () => {
  const entries = [
    { name: '微信', secret: 'abc123XYZ!' },
    { name: 'GitHub', secret: 'gh_!@#$%^&*()_+' },
    { name: '', secret: 'no-name-secret' },
  ];
  const masterPwd = 'MyStrongPass2026';
  const kek = rnd(32);

  console.log('== 模拟设备侧加密 ==');
  const kexp = rnd(32);
  const dataNonce = rnd(12);
  const dataCipher = await aesEnc(kexp, dataNonce, packBinary(entries));

  const wrapNonce = rnd(12);
  const wrappedKexp = await aesEnc(kek, wrapNonce, kexp);
  const wrapped60 = new Uint8Array(60);
  wrapped60.set(wrapNonce, 0);
  wrapped60.set(wrappedKexp, 12);
  console.log(`  data 密文 ${dataCipher.length} 字节，wrapped ${wrapped60.length} 字节`);
  if (wrapped60.length === 60) { ok('导出头长度 60'); } else { bad('导出头长度'); }

  console.log('== App 换锁 ==');
  const file = await exp.fromDevice(wrapped60, dataNonce, dataCipher, kek, masterPwd);
  const obj = JSON.parse(file);
  if (obj.magic === 'AMFNL1' && obj.v === 2) { ok('文件头正确（v2）'); }
  else { bad('文件头', JSON.stringify({ magic: obj.magic, v: obj.v })); }
  if (obj.kdf === 'PBKDF2-HMAC-SHA256' && obj.iter >= 200000) { ok('KDF 参数合规'); }
  else { bad('KDF', obj.kdf + '/' + obj.iter); }
  // data 必须原样带走（设备密文未变）
  const sameData = Buffer.from(obj.data, 'base64').equals(Buffer.from(dataCipher));
  if (sameData) { ok('设备密文原样保留（未解未重加密）'); } else { bad('密文被改动'); }
  // wrapped 必须是新的（换了锁）
  const newWrapped = Buffer.from(obj.wrapped, 'base64');
  if (!newWrapped.equals(Buffer.from(wrappedKexp))) { ok('K_export 已换锁'); }
  else { bad('wrapped 未更新'); }

  console.log('== 导入解密 ==');
  const back = await exp.openPackage(file, masterPwd);
  if (JSON.stringify(back.entries) === JSON.stringify(entries)) { ok('条目完全一致'); }
  else { bad('条目不一致', JSON.stringify(back.entries)); }

  console.log('== 安全性 ==');
  try { await exp.openPackage(file, 'WrongPass2026'); bad('错误密码应失败'); }
  catch (e) { ok('错误密码被拒：' + e.message); }

  const tampered = JSON.parse(file);
  tampered.data = tampered.data.slice(0, -8) + 'AAAAAAAA';
  try { await exp.openPackage(JSON.stringify(tampered), masterPwd); bad('篡改应被发现'); }
  catch (e) { ok('篡改被拒（GCM）：' + e.message); }

  const tampered2 = JSON.parse(file);
  tampered2.wrapped = Buffer.from(rnd(48)).toString('base64');
  try { await exp.openPackage(JSON.stringify(tampered2), masterPwd); bad('换掉 wrapped 应失败'); }
  catch (e) { ok('伪造 wrapped 被拒：' + e.message); }

  try { await exp.fromDevice(wrapped60, dataNonce, dataCipher, kek, '123456'); bad('弱密码应被拒'); }
  catch (e) { ok('弱密码被拒：' + e.message); }

  try { await exp.fromDevice(wrapped60, dataNonce, dataCipher, rnd(32), masterPwd); bad('错误 KEK 应失败'); }
  catch (e) { ok('错误 KEK 被拒：' + e.message); }

  try { await exp.openPackage('{"magic":"OTHER"}', masterPwd); bad('魔数校验应失败'); }
  catch (e) { ok('魔数不匹配被拒：' + e.message); }

  try { await exp.openPackage('not json', masterPwd); bad('非 JSON 应失败'); }
  catch (e) { ok('非 JSON 被拒：' + e.message); }

  console.log('');
  console.log(fail === 0 ? `ALL EXPORT TESTS PASSED (${pass})` : `${fail} FAILED, ${pass} passed`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => {
  console.error('测试异常：', e);
  process.exit(1);
});
