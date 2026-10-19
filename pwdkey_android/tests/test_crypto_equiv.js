/**
 * test_crypto_equiv.js - 验证「WebCrypto 加速版」与「纯 JS 版」的 KEK 完全一致
 *
 * Android App 版把 PBKDF2 换成了原生实现（快 ~50 倍），这属于密码学路径的
 * 改动，必须有对拍证据：
 *   pbkdf2Sha256(同步纯 JS)  ===  deriveKekAsyncJs  ===  WebCrypto 版
 * 并且要对 200000 次迭代（真实参数）也成立。
 *
 * 运行：node tests/test_crypto_equiv.js
 */
const path = require('path');
const crypto = require(path.join(__dirname, '..', 'www', 'src', 'utils', 'crypto.js'));

let failures = 0;

function assert(cond, name, extra) {
  if (cond) {
    console.log('  PASS: ' + name);
  } else {
    failures++;
    console.log('  FAIL: ' + name + (extra ? '  -> ' + extra : ''));
  }
}

function toHex(u8) {
  return Array.from(u8).map((b) => (b + 0x100).toString(16).slice(1)).join('');
}

async function checkCase(pwd, saltHex, iterations) {
  const salt = new Uint8Array(Buffer.from(saltHex, 'hex'));
  const pwdBytes = crypto.utf8ToBytes(pwd);

  const sync = crypto.pbkdf2Sha256(pwdBytes, salt, iterations);
  const jsAsync = await crypto.deriveKekAsyncJs(pwdBytes, salt, iterations);
  const auto = await crypto.deriveKekAsync(pwdBytes, salt, iterations);

  const hSync = toHex(sync);
  const hJs = toHex(jsAsync);
  const hAuto = toHex(auto);

  assert(hSync === hJs, `sync == async-js (iter=${iterations})`);
  assert(hSync === hAuto, `sync == auto/webcrypto (iter=${iterations})`, hAuto.slice(0, 16));

  /* 再与 Node 原生 crypto 对拍，排除"两个实现一起错"的可能 */
  const nodeKek = require('crypto')
    .pbkdf2Sync(Buffer.from(pwd, 'utf8'), Buffer.from(saltHex, 'hex'),
                iterations, 32, 'sha256');
  assert(toHex(nodeKek) === hSync, `sync == node pbkdf2Sync (iter=${iterations})`);

  return hAuto;
}

async function main() {
  console.log('== WebCrypto 可用性 ==');
  assert(crypto.webCryptoAvailable() === true, 'crypto.subtle 可用（Node 22）');

  console.log('== 小迭代对拍（快速） ==');
  await checkCase('TestPwd-2026!', '000102030405060708090a0b0c0d0e0f', 1000);
  await checkCase('p@ss w0rd', 'ffffffffffffffffffffffffffffffff', 1);
  await checkCase('中文密码不算', 'aabbccddeeff00112233445566778899', 5000);

  console.log('== 真实参数对拍（200000 次） ==');
  const t0 = Date.now();
  const webKek = await checkCase('TestPwd-2026!',
    '2caa2be4c230409c1821a92a9dee6702', 200000);
  const t1 = Date.now();
  console.log(`  KEK = ${webKek}`);
  console.log(`  200k 迭代耗时（WebCrypto 路径，含 3 次计算）: ${t1 - t0} ms`);

  console.log('== 整条密钥链一致性（VERIFIER / PROOF） ==');
  {
    const salt = new Uint8Array(Buffer.from('2caa2be4c230409c1821a92a9dee6702', 'hex'));
    const pwdBytes = crypto.utf8ToBytes('TestPwd-2026!');
    const kekWeb = await crypto.deriveKekAsync(pwdBytes, salt, 200000);
    const kekJs = await crypto.deriveKekAsyncJs(pwdBytes, salt, 200000);
    const vA = crypto.computeVerifier(kekWeb);
    const vB = crypto.computeVerifier(kekJs);
    assert(toHex(vA) === toHex(vB), 'VERIFIER 一致');

    const nonce = new Uint8Array(32).map((_, i) => i);
    const pA = crypto.computeProof(vA, nonce, 0x12345678);
    const pB = crypto.computeProof(vB, nonce, 0x12345678);
    assert(toHex(pA) === toHex(pB), 'PROOF 一致');
  }

  console.log(failures === 0 ? '\nALL CRYPTO EQUIV TESTS PASSED' : `\n${failures} FAILURES`);
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.error('FATAL:', e);
  process.exit(1);
});
