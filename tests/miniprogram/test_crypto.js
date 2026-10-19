/* Node test: verify optimized PBKDF2-HMAC-SHA256 (same code path as mini-program)
 * against RFC published test vectors + measure performance.
 */
const CryptoJS = require("../../pwdkey_app/miniprogram/libs/crypto-js/core.js");
require("../../pwdkey_app/miniprogram/libs/crypto-js/sha256.js");
require("../../pwdkey_app/miniprogram/libs/crypto-js/hmac.js");
require("../../pwdkey_app/miniprogram/libs/crypto-js/enc-hex.js");

function pbkdf2_32(pwdHex, saltHex, c) {
  const keyWA = CryptoJS.enc.Hex.parse(pwdHex);
  const saltWA = CryptoJS.enc.Hex.parse(saltHex);
  const hmac = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, keyWA);
  const block = saltWA.clone().concat(CryptoJS.lib.WordArray.create([0x00000001], 4));
  hmac.reset();
  let u = hmac.update(block).finalize();
  const t = u.clone();
  for (let i = 1; i < c; i++) {
    hmac.reset();
    u = hmac.update(u).finalize();
    for (let w = 0; w < t.words.length; w++) t.words[w] ^= u.words[w];
  }
  return CryptoJS.enc.Hex.stringify(t);
}

const vectors = [
  ["password", "salt", 1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"],
  ["password", "salt", 2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"],
  ["password", "salt", 4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"],
  ["passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
   "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1"],
];

let pass = 0;
for (const [p, s, c, exp] of vectors) {
  const got = pbkdf2_32(Buffer.from(p).toString("hex"), Buffer.from(s).toString("hex"), c);
  const ok = got === exp;
  if (ok) pass++;
  console.log(`c=${c}: ${ok ? "PASS" : "FAIL"}  got=${got.slice(0, 24)}...`);
}
console.log(`vectors: ${pass}/${vectors.length} passed`);

// performance: 200k iterations (the device's KDF_ITER)
const pwdHex = Buffer.from("MyMasterPwd2026!").toString("hex");
const saltHex = "9a516a9893f760c2d2e94d118721601c";
let t0 = Date.now();
const kek = pbkdf2_32(pwdHex, saltHex, 200000);
console.log(`200k iterations (node/V8): ${Date.now() - t0} ms`);
console.log(`KEK = ${kek}`);

// cross-check against node's built-in pbkdf2 (ground truth)
const crypto = require("crypto");
const ref = crypto.pbkdf2Sync(Buffer.from("MyMasterPwd2026!"), Buffer.from(saltHex, "hex"),
                              200000, 32, "sha256").toString("hex");
console.log(`cross-check vs node crypto: ${kek === ref ? "PASS" : "FAIL"}`);
