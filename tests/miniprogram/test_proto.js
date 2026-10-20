/* Node test: protocol frame/TLV correctness + JS<->Python cross-check. */
const proto = require("../../pwdkey_app/miniprogram/libs/proto.js");
const crypto = require("../../pwdkey_app/miniprogram/utils/crypto.js");
const { execFileSync } = require("child_process");

let failures = 0;
function assert(cond, name) {
  if (cond) { console.log(`  PASS: ${name}`); }
  else { console.log(`  FAIL: ${name}`); failures++; }
}

/* ---------- 1) frame building ---------- */
console.log("== buildFrames ==");
{
  // single frame
  const t = proto.tlv(0x07, proto.u16le(1));
  const f = proto.buildFrames(0x01, t, 14);
  assert(f.length === 1, "single frame for short payload");
  assert(f[0][0] === 0xA5 && f[0][1] === 0x01 && f[0][2] === 0x01, "header magic/ver/opcode");
  assert(f[0][3] === proto.FLAG_LAST, "FLAGS = LAST");
  assert(proto.readU16le(f[0], 4) === t.length, "TOTAL_LEN correct");

  // multi frame (18 bytes payload -> 14 + 4)
  const big = new Uint8Array(18).fill(0xAB);
  const fs = proto.buildFrames(0x03, big, 14);
  assert(fs.length === 2, "two fragments for 18 bytes @14");
  assert(fs[0][3] === proto.FLAG_MORE, "frag0 = MORE");
  assert(fs[1][3] === proto.FLAG_LAST, "frag1 = LAST");
  assert(fs[0].length === 20 && fs[1].length === 10, "fragment sizes 20/10");
  assert(proto.readU16le(fs[0], 4) === 18 && proto.readU16le(fs[1], 4) === 18,
         "TOTAL_LEN consistent across fragments");
}

/* ---------- 2) receive assembler ---------- */
console.log("== RecvAssembler ==");
{
  // A response frame = ONE frame (6B header + payload), delivered in ATT-sized chunks
  const payload = new Uint8Array(50).map((_, i) => i);
  const respFrame = proto.buildFrames(0x20, payload, 4096)[0];  // single frame
  assert(respFrame.length === 56, "response frame is 56 bytes");

  const asm = new proto.RecvAssembler();
  const out = [];
  for (let off = 0; off < respFrame.length; off += 20) {
    out.push(...asm.push(respFrame.subarray(off, off + 20)));
  }
  assert(out.length === 1, "reassembled exactly 1 frame");
  assert(out[0].length === 6 + 50, "frame length ok");
  const p = proto.parseFrame(out[0]);
  assert(p && p.opcode === 0x20 && p.totalLen === 50, "parsed opcode/len");

  // garbage before magic
  const asm2 = new proto.RecvAssembler();
  const junk = proto.concatBytes(new Uint8Array([1, 2, 3, 0xAA]), respFrame);
  const o2 = asm2.push(junk.subarray(0, 30));
  assert(o2.length === 0, "garbage skipped, partial frame held");
  const o3 = asm2.push(junk.subarray(30));
  assert(o3.length === 1, "frame completed after garbage");

  // false magic inside data must not wedge the assembler
  const asm3 = new proto.RecvAssembler();
  const evil = proto.concatBytes(new Uint8Array([0xA5, 0xFF, 0xFF]), respFrame);
  const o4 = asm3.push(evil);
  assert(o4.length === 1, "false magic resync works");

  // request-side fragmentation: 105-byte AUTH_VERIFY -> 8 fragments, all <= 20B
  const t105 = new Uint8Array(105).fill(0x11);
  const frags = proto.buildFrames(0x03, t105, 14);
  assert(frags.length === 8, "105B payload -> 8 fragments");
  assert(frags.every((f) => f.length <= 20), "all fragments <= 20 bytes");
  assert(frags[7][3] === proto.FLAG_LAST && frags[0][3] === proto.FLAG_MORE,
         "first=MORE last=LAST");
}

/* ---------- 3) TLV round trip ---------- */
console.log("== TLV ==");
{
  const t = proto.concatBytes(
    proto.tlv(0x01, proto.asciiToBytes("K7M2QX9B")),
    proto.tlv(0x07, proto.u16le(42)),
    proto.tlv(0x03, crypto.utf8ToBytes("p@ssW0rd!#"))
  );
  const parsed = proto.parseTLVs(t);
  assert(proto.bytesToAscii(parsed[0x01][0]) === "K7M2QX9B", "ENTRY_ID decode");
  assert(proto.readU16le(parsed[0x07][0], 0) === 42, "REQUEST_ID decode");
  const s = parsed[0x03][0];
  assert(proto.bytesToAscii(s) === "p@ssW0rd!#", "SECRET decode");
  assert(proto.resultCode({ 0x08: [proto.u16le(0x4001)] }) === 0x4001, "resultCode");
}

/* ---------- 4) JS <-> Python cross check (protocol end-to-end crypto) ---------- */
console.log("== JS <-> Python cross-check ==");
{
  const pwd = "TestPwd-2026!";
  const saltHex = "9a516a9893f760c2d2e94d118721601c";
  const iters = 200000;
  const nonceHex = "00112233445566778899aabbccddeeff0102030405060708090a0b0c0d0e0f10";
  const seq = 3450719210;

  // Python 解释器：优先读环境变量 PYTHON，否则依次尝试常见命令名。
  // 故意不写死绝对路径，避免把开发者本机目录带进仓库。
  function findPython() {
    const cands = [process.env.PYTHON, "python3", "python", "py"].filter(Boolean);
    for (const exe of cands) {
      try {
        execFileSync(exe, ["--version"], { stdio: "ignore" });
        return exe;
      } catch (_) { /* 试下一个 */ }
    }
    return null;
  }

  const py = findPython();
  if (!py) {
    console.log("  SKIP: 未找到 python，跳过 JS<->Python 对拍（设 PYTHON 环境变量可指定）");
  } else {
    const pyOut = execFileSync(py,
      ["ref_python_calc.py", pwd, saltHex, String(iters), nonceHex, String(seq)],
      { cwd: __dirname }).toString().trim().split(/\r?\n/);

    const kek = crypto.pbkdf2Sha256(
      crypto.utf8ToBytes(pwd), proto.hexToBytes(saltHex), iters);
    const verifier = crypto.computeVerifier(kek);
    const proof = crypto.computeProof(verifier, proto.hexToBytes(nonceHex), seq);

    assert(proto.bytesToHex(kek) === pyOut[0], "KEK matches python");
    assert(proto.bytesToHex(verifier) === pyOut[1], "VERIFIER matches python");
    assert(proto.bytesToHex(proof) === pyOut[2], "PROOF matches python");
    console.log(`  KEK = ${proto.bytesToHex(kek)}`);
  }
}

console.log(failures === 0 ? "\nALL TESTS PASSED" : `\n${failures} FAILURES`);
process.exit(failures ? 1 : 0);
