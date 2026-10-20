/**
 * test_dom_smoke.js - 在 jsdom 里跑真实页面代码（含真实协议栈）
 *
 * 目的：没有真机时，尽可能验证 Android 版新写的 UI 层不会崩。
 *   - 真实的 proto / crypto / pwdkey / ui / router / 五个页面
 *   - 只有 BLE 被替换成一个"协议级假设备"（会正确应答 DEVICE_INFO）
 *
 * 覆盖：首屏渲染 -> 扫描 -> 连接 -> 已连接视图 -> 解锁页 -> 密码库页 -> 设备管理页
 *
 * 运行：node tests/test_dom_smoke.js
 */
const path = require('path');
const { JSDOM } = require('jsdom');

/* ============================================================
 * 1. DOM 环境
 * ============================================================ */
const HTML = `<!DOCTYPE html><html><body>
  <div class="appbar">
    <div class="appbar-inner">
      <div class="appbar-back">‹</div>
      <div class="appbar-title">PwdKey</div>
    </div>
  </div>
  <div id="page-root"></div>
</body></html>`;

const dom = new JSDOM(HTML, {
  url: 'https://localhost/',
  pretendToBeVisual: true,
});

const win = dom.window;

global.window = win;
global.document = win.document;
Object.defineProperty(global, 'navigator', { value: win.navigator, configurable: true });
global.localStorage = win.localStorage;
global.history = win.history;
global.HTMLElement = win.HTMLElement;
global.requestAnimationFrame = (cb) => setTimeout(cb, 0);
win.scrollTo = () => {};

/* ============================================================
 * 2. 假的 BLE 桥（协议级）
 * ============================================================ */
const proto = require(path.join(__dirname, '..', 'www', 'src', 'libs', 'proto.js'));
const { TAG, OP } = proto;
const crypto = require(path.join(__dirname, '..', 'www', 'src', 'utils', 'crypto.js'));

/* ---- 认证用的固定材料（让"生物 + PIN"这条链路可以端到端跑通） ---- */
const KEK_OK = new Uint8Array(32).fill(0x42);
const DEV_SALT = new Uint8Array(16).fill(7);
const NONCE_FIXED = new Uint8Array(32).fill(0x11);
const SEQ_FIXED = 1;
const VERIFIER = crypto.computeVerifier(KEK_OK);

function bytesEq(a, b) {
  if (!a || !b || a.length !== b.length) { return false; }
  for (let i = 0; i < a.length; i++) { if (a[i] !== b[i]) { return false; } }
  return true;
}

const DEV_ID = 'AA:BB:CC:DD:EE:FF';
const DEV_NAME = 'PwdKey-XXXX';

const fakeBle = {
  _notify: null,
  _asm: null,
  writes: 0,

  async initialize() {},
  async requestLEScan(opts, cb) {
    setTimeout(() => cb({
      device: { deviceId: DEV_ID, name: DEV_NAME },
      localName: DEV_NAME,
      rssi: -42,
    }), 5);
  },
  async stopLEScan() {},
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
    fakeBle.writes++;
    fakeBle._onWrite(new Uint8Array(dv.buffer, dv.byteOffset, dv.byteLength));
  },

  /* --- 收请求分片并重组 --- */
  _onWrite(u8) {
    const opcode = u8[2];
    const flags = u8[3];
    const total = u8[4] | (u8[5] << 8);
    const payload = u8.slice(6);

    if (!fakeBle._asm) {
      fakeBle._asm = { opcode, total, buf: payload };
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
    for (let off = 0; off < frame.length; off += 20) {
      const chunk = frame.slice(off, off + 20);
      setTimeout(() => {
        if (fakeBle._notify) {
          fakeBle._notify(new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength));
        }
      }, 2);
    }
  },

  _handle(opcode, body) {
    const tlvs = proto.parseTLVs(body);
    const ridRaw = proto.tlvLast(tlvs, TAG.REQUEST_ID);
    const rid = ridRaw ? proto.readU16le(ridRaw, 0) : 0;

    const result = (rc) => fakeBle._send(opcode, proto.concatBytes(
      proto.tlv(TAG.REQUEST_ID, proto.u16le(rid)),
      proto.tlv(TAG.RESULT_CODE, proto.u16le(rc))));

    if (opcode === OP.DEVICE_INFO) {
      /* 注意：DEVICE_INFO 成功响应没有 RESULT_CODE（固件真实行为） */
      fakeBle._send(opcode, proto.concatBytes(
        proto.tlv(TAG.REQUEST_ID, proto.u16le(rid)),
        proto.tlv(TAG.FW_VERSION, new Uint8Array([0, 1, 0])),
        proto.tlv(TAG.ENTRY_COUNT, proto.u16le(0)),
        proto.tlv(TAG.STATE, proto.u16le(0x0100)),      // 已设置主密码
        proto.tlv(TAG.LOCK_SECONDS, proto.u32le(0)),
        proto.tlv(TAG.SALT, new Uint8Array(16).fill(7)),
        proto.tlv(TAG.KDF_ITER, proto.u32le(200000)),
        proto.tlv(TAG.LAYOUT, new Uint8Array([0])),
      ));
      return;
    }

    /* 列表类命令回"空列表"，让页面走正常分支（否则会正确跳去解锁页） */
    if (opcode === OP.AUTH_START) {
      fakeBle._send(opcode, proto.concatBytes(
        proto.tlv(TAG.REQUEST_ID, proto.u16le(rid)),
        proto.tlv(TAG.NONCE, NONCE_FIXED),
        proto.tlv(TAG.SESSION_SEQ, proto.u32le(SEQ_FIXED))));
      return;
    }
    if (opcode === OP.AUTH_VERIFY) {
      const nonce = proto.tlvLast(tlvs, TAG.NONCE);
      const proof = proto.tlvLast(tlvs, TAG.PROOF);
      const kek = proto.tlvLast(tlvs, TAG.KEK_BLOB);
      const expect = crypto.computeProof(VERIFIER, nonce, SEQ_FIXED);
      const ok = !!kek && kek.length === 32
        && bytesEq(kek, KEK_OK)
        && bytesEq(proof, expect);
      result(ok ? 0 : 0x4001);
      return;
    }

    if (opcode === OP.PWD_LIST) {
      fakeBle._send(opcode, proto.concatBytes(
        proto.tlv(TAG.REQUEST_ID, proto.u16le(rid)),
        proto.tlv(TAG.ENTRY_COUNT, proto.u16le(0)),
        proto.tlv(TAG.PAGE_INDEX, new Uint8Array([0])),
      ));
      return;
    }
    if (opcode === OP.HOST_LIST) {
      fakeBle._send(opcode, proto.concatBytes(
        proto.tlv(TAG.REQUEST_ID, proto.u16le(rid)),
        proto.tlv(TAG.HOST_COUNT, new Uint8Array([0])),
        proto.tlv(TAG.PAGE_INDEX, new Uint8Array([0])),
      ));
      return;
    }

    /* 其它命令一律回"未认证"，足以驱动页面错误分支 */
    result(0x4002);
  },
};

/* 把 mock 塞进 require 缓存，替换真实的 Capacitor 插件 */
const blePluginPath = require.resolve('@capacitor-community/bluetooth-le');
require.cache[blePluginPath] = {
  id: blePluginPath,
  filename: blePluginPath,
  loaded: true,
  exports: { BleClient: fakeBle },
  children: [],
  paths: [],
};

/* ============================================================
 * 2.5 假的生物认证原生插件（BiometricWrap）
 *
 * 只模拟"外壳"：unwrap 交出信封、open 用 PIN 解出 KEK。
 * 真正的 Keystore / BiometricPrompt 在设备上跑，无法在 Node 里测；
 * 这里验证的是【页面的状态机与协议衔接】是否正确。
 * ============================================================ */
const bioMock = {
  enrolled: false,
  pin: '123456',
  salt: DEV_SALT,
  promptCount: 0,

  async status() {
    return {
      available: true,
      reason: 0,
      reasonText: '设备支持强生物认证',
      hasEnroll: this.enrolled,
    };
  },

  async unwrap() {
    this.promptCount++;
    if (!this.enrolled) {
      const e = new Error('尚未开启生物解锁');
      e.code = 'NO_ENROLL';
      throw e;
    }
    return { envelopeB64: 'RU5WRUxPUEU=' };
  },

  async open(args) {
    if (args.pin !== this.pin) {
      const e = new Error('PIN 不正确');
      e.code = 'PIN_INVALID';
      throw e;
    }
    return {
      kekB64: Buffer.from(KEK_OK).toString('base64'),
      deviceSaltB64: Buffer.from(this.salt).toString('base64'),
      pinIter: 600000,
    };
  },

  async enroll() { this.enrolled = true; return { ok: true }; },
  async clear() { this.enrolled = false; return { ok: true }; },
};

const biowrap = require(path.join(__dirname, '..', 'www', 'src', 'utils', 'biowrap.js'));
biowrap.setMock(bioMock);

/* ============================================================
 * 3. 载入应用
 * ============================================================ */
const router = require(path.join(__dirname, '..', 'www', 'src', 'router.js'));
require(path.join(__dirname, '..', 'www', 'src', 'main.js'));

const { pwdkey } = require(path.join(__dirname, '..', 'www', 'src', 'utils', 'pwdkey.js'));

/* ============================================================
 * 4. 断言工具
 * ============================================================ */
let failures = 0;

function assert(cond, name, extra) {
  if (cond) {
    console.log('  PASS: ' + name);
  } else {
    failures++;
    console.log('  FAIL: ' + name + (extra ? '  -> ' + extra : ''));
  }
}

const $ = (sel) => document.querySelector(sel);
const text = (sel) => ($(sel) ? $(sel).textContent.trim() : '');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** 按 PIN 键盘上的数字（位置是随机的，按 data-k 找） */
function clickPin(pin) {
  for (const ch of String(pin)) {
    const key = document.querySelector(`.pin-key[data-k="${ch}"]`);
    if (!key) { return false; }
    key.click();
  }
  return true;
}

/* ============================================================
 * 5. 流程
 * ============================================================ */
async function main() {
  console.log('== 启动 ==');
  window.dispatchEvent(new win.Event('DOMContentLoaded'));
  await sleep(30);
  assert(text('.hero-title') === 'PwdKey', '首屏渲染出 hero 标题');
  assert(!!$('#btn-scan'), '扫描按钮存在');
  assert(text('.appbar-title') === 'PwdKey', '顶栏标题正确');

  console.log('== 扫描（真实 ble.scan 路径 + 9s 窗口）==');
  $('#btn-scan').click();
  assert($('#btn-scan').disabled === true, '扫描中按钮禁用');
  await sleep(9600);
  assert(!!$('.device-item'), '扫描到设备并渲染列表');
  assert(text('.device-name') === DEV_NAME, '设备名显示正确', text('.device-name'));

  console.log('== 连接（真实 pwdkey.connect + 协议握手）==');
  $('.device-item').click();
  await sleep(600);
  assert(pwdkey.connected === true, 'pwdkey.connected = true');
  assert(!!$('#idx-on') && $('#idx-on').style.display !== 'none', '切换到已连接视图');
  assert(text('.title').indexOf(DEV_NAME) >= 0, '已连接视图显示设备名', text('.title'));
  assert(text('.badge').indexOf('已启用') >= 0, '状态徽标为已启用');
  assert(fakeBle.writes > 0, '确实向设备写了数据');

  console.log('== 路由：进入解锁页 ==');
  $('#btn-main').click();
  await sleep(50);
  assert(text('.title') === '解锁设备', '解锁页标题', text('.title'));
  assert(!!$('#u-pwd'), '密码输入框存在');
  assert($('#u-go').disabled === true, '空密码时解锁按钮禁用');
  assert(router.depth() === 2, '页面栈深度为 2');

  console.log('== 路由：返回 ==');
  router.back();
  await sleep(50);
  assert(router.depth() === 1, '返回后栈深度为 1');

  console.log('== 生物解锁：salt 不匹配时必须拒绝（不消耗设备失败计数）==');
  bioMock.enrolled = true;
  bioMock.salt = new Uint8Array(16).fill(9);   // 模拟设备主密码已被改过
  router.reset('unlock');
  await sleep(120);
  assert(text('.title') === '输入 6 位 PIN', '自动进入 PIN 输入态', text('.title'));
  assert(clickPin('123456'), '能找到 6 个 PIN 按键');
  await sleep(350);
  assert(text('.dialog-title').indexOf('过期') >= 0,
    'salt 不匹配时提示"指纹解锁已过期"', text('.dialog-title'));
  const staleOk = $('.dialog [data-act="ok"]');
  if (staleOk) { staleOk.click(); }
  await sleep(80);
  assert(pwdkey.isUnlocked() === false, 'salt 不匹配时没有建立会话');

  console.log('== 生物解锁：PIN 错误计数 ==');
  bioMock.salt = DEV_SALT;
  bioMock.enrolled = true;
  router.reset('unlock');
  await sleep(120);
  clickPin('000000');
  await sleep(300);
  assert(text('.err-box').indexOf('还可尝试 4 次') >= 0,
    'PIN 错误后提示剩余次数', text('.err-box'));

  console.log('== 生物解锁：正确 PIN 走通全链路 ==');
  assert(clickPin('123456'), '重新输入正确 PIN');
  await sleep(400);
  assert(pwdkey.isUnlocked() === true, '生物 + PIN 解锁成功，会话已建立');
  assert(text('.page-topbar-title') === '密码库', '解锁后进入密码库', text('.page-topbar-title'));

  console.log('== 密码库页渲染（伪造已解锁）==');
  /* 直接伪造会话，绕过 PBKDF2 —— 本测试只关心 UI 不崩 */
  pwdkey.kek = new Uint8Array(32);
  pwdkey.verifier = new Uint8Array(32);
  router.go('vault');
  await sleep(150);
  if (!document.querySelector('.page-topbar-title')) {
    console.log('  [DEBUG] current =', router.current());
    console.log('  [DEBUG] root    =', JSON.stringify(document.getElementById('page-root').innerHTML.slice(0, 160)));
  }
  assert(text('.page-topbar-title') === '密码库', '密码库标题', text('.page-topbar-title'));
  assert(!!$('#v-list'), '列表容器存在');
  const vaultBody = $('#v-list').textContent;
  assert(typeof vaultBody === 'string' && vaultBody.length > 0, '列表区有内容（空库或错误提示）');

  console.log('== 设备管理页渲染 ==');
  router.go('hosts');
  await sleep(150);
  assert(text('.page-topbar-title') === '已连接的电脑', '设备管理页标题');
  assert(!!$('#h-list'), '设备列表容器存在');

  console.log('== 弹层组件 ==');
  const ui = require(path.join(__dirname, '..', 'www', 'src', 'ui.js'));
  const modalPromise = ui.modal({ title: '测试弹窗', content: '内容', confirmText: '好' });
  await sleep(20);
  assert(!!$('.dialog-title') && text('.dialog-title') === '测试弹窗', 'modal 已插入 DOM');
  $('.dialog [data-act="ok"]').click();
  const mr = await modalPromise;
  assert(mr.confirm === true, 'modal 点确定返回 confirm=true');
  assert(!$('.dialog'), 'modal 关闭后已移除');

  const sheetPromise = ui.actionSheet({ itemList: ['甲', '乙'] });
  await sleep(20);
  const items = document.querySelectorAll('.sheet-item');
  assert(items.length === 3, 'action sheet 渲染 2 项 + 取消');
  items[1].click();
  const sr = await sheetPromise;
  assert(sr && sr.tapIndex === 1, 'action sheet 返回正确 index');

  console.log('== 切后台锁定 ==');
  Object.defineProperty(document, 'hidden', { value: true, configurable: true });
  document.dispatchEvent(new win.Event('visibilitychange'));
  await sleep(1000);
  assert(pwdkey.isUnlocked() === false, '切后台后会话被清除（kek=null）');

  console.log(failures === 0 ? '\nALL DOM SMOKE TESTS PASSED' : `\n${failures} FAILURES`);
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.error('FATAL:', e);
  process.exit(1);
});
