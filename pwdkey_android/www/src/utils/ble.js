/**
 * ble.js - Android (Capacitor) 的 BLE 适配器
 *
 * 为什么需要重写：Android WebView **不支持 Web Bluetooth**，所以 BLE 必须走原生。
 * 本文件用 @capacitor-community/bluetooth-le 实现，并**刻意保持与小程序版
 * utils/ble.js 完全相同的公开接口**（scan / connect / onNotify / writeChunks /
 * disconnect），因此 utils/pwdkey.js 及其上层逻辑可以一字不改地复用。
 *
 * 管理服务 UUID: 0xFFF0 | 命令 0xFFF3(W) | 响应 0xFFF4(N)
 */
const { BleClient } = require('@capacitor-community/bluetooth-le');

const UUID_SVC = '0000fff0-0000-1000-8000-00805f9b34fb';
const UUID_CMD = '0000fff3-0000-1000-8000-00805f9b34fb';
const UUID_RESP = '0000fff4-0000-1000-8000-00805f9b34fb';

const NAME_PREFIX = 'PwdKey';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** DataView -> 独立的 Uint8Array（必须拷贝：WebView 会复用底层缓冲） */
function dvToU8(dv) {
  const out = new Uint8Array(dv.byteLength);
  for (let i = 0; i < dv.byteLength; i++) {
    out[i] = dv.getUint8(i);
  }
  return out;
}

/** Uint8Array -> 精确长度的 DataView */
function u8ToDv(u8) {
  const ab = new ArrayBuffer(u8.length);
  new Uint8Array(ab).set(u8);
  return new DataView(ab);
}

class Ble {
  constructor() {
    this.deviceId = null;
    this.connected = false;
    this.mtu = 23;
    this.svcId = null;
    this.cmdCharId = null;
    this.respCharId = null;
    this._notifyCb = null;
    this._lostCb = null;
    this._ready = false;
    this._expectDisconnect = false;
  }

  /* ---------------- 初始化 / 权限 ---------------- */

  async _init() {
    if (this._ready) { return; }
    try {
      await BleClient.initialize({ androidNeverForLocation: true });
      this._ready = true;
    } catch (e) {
      throw new Error('蓝牙初始化失败：' + (e.message || e));
    }
  }

  /* ---------------- 扫描 ---------------- */

  /**
   * 扫描 PwdKey-* 设备。
   * @param {number} timeoutMs
   * @returns {Promise<{devices:Array<{deviceId,name,rssi}>, totalSeen:number}>}
   *   totalSeen = 去重后看到的 BLE 设备总数，用于区分"权限问题"与"设备不在附近"
   */
  async scan(timeoutMs = 10000) {
    await this._init();

    const found = new Map();
    const seenIds = new Set();
    let totalSeen = 0;

    try {
      await BleClient.requestLEScan({ allowDuplicates: true }, (result) => {
        const dev = result.device || {};
        const id = dev.deviceId;
        if (!seenIds.has(id)) {
          seenIds.add(id);
          totalSeen++;
        }
        const name = result.localName || dev.name || '';
        if (name.indexOf(NAME_PREFIX) === 0) {
          /* 后报覆盖先报：首包常常还没有名字，去重同时保留最新信号强度 */
          found.set(id, {
            deviceId: id,
            name,
            rssi: typeof result.rssi === 'number' ? result.rssi : null,
          });
        }
      });
    } catch (e) {
      const m = (e.message || String(e)).toLowerCase();
      if (m.indexOf('permission') >= 0 || m.indexOf('denied') >= 0) {
        throw new Error('缺少蓝牙权限：请在系统设置里允许本应用使用「附近的设备」');
      }
      if (m.indexOf('disabled') >= 0 || m.indexOf('not available') >= 0) {
        throw new Error('蓝牙未开启，请打开手机蓝牙后重试');
      }
      throw new Error('扫描启动失败：' + (e.message || e));
    }

    await sleep(timeoutMs);
    try { await BleClient.stopLEScan(); } catch (e) { /* ignore */ }

    const devices = Array.from(found.values())
      .sort((a, b) => (b.rssi === null ? -999 : b.rssi) - (a.rssi === null ? -999 : a.rssi));
    return { devices, totalSeen };
  }

  /* ---------------- 连接 ---------------- */

  /**
   * 连接 + 发现特征 + 订阅通知。
   *
   * 与小程序同理：底层 GATT 连接可能残留（应用重启后），直接连会报
   * "already connected"，因此先主动清理再重试一次。
   */
  async connect(deviceId) {
    await this._init();
    if (this.connected) { await this.disconnect(); }

    await BleClient.disconnect(deviceId).catch(() => {});
    await sleep(150);

    try {
      await this._connectRaw(deviceId);
    } catch (e) {
      const m = (e.message || String(e)).toLowerCase();
      if (m.indexOf('already') >= 0 || m.indexOf('busy') >= 0 || m.indexOf('133') >= 0) {
        await BleClient.disconnect(deviceId).catch(() => {});
        await sleep(500);
        await this._connectRaw(deviceId);
      } else {
        throw new Error('连接失败：' + (e.message || e));
      }
    }

    this.deviceId = deviceId;
    this.connected = true;

    /* Android 必须显式协商大 MTU：设备响应帧最长约 100+ 字节，
     * 若停在默认 23（只能通知 20 字节）会直接失败。 */
    try {
      const mtu = await BleClient.requestMtu(deviceId, 256);
      this.mtu = mtu || 256;
    } catch (e) {
      this.mtu = 23;
    }

    /* 服务 / 特征发现 */
    let services = [];
    try {
      services = await BleClient.getServices(deviceId);
    } catch (e) {
      await this.disconnect();
      throw new Error('读取服务列表失败：' + (e.message || e));
    }
    const svc = (services || []).find((s) => (s.uuid || '').toLowerCase() === UUID_SVC);
    if (!svc) {
      await this.disconnect();
      throw new Error('未找到管理服务（0xFFF0），请确认设备固件正确');
    }
    this.svcId = UUID_SVC;

    for (const c of (svc.characteristics || [])) {
      const u = (c.uuid || '').toLowerCase();
      if (u === UUID_CMD) { this.cmdCharId = UUID_CMD; }
      if (u === UUID_RESP) { this.respCharId = UUID_RESP; }
    }
    if (!this.cmdCharId || !this.respCharId) {
      await this.disconnect();
      throw new Error('管理服务特征不完整，请确认设备固件版本');
    }

    /* 订阅响应通知 */
    try {
      await BleClient.startNotifications(deviceId, UUID_SVC, UUID_RESP, (dv) => {
        if (this._notifyCb) { this._notifyCb(dvToU8(dv)); }
      });
    } catch (e) {
      await this.disconnect();
      throw new Error('订阅设备响应失败：' + (e.message || e));
    }
  }

  _connectRaw(deviceId) {
    return BleClient.connect(deviceId, (id) => this._handleDisconnect(id), {
      timeout: 15000,
    });
  }

  _handleDisconnect() {
    if (this._expectDisconnect) { return; }
    if (!this.connected) { return; }
    this.connected = false;
    this.deviceId = null;
    if (this._lostCb) { this._lostCb(); }
  }

  /** 底层链路意外断开时回调（由 app 层注册，用于回首页并清理会话） */
  onConnectionLost(cb) {
    this._lostCb = cb;
  }

  onNotify(cb) {
    this._notifyCb = cb;
  }

  /* ---------------- 写入（串行分片） ---------------- */

  /**
   * 依次写入各分片（每片 ≤ 20 字节）。串行 + 等待 GATT 回执，
   * 保证设备端分片重组不会因拥塞丢片。
   */
  async writeChunks(chunks) {
    if (!this.connected) { throw new Error('设备未连接'); }
    for (const c of chunks) {
      if (c.length > 20) {
        throw new Error('内部分片错误（片长 ' + c.length + ' > 20）');
      }
      await BleClient.write(this.deviceId, UUID_SVC, UUID_CMD, u8ToDv(c));
    }
  }

  /* ---------------- 断开 ---------------- */

  async disconnect() {
    const id = this.deviceId;
    this.deviceId = null;
    this.connected = false;
    this.svcId = null;
    this.cmdCharId = null;
    this.respCharId = null;
    if (id) {
      this._expectDisconnect = true;
      try {
        await BleClient.stopNotifications(id, UUID_SVC, UUID_RESP).catch(() => {});
        await BleClient.disconnect(id).catch(() => {});
      } finally {
        this._expectDisconnect = false;
      }
    }
  }
}

module.exports = new Ble();
