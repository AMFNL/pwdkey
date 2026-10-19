/**
 * ble.js - 微信小程序 BLE 封装（单例）
 *
 * 负责: 适配器、扫描(PwdKey-*)、连接、特征发现、分片写入(串行)、通知接收。
 * 管理服务 UUID: 0xFFF0 | 命令 0xFFF3(W) | 响应 0xFFF4(N)
 */
const UUID_SVC = '0000FFF0-0000-1000-8000-00805F9B34FB';
const UUID_CMD = '0000FFF3-0000-1000-8000-00805F9B34FB';
const UUID_RESP = '0000FFF4-0000-1000-8000-00805F9B34FB';

const NAME_PREFIX = 'PwdKey';

function wxAsync(fn, opts) {
  return new Promise((resolve, reject) => {
    fn(Object.assign({}, opts, {
      success: resolve,
      fail: (err) => reject(new Error(err.errMsg || JSON.stringify(err))),
    }));
  });
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
    this._listenerBound = false;
  }

  /* ---------------- 适配器 ---------------- */

  openAdapter() {
    return wxAsync(wx.openBluetoothAdapter).catch((e) => {
      // 已初始化时忽略
      if (/already/i.test(e.message)) { return; }
      throw new Error('蓝牙未开启，请打开手机蓝牙后重试');
    });
  }

  closeAdapter() {
    return wxAsync(wx.closeBluetoothAdapter).catch(() => {});
  }

  /* ---------------- 扫描 ---------------- */

  /**
   * 扫描 PwdKey-* 设备。
   * @param {number} timeoutMs 扫描时长
   * @returns {Promise<{devices:Array<{deviceId,name,rssi}>, totalSeen:number}>}
   *   totalSeen = 扫描期间看到的全部 BLE 设备数（用于区分"权限问题"与"设备不在附近"）
   */
  async scan(timeoutMs = 10000) {
    await this.openAdapter();
    const found = new Map();
    let totalSeen = 0;

    const onFound = (res) => {
      for (const d of (res.devices || [])) {
        totalSeen++;
        const name = d.name || d.localName || '';
        if (name.indexOf(NAME_PREFIX) === 0) {
          // 后报覆盖先报：首报可能尚无名称，去重同时保留最新信号
          found.set(d.deviceId, {
            deviceId: d.deviceId,
            name,
            rssi: d.RSSI,
          });
        }
      }
    };

    wx.onBluetoothDeviceFound(onFound);
    try {
      await wxAsync(wx.startBluetoothDevicesDiscovery, {
        allowDuplicatesKey: true,   // 持续上报（部分 Android 首次发现时名称为空）
      });
    } catch (e) {
      if (wx.offBluetoothDeviceFound) { wx.offBluetoothDeviceFound(onFound); }
      const m = (e.message || '').toLowerCase();
      if (m.indexOf('10001') >= 0 || m.indexOf('not available') >= 0) {
        throw new Error('蓝牙未开启或不可用：请打开手机蓝牙后重试');
      }
      if (m.indexOf('auth') >= 0 || m.indexOf('permission') >= 0 || m.indexOf('deny') >= 0) {
        throw new Error('微信缺少蓝牙权限：iOS 到 设置→微信→蓝牙 打开；Android 允许“附近的设备”权限');
      }
      throw new Error('扫描启动失败：' + e.message);
    }

    await new Promise((r) => setTimeout(r, timeoutMs));

    await wxAsync(wx.stopBluetoothDevicesDiscovery).catch(() => {});
    if (wx.offBluetoothDeviceFound) { wx.offBluetoothDeviceFound(onFound); }

    const devices = Array.from(found.values())
      .sort((a, b) => (b.rssi || -999) - (a.rssi || -999));
    return { devices, totalSeen };
  }

  /* ---------------- 连接 ---------------- */

  /**
   * 连接设备 + 发现特征 + 订阅通知。
   * 注意：小程序重启后底层 GATT 连接可能仍残留（微信进程级），直接
   * createBLEConnection 会报 "already connect" —— 因此先主动清理。
   */
  async connect(deviceId) {
    if (this.connected) { await this.disconnect(); }

    // 清理残留连接（对未连接的设备会报错，忽略即可）
    await wxAsync(wx.closeBLEConnection, { deviceId }).catch(() => {});
    await new Promise((r) => setTimeout(r, 150));

    try {
      await wxAsync(wx.createBLEConnection, { deviceId, timeout: 15000 });
    } catch (e) {
      if (/already/i.test(e.message)) {
        // 仍有残留：强制关闭后等待重试一次
        await wxAsync(wx.closeBLEConnection, { deviceId }).catch(() => {});
        await new Promise((r) => setTimeout(r, 400));
        await wxAsync(wx.createBLEConnection, { deviceId, timeout: 15000 });
      } else {
        throw new Error('连接失败：' + e.message);
      }
    }
    this.deviceId = deviceId;
    this.connected = true;

    // Android 需要显式请求大 MTU（长响应需要 >29 字节）；iOS 会自动协商 185
    try {
      const res = await wxAsync(wx.setBLEMTU, { deviceId, mtu: 256 });
      this.mtu = res.mtu || 256;
    } catch (e) {
      this.mtu = 23;   // iOS 或失败: 保持默认（iOS 实际可用更大）
    }

    // 服务发现
    const svcRes = await wxAsync(wx.getBLEDeviceServices, { deviceId });
    const svc = (svcRes.services || []).find(
      (s) => s.uuid.toUpperCase() === UUID_SVC);
    if (!svc) {
      await this.disconnect();
      throw new Error('未找到管理服务（0xFFF0），请确认设备固件正确');
    }
    this.svcId = svc.uuid;

    const chrRes = await wxAsync(wx.getBLEDeviceCharacteristics, {
      deviceId, serviceId: this.svcId,
    });
    for (const c of (chrRes.characteristics || [])) {
      const u = c.uuid.toUpperCase();
      if (u === UUID_CMD) { this.cmdCharId = c.uuid; }
      if (u === UUID_RESP) { this.respCharId = c.uuid; }
    }
    if (!this.cmdCharId || !this.respCharId) {
      await this.disconnect();
      throw new Error('管理服务特征不完整，请确认设备固件版本');
    }

    // 订阅响应通知
    this._bindListener();
    await wxAsync(wx.notifyBLECharacteristicValueChange, {
      deviceId, serviceId: this.svcId,
      characteristicId: this.respCharId, state: true,
    });
  }

  _bindListener() {
    if (this._listenerBound) { return; }
    this._listenerBound = true;
    wx.onBLECharacteristicValueChange((res) => {
      if (res.deviceId !== this.deviceId) { return; }
      if (!this._notifyCb) { return; }
      this._notifyCb(new Uint8Array(res.value));
    });
  }

  onNotify(cb) {
    this._notifyCb = cb;
  }

  /* ---------------- 写入（串行分片） ---------------- */

  /**
   * 依次写入各分片（每片 ≤ 20 字节）；串行 + 等待 GATT 回执，保证设备端
   * 分片重组不会因拥塞丢片。
   */
  async writeChunks(chunks) {
    if (!this.connected) { throw new Error('设备未连接'); }
    for (const c of chunks) {
      if (c.length > 20) {
        throw new Error('内部分片错误（片长 ' + c.length + ' > 20）');
      }
      await wxAsync(wx.writeBLECharacteristicValue, {
        deviceId: this.deviceId,
        serviceId: this.svcId,
        characteristicId: this.cmdCharId,
        value: c.buffer.slice(c.byteOffset, c.byteOffset + c.byteLength),
      });
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
      await wxAsync(wx.closeBLEConnection, { deviceId: id }).catch(() => {});
    }
  }
}

module.exports = new Ble();
