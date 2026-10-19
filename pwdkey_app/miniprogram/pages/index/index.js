/**
 * index - 连接与状态中心
 */
const ble = require('../../utils/ble.js');
const { pwdkey } = require('../../utils/pwdkey.js');

Page({
  data: {
    scanning: false,
    devices: [],
    connecting: false,
    connected: false,
    unlocked: false,
    devName: '',
    info: null,
    err: '',
  },

  onShow() {
    // info 缺失视为未连接（防止半连接脏状态被误显示）
    const reallyConnected = pwdkey.connected && !!pwdkey.info;
    this.setData({
      connected: reallyConnected,
      info: pwdkey.info,
      unlocked: pwdkey.isUnlocked(),
      devName: this.data.devName || wx.getStorageSync('lastDeviceName') || 'PwdKey',
    });
    if (pwdkey.connected && !pwdkey.info) {
      // 连接还在但信息缺失：补一次
      pwdkey.refreshInfo().then((info) => {
        this.setData({ connected: true, info });
      }).catch(() => {});
    } else if (!pwdkey.connected) {
      // 小程序重启后 JS 状态丢失：尝试用上次的设备自动恢复连接
      this.tryAutoReconnect();
    }
  },

  /** 静默尝试恢复上次的连接（免手动扫描；失败不打扰用户） */
  async tryAutoReconnect() {
    const lastId = wx.getStorageSync('lastDeviceId');
    if (!lastId || this._restoring || this.data.scanning || this.data.connecting) {
      return;
    }
    this._restoring = true;
    try {
      const info = await pwdkey.connect(lastId);
      this.setData({
        connected: true,
        info,
        devName: wx.getStorageSync('lastDeviceName') || 'PwdKey',
      });
      wx.showToast({ title: '已自动重连设备', icon: 'none', duration: 1200 });
    } catch (e) {
      /* 设备不在附近或未广播：静默失败，用户可手动扫描 */
    } finally {
      this._restoring = false;
    }
  },

  onUnload() {
    // 离开首页只提示，不断开（便于跨页使用会话）
  },

  async onScan() {
    if (this.data.scanning) { return; }
    this.setData({ scanning: true, devices: [], err: '' });
    try {
      const { devices, totalSeen } = await ble.scan(10000);
      this.setData({ devices });
      if (!devices.length) {
        if (totalSeen === 0) {
          this.setData({
            err: '未发现任何蓝牙设备 —— 多半是权限问题：\n' +
                 '· iOS：设置→微信→蓝牙 打开权限；确认系统蓝牙已开启\n' +
                 '· Android：允许微信“附近的设备”权限；旧系统还需打开“位置信息”开关',
          });
        } else {
          this.setData({
            err: `扫描完成：共发现 ${totalSeen} 个蓝牙设备，但没有 PwdKey。` +
                 '请把手机靠近设备（1 米内）再点一次扫描。',
          });
        }
      }
    } catch (e) {
      this.setData({ err: e.message || '扫描失败' });
    } finally {
      this.setData({ scanning: false });
    }
  },

  async onConnect(e) {
    const { deviceId, name } = e.currentTarget.dataset;
    if (this.data.connecting) { return; }
    this.setData({ connecting: true, err: '' });
    try {
      const info = await pwdkey.connect(deviceId);
      wx.setStorageSync('lastDeviceId', deviceId);
      wx.setStorageSync('lastDeviceName', name || '');
      this.setData({ connected: true, devName: name || 'PwdKey', info, devices: [] });
    } catch (err) {
      this.setData({ err: err.message || '连接失败' });
    } finally {
      this.setData({ connecting: false });
    }
  },

  async onDisconnect() {
    await pwdkey.disconnect();
    this.setData({ connected: false, info: null, devName: '' });
  },

  async onRefresh() {
    if (!pwdkey.connected) { return; }
    try {
      const info = await pwdkey.refreshInfo();
      this.setData({ info });
    } catch (e) {
      this.setData({ err: e.message });
    }
  },

  goSetup() {
    wx.navigateTo({ url: '/pages/setup/setup' });
  },

  goUnlock() {
    wx.navigateTo({ url: '/pages/unlock/unlock' });
  },

  goVault() {
    if (pwdkey.isUnlocked()) {
      wx.navigateTo({ url: '/pages/vault/vault' });
    } else {
      wx.navigateTo({ url: '/pages/unlock/unlock' });
    }
  },
});
