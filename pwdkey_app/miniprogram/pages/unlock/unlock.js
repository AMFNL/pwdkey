/**
 * unlock - 解锁设备（主密码认证）
 */
const { pwdkey } = require('../../utils/pwdkey.js');

Page({
  data: {
    pwd: '',
    showPwd: false,
    phase: 'input',      // input | computing | error
    progress: 0,
    err: '',
    lockedSeconds: 0,
  },

  onInput(e) { this.setData({ pwd: e.detail.value, err: '' }); },
  toggleShow() { this.setData({ showPwd: !this.data.showPwd }); },

  async onUnlock() {
    if (!this.data.pwd) { return; }
    this.setData({ phase: 'computing', progress: 0, err: '' });
    try {
      await pwdkey.unlock(this.data.pwd, {
        onProgress: (f) => this.setData({ progress: Math.floor(f * 100) }),
      });
      if (wx.vibrateShort) { wx.vibrateShort({ type: 'medium' }); }
      wx.redirectTo({ url: '/pages/vault/vault' });
    } catch (e) {
      const locked = (e.code === 0x4003 || e.code === 0x4004);
      this.setData({
        phase: 'input',
        pwd: '',
        err: e.message || '解锁失败',
        lockedSeconds: locked ? (pwdkey.info && pwdkey.info.lockSeconds) || 0 : 0,
      });
      if (e.code === 0x4004) {
        wx.showModal({
          title: '设备已永久锁定',
          content: '需使用恢复码重置设备（会清空全部密码）。请参考《使用手册》操作。',
          showCancel: false,
        });
      }
    }
  },

  onUnload() {
    // 清理输入
    this.setData({ pwd: '' });
  },
});
