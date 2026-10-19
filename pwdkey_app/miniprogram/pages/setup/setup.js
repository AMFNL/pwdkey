/**
 * setup - 首次设置主密码（S0 出厂态）
 */
const { pwdkey } = require('../../utils/pwdkey.js');

Page({
  data: {
    pwd1: '',
    pwd2: '',
    showPwd: false,
    phase: 'input',        // input | computing | waiting | done
    progress: 0,
    countdown: 0,
    recoveryCode: '',
    err: '',
    copied: false,
  },

  onInput1(e) { this.setData({ pwd1: e.detail.value, err: '' }); },
  onInput2(e) { this.setData({ pwd2: e.detail.value, err: '' }); },
  toggleShow() { this.setData({ showPwd: !this.data.showPwd }); },

  validate() {
    const { pwd1, pwd2 } = this.data;
    if (!pwd1) { return '请输入主密码'; }
    if (pwd1 !== pwd2) { return '两次输入不一致'; }
    if (!/^[\x20-\x7E]+$/.test(pwd1)) {
      return '主密码只能使用 ASCII 字符（英文/数字/常见符号）';
    }
    if (pwd1.length < 8) {
      return '主密码至少 8 位（建议 12 位以上，混合大小写/数字/符号）';
    }
    return '';
  },

  async onStart() {
    const err = this.validate();
    if (err) { this.setData({ err }); return; }

    this.setData({ phase: 'computing', progress: 0, err: '' });
    try {
      const code = await pwdkey.setPassword(this.data.pwd1, {
        onProgress: (f) => this.setData({ progress: Math.floor(f * 100) }),
        onWaiting: () => {
          this.setData({ phase: 'waiting' });
          this.startCountdown(60);
        },
      });
      this.stopCountdown();
      if (wx.vibrateShort) { wx.vibrateShort({ type: 'medium' }); }
      this.setData({ phase: 'done', recoveryCode: code });
    } catch (e) {
      this.stopCountdown();
      this.setData({ phase: 'input', err: e.message || '设置失败，请重试' });
    }
  },

  startCountdown(sec) {
    this.stopCountdown();
    this.setData({ countdown: sec });
    this._cd = setInterval(() => {
      const n = this.data.countdown - 1;
      this.setData({ countdown: n > 0 ? n : 0 });
      if (n <= 0) { this.stopCountdown(); }
    }, 1000);
  },

  stopCountdown() {
    if (this._cd) { clearInterval(this._cd); this._cd = null; }
  },

  copyCode() {
    wx.setClipboardData({
      data: this.data.recoveryCode,
      success: () => this.setData({ copied: true }),
    });
  },

  onDone() {
    wx.showToast({ title: '设备已启用', icon: 'success' });
    setTimeout(() => wx.navigateBack(), 600);
  },

  onUnload() { this.stopCountdown(); },
});
