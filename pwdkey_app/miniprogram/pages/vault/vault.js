/**
 * vault - 密码库（已解锁状态下的主操作页）
 */
const { pwdkey } = require('../../utils/pwdkey.js');

Page({
  data: {
    entries: [],
    loading: true,
    err: '',

    // 添加弹窗
    showAdd: false,
    addName: '',
    addPwd: '',
    addPwd2: '',
    addErr: '',
    adding: false,

    // 输出等待浮层
    typing: false,
    typeCountdown: 0,
    typeEntryId: '',

    // 配对等待浮层
    pairing: false,
    pairingCountdown: 0,
  },

  onLoad() {
    if (!pwdkey.isUnlocked()) {
      wx.redirectTo({ url: '/pages/unlock/unlock' });
      return;
    }
    this.loadEntries();
  },

  onShow() {
    if (pwdkey.connected && pwdkey.isUnlocked() && !this.data.loading) {
      this.loadEntries();
    }
  },

  async loadEntries() {
    this.setData({ loading: true, err: '' });
    try {
      const { ids } = await pwdkey.listEntries();
      this.setData({ entries: ids.map((id) => ({ id, name: '' })), loading: false });
      this.loadNames(ids);
    } catch (e) {
      this.setData({ loading: false, err: e.message || '读取失败' });
      if (e.code === 0x4002) {
        wx.redirectTo({ url: '/pages/unlock/unlock' });
      }
    }
  },

  /** 后台逐条补名称（名称仅存于设备，不阻塞列表展示） */
  async loadNames(ids) {
    for (const id of ids) {
      try {
        const name = await pwdkey.getEntryName(id);
        this.setData({
          entries: this.data.entries.map((it) =>
            it.id === id ? { id: it.id, name } : it),
        });
      } catch (e) { /* 单条失败忽略 */ }
      await new Promise((r) => setTimeout(r, 60));
    }
  },

  /* ---------------- 条目操作 ---------------- */

  onEntryTap(e) {
    const id = e.currentTarget.dataset.id;
    wx.showActionSheet({
      itemList: ['输出到电脑（键盘输入）', '查看名称', '删除条目'],
      success: (res) => {
        if (res.tapIndex === 0) { this.onType(id); }
        else if (res.tapIndex === 1) { this.onViewName(id); }
        else if (res.tapIndex === 2) { this.onDelete(id); }
      },
    });
  },

  onHosts() {
    wx.navigateTo({ url: '/pages/hosts/hosts' });
  },

  async onType(id) {
    if (this.data.typing || this.data.pairing) { return; }   // 防重入
    this.setData({ typing: true, typeCountdown: 0, typeEntryId: id });
    try {
      await pwdkey.typeEntry(id, {
        onWaiting: (timeoutMs) => {
          this.startCountdown('typeCountdown', Math.floor(timeoutMs / 1000));
        },
        // 多台电脑在线时：让用户按【名字】选择输出目标
        onPickTarget: (cands) => new Promise((resolve) => {
          this.stopCountdown('typeCountdown');
          wx.showActionSheet({
            itemList: cands.map((c) => `输出到 ${c.name}`),
            success: (res) => resolve(cands[res.tapIndex] ? cands[res.tapIndex].addr : null),
            fail: () => resolve(null),
          });
        }),
      });
      this.stopCountdown('typeCountdown');
      if (wx.vibrateShort) { wx.vibrateShort({ type: 'heavy' }); }
      this.setData({ typing: false });
      wx.showToast({ title: '已输出到电脑 ✓', icon: 'success', duration: 2000 });
    } catch (e) {
      this.stopCountdown('typeCountdown');
      this.setData({ typing: false });
      if (e.code === 0x3005) {
        wx.showModal({
          title: '⚠️ 输出中断',
          content: '电脑上可能只打出了部分密码！请检查并清除电脑上的输入框，然后重试。',
          showCancel: false,
        });
      } else if (e.code === 0x400B) {
        wx.showModal({
          title: '会话已过期',
          content: '为安全起见，解锁后 30 秒内才能输出密码。请重新解锁后重试。',
          confirmText: '去解锁',
          success: (r) => {
            if (r.confirm) { wx.redirectTo({ url: '/pages/unlock/unlock' }); }
          },
        });
      } else if (e.code === 0x3004) {
        wx.showToast({ title: '已取消', icon: 'none' });
      } else {
        wx.showToast({ title: e.message || '输出失败', icon: 'none', duration: 3000 });
      }
    }
  },

  onViewName(id) {
    const item = this.data.entries.find((it) => it.id === id);
    if (item && item.name) {
      wx.showModal({ title: '条目名称', content: item.name, showCancel: false });
      return;
    }
    wx.showLoading({ title: '读取中' });
    pwdkey.getEntryName(id).then((name) => {
      wx.hideLoading();
      wx.showModal({ title: '条目名称', content: name || '（无名称）', showCancel: false });
    }).catch((e) => {
      wx.hideLoading();
      wx.showToast({ title: e.message, icon: 'none' });
    });
  },

  onDelete(id) {
    wx.showModal({
      title: '删除条目',
      content: '确定删除 ' + id + '？删除后无法恢复。',
      confirmColor: '#dc2626',
      success: async (res) => {
        if (!res.confirm) { return; }
        try {
          await pwdkey.deleteEntry(id);
          wx.showToast({ title: '已删除', icon: 'success' });
          this.loadEntries();
        } catch (e) {
          wx.showToast({ title: e.message, icon: 'none' });
        }
      },
    });
  },

  /* ---------------- 添加条目 ---------------- */

  showAddDialog() {
    this.setData({ showAdd: true, addName: '', addPwd: '', addPwd2: '', addErr: '' });
  },
  hideAddDialog() { this.setData({ showAdd: false }); },
  onAddName(e) { this.setData({ addName: e.detail.value }); },
  onAddPwd1(e) { this.setData({ addPwd: e.detail.value }); },
  onAddPwd2(e) { this.setData({ addPwd2: e.detail.value }); },

  async onAddSubmit() {
    const { addName, addPwd, addPwd2 } = this.data;
    if (!addPwd) { this.setData({ addErr: '请输入密码' }); return; }
    if (addPwd !== addPwd2) { this.setData({ addErr: '两次输入不一致' }); return; }
    if (!/^[\x20-\x7E]+$/.test(addPwd)) {
      this.setData({ addErr: '密码只能使用 ASCII 字符（中文/emoji 无法通过键盘输入）' });
      return;
    }
    this.setData({ adding: true, addErr: '' });
    try {
      const id = await pwdkey.addEntry(addPwd, addName || '');
      this.setData({ showAdd: false, adding: false });
      wx.showToast({ title: '已添加 ' + id, icon: 'success' });
      this.loadEntries();
    } catch (e) {
      this.setData({ adding: false, addErr: e.message || '添加失败' });
    }
  },

  /* ---------------- 配对模式 ---------------- */

  async onPair() {
    if (this.data.typing || this.data.pairing) { return; }   // 防重入
    this.setData({ pairing: true, pairingCountdown: 0 });
    try {
      await pwdkey.enterPairing({
        onWaiting: () => this.startCountdown('pairingCountdown', 30),
      });
      this.stopCountdown('pairingCountdown');
      this.setData({ pairing: false });
      wx.showModal({
        title: '设备已进入配对模式',
        content: '请在 60 秒内到本机的「系统蓝牙设置 → 添加设备」里选择 PwdKey 设备完成配对。',
        showCancel: false,
      });
    } catch (e) {
      this.stopCountdown('pairingCountdown');
      this.setData({ pairing: false });
      wx.showToast({ title: e.message || '操作失败', icon: 'none', duration: 3000 });
    }
  },

  /* ---------------- 锁定 ---------------- */

  async onLock() {
    await pwdkey.lock();
    wx.showToast({ title: '已锁定', icon: 'success' });
    setTimeout(() => wx.navigateBack(), 400);
  },

  /* ---------------- 倒计时 ---------------- */

  startCountdown(key, sec) {
    this.stopCountdown(key);
    this.setData({ [key]: sec });
    this._timers = this._timers || {};
    this._timers[key] = setInterval(() => {
      const n = (this.data[key] || 0) - 1;
      this.setData({ [key]: n > 0 ? n : 0 });
      if (n <= 0) { this.stopCountdown(key); }
    }, 1000);
  },

  stopCountdown(key) {
    if (this._timers && this._timers[key]) {
      clearInterval(this._timers[key]);
      this._timers[key] = null;
    }
  },

  onUnload() {
    this.stopCountdown('typeCountdown');
    this.stopCountdown('pairingCountdown');
  },

  /** 阻止弹窗内点击冒泡到遮罩（避免误关闭） */
  noop() {},
});
