const { pwdkey, PwdKeyError } = require('../../utils/pwdkey.js');

Page({
  data: {
    hosts: [],        // 纯数据（不含 Uint8Array）
    loading: false,
    err: '',
    acting: false,
    busy: false,
    cur: null,        // { mac, name, online, hid, userNamed }
  },

  onShow() {
    this.load();
  },

  async load() {
    this.setData({ loading: true, err: '' });
    try {
      const hosts = await pwdkey.listHosts();
      /* addr(Uint8Array) 不进 setData（部分机型序列化会丢失），单独留一张映射表 */
      this._addrMap = {};
      hosts.forEach((h) => { this._addrMap[h.mac] = h.addr; });
      this.setData({ hosts, loading: false });
    } catch (e) {
      const msg = e instanceof PwdKeyError ? e.message : (e.message || String(e));
      this.setData({ loading: false, err: msg });
      if (e.code === 0x4002 || e.code === 0x400B) {
        wx.showModal({
          title: '需要解锁',
          content: '查看设备列表需要先用主密码解锁。',
          confirmText: '去解锁',
          success: (r) => {
            if (r.confirm) { wx.redirectTo({ url: '/pages/unlock/unlock' }); }
          },
        });
      }
    }
  },

  onRefresh() {
    this.load();
  },

  noop() {},

  onHostTap(e) {
    const mac = e.currentTarget.dataset.mac;
    const cur = this.data.hosts.find((h) => h.mac === mac);
    if (!cur) { return; }
    this.setData({ acting: true, cur });
  },

  onCloseAct() {
    this.setData({ acting: false, cur: null });
  },

  _addr(mac) {
    return this._addrMap && this._addrMap[mac];
  },

  _errText(e) {
    return e instanceof PwdKeyError ? e.message : (e.message || String(e));
  },

  onRename() {
    const cur = this.data.cur;
    if (!cur) { return; }
    wx.showModal({
      title: '给这台电脑起名',
      editable: true,
      placeholderText: '例如：书房台式机',
      content: cur.userNamed ? cur.name : '',
      maxLength: 10,
      success: async (r) => {
        if (!r.confirm) { return; }
        const name = (r.content || '').trim();
        if (!name) { return; }
        const addr = this._addr(cur.mac);
        if (!addr) { return; }
        wx.showLoading({ title: '保存中', mask: true });
        try {
          await pwdkey.renameHost(addr, name);
          wx.hideLoading();
          wx.showToast({ title: '已保存', icon: 'success' });
          this.setData({ acting: false, cur: null });
          await this.load();
        } catch (e) {
          wx.hideLoading();
          wx.showToast({ title: this._errText(e), icon: 'none', duration: 3000 });
        }
      },
    });
  },

  async onResetName() {
    const cur = this.data.cur;
    if (!cur) { return; }
    const addr = this._addr(cur.mac);
    if (!addr) { return; }
    wx.showLoading({ title: '处理中', mask: true });
    try {
      await pwdkey.renameHost(addr, '');
      wx.hideLoading();
      wx.showToast({ title: '已恢复默认名', icon: 'success' });
      this.setData({ acting: false, cur: null });
      await this.load();
    } catch (e) {
      wx.hideLoading();
      wx.showToast({ title: this._errText(e), icon: 'none', duration: 3000 });
    }
  },

  onDisconnect() {
    const cur = this.data.cur;
    if (!cur) { return; }
    if (!cur.online) {
      wx.showToast({ title: '这台当前不在线', icon: 'none' });
      return;
    }
    wx.showModal({
      title: '断开这台电脑？',
      content: `${cur.name} 当前在线。断开后这台电脑不能再把它当键盘用，需要在电脑上重新配对。`,
      confirmText: '断开',
      confirmColor: '#dc2626',
      success: async (r) => {
        if (!r.confirm) { return; }
        const addr = this._addr(cur.mac);
        if (!addr) { return; }
        this.setData({ busy: true });
        try {
          await pwdkey.disconnectHost(addr);
          this.setData({ busy: false, acting: false, cur: null });
          wx.showToast({ title: '已断开', icon: 'success' });
          await this.load();
        } catch (e) {
          this.setData({ busy: false });
          wx.showModal({ title: '无法断开', content: this._errText(e), showCancel: false });
        }
      },
    });
  },
});
