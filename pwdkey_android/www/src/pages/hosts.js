/**
 * pages/hosts.js - 已连接的电脑（改名 / 查看 / 断开），对应小程序 pages/hosts
 */
const { pwdkey } = require('../utils/pwdkey.js');
const ui = require('../ui.js');
const router = require('../router.js');

module.exports = {
  title: '已连接的电脑',

  render() {
    return `
      <div class="page-topbar">
        <div>
          <div class="page-topbar-title">已连接的电脑</div>
          <div class="muted">名字保存在设备上，换手机也不会丢</div>
        </div>
        <div class="icon-btn" id="h-refresh">⟳</div>
      </div>

      <div class="card list-card" id="h-list">
        <div class="empty muted">读取中…</div>
      </div>

      <div class="hint muted">
        名字优先用设备自动读到的蓝牙名；读不到时会显示为「电脑 XXXX」。<br>
        点击任意一台即可改名或断开连接。<br>
        Windows 电脑通常读不到蓝牙名，需要手动改名。
      </div>
    `;
  },

  mount() {
    const listEl = document.getElementById('h-list');
    let hosts = [];
    let addrMap = {};        // mac -> Uint8Array（不放进 DOM/dataset）

    document.getElementById('h-refresh').onclick = () => load();

    async function load() {
      listEl.innerHTML = `<div class="empty muted">读取中…</div>`;
      try {
        hosts = await pwdkey.listHosts();
        addrMap = {};
        hosts.forEach((h) => { addrMap[h.mac] = h.addr; });
        draw();
      } catch (e) {
        listEl.innerHTML = `<div class="err-box">${ui.esc(e.message || '读取失败')}</div>`;
        if (e.code === 0x4002 || e.code === 0x400B) {
          const r = await ui.modal({
            title: '需要解锁',
            content: '查看设备列表需要先用主密码解锁。',
            confirmText: '去解锁',
          });
          if (r.confirm) { router.go('unlock', { replace: true }); }
        }
      }
    }

    function draw() {
      if (!hosts.length) {
        listEl.innerHTML = `
          <div class="empty">
            <div class="empty-icon">🖥️</div>
            <div class="muted">还没有记录</div>
            <div class="muted" style="margin-top:0.6rem">在电脑上配对设备后，这里会自动出现</div>
          </div>`;
        return;
      }

      listEl.innerHTML = hosts.map((h) => `
        <div class="host ${h.online ? '' : 'host-off'}" data-mac="${ui.esc(h.mac)}">
          <div class="host-icon">${h.isUsb ? '🔌' : (h.hid ? '⌨️' : '📱')}</div>
          <div class="host-body">
            <div class="host-name">${ui.esc(h.name)}${h.isUsb ? '<span class="tag tag-usb">USB</span>' : ''}${h.userNamed ? '<span class="tag">自定义</span>' : ''}</div>
            <div class="host-mac mono">${h.isUsb ? (h.online ? '已通过数据线连接' : '未插线') : ui.esc(h.mac)}</div>
          </div>
          <div class="host-status">
            <div class="dot ${h.online ? 'dot-on' : 'dot-off'}"></div>
            <div class="host-status-text">${h.online ? '在线' : '离线'}</div>
          </div>
        </div>`).join('');

      listEl.querySelectorAll('.host').forEach((el) => {
        el.onclick = () => openActions(el.dataset.mac);
      });
    }

    /* ---------------- 操作浮层 ---------------- */

    function openActions(mac) {
      const h = hosts.find((x) => x.mac === mac);
      if (!h) { return; }

      const el = ui.h(`<div class="mask" id="h-act">
        <div class="dialog">
          <div class="dialog-title">${ui.esc(h.name)}</div>
          <div class="muted" style="text-align:center;margin-bottom:0.8rem">${h.isUsb ? 'USB 直连（有线）' : ui.esc(h.mac)}</div>
          <button class="btn btn-primary" data-act="rename">✏️ 改名</button>
          <button class="btn btn-ghost" data-act="reset">恢复默认名（${h.isUsb ? 'USB 直连' : '电脑 XXXX'}）</button>
          ${h.isUsb ? '' : '<button class="btn btn-danger" data-act="disc">断开这台</button>'}
          <button class="btn btn-ghost" data-act="close">关闭</button>
        </div>
      </div>`);

      el.addEventListener('click', async (ev) => {
        if (ev.target === el) { el.remove(); return; }
        const act = ev.target.getAttribute && ev.target.getAttribute('data-act');
        if (!act) { return; }

        if (act === 'close') { el.remove(); return; }

        if (act === 'rename') {
          el.remove();
          const r = await ui.modal({
            title: '给这台电脑起名',
            editable: true,
            placeholderText: '例如：书房台式机',
            content: h.userNamed ? h.name : '',
            maxLength: 10,
            confirmText: '保存',
          });
          if (!r.confirm) { return; }
          const name = (r.content || '').trim();
          if (!name) { return; }
          ui.showLoading('保存中');
          try {
            await pwdkey.renameHost(addrMap[h.mac], name);
            ui.hideLoading();
            ui.toast('已保存');
            load();
          } catch (e) {
            ui.hideLoading();
            ui.toast(e.message || '保存失败', { duration: 3000 });
          }
          return;
        }

        if (act === 'reset') {
          el.remove();
          ui.showLoading('处理中');
          try {
            await pwdkey.renameHost(addrMap[h.mac], '');
            ui.hideLoading();
            ui.toast('已恢复默认名');
            load();
          } catch (e) {
            ui.hideLoading();
            ui.toast(e.message || '操作失败', { duration: 3000 });
          }
          return;
        }

        if (act === 'disc') {
          el.remove();
          if (!h.online) {
            ui.toast('这台当前不在线');
            return;
          }
          const r = await ui.modal({
            title: '断开这台电脑？',
            content: `${h.name} 当前在线。断开后这台电脑不能再把它当键盘用，需要在电脑上重新配对。`,
            confirmText: '断开',
            confirmColor: '#dc2626',
          });
          if (!r.confirm) { return; }
          ui.showLoading('断开中');
          try {
            await pwdkey.disconnectHost(addrMap[h.mac]);
            ui.hideLoading();
            ui.toast('已断开');
            load();
          } catch (e) {
            ui.hideLoading();
            ui.modal({ title: '无法断开', content: e.message || '操作失败', showCancel: false });
          }
        }
      });

      document.body.appendChild(el);
    }

    load();
  },
};
