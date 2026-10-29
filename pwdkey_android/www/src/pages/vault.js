/**
 * pages/vault.js - 密码库（已解锁状态下的主操作页），对应小程序 pages/vault
 */
const { pwdkey } = require('../utils/pwdkey.js');
const exporter = require('../utils/export.js');
const ui = require('../ui.js');
const router = require('../router.js');

const ASCII_RE = /^[\x20-\x7E]+$/;

module.exports = {
  title: '密码库',

  render() {
    return `
      <div class="page-topbar">
        <div>
          <div class="page-topbar-title">密码库</div>
          <div class="muted" id="v-count">读取中…</div>
        </div>
        <div class="topbar-actions">
          <div class="icon-btn" id="v-sec">⚙️</div>
          <div class="icon-btn" id="v-hosts">🖥️</div>
          <div class="icon-btn" id="v-pair">🔗</div>
          <div class="icon-btn" id="v-lock">🔒</div>
        </div>
      </div>

      <div class="card list-card" id="v-list">
        <div class="empty muted">读取中…</div>
      </div>

      <div class="card">
        <button class="btn btn-primary" id="v-add">＋ 添加密码</button>
        <button class="btn btn-ghost" id="v-pair2">配对新电脑（蓝牙）</button>
        <button class="btn btn-ghost" id="v-usb">🔌 USB 直连（插线即用）</button>
        <button class="btn btn-ghost" id="v-hosts2">🖥️ 已连接的电脑（改名 / 断开）</button>
        <button class="btn btn-ghost" id="v-export">📦 导出加密备份</button>
        <button class="btn btn-ghost" id="v-import">📥 导入备份</button>
      </div>

      <div class="hint muted">
        输出密码时：先在电脑上点入输入框，再在设备上短按 BOOT 确认。
      </div>
    `;
  },

  mount() {
    const listEl = document.getElementById('v-list');
    const countEl = document.getElementById('v-count');

    let entries = [];          // [{id, name}]
    let busy = false;          // 输出 / 配对进行中（防重入）
    let timers = {};

    document.getElementById('v-sec').onclick = () => router.go('security');
    document.getElementById('v-hosts').onclick = () => router.go('hosts');
    document.getElementById('v-hosts2').onclick = () => router.go('hosts');
    document.getElementById('v-pair').onclick = onPair;
    document.getElementById('v-pair2').onclick = onPair;
    document.getElementById('v-usb').onclick = onUsbGuide;
    document.getElementById('v-export').onclick = onExport;
    document.getElementById('v-import').onclick = onImport;
    document.getElementById('v-lock').onclick = onLock;
    document.getElementById('v-add').onclick = showAddDialog;

    /* ---------------- 列表 ---------------- */

    async function loadEntries() {
      try {
        const { ids } = await pwdkey.listEntries();
        entries = ids.map((id) => ({ id, name: '' }));
        drawList();
        loadNames(ids);
      } catch (e) {
        listEl.innerHTML = `<div class="err-box">${ui.esc(e.message || '读取失败')}</div>`;
        if (e.code === 0x4002) { router.go('unlock', { replace: true }); }
      }
    }

    function drawList() {
      countEl.textContent = `${entries.length} 条 · 点击条目进行操作`;
      if (!entries.length) {
        listEl.innerHTML = `
          <div class="empty">
            <div class="empty-icon">📭</div>
            <div class="muted">还没有密码条目</div>
          </div>`;
        return;
      }
      listEl.innerHTML = entries.map((it) => `
        <div class="entry" data-id="${ui.esc(it.id)}">
          <div class="entry-icon">🔑</div>
          <div class="entry-body">
            <div class="entry-name">${ui.esc(it.name || '（读取名称中…）')}</div>
            <div class="entry-id mono">${ui.esc(it.id)}</div>
          </div>
          <div class="entry-arrow">›</div>
        </div>`).join('');

      listEl.querySelectorAll('.entry').forEach((el) => {
        el.onclick = () => onEntryTap(el.dataset.id);
      });
    }

    /** 后台逐条补名称（名称仅存于设备，不阻塞列表展示） */
    async function loadNames(ids) {
      for (const id of ids) {
        try {
          const name = await pwdkey.getEntryName(id);
          const it = entries.find((x) => x.id === id);
          if (it) { it.name = name; }
          const el = listEl.querySelector(`.entry[data-id="${id}"] .entry-name`);
          if (el) { el.textContent = name || '（无名称）'; }
        } catch (e) { /* 单条失败忽略 */ }
        await ui.sleep(60);
      }
    }

    /* ---------------- 条目操作 ---------------- */

    async function onEntryTap(id) {
      if (busy) { return; }
      const res = await ui.actionSheet({
        itemList: ['输出到电脑（键盘输入）', '重命名', '查看名称', '删除条目'],
      });
      if (!res) { return; }
      if (res.tapIndex === 0) { onType(id); }
      else if (res.tapIndex === 1) { onRename(id); }
      else if (res.tapIndex === 2) { onViewName(id); }
      else if (res.tapIndex === 3) { onDelete(id); }
    }

    async function onRename(id) {
      const it = entries.find((x) => x.id === id);
      const r = await ui.modal({
        title: '重命名条目',
        editable: true,
        placeholderText: '例如：微信',
        content: it && it.name ? it.name : '',
        maxLength: 20,
        confirmText: '保存',
      });
      if (!r.confirm) { return; }
      const name = (r.content || '').trim();
      if (!name) { ui.toast('名称不能为空'); return; }
      ui.showLoading('保存中');
      try {
        await pwdkey.renameEntry(id, name);
        ui.hideLoading();
        ui.toast('已重命名');
        loadEntries();
      } catch (e) {
        ui.hideLoading();
        ui.toast(e.message || '重命名失败');
      }
    }

    async function onViewName(id) {
      const it = entries.find((x) => x.id === id);
      if (it && it.name) {
        ui.modal({ title: '条目名称', content: it.name, showCancel: false });
        return;
      }
      ui.showLoading('读取中');
      try {
        const name = await pwdkey.getEntryName(id);
        ui.hideLoading();
        ui.modal({ title: '条目名称', content: name || '（无名称）', showCancel: false });
      } catch (e) {
        ui.hideLoading();
        ui.toast(e.message || '读取失败');
      }
    }

    async function onDelete(id) {
      const r = await ui.modal({
        title: '删除条目',
        content: '确定删除 ' + id + '？删除后无法恢复。',
        confirmText: '删除',
        confirmColor: '#dc2626',
      });
      if (!r.confirm) { return; }
      try {
        await pwdkey.deleteEntry(id);
        ui.toast('已删除');
        loadEntries();
      } catch (e) {
        ui.toast(e.message || '删除失败');
      }
    }

    /* ---------------- 输出密码 ---------------- */

    function showWaitingOverlay(icon, title) {
      const el = ui.h(`<div class="mask" id="v-wait">
        <div class="dialog" style="text-align:center">
          <div class="waiting-icon">${icon}</div>
          <div class="dialog-title">${title}</div>
          <div class="countdown" id="v-cd">0s</div>
          <div class="muted">确认电脑上光标已在正确的输入框内<br>长按设备按钮可取消</div>
        </div>
      </div>`);
      document.body.appendChild(el);
      return el;
    }

    function startCountdown(sec) {
      stopCountdown();
      let n = sec;
      const el = document.getElementById('v-cd');
      if (el) { el.textContent = n + 's'; }
      timers.cd = setInterval(() => {
        n = n > 0 ? n - 1 : 0;
        const e2 = document.getElementById('v-cd');
        if (e2) { e2.textContent = n + 's'; }
        if (n <= 0) { stopCountdown(); }
      }, 1000);
    }

    function stopCountdown() {
      if (timers.cd) { clearInterval(timers.cd); timers.cd = null; }
    }

    function closeWait() {
      stopCountdown();
      const el = document.getElementById('v-wait');
      if (el) { el.remove(); }
    }

    async function onType(id) {
      if (busy) { return; }
      busy = true;
      const overlay = showWaitingOverlay('⌨️', '准备输出…');

      try {
        await pwdkey.typeEntry(id, {
          onWaiting: (timeoutMs) => {
            const t = document.querySelector('#v-wait .dialog-title');
            if (t) { t.textContent = '请在设备上短按 BOOT 键'; }
            startCountdown(Math.floor(timeoutMs / 1000));
          },

          /* 多条通道在线：按【名字 + 通道】选目标 */
          onPickTarget: (cands) => new Promise((resolve) => {
            stopCountdown();
            const t = document.querySelector('#v-wait .dialog-title');
            if (t) { t.textContent = '请选择输出通道'; }
            ui.actionSheet({
              itemList: cands.map((c) => `输出到 ${c.name}${c.isUsb ? '（USB 有线）' : '（蓝牙）'}`),
            }).then((r) => resolve(r ? cands[r.tapIndex].addr : null));
          }),
        });

        closeWait();
        ui.vibrate();
        ui.toast('已输出到电脑 ✓', { duration: 2000 });
      } catch (e) {
        closeWait();
        if (e.code === 0x3005) {
          ui.modal({
            title: '⚠️ 输出中断',
            content: '电脑上可能只打出了部分密码！请检查并清除电脑上的输入框，然后重试。',
            showCancel: false,
          });
        } else if (e.code === 0x400B) {
          const r = await ui.modal({
            title: '会话已过期',
            content: '为安全起见，解锁后 30 秒内才能输出密码。请重新解锁后重试。',
            confirmText: '去解锁',
          });
          if (r.confirm) { router.go('unlock', { replace: true }); }
        } else if (e.code === 0x3004) {
          ui.toast('已取消');
        } else {
          ui.toast(e.message || '输出失败', { duration: 3000 });
        }
      } finally {
        busy = false;
        if (overlay && overlay.parentNode) { overlay.remove(); }
      }
    }

    /* ---------------- 添加条目 ---------------- */

    function showAddDialog() {
      let addName = '';
      let addPwd = '';
      let addPwd2 = '';
      let adding = false;

      const el = ui.h(`<div class="mask" id="v-addmask">
        <div class="dialog">
          <div class="dialog-title">添加密码</div>
          <div class="muted" style="text-align:center;margin-bottom:0.8rem">
            密码将加密保存在设备中（纯 ASCII）
          </div>
          <input class="input plain" id="a-name" placeholder="名称（如：招行网银）" maxlength="64" />
          <input class="input plain" id="a-pwd1" type="password" placeholder="密码" maxlength="128" />
          <input class="input plain" id="a-pwd2" type="password" placeholder="再次输入密码" maxlength="128" />
          <div class="err-box" id="a-err" style="display:none"></div>
          <button class="btn btn-primary" id="a-ok">保存到设备</button>
          <button class="btn btn-ghost" id="a-cancel">取消</button>
        </div>
      </div>`);

      const errEl = el.querySelector('#a-err');
      const okBtn = el.querySelector('#a-ok');

      const showErr = (m) => {
        errEl.textContent = m;
        errEl.style.display = m ? 'block' : 'none';
      };

      el.querySelector('#a-name').oninput = (e) => { addName = e.target.value; };
      el.querySelector('#a-pwd1').oninput = (e) => { addPwd = e.target.value; showErr(''); };
      el.querySelector('#a-pwd2').oninput = (e) => { addPwd2 = e.target.value; showErr(''); };

      /* 点遮罩关闭；点对话框内部不关闭 */
      el.addEventListener('click', (ev) => {
        if (ev.target === el) { el.remove(); }
      });

      el.querySelector('#a-cancel').onclick = () => el.remove();

      okBtn.onclick = async () => {
        if (adding) { return; }
        if (!addPwd) { showErr('请输入密码'); return; }
        if (addPwd !== addPwd2) { showErr('两次输入不一致'); return; }
        if (!ASCII_RE.test(addPwd)) {
          showErr('密码只能使用 ASCII 字符（中文/emoji 无法通过键盘输入）');
          return;
        }
        adding = true;
        okBtn.disabled = true;
        okBtn.textContent = '保存中…';
        showErr('');
        try {
          const id = await pwdkey.addEntry(addPwd, addName || '');
          el.remove();
          ui.toast('已添加 ' + id, { duration: 2000 });
          loadEntries();
        } catch (e) {
          adding = false;
          okBtn.disabled = false;
          okBtn.textContent = '保存到设备';
          showErr(e.message || '添加失败');
        }
      };

      document.body.appendChild(el);
      setTimeout(() => el.querySelector('#a-name').focus(), 80);
    }

    /* ---------------- 配对模式 ---------------- */

    async function onPair() {
      if (busy) { return; }
      busy = true;
      const overlay = showWaitingOverlay('🔗', '请在设备上短按 BOOT 键');
      const cdEl = document.getElementById('v-cd');
      if (cdEl) { cdEl.textContent = '30s'; }
      startCountdown(30);

      try {
        await pwdkey.enterPairing({ onWaiting: () => { /* 已显示 */ } });
        closeWait();
        await ui.modal({
          title: '设备已进入配对模式',
          content: '请在 60 秒内到【要使用它的那台电脑】的蓝牙设置里选择 PwdKey 设备完成配对。',
          showCancel: false,
        });
      } catch (e) {
        closeWait();
        ui.toast(e.message || '操作失败', { duration: 3000 });
      } finally {
        busy = false;
        if (overlay && overlay.parentNode) { overlay.remove(); }
      }
    }

    /* ---------------- USB 直连（有线）说明 ----------------
     * 有线不需要配对：插上数据线，设备就是一个标准 USB 键盘。
     * 这里只负责告诉用户怎么用、以及当前是否已连上。
     */

    async function onUsbGuide() {
      let online = false;
      let name = 'USB 直连';
      try {
        const list = await pwdkey.listHosts();
        const u = list.find((h) => h.isUsb);
        if (u) { online = u.online; name = u.name; }
      } catch (e) { /* 查不到就按"未连接"显示，不打断引导 */ }

      await ui.modal({
        title: online ? `${name} 已连接` : 'USB 直连（有线）',
        content: online
          ? '设备现在通过数据线连着电脑，可以直接输出密码，不需要配对。若同时有多条通道在线，输出前会让你选择走哪条。'
          : '把数据线插到电脑上，设备会立刻被识别为标准键盘，免驱、免配对。注意要用标着 USB/OTG 的那个口（不是充电口），而且必须是能传数据的线，纯充电线不行。',
        showCancel: false,
        confirmText: '知道了',
      });
    }

    /* ---------------- 加密导出 ---------------- */

    async function onExport() {
      if (busy) { return; }
      if (!pwdkey.isUnlocked()) {
        ui.toast('会话已失效，请重新解锁');
        return;
      }

      const r = await ui.modal({
        title: '导出加密备份',
        content:
          '请输入主密码。备份文件用这个密码加密，只有它能解开。\n\n'
          + '整个过程在设备内完成加密，密码明文不会出现在蓝牙传输里。',
        editable: true,
        placeholderText: '主密码（至少 12 位，含字母和数字）',
        confirmText: '开始导出',
      });
      if (!r.confirm) { return; }
      const pwd = (r.content || '').trim();
      if (!pwd) { return; }

      busy = true;
      const overlay = showWaitingOverlay('📦', '请在设备上短按 BOOT 确认');
      const cdEl = document.getElementById('v-cd');
      if (cdEl) { cdEl.textContent = '0%'; }

      try {
        /* 收数据 + 换锁（这一步会等 BOOT 确认，浮层上有进度百分比） */
        const content = await pwdkey.exportVault(pwd, {
          onProgress: (done, total) => {
            const el = document.getElementById('v-cd');
            if (el) { el.textContent = Math.round((done / total) * 100) + '%'; }
          },
        });

        /* 数据已经拿到了，立刻关掉"等待确认"浮层 ——
         * 后面的保存/分享是另一件事，不能让它卡住这个浮层。 */
        closeWait();

        ui.showLoading('保存中');
        let name;
        try {
          name = await exporter.saveAndShare(content);
        } finally {
          ui.hideLoading();
        }

        await ui.modal({
          title: '导出完成',
          content:
            `${name}\n\n`
            + '请把这个文件存到手机之外（电脑、U 盘都行）。\n'
            + '文件 + 你的主密码 = 全部密码，请当作钥匙保管。\n\n'
            + '设备在 30 分钟内不会允许再次导出。',
          showCancel: false,
          confirmText: '知道了',
        });
      } catch (e) {
        closeWait();
        ui.hideLoading();
        ui.modal({
          title: '导出失败',
          content: e.message || '未知错误',
          showCancel: false,
        });
      } finally {
        busy = false;
        if (overlay && overlay.parentNode) { overlay.remove(); }
      }
    }

    /* ---------------- 导入备份 ---------------- */

    async function onImport() {
      if (busy) { return; }
      if (!pwdkey.isUnlocked()) {
        ui.toast('会话已失效，请重新解锁');
        return;
      }

      /* 走原生选择器：Capacitor 的 WebView 没实现 onShowFileChooser，
         H5 的 input[type=file] 点了没反应，所以改用 VaultFile 插件。 */
      const cap = typeof window !== 'undefined' ? window.Capacitor : null;
      const vf = cap && cap.Plugins && cap.Plugins.VaultFile;
      if (!vf) {
        ui.modal({
          title: '无法导入',
          content: '当前环境不支持文件选择（请确认安装的是最新版 App）。',
          showCancel: false,
        });
        return;
      }

      let picked;
      try {
        picked = await vf.pickAndRead();
      } catch (e) {
        if (e && (e.code === 'CANCELLED' || e.code === 'PICKER_CANCELLED')) {
          return;
        }
        ui.modal({
          title: '无法打开文件',
          content: (e && e.message) || '文件选择器启动失败',
          showCancel: false,
        });
        return;
      }

      const text = (picked && picked.content) || '';
      const fileName = (picked && picked.name) || 'backup.amfnl';
      if (!text) {
        ui.modal({ title: '导入', content: '文件是空的，或不是文本格式。', showCancel: false });
        return;
      }

      const r = await ui.modal({
        title: '导入备份',
        content: `文件：${fileName}\n\n请输入导出时使用的主密码。`,
        editable: true,
        placeholderText: '主密码',
        confirmText: '继续',
      });
      if (!r.confirm) { return; }
      const pwd = (r.content || '').trim();
      if (!pwd) { return; }

      ui.showLoading('解密中');
      let parsed;
      try {
        parsed = await exporter.openPackage(text, pwd);
      } catch (e) {
        ui.hideLoading();
        ui.modal({
          title: '无法解密',
          content: e.message || '密码错误或文件已损坏',
          showCancel: false,
        });
        return;
      }
      ui.hideLoading();

      if (!parsed.entries.length) {
        ui.modal({ title: '导入', content: '备份里没有条目。', showCancel: false });
        return;
      }

      const ok = await ui.modal({
        title: '确认导入',
        content:
          `文件里有 ${parsed.entries.length} 条密码`
          + (parsed.exportedAt ? `（导出于 ${parsed.exportedAt.slice(0, 10)}）` : '')
          + '。\n\n导入会【新增】到现有条目，不会覆盖或删除已有数据。',
        confirmText: '导入',
      });
      if (!ok.confirm) { return; }

      ui.showLoading('写入中');
      let done = 0;
      const failed = [];
      for (const e of parsed.entries) {
        try {
          await pwdkey.addEntry(e.secret, e.name || '');
          done++;
        } catch (err) {
          failed.push((e.name || '(无名称)') + '：' + (err.message || '失败'));
        }
      }
      ui.hideLoading();

      if (failed.length) {
        await ui.modal({
          title: `导入完成 ${done}/${parsed.entries.length}`,
          content: '以下条目失败：\n' + failed.slice(0, 5).join('\n')
                   + (failed.length > 5 ? `\n…另有 ${failed.length - 5} 条` : ''),
          showCancel: false,
        });
      } else {
        ui.toast(`已导入 ${done} 条`, { duration: 2500 });
      }
      loadEntries();
    }

    /* ---------------- 锁定 ---------------- */

    async function onLock() {
      await pwdkey.lock().catch(() => {});
      ui.toast('已锁定');
      router.goHome();
    }

    loadEntries();
  },
};
