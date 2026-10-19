/**
 * pages/index.js - 连接与状态中心（对应小程序 pages/index）
 */
const ble = require('../utils/ble.js');
const { pwdkey } = require('../utils/pwdkey.js');
const ui = require('../ui.js');
const router = require('../router.js');

module.exports = {
  title: 'PwdKey',

  render() {
    return `
      <div id="idx-off">
        <div class="hero">
          <div class="hero-logo">🔑</div>
          <div class="hero-title">PwdKey</div>
          <div class="hero-sub">蓝牙密码输入器 · 管理工具</div>
        </div>

        <div class="card">
          <button class="btn btn-primary" id="btn-scan">扫描附近设备</button>
          <div class="device-list" id="device-list"></div>
          <div class="err-box" id="idx-err" style="display:none"></div>
        </div>

        <div class="hint muted">
          出厂设备上电后会自动广播 120 秒（超时会重启继续）。<br>
          连接后即可设置主密码或解锁。
        </div>
      </div>

      <div id="idx-on" style="display:none"></div>
    `;
  },

  mount() {
    const offEl = document.getElementById('idx-off');
    const onEl = document.getElementById('idx-on');
    const errEl = document.getElementById('idx-err');
    const listEl = document.getElementById('device-list');
    const scanBtn = document.getElementById('btn-scan');

    let scanning = false;
    let connecting = false;

    const showErr = (msg) => {
      if (msg) {
        errEl.textContent = msg;
        errEl.style.display = 'block';
      } else {
        errEl.style.display = 'none';
      }
    };

    /* ---------- 已连接视图 ---------- */

    function renderConnected() {
      const info = pwdkey.info;
      if (!info) {
        /* 连接在但信息还没回来：当作加载中 */
        onEl.innerHTML = `<div class="card"><div class="muted" style="text-align:center">正在读取设备状态…</div></div>`;
        return;
      }
      const unlocked = pwdkey.isUnlocked();
      const devName = ui.store.get('lastDeviceName') || 'PwdKey';
      const lockText = info.lockSeconds > 0
        ? `锁定中（剩 ${info.lockSeconds} 秒）` : '正常';

      onEl.innerHTML = `
        <div class="card dev-card">
          <div class="dev-head">
            <div>
              <div class="title">${ui.esc(devName)}</div>
              <div class="muted">固件 ${ui.esc(info.fw)} · 协议 v1.2</div>
            </div>
            <div class="badge ${info.passwordSet ? 'badge-ok' : 'badge-warn'}">
              ${info.passwordSet ? '已启用' : '未启用'}
            </div>
          </div>
          <div class="row"><span class="label">密码条目</span><span class="value">${info.entryCount} 条</span></div>
          <div class="row"><span class="label">主密码</span><span class="value">${info.passwordSet ? '已设置' : '未设置（出厂态）'}</span></div>
          <div class="row"><span class="label">锁定状态</span><span class="value">${lockText}</span></div>
          <div class="row"><span class="label">会话</span><span class="value">${unlocked ? '已解锁' : '未解锁'}</span></div>
        </div>

        <div class="card">
          <button class="btn btn-primary" id="btn-main">
            ${info.passwordSet ? (unlocked ? '进入密码库' : '解锁设备') : '首次设置主密码'}
          </button>
          <button class="btn btn-ghost" id="btn-refresh">刷新状态</button>
          <button class="btn btn-ghost" id="btn-disc">断开连接</button>
        </div>
      `;

      document.getElementById('btn-main').onclick = () => {
        if (!info.passwordSet) { router.go('setup'); }
        else if (pwdkey.isUnlocked()) { router.go('vault'); }
        else { router.go('unlock'); }
      };

      document.getElementById('btn-refresh').onclick = async () => {
        try {
          await pwdkey.refreshInfo();
          renderConnected();
        } catch (e) {
          ui.toast(e.message || '刷新失败');
        }
      };

      document.getElementById('btn-disc').onclick = async () => {
        await pwdkey.disconnect().catch(() => {});
        updateView();
        ui.toast('已断开');
      };
    }

    function updateView() {
      const connected = pwdkey.connected && !!pwdkey.info;
      if (connected) {
        offEl.style.display = 'none';
        onEl.style.display = 'block';
        renderConnected();
      } else {
        onEl.style.display = 'none';
        offEl.style.display = 'block';
        /* 显示上次连接的设备名，让用户知道重连目标 */
        const last = ui.store.get('lastDeviceId');
        if (last && !listEl.dataset.done) {
          listEl.dataset.done = '1';
        }
      }
    }

    /* ---------- 扫描 ---------- */

    scanBtn.onclick = async () => {
      if (scanning) { return; }
      scanning = true;
      scanBtn.disabled = true;
      scanBtn.textContent = '正在扫描…';
      showErr('');
      listEl.innerHTML = '';

      try {
        const { devices, totalSeen } = await ble.scan(9000);
        if (!devices.length) {
          if (totalSeen === 0) {
            showErr('未发现任何蓝牙设备 —— 多半是权限问题：\n' +
              '· 请在系统设置里允许本应用使用「附近的设备」\n' +
              '· 确认手机蓝牙已开启');
          } else {
            showErr(`扫描完成：共发现 ${totalSeen} 个蓝牙设备，但没有 PwdKey。\n` +
              '请把手机靠近设备（1 米内）再点一次扫描。');
          }
        } else {
          listEl.innerHTML = devices.map((d) => `
            <div class="device-item" data-id="${ui.esc(d.deviceId)}" data-name="${ui.esc(d.name)}">
              <div class="device-name">${ui.esc(d.name)}</div>
              <div class="device-meta">
                <span class="muted">信号 ${d.rssi === null ? '?' : d.rssi} dBm</span>
                <span class="link-btn">连接</span>
              </div>
            </div>`).join('');

          listEl.querySelectorAll('.device-item').forEach((el) => {
            el.onclick = () => doConnect(el.dataset.id, el.dataset.name);
          });
        }
      } catch (e) {
        showErr(e.message || '扫描失败');
      } finally {
        scanning = false;
        scanBtn.disabled = false;
        scanBtn.textContent = '扫描附近设备';
      }
    };

    /* ---------- 连接 ---------- */

    async function doConnect(deviceId, name) {
      if (connecting) { return; }
      connecting = true;
      ui.showLoading('正在连接设备…');
      try {
        const info = await pwdkey.connect(deviceId);
        ui.store.set('lastDeviceId', deviceId);
        ui.store.set('lastDeviceName', name || '');
        ui.hideLoading();
        updateView();
        ui.toast('已连接 ' + (name || '设备'));
      } catch (e) {
        ui.hideLoading();
        showErr(e.message || '连接失败');
      } finally {
        connecting = false;
      }
    }

    /* ---------- 自动重连（免扫码） ---------- */

    (async function autoReconnect() {
      const lastId = ui.store.get('lastDeviceId');
      if (!lastId || pwdkey.connected) { return; }
      try {
        await pwdkey.connect(lastId);
        updateView();
        ui.toast('已自动重连设备');
      } catch (e) {
        /* 设备不在附近：静默失败，用户可手动扫描 */
      }
    })();

    updateView();
  },
};
