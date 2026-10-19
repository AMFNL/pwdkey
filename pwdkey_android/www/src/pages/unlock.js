/**
 * pages/unlock.js - 解锁设备（主密码认证），对应小程序 pages/unlock
 */
const { pwdkey } = require('../utils/pwdkey.js');
const ui = require('../ui.js');
const router = require('../router.js');

module.exports = {
  title: '解锁',

  render() {
    return `<div id="unlock-body"></div>`;
  },

  mount() {
    const body = document.getElementById('unlock-body');

    let phase = 'input';     // input | computing
    let pwd = '';
    let showPwd = false;
    let progress = 0;
    let err = '';
    let lockedSeconds = 0;

    function draw() {
      if (phase === 'computing') {
        body.innerHTML = `
          <div class="card center-card">
            <div class="spin">🔐</div>
            <div class="title">正在验证密钥…</div>
            <div class="muted" style="margin-top:0.4rem" id="u-pct">${progress}%</div>
            <div class="progress-wrap">
              <div class="progress-bar" id="u-bar" style="width:${progress}%"></div>
            </div>
          </div>
        `;
        return;
      }

      body.innerHTML = `
        <div class="card">
          <div class="title">解锁设备</div>
          <div class="desc muted">
            输入主密码完成认证。认证后 30 秒内可执行一次密码输出操作。
          </div>

          <input class="input" id="u-pwd" type="${showPwd ? 'text' : 'password'}"
                 placeholder="主密码" maxlength="64" value="${ui.esc(pwd)}" />

          <div class="row">
            <span class="label">显示密码</span>
            <div class="switch ${showPwd ? 'on' : ''}" id="u-show"></div>
          </div>

          ${err ? `<div class="err-box">${ui.esc(err)}</div>` : ''}

          <button class="btn btn-primary" id="u-go" ${!pwd ? 'disabled' : ''}>解锁</button>
        </div>

        <div class="hint muted">
          连续输错 3 次锁定 30 秒 / 6 次锁定 5 分钟 / 10 次永久锁定。<br>
          忘记主密码：请用恢复码重置（会清空全部密码）。
        </div>
      `;

      const input = document.getElementById('u-pwd');
      input.oninput = () => {
        pwd = input.value;
        err = '';
        const btn = document.getElementById('u-go');
        btn.disabled = !pwd;
      };
      input.onkeydown = (ev) => { if (ev.key === 'Enter' && pwd) { onUnlock(); } };
      document.getElementById('u-show').onclick = () => { showPwd = !showPwd; draw(); };
      document.getElementById('u-go').onclick = onUnlock;

      /* 桌面调试时直接聚焦，手机上由用户点击（避免一进页面就弹键盘挡住按钮） */
      if (window.matchMedia && window.matchMedia('(min-width: 640px)').matches) {
        input.focus();
      }
    }

    async function onUnlock() {
      if (!pwd) { return; }
      if (!pwdkey.connected) {
        ui.modal({ title: '未连接设备', content: '请先回到首页连接 PwdKey 设备。', showCancel: false });
        return;
      }

      phase = 'computing';
      progress = 0;
      err = '';
      draw();

      try {
        await pwdkey.unlock(pwd, {
          onProgress: (f) => {
            const p = Math.floor(f * 100);
            if (p !== progress) {
              progress = p;
              const bar = document.getElementById('u-bar');
              const pct = document.getElementById('u-pct');
              if (bar) { bar.style.width = p + '%'; }
              if (pct) { pct.textContent = p + '%'; }
            }
          },
        });
        ui.vibrate();
        router.go('vault', { replace: true });
      } catch (e) {
        const locked = (e.code === 0x4003 || e.code === 0x4004);
        phase = 'input';
        pwd = '';
        err = e.message || '解锁失败';
        lockedSeconds = locked ? ((pwdkey.info && pwdkey.info.lockSeconds) || 0) : 0;
        draw();
        if (e.code === 0x4004) {
          ui.modal({
            title: '设备已永久锁定',
            content: '需使用恢复码重置设备（会清空全部密码）。',
            showCancel: false,
          });
        }
      }
    }

    draw();
  },
};
