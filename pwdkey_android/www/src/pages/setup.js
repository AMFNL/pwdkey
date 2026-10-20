/**
 * pages/setup.js - 首次设置主密码（S0 出厂态），对应小程序 pages/setup
 * 阶段：input -> computing -> waiting -> done
 */
const { pwdkey } = require('../utils/pwdkey.js');
const bioenroll = require('../utils/bioenroll.js');
const ui = require('../ui.js');
const router = require('../router.js');

module.exports = {
  title: '首次设置',

  render() {
    return `<div id="setup-body"></div>`;
  },

  mount() {
    const body = document.getElementById('setup-body');

    let phase = 'input';
    let pwd1 = '';
    let pwd2 = '';
    let showPwd = false;
    let progress = 0;
    let countdown = 0;
    let recoveryCode = '';
    let copied = false;
    let err = '';
    let cdTimer = null;

    function stopCountdown() {
      if (cdTimer) { clearInterval(cdTimer); cdTimer = null; }
    }

    function startCountdown(sec) {
      stopCountdown();
      countdown = sec;
      cdTimer = setInterval(() => {
        countdown = countdown > 0 ? countdown - 1 : 0;
        const el = document.getElementById('setup-countdown');
        if (el) { el.textContent = countdown + 's'; }
        if (countdown <= 0) { stopCountdown(); }
      }, 1000);
    }

    function validate() {
      if (!pwd1) { return '请输入主密码'; }
      if (pwd1 !== pwd2) { return '两次输入不一致'; }
      if (!/^[\x20-\x7E]+$/.test(pwd1)) {
        return '主密码只能使用 ASCII 字符（英文/数字/常见符号）';
      }
      if (pwd1.length < 8) {
        return '主密码至少 8 位（建议 12 位以上，混合大小写/数字/符号）';
      }
      return '';
    }

    /* ---------------- 渲染 ---------------- */

    function draw() {
      if (phase === 'input') {
        body.innerHTML = `
          <div class="card">
            <div class="title">设置主密码</div>
            <div class="desc muted">
              主密码是设备唯一的安全凭据。设备只保存验证值、无法找回；
              忘记后只能用恢复码重置（会清空全部密码）。
            </div>

            <input class="input" id="s-pwd1" type="${showPwd ? 'text' : 'password'}"
                   placeholder="主密码（纯 ASCII 字符）" maxlength="64" value="${ui.esc(pwd1)}" />
            <input class="input" id="s-pwd2" type="${showPwd ? 'text' : 'password'}"
                   placeholder="再次输入确认" maxlength="64" value="${ui.esc(pwd2)}" />

            <div class="row">
              <span class="label">显示密码</span>
              <div class="switch ${showPwd ? 'on' : ''}" id="s-show"></div>
            </div>

            ${err ? `<div class="err-box">${ui.esc(err)}</div>` : ''}

            <button class="btn btn-primary" id="s-start"
              ${(!pwd1 || !pwd2) ? 'disabled' : ''}>开始设置</button>
          </div>

          <div class="hint muted">
            设置过程约需 3–10 秒（安全密钥计算），随后设备会要求你按一下 BOOT 键确认。
          </div>
        `;

        const i1 = document.getElementById('s-pwd1');
        const i2 = document.getElementById('s-pwd2');
        i1.oninput = () => { pwd1 = i1.value; err = ''; refreshStartBtn(); };
        i2.oninput = () => { pwd2 = i2.value; err = ''; refreshStartBtn(); };
        document.getElementById('s-show').onclick = () => { showPwd = !showPwd; draw(); };
        document.getElementById('s-start').onclick = onStart;
        return;
      }

      if (phase === 'computing') {
        body.innerHTML = `
          <div class="card center-card">
            <div class="spin">🔐</div>
            <div class="title">正在生成安全密钥…</div>
            <div class="muted" style="margin-top:0.4rem" id="setup-pct">PBKDF2 密钥派生 ${progress}%</div>
            <div class="progress-wrap">
              <div class="progress-bar" id="setup-bar" style="width:${progress}%"></div>
            </div>
            <div class="hint muted" style="margin-top:0.8rem">
              需要完成 20 万次迭代计算，请保持屏幕开启
            </div>
          </div>
        `;
        return;
      }

      if (phase === 'waiting') {
        body.innerHTML = `
          <div class="card center-card">
            <div class="waiting-icon">👆</div>
            <div class="title">请在设备上短按 BOOT 键</div>
            <div class="countdown" id="setup-countdown">${countdown}s</div>
            <div class="muted" style="text-align:center">
              找到设备上的 BOOT 按钮，<b>短按一下</b>（少于 2 秒）<br>
              长按会取消本次操作
            </div>
          </div>
        `;
        return;
      }

      /* done */
      body.innerHTML = `
        <div class="card">
          <div class="ok-icon">✅</div>
          <div class="title" style="text-align:center">设置成功</div>
          <div class="warn-box">
            ⚠️ 恢复码只显示这一次。忘记主密码时只有它能重置设备（会清空所有密码）。
            请立刻抄写到纸上，不要只存在手机里。
          </div>
          <div class="recovery-code">${ui.esc(recoveryCode)}</div>
          <button class="btn btn-ghost" id="s-copy">${copied ? '已复制 ✓' : '复制恢复码'}</button>
          <button class="btn btn-primary" id="s-done">我已抄写，完成</button>
        </div>

        <div class="card">
          <div class="title">开启生物解锁（推荐）</div>
          <div class="muted">
            设置一个 6 位 PIN，之后用<b>指纹或面容 + PIN</b>解锁，
            不必每次输入长主密码。两者缺一不可；主密码仍然保留作为兜底。
          </div>
          <button class="btn btn-primary" id="s-bio">☝️ 设置指纹 / 面容解锁</button>
        </div>
      `;
      document.getElementById('s-copy').onclick = async () => {
        const ok = await ui.copyText(recoveryCode);
        copied = ok;
        draw();
        ui.toast(ok ? '已复制' : '复制失败，请手动抄写');
      };
      document.getElementById('s-done').onclick = () => {
        ui.toast('设备已启用');
        router.goHome();
      };
      document.getElementById('s-bio').onclick = async () => {
        const ok = await bioenroll.enable({ silent: false });
        if (ok) {
          router.goHome();
        }
      };
    }

    function refreshStartBtn() {
      const btn = document.getElementById('s-start');
      if (btn) { btn.disabled = !pwd1 || !pwd2; }
      const box = body.querySelector('.err-box');
      if (err && !box) {
        const div = document.createElement('div');
        div.className = 'err-box';
        div.textContent = err;
        const anchor = document.getElementById('s-start');
        anchor.parentNode.insertBefore(div, anchor);
      } else if (box) {
        if (err) { box.textContent = err; } else { box.remove(); }
      }
    }

    /* ---------------- 提交 ---------------- */

    async function onStart() {
      err = validate();
      if (err) { draw(); return; }

      if (!pwdkey.connected) {
        ui.modal({ title: '未连接设备', content: '请先回到首页连接 PwdKey 设备。', showCancel: false });
        return;
      }

      phase = 'computing';
      progress = 0;
      err = '';
      draw();

      try {
        const code = await pwdkey.setPassword(pwd1, {
          onProgress: (f) => {
            const p = Math.floor(f * 100);
            if (p !== progress) {
              progress = p;
              const bar = document.getElementById('setup-bar');
              if (bar) { bar.style.width = p + '%'; }
              const label = document.getElementById('setup-pct');
              if (label) { label.textContent = `PBKDF2 密钥派生 ${p}%`; }
            }
          },
          onWaiting: () => {
            phase = 'waiting';
            countdown = 60;
            draw();
            startCountdown(60);
          },
        });

        stopCountdown();
        ui.vibrate();
        recoveryCode = code;
        phase = 'done';
        draw();
      } catch (e) {
        stopCountdown();
        phase = 'input';
        err = e.message || '设置失败，请重试';
        draw();
      }
    }

    draw();
  },
};
