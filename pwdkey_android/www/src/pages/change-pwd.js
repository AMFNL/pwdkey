/**
 * pages/change-pwd.js - 修改主密码（v1.1）
 *
 * 流程（固件 v1.2 已支持，无需改固件）：
 *   input ──▶ 本地校验旧密码 ──▶ 设备等 BOOT 确认 ──▶ 设备返回新 salt
 *         ──▶ 派生新 KEK ──▶ PROOF2(旧 verifier) ──▶ 设备重加密全库
 *         ──▶ 显示新恢复码（旧码作废）──▶ 回抄校验
 *
 * 两个容易踩的点，这里都做了防护：
 *   1. 旧密码先在本地校验：算错不会发到设备，避免白白累计失败次数（10 次永久锁定）。
 *   2. 改完立刻清掉手机端的生物信封：旧信封里装的是旧 KEK，继续留着只会在下次
 *      解锁时解出一个失效密钥。清掉并引导重新开启，比"静默 rewrap"少一种失败状态。
 */
const { pwdkey } = require('../utils/pwdkey.js');
const biowrap = require('../utils/biowrap.js');
const bioenroll = require('../utils/bioenroll.js');
const ui = require('../ui.js');
const router = require('../router.js');

const ASCII_RE = /^[\x20-\x7E]+$/;

module.exports = {
  title: '修改主密码',

  render() {
    return `<div id="cp-body"></div>`;
  },

  mount() {
    const body = document.getElementById('cp-body');

    let phase = 'input';        // input | computing | waiting | done
    let oldPwd = '';
    let newPwd = '';
    let newPwd2 = '';
    let showPwd = false;
    let progress = 0;
    let countdown = 0;
    let err = '';
    let recoveryCode = '';
    let copied = false;
    let verified = false;
    let timer = null;

    function stopTimer() {
      if (timer) { clearInterval(timer); timer = null; }
    }

    function draw() {
      if (phase === 'computing') {
        body.innerHTML = `
          <div class="card center-card">
            <div class="spin">🔑</div>
            <div class="title">正在派生新密钥…</div>
            <div class="muted" style="margin-top:0.4rem" id="cp-pct">${progress}%</div>
            <div class="progress-wrap">
              <div class="progress-bar" id="cp-bar" style="width:${progress}%"></div>
            </div>
            <div class="hint muted" style="margin-top:0.8rem">
              主密码使用 PBKDF2 20 万次迭代，请保持屏幕开启
            </div>
          </div>`;
        return;
      }

      if (phase === 'waiting') {
        body.innerHTML = `
          <div class="card center-card">
            <div class="waiting-icon">👆</div>
            <div class="title">请在设备上短按 BOOT 键</div>
            <div class="countdown" id="cp-cd">${countdown}s</div>
            <div class="muted" style="text-align:center">
              找到设备上的 BOOT 按钮，<b>短按一下</b>（少于 2 秒）<br>
              长按会取消本次操作
            </div>
          </div>`;
        return;
      }

      if (phase === 'done') {
        body.innerHTML = `
          <div class="card">
            <div class="ok-icon">✅</div>
            <div class="title" style="text-align:center">主密码已修改</div>
            <div class="warn-box">
              ⚠️ 设备已用新密码重新加密全部密码条目。<br>
              下面这个<b>新恢复码</b>只显示这一次，<b>旧恢复码已立即失效</b>。
              请立刻抄写到纸上。
            </div>
            <div class="recovery-code">${ui.esc(recoveryCode)}</div>
            <button class="btn btn-ghost" id="cp-copy">${copied ? '已复制 ✓' : '复制恢复码'}</button>
            ${verified ? '<div class="hint muted" style="text-align:center">已通过回抄校验 ✓</div>' : ''}
            <button class="btn btn-primary" id="cp-finish">我已抄写，完成</button>
          </div>

          <div class="card">
            <div class="title">生物解锁</div>
            <div class="muted">
              主密码变了，指纹解锁里保存的旧密钥已经失效，本次已自动关闭。
              需要的话可以现在重新开启。
            </div>
            <button class="btn btn-ghost" id="cp-bio">☝️ 重新开启生物解锁</button>
          </div>
        `;

        document.getElementById('cp-copy').onclick = async () => {
          const ok = await ui.copyText(recoveryCode);
          copied = ok;
          draw();
          ui.toast(ok ? '已复制' : '复制失败，请手动抄写');
        };
        document.getElementById('cp-finish').onclick = onFinish;
        document.getElementById('cp-bio').onclick = async () => {
          const ok = await bioenroll.enable({ silent: false, reason: '重新设置一个 6 位 PIN' });
          if (ok) { ui.toast('已开启生物解锁'); }
        };
        return;
      }

      /* input */
      body.innerHTML = `
        <div class="card">
          <div class="title">修改主密码</div>
          <div class="desc muted">
            设备会用新密码重新加密全部条目，并生成新的恢复码。
            过程中需要你在设备上按一下 BOOT 键。
          </div>

          <input class="input" id="cp-old" type="${showPwd ? 'text' : 'password'}"
                 placeholder="当前主密码" maxlength="64" value="${ui.esc(oldPwd)}" />
          <input class="input" id="cp-new1" type="${showPwd ? 'text' : 'password'}"
                 placeholder="新主密码（≥ 8 位，纯 ASCII）" maxlength="64" value="${ui.esc(newPwd)}" />
          <input class="input" id="cp-new2" type="${showPwd ? 'text' : 'password'}"
                 placeholder="再次输入新主密码" maxlength="64" value="${ui.esc(newPwd2)}" />

          <div class="row">
            <span class="label">显示密码</span>
            <div class="switch ${showPwd ? 'on' : ''}" id="cp-show"></div>
          </div>

          ${err ? `<div class="err-box">${ui.esc(err)}</div>` : ''}

          <button class="btn btn-primary" id="cp-go"
            ${(!oldPwd || !newPwd || !newPwd2) ? 'disabled' : ''}>确认修改</button>
        </div>

        <div class="hint muted">
          旧主密码只在手机本地校验，不会额外增加设备的失败次数。<br>
          修改完成后旧恢复码立即作废，请务必抄下新的。
        </div>
      `;

      const iOld = document.getElementById('cp-old');
      const iN1 = document.getElementById('cp-new1');
      const iN2 = document.getElementById('cp-new2');
      const btn = document.getElementById('cp-go');

      const sync = () => {
        btn.disabled = !oldPwd || !newPwd || !newPwd2;
      };
      iOld.oninput = () => { oldPwd = iOld.value; err = ''; sync(); };
      iN1.oninput = () => { newPwd = iN1.value; err = ''; sync(); };
      iN2.oninput = () => { newPwd2 = iN2.value; err = ''; sync(); };
      document.getElementById('cp-show').onclick = () => { showPwd = !showPwd; draw(); };
      btn.onclick = onSubmit;
    }

    function validate() {
      if (!oldPwd) { return '请输入当前主密码'; }
      if (!newPwd) { return '请输入新主密码'; }
      if (newPwd !== newPwd2) { return '两次输入的新密码不一致'; }
      if (!ASCII_RE.test(newPwd)) { return '主密码只能使用 ASCII 字符（英文/数字/常见符号）'; }
      if (newPwd.length < 8) { return '新主密码至少 8 位（建议 12 位以上）'; }
      if (newPwd === oldPwd) { return '新密码不能与旧密码相同'; }
      return '';
    }

    async function onSubmit() {
      if (!pwdkey.connected) {
        ui.modal({ title: '未连接设备', content: '请先回到首页连接 PwdKey 设备。', showCancel: false });
        return;
      }
      if (!pwdkey.isUnlocked()) {
        ui.toast('会话已失效，请重新解锁');
        return;
      }

      err = validate();
      if (err) { draw(); return; }

      phase = 'computing';
      progress = 0;
      draw();

      try {
        const res = await pwdkey.changePassword(oldPwd, newPwd, {
          onProgress: (f) => {
            const p = Math.floor(f * 100);
            if (p !== progress) {
              progress = p;
              const bar = document.getElementById('cp-bar');
              const pct = document.getElementById('cp-pct');
              if (bar) { bar.style.width = p + '%'; }
              if (pct) { pct.textContent = p + '%'; }
            }
          },
          onWaiting: () => {
            phase = 'waiting';
            countdown = 60;
            draw();
            stopTimer();
            timer = setInterval(() => {
              countdown = countdown > 0 ? countdown - 1 : 0;
              const el = document.getElementById('cp-cd');
              if (el) { el.textContent = countdown + 's'; }
              if (countdown <= 0) { stopTimer(); }
            }, 1000);
          },
        });

        stopTimer();
        recoveryCode = res.recoveryCode || '';
        ui.store.set('pwd_changed_at', String(Date.now()));

        /* 旧信封里的 KEK 已经失效，主动清掉，避免下次解锁解出一个废密钥 */
        await biowrap.clear().catch(() => {});

        ui.vibrate();
        phase = 'done';
        draw();
      } catch (e) {
        stopTimer();
        phase = 'input';
        err = e.message || '修改失败，请重试';
        draw();
      }
    }

    /* ---------------- 回抄校验 ---------------- */

    function pickIndexes(len, n) {
      const pool = [];
      for (let i = 0; i < len; i++) { pool.push(i); }
      const out = [];
      for (let i = 0; i < n && pool.length; i++) {
        const k = Math.floor(Math.random() * pool.length);
        out.push(pool.splice(k, 1)[0]);
      }
      return out.sort((a, b) => a - b);
    }

    async function onFinish() {
      if (!recoveryCode || verified) { finish(); return; }

      const idx = pickIndexes(recoveryCode.length, 4);
      const expect = idx.map((i) => recoveryCode[i]).join('').toUpperCase();
      const masked = recoveryCode.split('')
        .map((c, i) => (idx.indexOf(i) >= 0 ? '_' : c)).join('');
      const ask = idx.map((i) => i + 1).join('、');

      let tries = 0;
      for (;;) {
        const r = await ui.modal({
          title: '确认已抄写',
          content: `请核对恢复码，输入第 ${ask} 位字符（共 4 个，不分大小写）。\n\n${masked}`,
          editable: true,
          placeholderText: '4 个字符',
          maxLength: 8,
          confirmText: '校验',
          cancelText: tries >= 1 ? '跳过校验' : '取消',
        });
        if (!r.confirm) { break; }
        if ((r.content || '').trim().toUpperCase() === expect) {
          verified = true;
          ui.toast('校验通过 ✓');
          draw();
          return;
        }
        tries++;
        if (tries >= 2) {
          await ui.modal({
            title: '校验未通过',
            content: '请务必确认恢复码已经完整抄写。若确实抄错了，可以直接返回重新设置主密码。',
            showCancel: false,
          });
          break;
        }
        await ui.modal({
          title: '不一致',
          content: '输入的字符与恢复码不匹配，请再核对一次。',
          showCancel: false,
        });
      }

      finish();
    }

    function finish() {
      router.goHome();
    }

    draw();
  },
};
