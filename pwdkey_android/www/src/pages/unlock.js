/**
 * pages/unlock.js - 解锁设备
 *
 * v1.1 起有两条路径，最终都汇到 pwdkey 的 AUTH_VERIFY：
 *
 *   A. 生物 + PIN（默认，若已开启）
 *      指纹/面容 ──▶ 原生解出信封 ──▶ 6 位 PIN 解出 KEK ──▶ AUTH_VERIFY
 *      没通过生物认证就拿不到信封，所以"没指纹"时攻击者连可以爆破 PIN 的
 *      密文都没有；PIN 只是过了生物这道门之后的第二道锁。
 *
 *   B. 主密码（兜底，永远保留）
 *      换机、新增指纹导致密钥失效、指纹模块坏了、想关闭生物解锁 —— 都走这条。
 *
 * 关键防呆：生物路径拿到的 KEK 会先和设备的 salt 比对。若主密码已在别处被
 * 修改（或设备被恢复出厂），本地信封里的旧 KEK 已失效 —— 此时【绝不能】
 * 发 AUTH_VERIFY，否则会白白消耗设备的失败计数，累计 10 次设备就永久锁死了。
 */
const { pwdkey } = require('../utils/pwdkey.js');
const biowrap = require('../utils/biowrap.js');
const bioenroll = require('../utils/bioenroll.js');
const pinpad = require('../components/pinpad.js');
const ui = require('../ui.js');
const router = require('../router.js');

function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) { return false; }
  for (let i = 0; i < a.length; i++) { if (a[i] !== b[i]) { return false; } }
  return true;
}

module.exports = {
  title: '解锁',

  render() {
    return `<div id="unlock-body"></div>`;
  },

  mount() {
    const body = document.getElementById('unlock-body');

    let phase = 'loading';     // loading | bio | pin | pwd | computing
    let pwd = '';
    let showPwd = false;
    let progress = 0;
    let err = '';
    let pinMsg = '';
    let envelope = null;
    let pinTries = 0;
    let busy = false;

    const bio = { supported: false, available: false, hasEnroll: false, reasonText: '' };

    /* ---------------- 引导 ---------------- */

    async function boot() {
      if (!pwdkey.connected) {
        phase = 'pwd';
        draw();
        return;
      }
      try {
        Object.assign(bio, await biowrap.status());
      } catch (e) { /* 保持默认值 */ }

      if (bio.hasEnroll && bio.available) {
        startBio();
      } else {
        phase = 'pwd';
        draw();
      }
    }

    async function startBio() {
      phase = 'bio';
      err = '';
      draw();

      try {
        envelope = await biowrap.unwrap();
        pinTries = 0;
        pinMsg = '';
        phase = 'pin';
        draw();
      } catch (e) {
        envelope = null;
        /* 用户主动取消 / 密钥失效 / 系统锁定 —— 都退回主密码，不弹错误框打断 */
        if (e.code === 'KEY_INVALIDATED') {
          await ui.modal({
            title: '生物密钥已失效',
            content: '系统里的指纹或面容发生了变化。请用主密码解锁，然后重新开启生物解锁。',
            showCancel: false,
          });
        } else if (e.code === 'LOCKOUT' || e.code === 'LOCKOUT_PERMANENT') {
          await ui.modal({
            title: '生物识别被锁定',
            content: bioenroll.bioErrorText(e) + '\n\n本次请用主密码解锁。',
            showCancel: false,
          });
        } else if (e.code !== 'USER_CANCELED') {
          ui.toast(bioenroll.bioErrorText(e), { duration: 2500 });
        }
        phase = 'pwd';
        draw();
      }
    }

    /* ---------------- 渲染 ---------------- */

    function draw() {
      if (!body) { return; }

      if (phase === 'loading') {
        body.innerHTML = `
          <div class="card center-card">
            <div class="spin">🔐</div>
            <div class="muted">正在检查解锁方式…</div>
          </div>`;
        return;
      }

      if (phase === 'bio') {
        body.innerHTML = `
          <div class="card center-card">
            <div class="spin">☝️</div>
            <div class="title">请验证指纹或面容</div>
            <div class="muted" style="margin-top:0.4rem;text-align:center">
              系统弹窗中完成验证后，还需要输入 6 位 PIN
            </div>
            <button class="btn btn-ghost" id="u-usePwd" style="margin-top:1rem">改用主密码</button>
          </div>`;
        document.getElementById('u-usePwd').onclick = () => { phase = 'pwd'; draw(); };
        return;
      }

      if (phase === 'pin') {
        body.innerHTML = `
          <div class="card">
            <div class="title" style="text-align:center">输入 6 位 PIN</div>
            <div class="muted" style="text-align:center">
              指纹已通过。PIN 与指纹缺一不可。
            </div>
            ${pinMsg ? `<div class="err-box" style="margin-top:0.8rem">${ui.esc(pinMsg)}</div>` : ''}
            <div id="pin-slot"></div>
            <button class="btn btn-ghost" id="u-usePwd2">改用主密码</button>
          </div>`;
        const pad = pinpad.create({ onSubmit: onPin });
        document.getElementById('pin-slot').appendChild(pad.el);
        document.getElementById('u-usePwd2').onclick = () => {
          envelope = null;
          phase = 'pwd';
          draw();
        };
        return;
      }

      if (phase === 'computing') {
        body.innerHTML = `
          <div class="card center-card">
            <div class="spin">🔐</div>
            <div class="title">正在验证密钥…</div>
            <div class="muted" style="margin-top:0.4rem" id="u-pct">${progress}%</div>
            <div class="progress-wrap">
              <div class="progress-bar" id="u-bar" style="width:${progress}%"></div>
            </div>
          </div>`;
        return;
      }

      /* pwd */
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

          <button class="btn btn-primary" id="u-go" ${(!pwd || busy) ? 'disabled' : ''}>解锁</button>
          ${(bio.hasEnroll && bio.available)
            ? '<button class="btn btn-ghost" id="u-bio">☝️ 改用指纹 / 面容解锁</button>' : ''}
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
        btn.disabled = !pwd || busy;
      };
      input.onkeydown = (ev) => { if (ev.key === 'Enter' && pwd && !busy) { onUnlock(); } };
      document.getElementById('u-show').onclick = () => { showPwd = !showPwd; draw(); };
      document.getElementById('u-go').onclick = onUnlock;

      const bioBtn = document.getElementById('u-bio');
      if (bioBtn) { bioBtn.onclick = startBio; }

      /* 桌面调试时直接聚焦，手机上由用户点击（避免一进页面就弹键盘挡住按钮） */
      if (window.matchMedia && window.matchMedia('(min-width: 640px)').matches) {
        input.focus();
      }
    }

    /* ---------------- 生物 + PIN ---------------- */

    async function onPin(pin) {
      if (!envelope) {
        phase = 'pwd';
        draw();
        return;
      }

      try {
        const out = await biowrap.open(envelope, pin);

        /* 先做本地校验：设备 salt 变了说明主密码被改过 / 设备被重置过，
           此时旧 KEK 必然校验失败。直接走主密码，绝不给设备记账。 */
        const devSalt = pwdkey.info && pwdkey.info.salt;
        if (!devSalt || !bytesEqual(out.deviceSalt, devSalt)) {
          envelope = null;
          await biowrap.clear().catch(() => {});
          await ui.modal({
            title: '指纹解锁已过期',
            content: '设备的主密码被修改过（或设备被重置），本地保存的密钥已失效。'
                   + '请用主密码解锁，之后可在「安全设置」里重新开启生物解锁。',
            showCancel: false,
          });
          phase = 'pwd';
          draw();
          return;
        }

        await pwdkey.unlockWithKek(out.kek);
        ui.vibrate();
        router.go('vault', { replace: true });
      } catch (e) {
        if (e.code === 'PIN_INVALID') {
          pinTries++;
          const left = biowrap.MAX_PIN_TRIES - pinTries;
          if (left <= 0) {
            envelope = null;
            pinMsg = '';
            await ui.modal({
              title: '尝试次数过多',
              content: '为防止他人反复猜 PIN，请重新验证指纹或面容。',
              showCancel: false,
            });
            startBio();
          } else {
            pinMsg = `PIN 错误，还可尝试 ${left} 次`;
            draw();
          }
          return;
        }

        const locked = (e.code === 0x4003 || e.code === 0x4004);
        envelope = null;
        pinMsg = '';
        if (e.code === 0x4004) {
          await ui.modal({
            title: '设备已永久锁定',
            content: '需使用恢复码重置设备（会清空全部密码）。',
            showCancel: false,
          });
        }
        phase = 'pwd';
        err = locked ? (e.message || '设备锁定中') : (e.message || '解锁失败');
        draw();
      }
    }

    /* ---------------- 主密码 ---------------- */

    async function onUnlock() {
      if (!pwd || busy) { return; }
      if (!pwdkey.connected) {
        ui.modal({ title: '未连接设备', content: '请先回到首页连接 PwdKey 设备。', showCancel: false });
        return;
      }

      busy = true;
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

        /* 已解锁：顺手提示开启生物解锁（只提示一次） */
        await maybeOfferBio();

        busy = false;
        router.go('vault', { replace: true });
      } catch (e) {
        busy = false;
        const locked = (e.code === 0x4003 || e.code === 0x4004);
        phase = 'pwd';
        pwd = '';
        err = e.message || '解锁失败';
        draw();
        if (e.code === 0x4004) {
          ui.modal({
            title: '设备已永久锁定',
            content: '需使用恢复码重置设备（会清空全部密码）。',
            showCancel: false,
          });
        } else if (locked) {
          ui.toast(err, { duration: 2500 });
        }
      }
    }

    async function maybeOfferBio() {
      if (!bio.supported || !bio.available || bio.hasEnroll) { return; }
      if (ui.store.get('bio_offer_done') === '1') { return; }
      ui.store.set('bio_offer_done', '1');

      const r = await ui.modal({
        title: '开启生物解锁？',
        content: '开启后，下次可以用指纹或面容 + 6 位 PIN 解锁，不必再输入长主密码。\n'
               + '主密码仍然保留，换手机或指纹变更时用它兜底。',
        confirmText: '开启',
        cancelText: '以后再说',
      });
      if (r.confirm) {
        await bioenroll.enable({ silent: false });
      }
    }

    boot();
  },
};
