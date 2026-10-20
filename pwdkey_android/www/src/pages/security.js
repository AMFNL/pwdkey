/**
 * pages/security.js - 安全设置（v1.1）
 *
 * 三件事：
 *   1. 生物解锁开关（指纹/面容 + 6 位 PIN）
 *   2. 修改主密码（事件驱动，不做定期过期）
 *   3. 恢复码状态说明
 *
 * 关于"定期更换主密码"：故意不提供倒计时/强制过期。理由是每次改主密码都会
 * 让设备重新加密全库并生成【新恢复码】（旧码立即作废），漏抄一次就等于丢了
 * 唯一的兜底入口 —— 风险远大于收益。这里只显示上次修改时间，让用户自己判断。
 */
const { pwdkey } = require('../utils/pwdkey.js');
const biowrap = require('../utils/biowrap.js');
const bioenroll = require('../utils/bioenroll.js');
const ui = require('../ui.js');
const router = require('../router.js');

function fmtDate(ts) {
  if (!ts) { return '从未修改'; }
  const d = new Date(ts);
  const p = (n) => (n < 10 ? '0' + n : '' + n);
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

module.exports = {
  title: '安全设置',

  render() {
    return `
      <div class="card">
        <div class="title">生物解锁</div>
        <div class="muted" id="sec-bio-desc">检测中…</div>
        <div class="hint muted" id="sec-bio-hint" style="margin-top:0.6rem"></div>
        <button class="btn btn-primary" id="sec-bio-btn" disabled>检测中…</button>
      </div>

      <div class="card">
        <div class="title">主密码</div>
        <div class="muted" id="sec-pwd-desc">—</div>
        <div class="hint muted" style="margin-top:0.6rem">
          主密码是设备密钥的唯一来源，无法找回。修改后设备会用新密码重新加密全部条目，
          并生成<b>新的恢复码</b>（旧恢复码立即失效）。
        </div>
        <button class="btn btn-ghost" id="sec-pwd-btn">修改主密码</button>
      </div>

      <div class="card">
        <div class="title">恢复码</div>
        <div class="muted">
          忘记主密码时，只有恢复码能重置设备（会清空全部密码）。
          它只显示一次，请务必抄写在纸上单独保管。
        </div>
      </div>

      <div class="card">
        <div class="title">关于定期更换主密码</div>
        <div class="muted">
          本设备不强制定期更换。主密码在离线环境下无法被在线撞库，
          强度足够时"换得勤"并不能提升安全，反而每次都要重新抄写恢复码。
          建议只在<b>怀疑泄露</b>或<b>想提升密码强度</b>时修改。
        </div>
      </div>
    `;
  },

  mount() {
    const descEl = document.getElementById('sec-bio-desc');
    const hintEl = document.getElementById('sec-bio-hint');
    const btn = document.getElementById('sec-bio-btn');
    const pwdDesc = document.getElementById('sec-pwd-desc');

    let bio = { supported: false, available: false, hasEnroll: false, reasonText: '' };

    pwdDesc.textContent = '上次修改：' + fmtDate(parseInt(ui.store.get('pwd_changed_at', '0'), 10));

    document.getElementById('sec-pwd-btn').onclick = () => {
      if (!pwdkey.isUnlocked()) {
        ui.toast('请先解锁设备');
        return;
      }
      router.go('change-pwd');
    };

    btn.onclick = async () => {
      if (!pwdkey.isUnlocked()) {
        ui.toast('会话已失效，请重新解锁');
        return;
      }
      if (bio.hasEnroll) {
        const r = await ui.modal({
          title: '关闭生物解锁',
          content: '关闭后将只能用主密码解锁。已保存的 KEK 信封会被删除。',
          confirmText: '关闭',
          confirmColor: '#dc2626',
        });
        if (!r.confirm) { return; }
        await bioenroll.disable();
        await refresh();
      } else {
        const ok = await bioenroll.enable({ silent: false });
        if (ok) { await refresh(); }
      }
    };

    async function refresh() {
      try {
        bio = await biowrap.status();
      } catch (e) {
        bio = { supported: false, available: false, hasEnroll: false, reasonText: '状态读取失败' };
      }

      btn.disabled = false;

      if (!bio.supported) {
        descEl.textContent = '未开启';
        hintEl.textContent = '当前环境不支持生物认证（微信小程序版仍只用主密码）。';
        btn.textContent = '不可用';
        btn.disabled = true;
        return;
      }

      if (bio.hasEnroll) {
        descEl.textContent = '已开启 · 指纹/面容 + 6 位 PIN';
        hintEl.textContent = '解锁时先验证指纹或面容，再输入 6 位 PIN，两者缺一不可。';
        btn.textContent = '关闭生物解锁';
        btn.className = 'btn btn-ghost';
        return;
      }

      descEl.textContent = '未开启';
      btn.className = 'btn btn-primary';
      if (!bio.available) {
        hintEl.textContent = bio.reasonText || '设备不支持强生物认证';
        btn.textContent = '无法开启';
        btn.disabled = true;
      } else {
        hintEl.textContent = '开启后解锁只需 1–2 秒，不必每次输入长主密码。';
        btn.textContent = '开启生物解锁';
      }
    }

    refresh();
  },
};
