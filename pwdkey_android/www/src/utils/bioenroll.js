/**
 * bioenroll.js - 「开启 / 关闭生物解锁」的完整交互流程
 *
 * 三个入口共用：首次设置成功后、解锁页（主密码解锁后提示）、安全设置页。
 *
 * 开启时做的事：
 *   1. 检查设备是否支持强生物认证（BIOMETRIC_STRONG）
 *   2. 让用户设置 6 位 PIN（输两遍）
 *   3. 用当前 KEK + 设备 salt 构造信封，交给原生用生物密钥包外层
 *
 * 关闭时：直接清掉原生信封与 Keystore 密钥。
 */

const biowrap = require('./biowrap.js');
const pinpad = require('../components/pinpad.js');
const ui = require('../ui.js');
const { pwdkey } = require('./pwdkey.js');

/**
 * @param {{silent?:boolean, reason?:string}} opts
 * @returns {Promise<boolean>} 是否成功开启
 */
async function enable(opts) {
  const o = opts || {};

  if (!pwdkey.isUnlocked()) {
    ui.toast('请先解锁设备');
    return false;
  }
  if (!pwdkey.info || !pwdkey.info.salt) {
    ui.toast('设备信息未就绪，请重试');
    return false;
  }

  const st = await biowrap.status();
  if (!st.supported) {
    await ui.modal({
      title: '当前环境不支持',
      content: '生物解锁需要在安卓 App 内使用（微信小程序仍只用主密码）。',
      showCancel: false,
    });
    return false;
  }
  if (!st.available) {
    await ui.modal({
      title: '无法开启生物解锁',
      content: st.reasonText + '\n\n请先在系统设置里录入指纹或 3D 面容后重试。',
      showCancel: false,
    });
    return false;
  }

  const subtitle = o.reason
    ? o.reason
    : '6 位数字。指纹/面容认的是"人"，PIN 认的是"你知道的事"，两者缺一不可。';

  const pin1 = await pinpad.prompt({ title: '设置解锁 PIN', subtitle: subtitle });
  if (!pin1) { return false; }

  const pin2 = await pinpad.prompt({
    title: '再次输入 PIN',
    subtitle: '两次输入的 PIN 必须一致',
  });
  if (!pin2) { return false; }
  if (pin1 !== pin2) {
    await ui.modal({
      title: '两次输入不一致',
      content: '请重新开启并设置 PIN。',
      showCancel: false,
    });
    return false;
  }

  try {
    await biowrap.enroll({
      kek: pwdkey.kek,
      pin: pin1,
      deviceSalt: pwdkey.info.salt,
    });
    if (!o.silent) {
      ui.vibrate();
      ui.toast('已开启生物解锁', { duration: 2000 });
    }
    return true;
  } catch (e) {
    await ui.modal({
      title: '开启失败',
      content: bioErrorText(e),
      showCancel: false,
    });
    return false;
  }
}

async function disable() {
  try {
    await biowrap.clear();
    ui.toast('已关闭生物解锁，之后需要输入主密码');
    return true;
  } catch (e) {
    ui.toast(bioErrorText(e));
    return false;
  }
}

/** 把原生错误码翻译成人话 */
function bioErrorText(e) {
  const code = (e && e.code) || '';
  switch (code) {
    case 'USER_CANCELED': return '已取消生物认证。';
    case 'KEY_INVALIDATED':
      return '系统里的指纹/面容发生了变更，旧密钥已失效。请用主密码解锁后重新开启。';
    case 'LOCKOUT':
      return '生物识别尝试次数过多，已被系统暂时锁定。请稍后再试，或改用主密码。';
    case 'LOCKOUT_PERMANENT':
      return '生物识别已被系统永久锁定，需要先用设备锁屏密码解锁手机。';
    case 'NO_ENROLL': return '尚未开启生物解锁。';
    case 'NO_BIOMETRICS':
      return '系统里还没有录入指纹或面容。';
    case 'NO_HARDWARE': return '这台设备没有可用的生物识别硬件。';
    case 'BUSY': return '上一次认证还没结束，请稍候。';
    default: return (e && e.message) || '操作失败，请重试。';
  }
}

module.exports = { enable, disable, bioErrorText };
