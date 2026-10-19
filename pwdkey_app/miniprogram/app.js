/**
 * app.js - PwdKey 小程序入口
 */
const { pwdkey } = require('./utils/pwdkey.js');

App({
  onHide() {
    // 切后台即锁定设备会话（KEK 从内存清除）
    if (pwdkey.isUnlocked()) {
      pwdkey.lock().catch(() => {});
    }
  },
});
