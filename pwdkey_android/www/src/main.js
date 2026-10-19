/**
 * main.js - 应用入口
 * 负责：注册路由、连接状态兜底、切后台自动锁定（对应小程序 app.js 的 onHide）
 */
const ui = require('./ui.js');
const router = require('./router.js');
const ble = require('./utils/ble.js');
const { pwdkey } = require('./utils/pwdkey.js');

router.register('index', require('./pages/index.js'));
router.register('setup', require('./pages/setup.js'));
router.register('unlock', require('./pages/unlock.js'));
router.register('vault', require('./pages/vault.js'));
router.register('hosts', require('./pages/hosts.js'));

/* ---------------- 启动 ---------------- */

window.addEventListener('DOMContentLoaded', () => {
  history.replaceState({ page: 'index', depth: 1 }, '', '#index');
  router.render();

  /* 底部安全区（避免手势条盖住按钮） */
  document.documentElement.style.setProperty(
    '--sab', 'env(safe-area-inset-bottom)');

  /* 原生返回键：Capacitor 的 BridgeActivity 在 WebView 可回退时会调 history.back()，
     我们已在 router 里监听 popstate，因此无需额外处理。 */
});

/* ---------------- 底层链路意外断开 ---------------- */

ble.onConnectionLost(() => {
  pwdkey.connected = false;
  pwdkey.info = null;
  pwdkey.kek = null;
  pwdkey.verifier = null;
  ui.toast('设备连接已断开');
  router.reset('index');
});

/* ---------------- 切后台自动锁定 ----------------
 * 与小程序一致：退到后台即销毁设备会话（KEK 从内存清除）。
 * 延时 800ms 再锁，避免系统权限弹窗造成的瞬时失焦误锁。
 */

let hideTimer = null;

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    if (hideTimer) { clearTimeout(hideTimer); }
    hideTimer = setTimeout(() => {
      hideTimer = null;
      if (document.hidden && pwdkey.isUnlocked()) {
        pwdkey.lock().catch(() => {});
      }
    }, 800);
  } else {
    if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
  }
});

/* 页面从后台恢复时，如果停在需要解锁的页面但会话已失效，回首页 */
window.addEventListener('pageshow', () => {
  const page = router.current();
  if ((page === 'vault' || page === 'hosts') && !pwdkey.isUnlocked()) {
    router.reset('index');
  }
});
