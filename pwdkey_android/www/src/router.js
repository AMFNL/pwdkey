/**
 * router.js - 极简页面栈路由
 *
 * 对应小程序的 navigateTo / redirectTo / navigateBack：
 *   go(name)               -> navigateTo
 *   go(name, {replace:true}) -> redirectTo
 *   back()                 -> navigateBack
 * 用 history 记录栈，Android 硬件返回键（WebView goBack）也能正确回退。
 */

const routes = {};
let stack = ['index'];

/* 我们自己调用 history.back() 时，浏览器会异步回一个 popstate。
 * 那一次不需要再改栈（栈已经改过了），用时间窗屏蔽掉，避免"退两次"或
 * 者延迟到达的 popstate 覆盖掉刚打开的新页面。 */
let programmaticBackAt = 0;
const PROGRAMMATIC_WINDOW_MS = 120;

function register(name, page) {
  routes[name] = page;
}

function current() {
  return stack[stack.length - 1];
}

function render() {
  const name = current();
  const page = routes[name];
  if (!page) { return; }

  const root = document.getElementById('page-root');
  root.innerHTML = page.render();

  const backBtn = document.querySelector('.appbar-back');
  const titleEl = document.querySelector('.appbar-title');
  const canBack = stack.length > 1;
  if (backBtn) {
    backBtn.style.visibility = canBack ? 'visible' : 'hidden';
    backBtn.onclick = canBack ? back : null;
  }
  if (titleEl) {
    titleEl.textContent = page.title || 'PwdKey';
    titleEl.className = 'appbar-title' + (canBack ? '' : ' no-back');
  }

  window.scrollTo(0, 0);
  if (page.mount) { page.mount(); }
}

/** 只重绘当前页面（保持栈不变）——用于数据刷新 */
function refresh() {
  const page = routes[current()];
  if (!page) { return; }
  const root = document.getElementById('page-root');
  const y = window.scrollY;
  root.innerHTML = page.render();
  if (page.mount) { page.mount(); }
  window.scrollTo(0, y);
}

function go(name, opts) {
  const o = opts || {};
  if (o.replace) {
    stack[stack.length - 1] = name;
    history.replaceState({ page: name, depth: stack.length }, '', '#' + name);
  } else {
    stack.push(name);
    history.pushState({ page: name, depth: stack.length }, '', '#' + name);
  }
  render();
}

/**
 * 返回上一层。
 * 栈是唯一的真相：先改栈并立即渲染，再让浏览器历史同步后退一格。
 * 这样不依赖 popstate 的到达时机（各 WebView 实现差异较大）。
 */
function back() {
  if (stack.length <= 1) { return; }
  stack.pop();
  programmaticBackAt = Date.now();
  try { history.back(); } catch (e) { /* 某些 WebView 在无历史时抛错 */ }
  render();
}

/** 回到首页并清空栈（连接断开、设置完成等场景） */
function reset(name) {
  stack = [name || 'index'];
  history.replaceState({ page: stack[0], depth: 1 }, '', '#' + stack[0]);
  render();
}

/** 用 replace 语义回首页：能退就退，退不动就重置 */
function goHome() {
  if (stack.length > 1) {
    back();
  } else {
    reset('index');
  }
}

function depth() {
  return stack.length;
}

/* 只有「用户按了系统返回键」才会走到这里（我们自己触发的会被时间窗屏蔽） */
window.addEventListener('popstate', () => {
  if (Date.now() - programmaticBackAt < PROGRAMMATIC_WINDOW_MS) {
    return;
  }
  if (stack.length > 1) {
    stack.pop();
    render();
  }
});

module.exports = { register, render, refresh, go, back, reset, goHome, current, depth };
