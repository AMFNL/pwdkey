/**
 * ui.js - 把小程序里用到的交互 API 换成 Web 实现
 *
 * 只做"翻译"，不引入任何框架：类名继续沿用 app.wxss 里的那套
 * （card / btn / mask / dialog / badge ...），所以样式可以照搬，视觉保持一致。
 */

const root = () => document.body;

/* ---------------- 基础工具 ---------------- */

/** HTML 转义（所有插值都必须过一遍，避免名字里带 < > 破坏结构） */
function esc(s) {
  return String(s === undefined || s === null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function h(html) {
  const t = document.createElement('template');
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------------- toast ---------------- */

let toastTimer = null;

function toast(title, opts) {
  const o = opts || {};
  const duration = o.duration || 1800;
  let el = document.getElementById('app-toast');
  if (el) { el.remove(); }
  el = h(`<div id="app-toast" class="toast">${esc(title)}</div>`);
  root().appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  if (toastTimer) { clearTimeout(toastTimer); }
  toastTimer = setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 200);
  }, duration);
}

/* ---------------- loading ---------------- */

let loadingCount = 0;

function showLoading(title) {
  loadingCount++;
  let el = document.getElementById('app-loading');
  if (!el) {
    el = h(`<div id="app-loading" class="mask loading-mask">
              <div class="loading-box">
                <div class="spinner"></div>
                <div class="loading-text"></div>
              </div>
            </div>`);
    root().appendChild(el);
  }
  el.querySelector('.loading-text').textContent = title || '处理中';
}

function hideLoading() {
  loadingCount = Math.max(0, loadingCount - 1);
  if (loadingCount === 0) {
    const el = document.getElementById('app-loading');
    if (el) { el.remove(); }
  }
}

/* ---------------- modal ---------------- */

/**
 * @param {{title?:string, content?:string, confirmText?:string, cancelText?:string,
 *          confirmColor?:string, showCancel?:boolean, editable?:boolean,
 *          placeholderText?:string, maxLength?:number}} opts
 * @returns {Promise<{confirm:boolean, content:string}>}
 */
function modal(opts) {
  const o = opts || {};
  return new Promise((resolve) => {
    const showCancel = o.showCancel !== false;
    const el = h(`<div class="mask">
      <div class="dialog">
        ${o.title ? `<div class="dialog-title">${esc(o.title)}</div>` : ''}
        ${o.content ? `<div class="dialog-content">${esc(o.content)}</div>` : ''}
        ${o.editable ? `<input class="input" id="modal-input"
              placeholder="${esc(o.placeholderText || '')}"
              maxlength="${o.maxLength || 64}" value="${esc(o.content || '')}" />` : ''}
        <div class="dialog-actions">
          ${showCancel ? `<button class="btn btn-ghost" data-act="cancel">${esc(o.cancelText || '取消')}</button>` : ''}
          <button class="btn btn-primary" data-act="ok"
            ${o.confirmColor ? `style="background:${esc(o.confirmColor)}"` : ''}>${esc(o.confirmText || '确定')}</button>
        </div>
      </div>
    </div>`);

    const input = el.querySelector('#modal-input');
    if (input) {
      /* 编辑类弹窗不要立刻弹键盘顶着对话框，等动画结束再聚焦 */
      setTimeout(() => { input.focus(); input.select(); }, 60);
    }

    function close(confirm) {
      const content = input ? input.value : '';
      el.remove();
      resolve({ confirm, content });
    }

    el.addEventListener('click', (ev) => {
      const act = ev.target.getAttribute && ev.target.getAttribute('data-act');
      if (act === 'ok') { close(true); }
      else if (act === 'cancel') { close(false); }
      else if (ev.target === el) { close(false); }   // 点遮罩 = 取消
    });

    if (input) {
      input.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter') { close(true); }
      });
    }

    root().appendChild(el);
  });
}

/* ---------------- action sheet ---------------- */

/**
 * @param {{itemList:string[], title?:string}} opts
 * @returns {Promise<{tapIndex:number}|null>} 取消时返回 null
 */
function actionSheet(opts) {
  const o = opts || {};
  return new Promise((resolve) => {
    const items = (o.itemList || []).map((label, i) =>
      `<div class="sheet-item" data-idx="${i}">${esc(label)}</div>`).join('');

    const el = h(`<div class="mask sheet-mask">
      <div class="sheet">
        ${o.title ? `<div class="sheet-title">${esc(o.title)}</div>` : ''}
        ${items}
        <div class="sheet-item sheet-cancel" data-idx="-1">取消</div>
      </div>
    </div>`);

    el.addEventListener('click', (ev) => {
      const raw = ev.target.getAttribute && ev.target.getAttribute('data-idx');
      if (raw === null || raw === undefined) {
        if (ev.target === el) { el.remove(); resolve(null); }
        return;
      }
      const idx = parseInt(raw, 10);
      el.remove();
      resolve(idx < 0 ? null : { tapIndex: idx });
    });

    root().appendChild(el);
  });
}

/* ---------------- 其它 ---------------- */

function vibrate() {
  try {
    if (navigator.vibrate) { navigator.vibrate(18); }
  } catch (e) { /* 无所谓 */ }
}

async function copyText(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (e) { /* 落到下面的兜底 */ }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    return true;
  } catch (e) {
    return false;
  }
}

/* 本地存储（对应小程序的 wx.getStorageSync / setStorageSync） */
const store = {
  get(key, dflt) {
    try {
      const v = localStorage.getItem(key);
      return v === null ? (dflt === undefined ? '' : dflt) : v;
    } catch (e) {
      return dflt === undefined ? '' : dflt;
    }
  },
  set(key, value) {
    try { localStorage.setItem(key, value); } catch (e) { /* 满/隐私模式 */ }
  },
  remove(key) {
    try { localStorage.removeItem(key); } catch (e) { /* ignore */ }
  },
};

module.exports = {
  esc, h, sleep, toast, modal, actionSheet,
  showLoading, hideLoading, vibrate, copyText, store,
};
