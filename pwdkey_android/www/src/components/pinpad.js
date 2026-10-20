/**
 * components/pinpad.js - 6 位 PIN 键盘（按键位置每次随机，抗肩窥）
 *
 * 两种用法：
 *   create({title, subtitle, onSubmit})  -> 内联在页面里（解锁页用）
 *   prompt({title, subtitle})            -> 全屏弹层，resolve 出 PIN 字符串或 null
 *
 * 为什么随机化：6 位 PIN 一旦被旁边的人看一次就永久泄露；随机布局让"记住手指
 * 位置"这种偷看方式失效，成本几乎为零。
 */

const KEY_LEN = 6;

function shuffle(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    const t = a[i]; a[i] = a[j]; a[j] = t;
  }
  return a;
}

function buildKeys() {
  const d = shuffle([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  /* 3x4：前 9 个数字 + [清空, 第 10 个数字, 退格] */
  return d.slice(0, 9).concat(['clear', d[9], 'del']);
}

function keyHtml(k) {
  if (k === 'clear') { return '<div class="pin-key pin-key-fn" data-k="clear">清空</div>'; }
  if (k === 'del') { return '<div class="pin-key pin-key-fn" data-k="del">⌫</div>'; }
  return `<div class="pin-key" data-k="${k}">${k}</div>`;
}

/**
 * @param {{title?:string, subtitle?:string, onSubmit:(pin:string)=>void}} opts
 * @returns {{el:HTMLElement, reset:()=>void, setError:(msg:string)=>void,
 *            setBusy:(busy:boolean)=>void, destroy:()=>void}}
 */
function create(opts) {
  const o = opts || {};
  let pin = '';
  let keys = buildKeys();
  let busy = false;

  const el = document.createElement('div');
  el.className = 'pinpad';

  function draw() {
    const dots = [];
    for (let i = 0; i < KEY_LEN; i++) {
      dots.push(`<span class="pin-dot${i < pin.length ? ' on' : ''}"></span>`);
    }
    el.innerHTML = `
      ${o.title ? `<div class="pin-title">${o.title}</div>` : ''}
      ${o.subtitle ? `<div class="pin-sub muted">${o.subtitle}</div>` : ''}
      <div class="pin-dots">${dots.join('')}</div>
      <div class="pin-msg" id="pin-msg"></div>
      <div class="pin-keys">${keys.map(keyHtml).join('')}</div>
    `;
    el.querySelectorAll('.pin-key').forEach((b) => {
      b.onclick = () => onKey(b.dataset.k);
    });
  }

  function onKey(k) {
    if (busy) { return; }
    if (k === 'clear') {
      pin = '';
      draw();
      return;
    }
    if (k === 'del') {
      pin = pin.slice(0, -1);
      draw();
      return;
    }
    if (pin.length >= KEY_LEN) { return; }
    pin += String(k);
    draw();
    if (pin.length === KEY_LEN) {
      const value = pin;
      busy = true;
      setTimeout(() => {
        if (o.onSubmit) { o.onSubmit(value); }
      }, 90);
    }
  }

  function reset() {
    pin = '';
    busy = false;
    keys = buildKeys();      // 每次重来都换布局
    draw();
  }

  function setError(msg) {
    const box = el.querySelector('#pin-msg');
    if (box) { box.textContent = msg || ''; }
    el.classList.add('pin-shake');
    setTimeout(() => el.classList.remove('pin-shake'), 320);
  }

  function setBusy(b) {
    busy = b;
    el.classList.toggle('pin-busy', b);
  }

  draw();

  return {
    el,
    reset,
    setError,
    setBusy,
    destroy() { el.remove(); },
  };
}

/**
 * 全屏弹层要一个 PIN。取消时 resolve(null)。
 * @param {{title?:string, subtitle?:string}} opts
 * @returns {Promise<string|null>}
 */
function prompt(opts) {
  const o = opts || {};
  return new Promise((resolve) => {
    const mask = document.createElement('div');
    mask.className = 'mask pin-mask';
    document.body.appendChild(mask);

    let done = false;

    const pad = create({
      title: o.title || '输入 6 位 PIN',
      subtitle: o.subtitle || '',
      onSubmit: (pin) => {
        done = true;
        mask.remove();
        resolve(pin);
      },
    });

    const cancel = document.createElement('div');
    cancel.className = 'pin-cancel';
    cancel.textContent = '取消';

    mask.appendChild(pad.el);
    mask.appendChild(cancel);

    cancel.onclick = () => {
      if (done) { return; }
      done = true;
      mask.remove();
      resolve(null);
    };
  });
}

module.exports = { KEY_LEN, create, prompt };
