// 一次性校验脚本：确认 bundle 内含 v1.1 全部新增文案与逻辑
const fs = require('fs');
const b = fs.readFileSync(process.argv[2] || 'www/js/app.bundle.js', 'utf8');

// 把 bundle 里的 \uXXXX 还原成真字符，方便统一匹配
const decoded = b.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));

const must = [
  ['指纹解锁已过期', '空信封防呆（salt 不匹配）'],
  ['生物密钥', '密钥失效提示'],
  ['生物认证', '设置页' ],
  ['安全设置', 'security 路由标题'],
  ['修改主密码', 'change-pwd 页'],
  ['PIN 与指纹缺一不可', 'AND 串联的 UI 提示'],
  ['BiometricWrap', '原生插件桥'],
  ['bio_offer_done', '只提示一次'],
  ['PIN_INVALID', 'PIN 错误码'],
  ['changePassword', '改密码入口'],
  ['unlockWithKek', 'KEK 直接解锁'],
  ['setMock', '测试注入点'],
  ['pinpad', 'PIN 键盘'],
  ['deviceSalt', '信封 salt 校验'],
];

let bad = 0;
for (const [k, why] of must) {
  const ok = decoded.includes(k);
  if (!ok) bad++;
  console.log((ok ? '  OK   ' : '  MISS ') + k + '  — ' + why);
}
console.log('\n' + (bad === 0 ? 'BUNDLE 完整性校验通过：v1.1 全部新增代码均已打包' : `有 ${bad} 项缺失`));
process.exit(bad === 0 ? 0 : 1);
