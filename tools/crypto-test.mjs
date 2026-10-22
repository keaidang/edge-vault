// Edge Vault — 浏览器加密库回归测试（Node 22 直接跑 public/js/crypto.js）
//
// 用法：node tools/crypto-test.mjs
//
// 覆盖：登录哈希随机盐、RSA 私钥包裹/解包、文件密钥包裹、文件名加解密（含 ArrayBuffer 密钥路径）、
//       EVF2 分块加解密与 GCM 完整性校验、假仓库确定性密钥派生
import {
  loginHash, generateMasterKeys, wrapPrivateKey, unwrapPrivateKey,
  wrapKeyWithPub, unwrapKeyWithPriv, encryptText, decryptText,
  fileEncrypt, fileDecrypt, deriveFileKey, newRawKey,
} from '../public/js/crypto.js';

const results = [];
const check = (name, ok, detail = '') => {
  results.push({ name, ok });
  console.log(`${ok ? '✅' : '❌'} ${name}${detail ? `  —  ${detail}` : ''}`);
};

const [h1, h2, h3] = await Promise.all([
  loginHash('passw0rd', 'login', 'saltA'),
  loginHash('passw0rd', 'login', 'saltB'),
  loginHash('passw0rd', 'login'),
]);
check('per-vault 盐使登录哈希不同', h1 !== h2 && h1 !== h3, `${h1.slice(0, 12)}… vs ${h2.slice(0, 12)}…`);
check('同一盐 + 同一口令哈希稳定', h1 === await loginHash('passw0rd', 'login', 'saltA'));

const { privJwk, pubJwk } = await generateMasterKeys();
const { wrapped, salt } = await wrapPrivateKey(privJwk, 'passw0rd');
check('私钥包裹（salt + AES-GCM）', !!salt && wrapped.length > 100, `wrapped=${wrapped.length}B`);
const privKey = await unwrapPrivateKey(wrapped, 'passw0rd');
let badPass = false;
try { await unwrapPrivateKey(wrapped, 'wrong-pass'); } catch { badPass = true; }
check('错误口令解包失败', badPass);

const rawKey = newRawKey();
const wrappedKey = await wrapKeyWithPub(pubJwk, rawKey);
const unwrappedKey = await unwrapKeyWithPriv(privKey, wrappedKey); // ArrayBuffer，与 app.js 调用方式一致
check('文件密钥 RSA-OAEP 包裹/解包', new Uint8Array(unwrappedKey).every((b, i) => b === rawKey[i]));

const ct = await encryptText(rawKey, '体检报告-2026 最终版.pdf');
check('文件名密文不含明文', !ct.includes('体检') && !ct.includes('pdf'));
check('文件名解密（ArrayBuffer 密钥路径）', await decryptText(unwrappedKey, ct) === '体检报告-2026 最终版.pdf');

const plain = new Uint8Array(600 * 1024).map((_, i) => i & 0xff);
const evf = await fileEncrypt(rawKey, plain);
const back = await fileDecrypt(rawKey, evf);
check('EVF2 分块文件加解密（600KB / 3 块）', back.length === plain.length && back.every((b, i) => b === plain[i]), `密文=${evf.byteLength}B`);
let tampered = false;
const broken = new Uint8Array(evf);
broken[broken.length - 1] ^= 0xff;
try { await fileDecrypt(rawKey, broken); } catch { tampered = true; }
check('篡改密文解密失败（GCM 完整性）', tampered);

const dk1 = await deriveFileKey('duress-pass', 'note-id-1');
const dk2 = await deriveFileKey('duress-pass', 'note-id-1');
check('假仓库密钥确定性派生', new Uint8Array(dk1).join() === new Uint8Array(dk2).join());

const failed = results.filter(r => !r.ok);
console.log(`\n结果: ${results.length - failed.length}/${results.length} 通过`);
process.exit(failed.length ? 1 : 0);
