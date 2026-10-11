// Edge Vault — 浏览器端加密库（WebCrypto 全实现，明文不出浏览器）
const enc = new TextEncoder();
const dec = new TextDecoder();

export const b64 = {
  enc(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(s);
  },
  dec(str) {
    const s = atob(str);
    const bytes = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
    return bytes;
  },
};

const PBKDF2_ITERS = 600000;

async function pbkdf2(password, saltStr, info) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(`${saltStr}:${info}`), iterations: PBKDF2_ITERS },
    key, 256,
  );
}

// 登录哈希（服务端只存此哈希；checkin 与 duress 用不同 info 区分）
export async function loginHash(password, kind) {
  const bits = await pbkdf2(password, 'edge-vault', kind === 'duress' ? 'duress' : 'checkin');
  return [...new Uint8Array(bits)].map(x => x.toString(16).padStart(2, '0')).join('');
}

// 假仓库（decoy）模式：按「口令+对象ID」确定性派生密钥，无需服务端存任何包裹材料
export async function deriveFileKey(password, label) {
  return pbkdf2(password, 'edge-vault-decoy', label);
}

// KEK：用于包裹 RSA 私钥
async function deriveKEK(password, saltB64) {
  const salt = b64.dec(saltB64);
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERS },
    key, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );
}

async function aesKey(raw, usages) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, usages);
}

async function aesEncrypt(key, data) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, data);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(nonce); out.set(new Uint8Array(ct), 12);
  return out;
}

async function aesDecrypt(key, packed) {
  const nonce = packed.slice(0, 12);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, packed.slice(12));
}

// ---- RSA 密钥对（初始化时生成）----
export async function generateMasterKeys() {
  const kp = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['encrypt', 'decrypt'],
  );
  const privJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const pubJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  return { privJwk, pubJwk };
}

// 包裹私钥（口令派生 KEK + AES-GCM）
export async function wrapPrivateKey(privJwk, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kek = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  const kekKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERS },
    kek, { name: 'AES-GCM', length: 256 }, false, ['encrypt'],
  );
  const packed = await aesEncrypt(kekKey, enc.encode(JSON.stringify(privJwk)));
  const out = new Uint8Array(salt.length + packed.length);
  out.set(salt); out.set(packed, salt.length);
  return { wrapped: b64.enc(out), salt: b64.enc(salt) };
}

export async function unwrapPrivateKey(wrappedB64, password) {
  const data = b64.dec(wrappedB64);
  const salt = data.slice(0, 16);
  const kek = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  const kekKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERS },
    kek, { name: 'AES-GCM', length: 256 }, false, ['decrypt'],
  );
  const jwkStr = dec(await aesDecrypt(kekKey, data.slice(16)));
  return crypto.subtle.importKey('jwk', JSON.parse(jwkStr), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
}

// RSA 包裹对称密钥 / 解包
export async function wrapKeyWithPub(pubJwk, rawKey) {
  const pub = await crypto.subtle.importKey('jwk', pubJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  return b64.enc(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, rawKey));
}
export async function unwrapKeyWithPriv(privKey, wrappedB64) {
  return crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, b64.dec(wrappedB64));
}

// ---- 文件加密（分块 AES-256-GCM，长度前缀格式：[4B magic EVF2] + 每块 [4B len][12B nonce][len B ct 含16B tag]）----
const CHUNK_SIZE = 256 * 1024;

export async function fileEncrypt(rawFileKey, fileBuf) {
  const key = await aesKey(rawFileKey, ['encrypt']);
  const parts = [enc.encode('EVF2')];
  for (let i = 0; i < fileBuf.byteLength; i += CHUNK_SIZE) {
    const chunk = fileBuf.subarray(i, Math.min(i + CHUNK_SIZE, fileBuf.byteLength));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, chunk);
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, ct.byteLength);
    parts.push(len, nonce, new Uint8Array(ct));
  }
  const total = parts.reduce((s, p) => s + p.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.byteLength; }
  return out;
}

export async function fileDecrypt(rawFileKey, cipherBuf) {
  const key = await aesKey(rawFileKey, ['decrypt']);
  if (dec.call(null, cipherBuf.slice(0, 4)) !== 'EVF2') throw new Error('密文格式不正确');
  let off = 4;
  const plain = [];
  while (off < cipherBuf.byteLength) {
    const len = new DataView(cipherBuf.buffer, cipherBuf.byteOffset + off).getUint32(0);
    off += 4;
    const nonce = cipherBuf.slice(off, off + 12); off += 12;
    const ct = cipherBuf.slice(off, off + len); off += len;
    plain.push(new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct)));
  }
  const total = plain.reduce((s, p) => s + p.byteLength, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of plain) { out.set(p, o); o += p.byteLength; }
  return out;
}

// ---- 笔记 ----
export async function encryptText(rawKey, text) { return b64.enc(await aesEncrypt(await aesKey(rawKey, ['encrypt']), enc.encode(text))); }
export async function decryptText(rawKey, b64str) { return dec(await aesDecrypt(await aesKey(rawKey, ['decrypt']), b64.dec(b64str))); }
export const newRawKey = () => crypto.getRandomValues(new Uint8Array(32));
