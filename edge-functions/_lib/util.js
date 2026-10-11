// 通用工具：JSON 响应 / 会话 / 审计链 / 常量
// 约定：state_kv / session_kv / audit_kv 为控制台绑定的 KV 全局变量
//       env 为 context.env（R2 凭据、内部 token 等环境变量）

const te = s => new TextEncoder().encode(s);

export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers } });
}
export const err = (msg, status = 400) => json({ ok: false, error: msg }, status);

// ---- 会话 ----
const SESSION_TTL = 12 * 3600; // 会话有效期 12h

function parseCookie(request) {
  const out = {};
  for (const pair of (request.headers.get('Cookie') || '').split(/;\s*/)) {
    const i = pair.indexOf('=');
    if (i > 0) out[pair.slice(0, i)] = pair.slice(i + 1);
  }
  return out;
}

export async function createSession(duress = false) {
  const token = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
  const now = Math.floor(Date.now() / 1000);
  await session_kv.put(`sess:${token}`, JSON.stringify({ duress, iat: now, exp: now + SESSION_TTL }));
  return {
    token,
    cookie: `ev_session=${token}; Max-Age=${SESSION_TTL}; Path=/; Secure; HttpOnly; SameSite=Strict`,
  };
}

export async function getSession(request) {
  const token = parseCookie(request).ev_session;
  if (!token) return null;
  const sess = await session_kv.get(`sess:${token}`, 'json');
  if (!sess || sess.exp < Math.floor(Date.now() / 1000)) return null;
  return sess;
}

export async function destroyAllSessions() {
  const res = await session_kv.list({ prefix: 'sess:' });
  for (const k of res.keys) await session_kv.delete(k.name);
}

// ---- 审计日志（链式哈希）----
async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey('raw', te(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, te(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function audit(env, action, detail = '') {
  const seq = Number((await audit_kv.get('audit:counter')) || 0) + 1;
  const ts = new Date().toISOString();
  const prev = (await audit_kv.get('audit:prev')) || 'GENESIS';
  const hash = await hmacHex(env.SESSION_SECRET, `${seq}|${ts}|${action}|${detail}|${prev}`);
  await audit_kv.put(`audit:${seq}`, JSON.stringify({ seq, ts, action, detail, prev, hash }));
  await audit_kv.put('audit:counter', String(seq));
  await audit_kv.put('audit:prev', hash);
}

export async function readAudit(limit = 200) {
  const counter = Number((await audit_kv.get('audit:counter')) || 0);
  const entries = [];
  const start = Math.max(1, counter - limit + 1);
  for (let i = counter; i >= start; i--) {
    const e = await audit_kv.get(`audit:${i}`, 'json');
    if (e) entries.push(e);
  }
  return { counter, entries };
}

// ---- 常量 ----
export const DEFAULT_QUOTA = 5 * 1024 * 1024 * 1024; // 保险库默认 5GB，可在设置菜单调整
export const randId = () => crypto.randomUUID().replace(/-/g, '').slice(0, 16);
export const nowSec = () => Math.floor(Date.now() / 1000);

// ---- 系统状态 ----
export async function getState() {
  return (await state_kv.get('state:system', 'json')) || { initialized: false };
}
export async function putState(s) {
  await state_kv.put('state:system', JSON.stringify(s));
}
export async function getStorageConfig() {
  return (await state_kv.get('config:storage', 'json')) || { vault_quota_bytes: DEFAULT_QUOTA, notes_excluded: true };
}
export async function getUsage() {
  return (await state_kv.get('usage:vault', 'json')) || { used_bytes: 0 };
}
