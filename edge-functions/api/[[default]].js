// Edge Vault — API 总路由（对齐 aegis-vault 服务端语义；平台差异见 docs/方案确认-v2.md）
// KV 全局绑定：state_kv / session_kv / audit_kv
// 环境变量：R2_ACCOUNT_ID / R2_ACCESS_KEY_ID / R2_SECRET_ACCESS_KEY / R2_BUCKET
//          SESSION_SECRET / INTERNAL_TOKEN / RESET_TOKEN(可选) / SESSION_BIND_IP(可选=1)
//
// 与原版一致的模型：固定四用户槽位、独立保险库、独立笔记密钥与笔记会话、每次敏感操作复用口令校验、
// 状态 HMAC 防篡改、CSRF、UA 指纹、失败限流、链式审计、单文件与总容量上限。

const USERS = ['admin', 'user1', 'user2', 'user3'];
const MODES = { vault: 'vault', notes: 'notes' };

const te = s => new TextEncoder().encode(s);
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const randId = n => crypto.randomUUID().replace(/-/g, '').slice(0, n);
const safeId = v => String(v ?? '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
const nowSec = () => Math.floor(Date.now() / 1000);

const SESSION_TTL = 12 * 3600;
const DEFAULT_QUOTA = 1024 * 1024 * 1024;   // 原版 MAX_VAULT_SIZE_MB=1024
const MAX_UPLOAD_BYTES = 64 * 1024 * 1024;   // 原版 MAX_UPLOAD_SIZE_MB=64
const MIN_PASSWORD_LEN = 12;
const MIN_CODE_LEN = 8;
const MAX_NOTE_BODY = 900 * 1024;            // Edge Functions 请求体 1MB
const VERIFY_WINDOW_SEC = 180;               // 二次口令校验有效期

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers } });
}
const err = (msg, status = 400) => json({ ok: false, error: msg }, status);

function timingSafeEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function body(request) {
  try { return await request.json(); } catch { return {}; }
}

async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey('raw', te(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, te(msg)));
}
async function sha256Hex(data) {
  const buf = typeof data === 'string' ? te(data) : data;
  return hex(await crypto.subtle.digest('SHA-256', buf));
}

// schedules 无法自定义请求头 → internal token 支持 header / query / payload 三通道
function internalAuthOk(request, env, bodyToken = '') {
  const expected = env.INTERNAL_TOKEN || '';
  if (!expected) return false;
  let fromQuery = '';
  try { fromQuery = new URL(request.url).searchParams.get('token') || ''; } catch { /* ignore */ }
  const given = request.headers.get('x-internal-token') || fromQuery || String(bodyToken || '');
  return timingSafeEq(given, expected);
}

// ==================== KV 兼容层 ====================
// EdgeOne KV list() → { keys:[{key}], complete, cursor }；Cloudflare → { keys:[{name}], list_complete }
const kvKeyName = k => (k && (k.name ?? k.key)) || '';
async function listAllKeys(kv, prefix) {
  const names = [];
  let cursor;
  for (let page = 0; page < 200; page++) {
    const res = await kv.list({ prefix, limit: 256, ...(cursor ? { cursor } : {}) });
    for (const k of (res && res.keys) || []) {
      const name = kvKeyName(k);
      if (name) names.push(name);
    }
    const complete = res ? (res.complete ?? res.list_complete ?? true) : true;
    cursor = res && res.cursor ? res.cursor : undefined;
    if (complete || !cursor) break;
  }
  return names;
}

// ==================== 强度校验（原版服务端校验的客户端替代，见 docs 平台差异）====================
function passwordProblem(pw, minLength = MIN_PASSWORD_LEN) {
  const s = String(pw || '').trim();
  if (s.length < minLength) return `密码长度至少需要 ${minLength} 个字符`;
  if (s.length > 256) return '密码长度不能超过 256 个字符';
  const kinds = [/[A-Z]/, /[a-z]/, /[0-9]/, /[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/].filter(re => re.test(s)).length;
  if (kinds < 3) return '密码必须包含至少 3 种类型：大小写、数字、特殊符号';
  return '';
}
function codeProblem(code, minLength = MIN_CODE_LEN) {
  const s = String(code || '').trim();
  if (s.length < minLength) return `码长度至少需要 ${minLength} 个字符`;
  if (s.length > 256) return '码长度不能超过 256 个字符';
  if (!/[a-zA-Z0-9]/.test(s) || new Set(s).size < 4) return '码必须包含足够的多样性（混合字符和数字）';
  return '';
}

// ==================== 系统状态（HMAC 防篡改，对齐原版 status.json + status.hmac）====================
const STATE_KEY = 'state:system';
function statePayload(st) {
  const { hmac, ...rest } = st || {};
  return JSON.stringify(rest);
}
async function putState(env, st) {
  const hmac = await hmacHex(env.SESSION_SECRET, statePayload(st));
  await state_kv.put(STATE_KEY, JSON.stringify({ ...st, hmac }));
}
// verify=false 仅供 destroyAll 内部使用，避免篡改态递归触发销毁
async function getState(env, verify = true) {
  const st = (await state_kv.get(STATE_KEY, 'json')) || { initialized: false };
  if (!verify || !st.hmac) return st;
  const expect = await hmacHex(env.SESSION_SECRET, statePayload(st));
  if (!timingSafeEq(expect, st.hmac)) {
    await destroyAll(env, 'state-tampered');
    return (await state_kv.get(STATE_KEY, 'json')) || { initialized: false, destroyed: true };
  }
  return st;
}

const isOverdue = st => st.initialized && !st.destroyed && st.last_checkin > 0 &&
  nowSec() - st.last_checkin > (st.checkin_timeout_hours || 72) * 3600;

// 访问即检：任何访问发现超时 → 立即销毁（每日 cron 仅兜底无人访问的情况）
async function lazySweep(env) {
  const st = await getState(env, false);
  if (!st.initialized || st.destroyed) return;
  if (isOverdue(st)) await destroyAll(env, 'checkin-timeout');
}

// ==================== 用户与会话 ====================
const isUser = name => USERS.includes(name);
const userKey = name => `user:${name}`;
const loginHashKey = name => `hash:login:${name}`;
const noteKeyKey = name => `nkey:${name}`;
const noteHashKey = name => `hash:note:${name}`;
const notesEnabledKey = name => `notes-enabled:${name}`;

async function getUser(name) { return isUser(name) ? await state_kv.get(userKey(name), 'json') : null; }
async function getNoteKey(name) { return isUser(name) ? await state_kv.get(noteKeyKey(name), 'json') : null; }
async function notesEnabled(name) { return (await state_kv.get(notesEnabledKey(name))) === '1'; }
async function configuredUsers() {
  const out = [];
  for (const name of USERS) {
    if (await getUser(name)) out.push({ name, notes: await notesEnabled(name) });
  }
  return out;
}

// 统一登录入口：先胁迫码，再保险库口令，最后笔记口令（对齐原版 authenticate / NotesManager.authenticate）
async function identify(hash) {
  const duress = await state_kv.get('hash:duress');
  if (duress && timingSafeEq(hash, duress)) return { duress: true };
  for (const name of USERS) {
    const stored = await state_kv.get(loginHashKey(name));
    if (stored && timingSafeEq(hash, stored)) return { user: name, mode: MODES.vault };
  }
  for (const name of USERS) {
    if (!(await notesEnabled(name))) continue;
    const stored = await state_kv.get(noteHashKey(name));
    if (stored && timingSafeEq(hash, stored)) return { user: name, mode: MODES.notes };
  }
  return null;
}

function parseCookie(request) {
  const out = {};
  for (const pair of (request.headers.get('Cookie') || '').split(/;\s*/)) {
    const i = pair.indexOf('=');
    if (i > 0) out[pair.slice(0, i)] = pair.slice(i + 1);
  }
  return out;
}
function clientIp(request) {
  const h = request.headers;
  return (h.get('eo-client-ip') || h.get('x-forwarded-for') || h.get('x-real-ip') || '').split(',')[0].trim();
}
async function fingerprint(request, env) {
  const parts = [request.headers.get('User-Agent') || ''];
  if (env.SESSION_BIND_IP === '1') parts.push(clientIp(request));
  return (await sha256Hex(parts.join('|'))).slice(0, 32);
}

async function createSession(request, env, { user, mode, csrf }) {
  const token = randId(32) + randId(32);
  const now = nowSec();
  const sess = { user, mode, csrf, iat: now, exp: now + SESSION_TTL, fp: await fingerprint(request, env) };
  await session_kv.put(`sess:${token}`, JSON.stringify(sess));
  return { token, sess, cookie: `ev_session=${token}; Max-Age=${SESSION_TTL}; Path=/; Secure; HttpOnly; SameSite=Strict` };
}

async function getSession(request, env) {
  const token = parseCookie(request).ev_session;
  if (!token) return null;
  const sess = await session_kv.get(`sess:${token}`, 'json');
  if (!sess || sess.exp < nowSec()) return null;
  if (!timingSafeEq(sess.fp || '', await fingerprint(request, env))) {
    await session_kv.delete(`sess:${token}`);
    return null;
  }
  return { ...sess, token };
}

async function destroyUserSessions(user) {
  for (const name of await listAllKeys(session_kv, 'sess:')) {
    const sess = await session_kv.get(name, 'json');
    if (!user || sess?.user === user) await session_kv.delete(name);
  }
}

// ==================== 审计（链式哈希，事件名对齐原版 AuditEvent）====================
async function audit(env, action, { user = '', detail = '', success = true } = {}) {
  const seq = Number((await audit_kv.get('audit:counter')) || 0) + 1;
  const ts = new Date().toISOString();
  const prev = (await audit_kv.get('audit:prev')) || 'GENESIS';
  const hash = await hmacHex(env.SESSION_SECRET, `${seq}|${ts}|${action}|${user}|${detail}|${success}|${prev}`);
  await audit_kv.put(`audit:${seq}`, JSON.stringify({ seq, ts, action, user, detail, success, prev, hash }));
  await audit_kv.put('audit:counter', String(seq));
  await audit_kv.put('audit:prev', hash);
}

async function verifyAuditChain(env, limit = 300) {
  const counter = Number((await audit_kv.get('audit:counter')) || 0);
  const entries = [];
  for (let i = counter; i >= Math.max(1, counter - limit + 1); i--) {
    const e = await audit_kv.get(`audit:${i}`, 'json');
    if (e) entries.push(e);
  }
  let chainOk = true;
  // entries[0] 最新 → 倒序遍历即从旧到新，逐条校验事件哈希与 prev 链接
  for (let i = entries.length - 1; i >= 0; i--) {
    const e = entries[i];
    const expect = await hmacHex(env.SESSION_SECRET, `${e.seq}|${e.ts}|${e.action}|${e.user || ''}|${e.detail || ''}|${e.success !== false}|${e.prev}`);
    if (!timingSafeEq(expect, e.hash || '')) { chainOk = false; break; }
    if (i > 0 && entries[i - 1].prev !== e.hash) { chainOk = false; break; }
  }
  return { counter, entries, chainOk };
}

// ==================== 失败限流（原版 rate_limiter 的最终一致降级版）====================
const RATE_MAX_FAILS = 5;
const RATE_WINDOW_SEC = 15 * 60;
async function isRateLimited(bucket) {
  const rl = (await state_kv.get(`ratelimit:${bucket}`, 'json')) || { count: 0, since: nowSec() };
  if (nowSec() - (rl.since || 0) > RATE_WINDOW_SEC) return false;
  return (rl.count || 0) >= RATE_MAX_FAILS;
}
async function bumpRateLimit(bucket) {
  const now = nowSec();
  const rl = (await state_kv.get(`ratelimit:${bucket}`, 'json')) || { count: 0, since: now };
  if (now - (rl.since || 0) > RATE_WINDOW_SEC) { rl.count = 0; rl.since = now; }
  rl.count = (rl.count || 0) + 1;
  await state_kv.put(`ratelimit:${bucket}`, JSON.stringify(rl));
}
async function clearRateLimit(bucket) { await state_kv.delete(`ratelimit:${bucket}`); }

// ==================== 存储配额 ====================
async function getStorageConfig() {
  return (await state_kv.get('config:storage', 'json')) || { vault_quota_bytes: DEFAULT_QUOTA };
}
async function getUsage() { return (await state_kv.get('usage:vault', 'json')) || { used_bytes: 0 }; }
async function putUsage(used) { await state_kv.put('usage:vault', JSON.stringify({ used_bytes: Math.max(0, used) })); }

// ==================== 键与业务辅助 ====================
const fileKeyPrefix = user => `file:${user}:`;
const noteKeyPrefix = user => `note:${user}:`;
const notesIndexKey = user => `notes-index:${user}`;
const fileR2Key = (user, id) => `vault/${user}/${id}.aes`;
const noteAttR2Key = (user, noteId, attId) => `notes/${user}/${noteId}/${attId}.aes`;

function csrfOk(request, sess) {
  const given = request.headers.get('x-csrf-token') || '';
  return !!sess.csrf && timingSafeEq(given, sess.csrf);
}
function verified(sess, scope) {
  const at = (sess.verify && sess.verify[scope]) || 0;
  return nowSec() - at <= VERIFY_WINDOW_SEC;
}
async function markVerified(sess, scope) {
  const next = { ...sess, verify: { ...(sess.verify || {}), [scope]: nowSec() } };
  await session_kv.put(`sess:${sess.token}`, JSON.stringify(next));
}

// ==================== R2（S3 兼容）SigV4 ====================
async function hmacR2(keyBuf, msg) {
  const key = await crypto.subtle.importKey('raw', keyBuf, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return crypto.subtle.sign('HMAC', key, te(msg));
}
async function sha256HexR2(data) {
  const buf = typeof data === 'string' ? te(data) : data;
  return hex(await crypto.subtle.digest('SHA-256', buf));
}
async function r2SigningKey(secret, dateStamp) {
  const kDate = await hmacR2(te(`AWS4${secret}`), dateStamp);
  return hmacR2(await hmacR2(await hmacR2(kDate, 'auto'), 's3'), 'aws4_request');
}
function r2Cfg(env) {
  return {
    host: `${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    bucket: env.R2_BUCKET,
    accessKey: env.R2_ACCESS_KEY_ID,
    secret: env.R2_SECRET_ACCESS_KEY,
  };
}
function amzDates() {
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  return { amzDate, dateStamp: amzDate.slice(0, 8) };
}

async function s3Request(env, method, path, params = {}, bodyStr = '') {
  const { host, bucket, accessKey, secret } = r2Cfg(env);
  const { amzDate, dateStamp } = amzDates();
  const fullPath = `/${bucket}${path}`;
  const query = Object.keys(params).sort()
    .map(k => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`).join('&');
  const payloadHash = await sha256HexR2(bodyStr);
  const headers = { host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate };
  const hNames = Object.keys(headers).sort();
  const signedHeaders = hNames.join(';');
  const canonical = [method, fullPath, query, hNames.map(h => `${h}:${headers[h]}`).join('\n') + '\n', signedHeaders, payloadHash].join('\n');
  const scope = `${dateStamp}/auto/s3/aws4_request`;
  const sts = ['AWS4-HMAC-SHA256', amzDate, scope, await sha256HexR2(canonical)].join('\n');
  const sig = hex(await hmacR2(await r2SigningKey(secret, dateStamp), sts));
  const auth = `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${sig}`;
  return fetch(`https://${host}${fullPath}${query ? `?${query}` : ''}`, {
    method, headers: { ...headers, Authorization: auth }, body: bodyStr || undefined,
  });
}

async function presign(env, method, objectKey, expires = 900) {
  const { host, bucket, accessKey, secret } = r2Cfg(env);
  const { amzDate, dateStamp } = amzDates();
  const fullPath = `/${bucket}/${objectKey}`;
  const scope = `${dateStamp}/auto/s3/aws4_request`;
  const qp = new URLSearchParams({
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${accessKey}/${scope}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expires),
    'X-Amz-SignedHeaders': 'host',
  });
  const canonical = [method, fullPath, qp.toString(), `host:${host}\n`, 'host', 'UNSIGNED-PAYLOAD'].join('\n');
  const sts = ['AWS4-HMAC-SHA256', amzDate, scope, await sha256HexR2(canonical)].join('\n');
  const sig = hex(await hmacR2(await r2SigningKey(secret, dateStamp), sts));
  qp.set('X-Amz-Signature', sig);
  return `https://${host}${fullPath}?${qp}`;
}

async function listAllObjects(env, prefix) {
  const keys = [];
  let token = '';
  do {
    const params = { 'list-type': '2', prefix, 'max-keys': '1000' };
    if (token) params['continuation-token'] = token;
    const res = await s3Request(env, 'GET', '', params);
    if (!res.ok) throw new Error(`ListObjects failed: ${res.status}`);
    const xml = await res.text();
    for (const m of xml.matchAll(/<Key>([^<]+)<\/Key>/g)) keys.push(m[1]);
    token = /<NextContinuationToken>([^<]+)<\/NextContinuationToken>/.exec(xml)?.[1] || '';
  } while (token);
  return keys;
}

async function deleteObjects(env, keys) {
  let deleted = 0;
  for (let i = 0; i < keys.length; i += 1000) {
    const batch = keys.slice(i, i + 1000);
    const bodyStr = `<Delete><Quiet>true</Quiet>${batch.map(k => `<Object><Key>${k}</Key></Object>`).join('')}</Delete>`;
    const res = await s3Request(env, 'POST', '', { delete: '' }, bodyStr);
    if (!res.ok) throw new Error(`DeleteObjects failed: ${res.status}`);
    deleted += batch.length;
  }
  return deleted;
}

async function purgeR2(env) {
  let deleted = 0;
  for (const prefix of ['vault/', 'notes/', 'decoy/']) {
    try {
      const keys = await listAllObjects(env, prefix);
      if (keys.length) deleted += await deleteObjects(env, keys);
    } catch { /* 单前缀失败不阻断：不可恢复性由删除密钥保证 */ }
  }
  return deleted;
}

// ==================== 销毁（先删钥、后删密文）====================
async function destroyAll(env, reason) {
  for (const prefix of ['user:', 'hash:login:', 'hash:note:', 'nkey:', 'notes-enabled:']) {
    for (const name of await listAllKeys(state_kv, prefix)) await state_kv.delete(name);
  }
  // 旧版单用户实现的残留键
  for (const legacy of ['key:me', 'hash:login', 'hash:checkin', 'hash:duress', 'hash:duress_checkin']) await state_kv.delete(legacy);
  const r2Deleted = await purgeR2(env);
  for (const prefix of ['file:', 'note:', 'notes-index', 'usage:', 'ratelimit:', 'decoy:']) {
    for (const name of await listAllKeys(state_kv, prefix)) await state_kv.delete(name);
  }
  await destroyUserSessions(null);
  const st = await getState(env, false);
  await putState(env, { ...st, destroyed: true, destroyed_at: new Date().toISOString(), destroy_reason: reason });
  await audit(env, 'SYSTEM_DESTROYED', { detail: `${reason} r2_deleted=${r2Deleted}` });
  return r2Deleted;
}

// ==================== 路由 ====================
export async function onRequest(context) {
  const { request, env, waitUntil } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/?/, '');
  const method = request.method;

  try {
    // ---------- 公开端点 ----------
    if (path === 'state' && method === 'GET') {
      const st = await getState(env);
      if (isOverdue(st)) waitUntil(lazySweep(env).catch(() => {}));
      const sess = await getSession(request, env);
      return json({
        ok: true,
        initialized: !!st.initialized,
        destroyed: !!st.destroyed,
        overdue: isOverdue(st),
        last_checkin: st.last_checkin || 0,
        checkin_timeout_hours: st.checkin_timeout_hours || 72,
        auth_salt: st.auth_salt || '',
        users: await configuredUsers(),
        quota: await getStorageConfig(),
        usage: await getUsage(),
        session: sess ? { user: sess.user, mode: sess.mode, csrf: sess.csrf } : null,
      });
    }

    if (path === 'init' && method === 'POST') {
      const st = await getState(env);
      const b = await body(request);
      const resetAllowed = !!env.RESET_TOKEN && timingSafeEq(String(b.reset_token || ''), env.RESET_TOKEN);
      if (st.initialized && !st.destroyed && !resetAllowed) {
        return err('已初始化，拒绝重复初始化（重置需在服务端配置 RESET_TOKEN）', 403);
      }
      for (const f of ['wrapped_priv_key', 'salt', 'pub_key', 'login_hash', 'checkin_hash', 'auth_salt']) {
        if (typeof b[f] === 'undefined' || b[f] === '') return err(`缺少字段 ${f}`);
      }
      if (st.initialized) await destroyAll(env, resetAllowed ? 'manual-reset' : 'reset-after-destroy');
      const now = nowSec();
      await state_kv.put(userKey('admin'), JSON.stringify({ wrapped: b.wrapped_priv_key, salt: b.salt, pub: b.pub_key, created: now, updated: now }));
      await state_kv.put(loginHashKey('admin'), String(b.login_hash));
      await state_kv.put('hash:checkin', String(b.checkin_hash));
      if (b.duress_hash) await state_kv.put('hash:duress', String(b.duress_hash));
      // 胁迫码需同时能被「登录框」与「签到框」命中，两者派生 kind 不同，故各存一份
      if (b.duress_hash_checkin) await state_kv.put('hash:duress_checkin', String(b.duress_hash_checkin));
      if (!(await state_kv.get('config:storage'))) {
        await state_kv.put('config:storage', JSON.stringify({ vault_quota_bytes: DEFAULT_QUOTA }));
      }
      await putState(env, {
        initialized: true, destroyed: false, created_at: now, last_checkin: now,
        checkin_timeout_hours: Number(b.checkin_timeout_hours) || 72,
        auth_salt: String(b.auth_salt).slice(0, 64),
      });
      await audit(env, 'SYSTEM_RESET', { detail: 'initialization' });
      await audit(env, 'USER_CREATED', { user: 'admin', detail: 'bootstrap' });
      return json({ ok: true });
    }

    if (path === 'login' && method === 'POST') {
      const st = await getState(env);
      if (!st.initialized) return err('系统未初始化', 403);
      if (st.destroyed) return err('系统已销毁', 403);
      if (isOverdue(st)) {
        await destroyAll(env, 'checkin-timeout');
        return err('系统已销毁', 403);
      }
      if (await isRateLimited('login')) {
        await audit(env, 'RATE_LIMIT_EXCEEDED', { detail: 'login', success: false });
        return err('尝试过多，请稍后重试', 429);
      }
      const b = await body(request);
      const hash = String(b.hash || '');
      if (!hash) return err('缺少 hash');

      const who = await identify(hash);
      if (!who) {
        await bumpRateLimit('login');
        await audit(env, 'AUTH_LOGIN_FAILED', { detail: 'invalid_credential', success: false });
        return err('身份验证失败', 401);
      }
      if (who.duress) {
        // 原版语义：命中胁迫码 → 立即销毁 + 通用失败提示
        await audit(env, 'DURESS_TRIGGERED');
        await destroyAll(env, 'duress');
        await clearRateLimit('login');
        return err('身份验证失败', 401);
      }
      await clearRateLimit('login');
      const csrf = randId(32);
      const { cookie } = await createSession(request, env, { user: who.user, mode: who.mode, csrf });
      await audit(env, 'AUTH_LOGIN_SUCCESS', { user: who.user, detail: who.mode });
      return json({ ok: true, mode: who.mode, user: who.user, csrf }, 200, { 'Set-Cookie': cookie });
    }

    if (path === 'checkin' && method === 'POST') {
      if (await isRateLimited('checkin')) {
        await audit(env, 'RATE_LIMIT_EXCEEDED', { detail: 'checkin', success: false });
        return err('签到尝试过多，请稍后重试', 429);
      }
      const b = await body(request);
      const hash = String(b.hash || '');
      const duress = await state_kv.get('hash:duress');
      const duressCheckin = await state_kv.get('hash:duress_checkin');
      if ((duress && timingSafeEq(hash, duress)) || (duressCheckin && timingSafeEq(hash, duressCheckin))) {
        await audit(env, 'DURESS_TRIGGERED');
        await destroyAll(env, 'duress');
        return err('签到失败', 401);
      }
      const checkinHash = await state_kv.get('hash:checkin');
      if (!checkinHash || !timingSafeEq(hash, checkinHash)) {
        await bumpRateLimit('checkin');
        await audit(env, 'CHECKIN_FAILED', { detail: 'invalid_code', success: false });
        return err('签到码错误', 401);
      }
      await clearRateLimit('checkin');
      const st = await getState(env);
      st.last_checkin = nowSec();
      await putState(env, st);
      await audit(env, 'CHECKIN_SUCCESS');
      return json({ ok: true, last_checkin: st.last_checkin, checkin_timeout_hours: st.checkin_timeout_hours || 72 });
    }

    // ---------- schedules 内部端点 ----------
    if (path === 'internal/sweep' && method === 'POST') {
      const b = await body(request);
      if (!internalAuthOk(request, env, b.token)) return err('forbidden', 403);
      const st = await getState(env);
      if (!st.initialized || st.destroyed) return json({ ok: true, skipped: 'not-active' });
      if (!isOverdue(st)) return json({ ok: true, skipped: 'in-time', last_checkin: st.last_checkin });
      const deleted = await destroyAll(env, 'checkin-timeout');
      return json({ ok: true, destroyed: true, deleted_r2_objects: deleted });
    }

    if (path === 'internal/archive' && method === 'POST') {
      const b = await body(request);
      if (!internalAuthOk(request, env, b.token)) return err('forbidden', 403);
      const counter = Number((await audit_kv.get('audit:counter')) || 0);
      if (!counter) return json({ ok: true, skipped: 'empty' });
      const dayAgo = new Date(Date.now() - 86400000).toISOString();
      const lines = [];
      let verifiedCount = 0, broken = 0;
      for (let i = 1; i <= counter; i++) {
        const e = await audit_kv.get(`audit:${i}`, 'json');
        if (!e) continue;
        if (e.ts < dayAgo) {
          const expect = await hmacHex(env.SESSION_SECRET, `${e.seq}|${e.ts}|${e.action}|${e.user || ''}|${e.detail || ''}|${e.success !== false}|${e.prev}`);
          if (expect === e.hash) verifiedCount++; else broken++;
          lines.push(JSON.stringify(e));
          await audit_kv.delete(`audit:${i}`);
        }
      }
      if (!lines.length) return json({ ok: true, skipped: 'nothing-to-archive' });
      const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
      const res = await fetch(await presign(env, 'PUT', `archive/audit-${date}.jsonl`, 3600), {
        method: 'PUT', body: lines.join('\n') + '\n',
      });
      if (!res.ok) return err(`archive upload failed: ${res.status}`, 500);
      await audit(env, 'AUDIT_ARCHIVED', { detail: `archived=${lines.length} verified=${verifiedCount} broken=${broken}` });
      return json({ ok: true, archived: lines.length, verified: verifiedCount, broken });
    }

    // ---------- 会话 / CSRF ----------
    const sess = await getSession(request, env);
    if (!sess) return err('未登录', 401);
    const st = await getState(env);
    if (!st.initialized || st.destroyed) return err('系统已销毁', 403);
    if (isOverdue(st)) {
      await destroyAll(env, 'checkin-timeout');
      return err('系统已销毁', 403);
    }
    if (method !== 'GET' && !csrfOk(request, sess)) return err('CSRF 校验失败', 403);

    const isVault = sess.mode === MODES.vault;
    const isNotes = sess.mode === MODES.notes;
    const isAdmin = isVault && sess.user === 'admin';

    if (path === 'logout' && method === 'POST') {
      await session_kv.delete(`sess:${sess.token}`);
      await audit(env, 'AUTH_LOGOUT', { user: sess.user });
      return json({ ok: true });
    }

    if (path === 'keyinfo' && method === 'GET') {
      const scope = url.searchParams.get('scope') || sess.mode;
      if (scope === 'notes') {
        if (!isNotes) return err('需要笔记会话', 403);
        const nk = await getNoteKey(sess.user);
        if (!nk) return err('笔记密钥不存在', 404);
        return json({ ok: true, note: nk, user: sess.user });
      }
      if (!isVault) return err('需要保险库会话', 403);
      const u = await getUser(sess.user);
      if (!u) return err('密钥不存在', 404);
      return json({ ok: true, user: u, name: sess.user });
    }

    // 二次口令校验：下载/删除文件、查看/删除笔记、附件操作前调用
    if (path === 'verify' && method === 'POST') {
      const b = await body(request);
      const scope = b.scope === 'notes' ? 'notes' : 'vault';
      const bucket = `verify:${scope}:${sess.user}`;
      if (await isRateLimited(bucket)) {
        await audit(env, 'RATE_LIMIT_EXCEEDED', { user: sess.user, detail: bucket, success: false });
        return err('尝试过多，请稍后重试', 429);
      }
      const hash = String(b.hash || '');
      const stored = scope === 'notes' ? await state_kv.get(noteHashKey(sess.user)) : await state_kv.get(loginHashKey(sess.user));
      if (!stored || !timingSafeEq(hash, stored)) {
        await bumpRateLimit(bucket);
        await audit(env, scope === 'notes' ? 'NOTE_ACCESS_FAILED' : 'INVALID_REQUEST', { user: sess.user, detail: `verify_${scope}`, success: false });
        return err('口令错误', 401);
      }
      await clearRateLimit(bucket);
      await markVerified(sess, scope);
      return json({ ok: true, scope });
    }

    // ---------- 管理端 ----------
    if (path === 'manage/user' && method === 'POST') {
      if (!isAdmin) return err('需要管理员保险库会话', 403);
      const b = await body(request);
      const target = String(b.target_user || '');
      if (!isUser(target)) return err('用户槽位无效', 400);
      for (const f of ['wrapped_priv_key', 'salt', 'pub_key', 'login_hash']) {
        if (typeof b[f] === 'undefined' || b[f] === '') return err(`缺少字段 ${f}`);
      }
      const existing = await getUser(target);
      if (existing && (await listAllKeys(state_kv, fileKeyPrefix(target))).length) {
        return err('目标用户已有加密文件，禁止直接重置密钥', 409);
      }
      const now = nowSec();
      await state_kv.put(userKey(target), JSON.stringify({
        wrapped: b.wrapped_priv_key, salt: b.salt, pub: b.pub_key,
        created: existing?.created || now, updated: now,
      }));
      await state_kv.put(loginHashKey(target), String(b.login_hash));
      await destroyUserSessions(target);
      await audit(env, existing ? 'USER_PASSWORD_UPDATED' : 'USER_CREATED', { user: sess.user, detail: target });
      return json({ ok: true, target_user: target, created: !existing });
    }

    if (path === 'manage/notes' && method === 'POST') {
      if (!isAdmin) return err('需要管理员保险库会话', 403);
      const b = await body(request);
      const target = String(b.target_user || '');
      if (!isUser(target)) return err('用户槽位无效', 400);
      if (!(await getUser(target))) return err('目标用户尚未创建密钥', 409);

      if (b.enabled === false) {
        await state_kv.delete(notesEnabledKey(target));
        await destroyUserSessions(target);
        await audit(env, 'NOTE_FEATURE_UPDATED', { user: sess.user, detail: `${target}:disabled` });
        return json({ ok: true, enabled: false });
      }

      const hasNoteKey = !!(await getNoteKey(target));
      if (!hasNoteKey || b.note_login_hash) {
        for (const f of ['wrapped_note_key', 'salt', 'pub_key', 'note_login_hash']) {
          if (typeof b[f] === 'undefined' || b[f] === '') return err(`缺少字段 ${f}`);
        }
        if (hasNoteKey && (await listAllKeys(state_kv, noteKeyPrefix(target))).length) {
          return err('目标用户已有笔记，禁止直接重置笔记密钥', 409);
        }
        await state_kv.put(noteKeyKey(target), JSON.stringify({ wrapped: b.wrapped_note_key, salt: b.salt, pub: b.pub_key, updated: nowSec() }));
        await state_kv.put(noteHashKey(target), String(b.note_login_hash));
      }
      await state_kv.put(notesEnabledKey(target), '1');
      await destroyUserSessions(target);
      await audit(env, 'NOTE_FEATURE_UPDATED', { user: sess.user, detail: `${target}:enabled` });
      return json({ ok: true, enabled: true });
    }

    if (path === 'codes/checkin' && method === 'POST') {
      if (!isAdmin) return err('需要管理员保险库会话', 403);
      const b = await body(request);
      if (!b.hash) return err('缺少 hash');
      await state_kv.put('hash:checkin', String(b.hash));
      await audit(env, 'CHECKIN_CODE_UPDATED', { user: sess.user });
      return json({ ok: true });
    }

    if (path === 'codes/duress' && method === 'POST') {
      if (!isAdmin) return err('需要管理员保险库会话', 403);
      const b = await body(request);
      if (!b.hash) return err('缺少 hash');
      await state_kv.put('hash:duress', String(b.hash));
      if (b.hash_checkin) await state_kv.put('hash:duress_checkin', String(b.hash_checkin));
      await audit(env, 'DURESS_CODE_UPDATED', { user: sess.user });
      return json({ ok: true });
    }

    if (path === 'config/storage') {
      if (method === 'GET') return json({ ok: true, ...(await getStorageConfig()), usage: await getUsage() });
      if (method === 'POST') {
        if (!isAdmin) return err('需要管理员保险库会话', 403);
        const b = await body(request);
        const q = Number(b.vault_quota_bytes);
        if (!Number.isFinite(q) || q < 1024 * 1024 || q > 1024 * 1024 * 1024 * 1024) return err('配额值无效');
        await state_kv.put('config:storage', JSON.stringify({ vault_quota_bytes: Math.floor(q) }));
        await audit(env, 'CONFIG_UPDATED', { user: sess.user, detail: `quota=${Math.floor(q)}` });
        return json({ ok: true });
      }
    }

    if (path === 'logs' && method === 'GET') {
      if (!isAdmin) return err('需要管理员会话', 403);
      await audit(env, 'AUDIT_VIEWED', { user: sess.user });
      const { counter, entries, chainOk } = await verifyAuditChain(env, 300);
      return json({ ok: true, counter, entries, chain_ok: chainOk });
    }

    if (path === 'destroy' && method === 'POST') {
      if (!isAdmin) return err('需要管理员会话', 403);
      if (!verified(sess, 'vault')) return err('请先重新验证访问密码', 428);
      const deleted = await destroyAll(env, 'manual');
      return json({ ok: true, deleted_r2_objects: deleted });
    }

    // ---------- 保险库文件 ----------
    if (path === 'upload/meta' && method === 'POST') {
      if (!isVault) return err('需要保险库会话', 403);
      const b = await body(request);
      const size = Number(b.size);
      if (!Number.isFinite(size) || size <= 0) return err('大小无效');
      if (size > MAX_UPLOAD_BYTES) return err(`单文件上限 ${Math.floor(MAX_UPLOAD_BYTES / 1048576)}MB`, 413);
      const cfg = await getStorageConfig();
      const usage = await getUsage();
      if (usage.used_bytes + size > cfg.vault_quota_bytes) {
        return err(`保险库已满（上限 ${Math.floor(cfg.vault_quota_bytes / 1048576)}MB）`, 403);
      }
      const id = randId(16);
      await state_kv.put(`${fileKeyPrefix(sess.user)}${id}`, JSON.stringify({
        id, size, r2_key: fileR2Key(sess.user, id),
        name_enc: b.name_enc || '', wrapped_key: b.wrapped_key || '',
        created: nowSec(), status: 'uploading',
      }));
      return json({ ok: true, id, upload_url: await presign(env, 'PUT', fileR2Key(sess.user, id), 3600) });
    }

    if (path === 'upload/done' && method === 'POST') {
      if (!isVault) return err('需要保险库会话', 403);
      const b = await body(request);
      const id = safeId(b.id);
      const key = `${fileKeyPrefix(sess.user)}${id}`;
      const meta = await state_kv.get(key, 'json');
      if (!meta) return err('文件不存在', 404);
      if (meta.status === 'ready') return json({ ok: true });
      meta.status = 'ready';
      await state_kv.put(key, JSON.stringify(meta));
      const usage = await getUsage();
      await putUsage(usage.used_bytes + meta.size);
      await audit(env, 'FILE_UPLOADED', { user: sess.user, detail: `${id} size=${meta.size}` });
      return json({ ok: true });
    }

    if (path === 'files' && method === 'GET') {
      if (!isVault) return err('需要保险库会话', 403);
      const files = [];
      const now = nowSec();
      for (const name of await listAllKeys(state_kv, fileKeyPrefix(sess.user))) {
        const m = await state_kv.get(name, 'json');
        if (!m) continue;
        if (m.status === 'ready') { files.push(m); continue; }
        // 中断的上传（关页 / 断网）不会写 upload/done，超过 1 小时清掉，避免 KV 残留
        if (now - (m.created || 0) > 3600) await state_kv.delete(name);
      }
      files.sort((a, b2) => b2.created - a.created);
      return json({ ok: true, files, usage: await getUsage() });
    }

    if (path.startsWith('download/') && method === 'GET') {
      if (!isVault) return err('需要保险库会话', 403);
      if (!verified(sess, 'vault')) return err('请先重新验证访问密码', 428);
      const id = safeId(path.slice('download/'.length));
      if (!id) return err('id 无效');
      const meta = await state_kv.get(`${fileKeyPrefix(sess.user)}${id}`, 'json');
      if (!meta || meta.status !== 'ready') return err('文件不存在', 404);
      await audit(env, 'FILE_DOWNLOADED', { user: sess.user, detail: meta.id });
      return json({
        ok: true, url: await presign(env, 'GET', meta.r2_key, 900),
        name_enc: meta.name_enc, wrapped_key: meta.wrapped_key, size: meta.size,
      });
    }

    if (path.startsWith('files/delete/') && method === 'POST') {
      if (!isVault) return err('需要保险库会话', 403);
      if (!verified(sess, 'vault')) return err('请先重新验证访问密码', 428);
      const id = safeId(path.slice('files/delete/'.length));
      if (!id) return err('id 无效');
      const key = `${fileKeyPrefix(sess.user)}${id}`;
      const meta = await state_kv.get(key, 'json');
      if (!meta) return err('文件不存在', 404);
      await deleteObjects(env, [meta.r2_key]);
      await state_kv.delete(key);
      if (meta.status === 'ready') {
        const usage = await getUsage();
        await putUsage(usage.used_bytes - (meta.size || 0));
      }
      await audit(env, 'FILE_DELETED', { user: sess.user, detail: id });
      return json({ ok: true });
    }

    // ---------- 神盾笔记（独立密钥 + 独立会话）----------
    if (path === 'notes/list' && method === 'GET') {
      if (!isNotes) return err('需要笔记会话', 403);
      const index = (await state_kv.get(notesIndexKey(sess.user), 'json')) || [];
      return json({ ok: true, notes: index });
    }

    if (path === 'notes/save' && method === 'POST') {
      if (!isNotes) return err('需要笔记会话', 403);
      if (!(await notesEnabled(sess.user))) return err('当前账户未启用神盾笔记', 403);
      if (!verified(sess, 'notes')) return err('请先重新验证笔记密码', 428);
      const b = await body(request);
      if (!b.body_enc) return err('缺少 body_enc');
      if (String(b.body_enc).length > MAX_NOTE_BODY) return err('笔记正文过大（上限约 750KB 明文）', 413);
      const id = safeId(b.note_id) || randId(16);
      const key = `${noteKeyPrefix(sess.user)}${id}`;
      const existing = await state_kv.get(key, 'json');
      if (b.note_id && !existing) return err('笔记不存在', 404);
      const now = nowSec();
      const note = {
        id, title_enc: b.title_enc || '', body_enc: b.body_enc,
        wrapped_key: b.wrapped_key || existing?.wrapped_key || '',
        attachments: Array.isArray(b.attachments) ? b.attachments : (existing?.attachments || []),
        created: existing?.created || now, updated: now,
        // 原版「详细信息 → Modification History」：保留最近 200 次修改时间戳（与原版 notes_manager 一致）
        history: [...(existing?.history || []), now].slice(-200),
      };
      await state_kv.put(key, JSON.stringify(note));
      const index = (await state_kv.get(notesIndexKey(sess.user), 'json')) || [];
      const item = index.find(n => n.id === id) || { id, created: note.created };
      item.updated = now;
      item.attachments = note.attachments.length;
      // 索引里保留标题密文与包裹密钥，笔记列表才能在浏览器内解密出标题（与原版「笔记菜单显示标题」一致）
      item.title_enc = note.title_enc || '';
      item.wrapped_key = note.wrapped_key || '';
      if (!index.some(n => n.id === id)) index.unshift(item);
      index.sort((a, b2) => b2.updated - a.updated);
      await state_kv.put(notesIndexKey(sess.user), JSON.stringify(index));
      await audit(env, 'NOTE_SAVED', { user: sess.user, detail: id });
      return json({ ok: true, note_id: id, updated: now });
    }

    if (path.startsWith('notes/get/') && method === 'GET') {
      if (!isNotes) return err('需要笔记会话', 403);
      if (!verified(sess, 'notes')) return err('请先重新验证笔记密码', 428);
      const id = safeId(path.slice('notes/get/'.length));
      const note = await state_kv.get(`${noteKeyPrefix(sess.user)}${id}`, 'json');
      if (!note) {
        await audit(env, 'NOTE_ACCESS_FAILED', { user: sess.user, detail: `${id}:not-found`, success: false });
        return err('笔记不存在', 404);
      }
      await audit(env, 'NOTE_ACCESS_SUCCESS', { user: sess.user, detail: id });
      return json({ ok: true, note });
    }

    if (path.startsWith('notes/delete/') && method === 'POST') {
      if (!isNotes) return err('需要笔记会话', 403);
      if (!verified(sess, 'notes')) return err('请先重新验证笔记密码', 428);
      const id = safeId(path.slice('notes/delete/'.length));
      const key = `${noteKeyPrefix(sess.user)}${id}`;
      const note = await state_kv.get(key, 'json');
      if (note) {
        const keys = (note.attachments || []).map(a => noteAttR2Key(sess.user, id, safeId(a.id)));
        if (keys.length) await deleteObjects(env, keys).catch(() => {});
        await state_kv.delete(key);
      }
      const index = ((await state_kv.get(notesIndexKey(sess.user), 'json')) || []).filter(n => n.id !== id);
      await state_kv.put(notesIndexKey(sess.user), JSON.stringify(index));
      await audit(env, 'NOTE_DELETED', { user: sess.user, detail: id });
      return json({ ok: true });
    }

    if (path === 'notes/att/meta' && method === 'POST') {
      if (!isNotes) return err('需要笔记会话', 403);
      // 与其他笔记端点一致：上传附件前也必须通过二次笔记口令校验
      if (!verified(sess, 'notes')) return err('请先重新验证笔记密码', 428);
      const b = await body(request);
      const noteId = safeId(b.note_id);
      const note = noteId ? await state_kv.get(`${noteKeyPrefix(sess.user)}${noteId}`, 'json') : null;
      if (!note) return err('请先保存笔记再上传附件', 409);
      const attId = randId(16);
      return json({ ok: true, att_id: attId, upload_url: await presign(env, 'PUT', noteAttR2Key(sess.user, noteId, attId), 3600) });
    }

    if (path.startsWith('notes/att/') && method === 'GET') {
      if (!isNotes) return err('需要笔记会话', 403);
      if (!verified(sess, 'notes')) return err('请先重新验证笔记密码', 428);
      const attId = safeId(path.slice('notes/att/'.length));
      const noteId = safeId(url.searchParams.get('note_id'));
      if (!attId || !noteId) return err('参数无效');
      const note = await state_kv.get(`${noteKeyPrefix(sess.user)}${noteId}`, 'json');
      if (!note || !(note.attachments || []).some(a => safeId(a.id) === attId)) return err('附件不存在', 404);
      await audit(env, 'NOTE_ATTACHMENT_DOWNLOADED', { user: sess.user, detail: `${noteId}/${attId}` });
      return json({ ok: true, url: await presign(env, 'GET', noteAttR2Key(sess.user, noteId, attId), 900) });
    }

    if (path === 'notes/att/delete' && method === 'POST') {
      if (!isNotes) return err('需要笔记会话', 403);
      if (!verified(sess, 'notes')) return err('请先重新验证笔记密码', 428);
      const b = await body(request);
      const attId = safeId(b.att_id);
      const noteId = safeId(b.note_id);
      if (!attId || !noteId) return err('参数无效');
      const key = `${noteKeyPrefix(sess.user)}${noteId}`;
      const note = await state_kv.get(key, 'json');
      if (!note) return err('笔记不存在', 404);
      await deleteObjects(env, [noteAttR2Key(sess.user, noteId, attId)]).catch(() => {});
      note.attachments = (note.attachments || []).filter(a => safeId(a.id) !== attId);
      note.updated = nowSec();
      await state_kv.put(key, JSON.stringify(note));
      const index = (await state_kv.get(notesIndexKey(sess.user), 'json')) || [];
      const item = index.find(n => n.id === noteId);
      if (item) {
        item.attachments = note.attachments.length;
        item.updated = note.updated;
        await state_kv.put(notesIndexKey(sess.user), JSON.stringify(index));
      }
      await audit(env, 'NOTE_ATTACHMENT_DELETED', { user: sess.user, detail: `${noteId}/${attId}` });
      return json({ ok: true });
    }

    return err('not found', 404);
  } catch (e) {
    return json({ ok: false, error: e.message || 'internal error' }, 500);
  }
}
