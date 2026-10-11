// Edge Vault — API 总路由（单文件版：工具函数全部内联，无跨文件导入）
// KV 为控制台绑定的全局变量：state_kv / session_kv / audit_kv
// 环境变量：R2_ACCOUNT_ID / R2_ACCESS_KEY_ID / R2_SECRET_ACCESS_KEY / R2_BUCKET
//          SESSION_SECRET / INTERNAL_TOKEN
// 胁迫模式：胁迫口令登录 → duress 会话 → 数据操作重定向 decoy/ 隔离空间，真实数据后台立即销毁

const te = s => new TextEncoder().encode(s);
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const randId = () => crypto.randomUUID().replace(/-/g, '').slice(0, 16);
const nowSec = () => Math.floor(Date.now() / 1000);
const DEFAULT_QUOTA = 5 * 1024 * 1024 * 1024; // 保险库默认 5GB，可调
const SESSION_TTL = 12 * 3600;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers } });
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

function internalAuthOk(request, env) {
  return timingSafeEq(request.headers.get('x-internal-token') || '', env.INTERNAL_TOKEN || '');
}

// ==================== 会话 ====================
function parseCookie(request) {
  const out = {};
  for (const pair of (request.headers.get('Cookie') || '').split(/;\s*/)) {
    const i = pair.indexOf('=');
    if (i > 0) out[pair.slice(0, i)] = pair.slice(i + 1);
  }
  return out;
}

async function createSession(duress = false) {
  const token = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
  const now = nowSec();
  await session_kv.put(`sess:${token}`, JSON.stringify({ duress, iat: now, exp: now + SESSION_TTL }));
  return { token, cookie: `ev_session=${token}; Max-Age=${SESSION_TTL}; Path=/; Secure; HttpOnly; SameSite=Strict` };
}

async function getSession(request) {
  const token = parseCookie(request).ev_session;
  if (!token) return null;
  const sess = await session_kv.get(`sess:${token}`, 'json');
  if (!sess || sess.exp < nowSec()) return null;
  return sess;
}

// ==================== 审计日志（链式哈希） ====================
async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey('raw', te(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, te(msg)));
}

async function audit(env, action, detail = '') {
  const seq = Number((await audit_kv.get('audit:counter')) || 0) + 1;
  const ts = new Date().toISOString();
  const prev = (await audit_kv.get('audit:prev')) || 'GENESIS';
  const hash = await hmacHex(env.SESSION_SECRET, `${seq}|${ts}|${action}|${detail}|${prev}`);
  await audit_kv.put(`audit:${seq}`, JSON.stringify({ seq, ts, action, detail, prev, hash }));
  await audit_kv.put('audit:counter', String(seq));
  await audit_kv.put('audit:prev', hash);
}

async function readAudit(limit = 200) {
  const counter = Number((await audit_kv.get('audit:counter')) || 0);
  const entries = [];
  for (let i = counter; i >= Math.max(1, counter - limit + 1); i--) {
    const e = await audit_kv.get(`audit:${i}`, 'json');
    if (e) entries.push(e);
  }
  return { counter, entries };
}

// ==================== 系统状态 ====================
async function getState() { return (await state_kv.get('state:system', 'json')) || { initialized: false }; }
async function putState(s) { await state_kv.put('state:system', JSON.stringify(s)); }
async function getStorageConfig() { return (await state_kv.get('config:storage', 'json')) || { vault_quota_bytes: DEFAULT_QUOTA, notes_excluded: true }; }
async function getUsage() { return (await state_kv.get('usage:vault', 'json')) || { used_bytes: 0 }; }

// ==================== R2 (S3 兼容) SigV4 ====================
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

// 服务端签名请求（ListObjectsV2 / DeleteObjects）
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

// 预签名 URL（浏览器直传/直下）
async function presign(env, method, objectKey, expires = 3600) {
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

// 列出前缀下全部对象（自毁扫描用）
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

// 批量删除（每次最多 1000 个）
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

// ==================== 销毁流程 ====================
// keepSessionToken：胁迫会话的 token——不删它，让胁迫者停留在假仓库里
async function destroyAll(env, reason, keepSessionToken = null) {
  for (const k of ['key:me', 'hash:login', 'hash:checkin']) await state_kv.delete(k);
  let r2Deleted = 0;
  for (const prefix of ['vault/', 'notes/']) {
    const keys = await listAllObjects(env, prefix);
    if (keys.length) r2Deleted += await deleteObjects(env, keys);
  }
  for (const [kv, prefix] of [[state_kv, 'file:'], [state_kv, 'note:'], [state_kv, 'notes-index']]) {
    const res = await kv.list({ prefix });
    for (const k of res.keys) await kv.delete(k.name);
  }
  const res = await session_kv.list({ prefix: 'sess:' });
  for (const k of res.keys) {
    if (keepSessionToken && k.name === `sess:${keepSessionToken}`) continue;
    await session_kv.delete(k.name);
  }
  await state_kv.delete('usage:vault');
  const st = await getState();
  await putState({ ...st, destroyed: true, destroyed_at: new Date().toISOString(), destroy_reason: reason });
  await audit(env, 'destroy', `${reason} r2_deleted=${r2Deleted}`);
  return r2Deleted;
}

// 对胁迫者呈现的"假状态"
function fakeState() {
  return {
    ok: true, initialized: true, destroyed: false,
    last_checkin: nowSec(), checkin_timeout_hours: 72,
    quota: { vault_quota_bytes: DEFAULT_QUOTA, notes_excluded: true },
    usage: { used_bytes: 0 },
  };
}

  // 免费套餐 cron 最低 1 天/次：自毁采用"访问即检 + 每日兜底扫描"
  // 任何请求到达时若签到已超时 → 后台立即销毁
  async function lazySweep() {
    const st0 = await getState();
    if (!st0.initialized || st0.destroyed) return;
    if (nowSec() - st0.last_checkin > (st0.checkin_timeout_hours || 72) * 3600) {
      await destroyAll(env, 'checkin-timeout');
    }
  }

  function isOverdue(st) {
    return st.initialized && !st.destroyed && st.last_checkin > 0 &&
      nowSec() - st.last_checkin > (st.checkin_timeout_hours || 72) * 3600;
  }

  // ==================== 路由 ====================
  export async function onRequest(context) {
  const { request, env, waitUntil } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/?/, '');
  const method = request.method;

  try {
    if (path === 'state' && method === 'GET') {
      const sess = await getSession(request);
      const st = await getState();
      // 访问即检：签到超时 → 立即后台销毁
      if (isOverdue(st)) waitUntil(lazySweep().catch(() => {}));
      if ((sess?.duress) || (!sess && st.initialized && st.destroyed)) return json(fakeState());
      const cfg = await getStorageConfig();
      const usage = await getUsage();
      const overdue = !!sess && !st.destroyed && isOverdue(st);
      return json({
        ok: true, initialized: !!st.initialized, destroyed: !!st.destroyed, overdue,
        last_checkin: st.last_checkin || 0, checkin_timeout_hours: st.checkin_timeout_hours || 72,
        quota: cfg, usage,
      });
    }

    if (path === 'init' && method === 'POST') {
      const st = await getState();
      // ⚠️ 临时开放重置（用户忘记密码，保险库为空）——重置完成后必须恢复下行注释
      // if (st.initialized && !st.destroyed) return err('已初始化，拒绝重复初始化', 403);
      if (st.initialized) {
        for (const p of ['file:', 'note:']) {
          const r = await state_kv.list({ prefix: p });
          for (const k of r.keys) await state_kv.delete(k.name);
        }
        await state_kv.delete('notes-index');
        await state_kv.delete('usage:vault');
        await state_kv.delete('key:me');
        for (const hk of ['hash:login', 'hash:checkin', 'hash:duress']) await state_kv.delete(hk);
      }
      const b = await body(request);
      for (const f of ['wrapped_priv_key', 'salt', 'pub_key', 'login_hash', 'checkin_hash', 'duress_hash']) {
        if (b[f] === undefined) return err(`缺少字段 ${f}`);
      }
      await putState({
        initialized: true, destroyed: false, created_at: nowSec(), last_checkin: nowSec(),
        checkin_timeout_hours: Number(b.checkin_timeout_hours) || 72,
      });
      await state_kv.put('hash:login', b.login_hash);
      await state_kv.put('hash:checkin', b.checkin_hash);
      await state_kv.put('hash:duress', b.duress_hash);
      await state_kv.put('key:me', JSON.stringify({ wrapped: b.wrapped_priv_key, salt: b.salt, pub: b.pub_key }));
      if (!(await state_kv.get('config:storage'))) {
        await state_kv.put('config:storage', JSON.stringify({ vault_quota_bytes: DEFAULT_QUOTA, notes_excluded: true }));
      }
      await audit(env, 'init', 'system initialized');
      return json({ ok: true });
    }

    if (path === 'login' && method === 'POST') {
      const st = await getState();
      if (!st.initialized) return err('系统未初始化', 403);
      // 访问即检：签到超时 → 立即销毁，登录直接失败
      if (isOverdue(st)) {
        await destroyAll(env, 'checkin-timeout');
        return err('系统已销毁', 403);
      }
      const b = await body(request);
      const hash = String(b.hash || '');
      const checkinHash = await state_kv.get('hash:checkin');
      const duressHash = await state_kv.get('hash:duress');
      let duress = false;
      if (checkinHash && timingSafeEq(hash, await state_kv.get('hash:login'))) duress = false;
      else if (duressHash && timingSafeEq(hash, duressHash)) duress = true;
      else { await audit(env, 'login_fail'); return err('口令错误', 401); }
      const { token, cookie } = await createSession(duress);
      if (duress) {
        waitUntil(destroyAll(env, 'duress', token).catch(() => {}));
        return json({ ok: true, mode: 'decoy' }, 200, { 'Set-Cookie': cookie });
      }
      await audit(env, 'login', 'normal');
      return json({ ok: true, mode: 'real' }, 200, { 'Set-Cookie': cookie });
    }

    if (path === 'keyinfo' && method === 'GET') {
      const sess = await getSession(request);
      if (!sess) return err('未登录', 401);
      if (sess.duress) return json({ ok: true, decoy: true });
      const keyInfo = await state_kv.get('key:me', 'json');
      if (!keyInfo) return err('密钥不存在', 404);
      return json({ ok: true, ...keyInfo });
    }

    // ---------- 以下端点要求会话（checkin 凭签到码公开访问） ----------
    const sess = await getSession(request);
    const duress = !!sess?.duress;
    if (!sess && !['checkin', 'internal/sweep', 'internal/archive'].includes(path)) return err('未登录', 401);

    // 签到（公开端点，原版协议：凭签到码重置计时器，无需会话）
    if (path === 'checkin' && method === 'POST') {
      const b = await body(request);
      const checkinHash = await state_kv.get('hash:checkin');
      if (!checkinHash || !timingSafeEq(String(b.hash || ''), checkinHash)) {
        await audit(env, 'checkin_fail');
        return err('签到码错误', 401);
      }
      const st = await getState();
      st.last_checkin = nowSec();
      await putState(st);
      await audit(env, 'checkin');
      return json({ ok: true, last_checkin: st.last_checkin, checkin_timeout_hours: st.checkin_timeout_hours || 72 });
    }

    if (path === 'logout' && method === 'POST') {
      const token = (request.headers.get('Cookie') || '').match(/ev_session=([^;]+)/)?.[1];
      if (token) await session_kv.delete(`sess:${token}`);
      return json({ ok: true });
    }

    if (path === 'config/storage') {
      if (method === 'GET') {
        if (duress) {
          const res = await state_kv.list({ prefix: 'decoy:file:' });
          let used = 0;
          for (const k of res.keys) { const m = await state_kv.get(k.name, 'json'); if (m?.status === 'ready') used += m.size || 0; }
          return json({ ok: true, vault_quota_bytes: DEFAULT_QUOTA, notes_excluded: true, usage: { used_bytes: used } });
        }
        return json({ ok: true, ...(await getStorageConfig()), usage: await getUsage() });
      }
      if (method === 'POST') {
        if (duress) return json({ ok: true });
        const b = await body(request);
        const q = Number(b.vault_quota_bytes);
        if (!Number.isFinite(q) || q < 1024 * 1024 || q > 1024 * 1024 * 1024 * 1024) return err('配额值无效');
        await state_kv.put('config:storage', JSON.stringify({ vault_quota_bytes: Math.floor(q), notes_excluded: true }));
        await audit(env, 'config_quota', String(q));
        return json({ ok: true });
      }
    }

    if (path === 'upload/meta' && method === 'POST') {
      const b = await body(request);
      const size = Number(b.size);
      if (!Number.isFinite(size) || size <= 0) return err('大小无效');
      const id = duress && b.client_id ? String(b.client_id).replace(/[^a-zA-Z0-9]/g, '').slice(0, 32) || randId() : randId();
      if (duress) {
        await state_kv.put(`decoy:file:${id}`, JSON.stringify({ id, size, r2_key: `decoy/${id}.aes`, name: b.name || '未命名', created: nowSec(), status: 'uploading' }));
        return json({ ok: true, id, upload_url: await presign(env, 'PUT', `decoy/${id}.aes`, 3600) });
      }
      const cfg = await getStorageConfig();
      const usage = await getUsage();
      if (usage.used_bytes + size > cfg.vault_quota_bytes) {
        return err(`超出保险库配额：已用 ${usage.used_bytes}/${cfg.vault_quota_bytes} 字节`, 403);
      }
      await state_kv.put(`file:${id}`, JSON.stringify({
        id, size, r2_key: `vault/${id}.aes`, name_enc: b.name_enc, wrapped_key: b.wrapped_key,
        created: nowSec(), status: 'uploading',
      }));
      return json({ ok: true, id, upload_url: await presign(env, 'PUT', `vault/${id}.aes`, 3600) });
    }

    if (path === 'upload/done' && method === 'POST') {
      const b = await body(request);
      const prefix = duress ? 'decoy:file:' : 'file:';
      const meta = await state_kv.get(`${prefix}${b.id}`, 'json');
      if (!meta) return err('文件不存在', 404);
      meta.status = 'ready';
      await state_kv.put(`${prefix}${b.id}`, JSON.stringify(meta));
      if (!duress) {
        const usage = await getUsage();
        usage.used_bytes += meta.size;
        await state_kv.put('usage:vault', JSON.stringify(usage));
        await audit(env, 'file_upload', `${meta.id} size=${meta.size}`);
      }
      return json({ ok: true });
    }

    if (path === 'files' && method === 'GET') {
      if (duress) {
        const res = await state_kv.list({ prefix: 'decoy:file:' });
        const files = [];
        let used = 0;
        for (const k of res.keys) {
          const m = await state_kv.get(k.name, 'json');
          if (m && m.status === 'ready') { files.push(m); used += m.size || 0; }
        }
        files.sort((a, b2) => b2.created - a.created);
        return json({ ok: true, files, usage: { used_bytes: used }, decoy: true });
      }
      const res = await state_kv.list({ prefix: 'file:' });
      const files = [];
      for (const k of res.keys) {
        const m = await state_kv.get(k.name, 'json');
        if (m && m.status === 'ready') files.push(m);
      }
      files.sort((a, b2) => b2.created - a.created);
      return json({ ok: true, files, usage: await getUsage() });
    }

    if (path.startsWith('download/') && method === 'GET') {
      const id = path.slice('download/'.length);
      if (duress) {
        const meta = await state_kv.get(`decoy:file:${id}`, 'json');
        if (!meta || meta.status !== 'ready') return err('文件不存在', 404);
        return json({ ok: true, url: await presign(env, 'GET', meta.r2_key, 1800), name: meta.name, size: meta.size, decoy: true });
      }
      const meta = await state_kv.get(`file:${id}`, 'json');
      if (!meta || meta.status !== 'ready') return err('文件不存在', 404);
      return json({
        ok: true, url: await presign(env, 'GET', meta.r2_key, 1800),
        name_enc: meta.name_enc, wrapped_key: meta.wrapped_key, size: meta.size,
      });
    }

    if (path.startsWith('files/delete/') && method === 'POST') {
      const id = path.slice('files/delete/'.length);
      const prefix = duress ? 'decoy:file:' : 'file:';
      const meta = await state_kv.get(`${prefix}${id}`, 'json');
      if (!meta) return err('文件不存在', 404);
      await deleteObjects(env, [meta.r2_key]);
      await state_kv.delete(`${prefix}${id}`);
      if (!duress) {
        const usage = await getUsage();
        usage.used_bytes = Math.max(0, usage.used_bytes - meta.size);
        await state_kv.put('usage:vault', JSON.stringify(usage));
        await audit(env, 'file_delete', id);
      }
      return json({ ok: true });
    }

    // ---------- 笔记 ----------
    if (path === 'notes/list' && method === 'GET') {
      const index = (await state_kv.get(duress ? 'decoy:notes-index' : 'notes-index', 'json')) || [];
      return json({ ok: true, notes: index, decoy: duress });
    }

    if (path === 'notes/save' && method === 'POST') {
      const b = await body(request);
      if (!b.note_id || !b.body_enc) return err('缺少 note_id / body_enc');
      const id = b.note_id;
      const now = nowSec();
      const idxKey = duress ? 'decoy:notes-index' : 'notes-index';
      const notePrefix = duress ? 'decoy:note:' : 'note:';
      const index = (await state_kv.get(idxKey, 'json')) || [];
      const item = index.find(n => n.id === id) || { id, created: now };
      Object.assign(item, { title_enc: b.title_enc || '', updated: now });
      if (!index.find(n => n.id === id)) index.unshift(item);
      await state_kv.put(idxKey, JSON.stringify(index));
      await state_kv.put(`${notePrefix}${id}`, JSON.stringify({
        id, title_enc: b.title_enc || '', body_enc: b.body_enc,
        wrapped_key: b.wrapped_key || '', attachments: b.attachments || [],
        created: item.created, updated: now,
      }));
      return json({ ok: true, updated: now });
    }

    if (path.startsWith('notes/get/') && method === 'GET') {
      const id = path.slice('notes/get/'.length);
      const note = await state_kv.get(`${duress ? 'decoy:note:' : 'note:'}${id}`, 'json');
      if (!note) return err('笔记不存在', 404);
      return json({ ok: true, note, decoy: duress });
    }

    if (path.startsWith('notes/delete/') && method === 'POST') {
      const id = path.slice('notes/delete/'.length);
      const note = await state_kv.get(`${duress ? 'decoy:note:' : 'note:'}${id}`, 'json');
      if (note) {
        const r2Keys = (note.attachments || []).map(a => `notes/att/${a.id}`);
        if (r2Keys.length && !duress) await deleteObjects(env, r2Keys);
        await state_kv.delete(`${duress ? 'decoy:note:' : 'note:'}${id}`);
      }
      const idxKey = duress ? 'decoy:notes-index' : 'notes-index';
      const index = ((await state_kv.get(idxKey, 'json')) || []).filter(n => n.id !== id);
      await state_kv.put(idxKey, JSON.stringify(index));
      if (!duress) await audit(env, 'note_delete', id);
      return json({ ok: true });
    }

    if (path === 'notes/att/meta' && method === 'POST') {
      const attId = randId();
      const r2Key = duress ? `decoy/att/${attId}` : `notes/att/${attId}`;
      return json({ ok: true, att_id: attId, upload_url: await presign(env, 'PUT', r2Key, 3600) });
    }

    if (path === 'notes/att/delete' && method === 'POST') {
      const b = await body(request);
      if (!b.att_id) return err('缺少 att_id');
      const r2Key = `${duress ? 'decoy' : 'notes'}/att/${String(b.att_id).replace(/[^a-zA-Z0-9]/g, '')}`;
      await deleteObjects(env, [r2Key]);
      return json({ ok: true });
    }

    if (path.startsWith('notes/att/') && method === 'GET') {
      const attId = path.slice('notes/att/'.length);
      const r2Key = duress ? `decoy/att/${attId}` : `notes/att/${attId}`;
      return json({ ok: true, url: await presign(env, 'GET', r2Key, 1800) });
    }

    if (path === 'logs' && method === 'GET') {
      if (duress) return json({ ok: true, counter: 0, entries: [] });
      return json({ ok: true, ...(await readAudit(300)) });
    }

    if (path === 'destroy' && method === 'POST') {
      if (duress) return json({ ok: true, deleted_r2_objects: 0 });
      const deleted = await destroyAll(env, 'manual');
      return json({ ok: true, deleted_r2_objects: deleted });
    }

    // ---------- schedules 内部端点 ----------
    if (path === 'internal/sweep' && method === 'POST') {
      if (!internalAuthOk(request, env)) return err('forbidden', 403);
      const st = await getState();
      if (!st.initialized || st.destroyed) return json({ ok: true, skipped: 'not-active' });
      const overdue = nowSec() - st.last_checkin > (st.checkin_timeout_hours || 72) * 3600;
      if (!overdue) return json({ ok: true, skipped: 'in-time', last_checkin: st.last_checkin });
      const deleted = await destroyAll(env, 'checkin-timeout');
      return json({ ok: true, destroyed: true, deleted_r2_objects: deleted });
    }

    if (path === 'internal/archive' && method === 'POST') {
      if (!internalAuthOk(request, env)) return err('forbidden', 403);
      const counter = Number((await audit_kv.get('audit:counter')) || 0);
      if (!counter) return json({ ok: true, skipped: 'empty' });
      const dayAgo = new Date(Date.now() - 86400000).toISOString();
      const lines = [];
      for (let i = 1; i <= counter; i++) {
        const e = await audit_kv.get(`audit:${i}`, 'json');
        if (!e) continue;
        if (e.ts < dayAgo) { lines.push(JSON.stringify(e)); await audit_kv.delete(`audit:${i}`); }
      }
      if (!lines.length) return json({ ok: true, skipped: 'nothing-to-archive' });
      const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
      const res = await fetch(await presign(env, 'PUT', `archive/audit-${date}.jsonl`, 3600), {
        method: 'PUT', body: lines.join('\n') + '\n',
      });
      if (!res.ok) return err(`archive upload failed: ${res.status}`, 500);
      await audit(env, 'archive', `archived=${lines.length}`);
      return json({ ok: true, archived: lines.length });
    }

    return err('not found', 404);
  } catch (e) {
    return json({ ok: false, error: e.message || 'internal error' }, 500);
  }
}
