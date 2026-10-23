// Edge Vault — 边缘函数回归测试（模拟 EdgeOne KV + R2，零真实凭据）
// 用法：node tools/api-smoke-test.mjs
import { copyFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const tmp = mkdtempSync(join(tmpdir(), 'edge-vault-'));
copyFileSync(join(root, 'edge-functions/api/[[default]].js'), join(tmp, 'fn.mjs'));
const { onRequest } = await import(pathToFileURL(join(tmp, 'fn.mjs')).href);

// EdgeOne KV 形状：{ keys:[{key}], complete, cursor }
class MockKV {
  constructor(pageSize = 2) { this.map = new Map(); this.pageSize = pageSize; }
  async get(k, type) {
    const v = this.map.get(k);
    if (v === undefined) return null;
    return type === 'json' ? JSON.parse(v) : v;
  }
  async put(k, v) { this.map.set(k, String(v)); }
  async delete(k) { this.map.delete(k); }
  async list({ prefix = '', limit = 256, cursor } = {}) {
    const all = [...this.map.keys()].filter(k => k.startsWith(prefix)).sort();
    const start = cursor ? Math.max(0, all.indexOf(cursor)) : 0;
    const size = Math.min(limit, this.pageSize);
    const page = all.slice(start, start + size);
    const done = start + size >= all.length;
    return { keys: page.map(key => ({ key })), complete: done, cursor: done ? null : all[start + size] };
  }
  keys(prefix = '') { return [...this.map.keys()].filter(k => k.startsWith(prefix)); }
}

const reset = () => {
  globalThis.state_kv = new MockKV();
  globalThis.session_kv = new MockKV(50);
  globalThis.audit_kv = new MockKV(50);
};

const env = {
  R2_ACCOUNT_ID: 'testacct', R2_ACCESS_KEY_ID: 'AK', R2_SECRET_ACCESS_KEY: 'SK',
  R2_BUCKET: 'edge-vault', SESSION_SECRET: 'x'.repeat(64), INTERNAL_TOKEN: 'internal-token',
};

// R2 模拟：ListObjectsV2 / DeleteObjects
const objects = new Map();
globalThis.fetch = async (url, init = {}) => {
  const u = new URL(String(url));
  const m = (init.method || 'GET').toUpperCase();
  if (u.searchParams.get('list-type') === '2') {
    const prefix = u.searchParams.get('prefix') || '';
    const keys = [...objects.keys()].filter(k => k.startsWith(prefix)).sort();
    return new Response(`<ListBucketResult>${keys.map(k => `<Contents><Key>${k}</Key></Contents>`).join('')}</ListBucketResult>`, { status: 200 });
  }
  if (u.searchParams.has('delete') && m === 'POST') {
    const txt = typeof init.body === 'string' ? init.body : new TextDecoder().decode(init.body || new Uint8Array());
    for (const x of txt.matchAll(/<Key>([^<]+)<\/Key>/g)) objects.delete(x[1]);
    return new Response('<DeleteResult/>', { status: 200 });
  }
  return new Response('', { status: 200 });
};

const call = async (path, { method = 'GET', body, cookie, csrf, headers = {} } = {}) => {
  const h = { 'Content-Type': 'application/json', 'User-Agent': 'ev-test/1.0', ...headers };
  if (cookie) h.Cookie = cookie;
  if (csrf) h['x-csrf-token'] = csrf;
  const request = new Request(`https://v.test/api/${path}`, {
    method, headers: h, body: body === undefined ? undefined : JSON.stringify(body),
  });
  const pending = [];
  const res = await onRequest({ request, env, waitUntil: p => pending.push(p), passThroughOnException: () => {} });
  const data = await res.json().catch(() => ({}));
  await Promise.allSettled(pending);
  await new Promise(r => setTimeout(r, 5));
  return { data, status: res.status, setCookie: res.headers.get('set-cookie') || '' };
};

const results = [];
const check = (name, ok, detail = '') => {
  results.push({ name, ok });
  console.log(`${ok ? '✅' : '❌'} ${name}${detail ? `  —  ${detail}` : ''}`);
};
const sessionOf = r => (r.setCookie || '').split(';')[0];

const AUTH_SALT = 'salt-test';
const initBody = {
  wrapped_priv_key: 'WRAPPED_ADMIN', salt: 'S1', pub_key: { kty: 'RSA' },
  login_hash: 'H_ADMIN', checkin_hash: 'H_CHECKIN', duress_hash: 'H_DURESS',
  auth_salt: AUTH_SALT, checkin_timeout_hours: 72,
};

// ==================== 用例 ====================
reset();
let r = await call('state');
check('未初始化：initialized=false', r.data.initialized === false, JSON.stringify(r.data).slice(0, 60));

r = await call('init', { method: 'POST', body: initBody });
check('初始化 admin + 签到/胁迫哈希', r.data.ok === true, JSON.stringify(r.data));

r = await call('state');
check('state 返回 auth_salt 与已配置用户', r.data.auth_salt === AUTH_SALT && r.data.users.some(u => u.name === 'admin'), JSON.stringify(r.data.users));

// 未登录重复 init → 拒绝
r = await call('init', { method: 'POST', body: { ...initBody, login_hash: 'ATTACKER' } });
check('未登录重复 init 被拒绝（403）', r.status === 403, `HTTP ${r.status}`);

// 登录
r = await call('login', { method: 'POST', body: { hash: 'H_ADMIN' } });
check('admin 登录 → vault 模式并下发 csrf', r.data.mode === 'vault' && !!r.data.csrf, JSON.stringify(r.data));
const adminSess = { cookie: sessionOf(r), csrf: r.data.csrf };
// 会话 Cookie 必须是 Lax（Strict 会在从外部链接/新标签进入时被浏览器丢弃 → 已登录却要求重新登录）
check('会话 Cookie 为 SameSite=Lax 且 HttpOnly', /SameSite=Lax/i.test(r.setCookie) && /HttpOnly/i.test(r.setCookie) && !/SameSite=Strict/i.test(r.setCookie), r.setCookie.replace(/ev_session=[^;]+/, 'ev_session=***'));
// 刚登录尚未二次验证
r = await call('state', { cookie: adminSess.cookie });
check('state 回传 verified 状态（登录后 vault=false）', r.data.verified && r.data.verified.vault === false, JSON.stringify(r.data.verified));

// CSRF
r = await call('manage/user', { method: 'POST', cookie: adminSess.cookie, body: { target_user: 'user1' } });
check('缺少 CSRF 头 → 403', r.status === 403, `HTTP ${r.status}`);

// 创建 user1
r = await call('manage/user', {
  method: 'POST', cookie: adminSess.cookie, csrf: adminSess.csrf,
  body: { target_user: 'user1', wrapped_priv_key: 'WU1', salt: 'S1', pub_key: { kty: 'RSA' }, login_hash: 'H_USER1' },
});
check('admin 创建 user1 密钥', r.data.ok === true && r.data.created === true, JSON.stringify(r.data));

// 槽位校验
r = await call('manage/user', {
  method: 'POST', cookie: adminSess.cookie, csrf: adminSess.csrf,
  body: { target_user: 'hacker', wrapped_priv_key: 'W', salt: 'S', pub_key: {}, login_hash: 'H' },
});
check('非法用户槽位被拒绝', r.status === 400, `HTTP ${r.status}`);

// user1 登录 + 隔离
r = await call('login', { method: 'POST', body: { hash: 'H_USER1' } });
check('user1 口令登录 → user=user1', r.data.user === 'user1' && r.data.mode === 'vault', JSON.stringify(r.data));
const u1 = { cookie: sessionOf(r), csrf: r.data.csrf };

r = await call('keyinfo', { cookie: u1.cookie });
check('keyinfo 返回当前用户密钥材料', r.data.name === 'user1' && r.data.user.wrapped === 'WU1', JSON.stringify(r.data).slice(0, 70));

r = await call('upload/meta', { method: 'POST', cookie: u1.cookie, csrf: u1.csrf, body: { size: 1024, name_enc: 'CT', wrapped_key: 'WK' } });
const fileId = r.data.id;
check('user1 上传登记返回预签名 URL', r.data.ok && /X-Amz-Signature/.test(r.data.upload_url || ''), (r.data.upload_url || '').slice(0, 40));
await call('upload/done', { method: 'POST', cookie: u1.cookie, csrf: u1.csrf, body: { id: fileId } });

r = await call('files', { cookie: u1.cookie });
check('user1 能看到自己的文件', r.data.files.length === 1, `files=${r.data.files.length}`);
check('配额累加正确', r.data.usage.used_bytes === 1024, `used=${r.data.usage.used_bytes}`);

r = await call('files', { cookie: adminSess.cookie });
check('admin 看不到 user1 的文件（按用户隔离）', r.data.files.length === 0, `files=${r.data.files.length}`);



// 二次口令校验（下载前必须 verify）
r = await call(`download/${fileId}`, { cookie: u1.cookie });
check('未二次验证口令 → 428', r.status === 428, `HTTP ${r.status}`);
r = await call('verify', { method: 'POST', cookie: u1.cookie, csrf: u1.csrf, body: { scope: 'vault', hash: 'WRONG' } });
check('verify 错误口令 → 401', r.status === 401, `HTTP ${r.status}`);
r = await call('verify', { method: 'POST', cookie: u1.cookie, csrf: u1.csrf, body: { scope: 'vault', hash: 'H_USER1' } });
check('verify 正确口令 → 200', r.data.ok === true, JSON.stringify(r.data));
// 二次校验窗口内应回传 vault=true，前端据此避免每次都弹口令
r = await call('state', { cookie: u1.cookie });
check('state 回传 verified=true（3 分钟窗口内免重复验证）', r.data.verified && r.data.verified.vault === true, JSON.stringify(r.data.verified));
r = await call(`download/${fileId}`, { cookie: u1.cookie });
check('验证后可下载（返回预签名 URL）', /X-Amz-Signature/.test(r.data.url || ''), (r.data.url || '').slice(0, 40));

// 笔记：admin 为用户启用笔记（独立密钥 + 独立口令）
r = await call('manage/notes', {
  method: 'POST', cookie: adminSess.cookie, csrf: adminSess.csrf,
  body: {
    target_user: 'user1', enabled: true,
    wrapped_note_key: 'WN1', salt: 'S2', pub_key: { kty: 'RSA' }, note_login_hash: 'H_NOTE1',
  },
});
check('admin 为 user1 启用神盾笔记', r.data.ok === true && r.data.enabled === true, JSON.stringify(r.data));

r = await call('login', { method: 'POST', body: { hash: 'H_NOTE1' } });
check('笔记口令登录 → notes 模式', r.data.mode === 'notes' && r.data.user === 'user1', JSON.stringify(r.data));
const noteSess = { cookie: sessionOf(r), csrf: r.data.csrf };

r = await call('files', { cookie: noteSess.cookie });
check('笔记会话无法访问保险库接口', r.status === 403, `HTTP ${r.status}`);

r = await call('keyinfo?scope=notes', { cookie: noteSess.cookie });
check('笔记会话可取得笔记密钥材料', r.data.note?.wrapped === 'WN1', JSON.stringify(r.data).slice(0, 60));

r = await call('notes/save', { method: 'POST', cookie: noteSess.cookie, csrf: noteSess.csrf, body: { body_enc: 'B' } });
check('未验证笔记口令 → 拒绝保存（428）', r.status === 428, `HTTP ${r.status}`);

r = await call('verify', { method: 'POST', cookie: noteSess.cookie, csrf: noteSess.csrf, body: { scope: 'notes', hash: 'H_NOTE1' } });
check('笔记口令二次验证通过', r.data.ok === true);

r = await call('notes/save', { method: 'POST', cookie: noteSess.cookie, csrf: noteSess.csrf, body: { title_enc: 'T', body_enc: 'B', wrapped_key: 'NK' } });
const noteId = r.data.note_id;
check('保存笔记成功', r.data.ok === true && !!noteId, JSON.stringify(r.data));

r = await call('notes/list', { cookie: noteSess.cookie });
check('笔记列表包含新笔记', r.data.notes.some(n => n.id === noteId), JSON.stringify(r.data.notes));

r = await call(`notes/get/${noteId}`, { cookie: noteSess.cookie });
check('读取笔记（含密文正文）', r.data.note?.body_enc === 'B', JSON.stringify(r.data.note || {}).slice(0, 60));

r = await call('notes/att/meta', { method: 'POST', cookie: noteSess.cookie, csrf: noteSess.csrf, body: { note_id: noteId } });
const attId = r.data.att_id;
check('附件上传登记成功', r.data.ok && !!attId, String(attId));

// 附件元数据要写回笔记后才能下载/删除（与原版一致：附件列表随笔记一起保存）
r = await call('notes/save', {
  method: 'POST', cookie: noteSess.cookie, csrf: noteSess.csrf,
  body: { note_id: noteId, title_enc: 'T', body_enc: 'B', wrapped_key: 'NK', attachments: [{ id: attId, name_enc: 'ATT', size: 10, created: Math.floor(Date.now() / 1000) }] },
});
check('附件元数据写回笔记', r.data.ok === true);

r = await call(`notes/att/${attId}?note_id=${noteId}`, { cookie: noteSess.cookie });
check('附件下载返回预签名 URL', /X-Amz-Signature/.test(r.data.url || ''), (r.data.url || '').slice(0, 40));

r = await call('notes/att/delete', { method: 'POST', cookie: noteSess.cookie, csrf: noteSess.csrf, body: { note_id: noteId, att_id: attId } });
check('删除附件成功', r.data.ok === true);

// 重置保护
r = await call('manage/notes', {
  method: 'POST', cookie: adminSess.cookie, csrf: adminSess.csrf,
  body: { target_user: 'user1', enabled: true, wrapped_note_key: 'NEW', salt: 'S', pub_key: {}, note_login_hash: 'NEW_HASH' },
});
check('已有笔记时禁止重置笔记密钥', r.status === 409, `HTTP ${r.status}`);


// 签到码在线更新
r = await call('codes/checkin', { method: 'POST', cookie: adminSess.cookie, csrf: adminSess.csrf, body: { hash: 'H_CHECKIN_NEW' } });
check('更新签到码成功', r.data.ok === true);
r = await call('checkin', { method: 'POST', body: { hash: 'H_CHECKIN' } });
check('旧签到码失效', r.status === 401, `HTTP ${r.status}`);
r = await call('checkin', { method: 'POST', body: { hash: 'H_CHECKIN_NEW' } });
check('新签到码可签到', r.data.ok === true, JSON.stringify(r.data));

// 审计链校验
r = await call('logs', { cookie: adminSess.cookie });
check('审计日志链完整（chain_ok）', r.data.chain_ok === true && r.data.entries.length > 5, `entries=${r.data.entries.length}, chain_ok=${r.data.chain_ok}`);
check('审计事件名对齐原版', r.data.entries.some(e => e.action === 'AUTH_LOGIN_SUCCESS') && r.data.entries.some(e => e.action === 'FILE_UPLOADED'));

// 审计链被篡改 → chain_ok=false
const firstAudit = await audit_kv.get('audit:1', 'json');
await audit_kv.put('audit:1', JSON.stringify({ ...firstAudit, detail: 'tampered' }));
r = await call('logs', { cookie: adminSess.cookie });
check('篡改审计条目后 chain_ok=false', r.data.chain_ok === false, `chain_ok=${r.data.chain_ok}`);
await audit_kv.put('audit:1', JSON.stringify(firstAudit));

// 状态 HMAC 篡改 → 触发销毁
const st = await state_kv.get('state:system', 'json');
await state_kv.put('state:system', JSON.stringify({ ...st, last_checkin: 1 }));
r = await call('state');
check('状态被篡改 → 触发销毁（destroyed=true）', r.data.destroyed === true, JSON.stringify(r.data).slice(0, 80));
check('销毁后用户密钥已清除', state_kv.keys('user:').length === 0, `user:*=${state_kv.keys('user:').length}`);

// 销毁后可直接重建
r = await call('init', { method: 'POST', body: { ...initBody, login_hash: 'H2', duress_hash: 'D2' } });
check('销毁后可重新初始化', r.data.ok === true, JSON.stringify(r.data));

// 胁迫码：登录 → 通用失败 + 全量销毁（重初始化时 duress_hash 已改成 D2）
r = await call('login', { method: 'POST', body: { hash: 'D2' } });
check('胁迫码登录 → 401 通用失败', r.status === 401 && /身份验证失败/.test(r.data.error || ''), JSON.stringify(r.data));
r = await call('state');
check('胁迫码触发全量销毁', r.data.destroyed === true, JSON.stringify(r.data).slice(0, 60));

// 内部端点
reset();
await call('init', { method: 'POST', body: initBody });
r = await call('internal/sweep', { method: 'POST', body: {} });
check('internal/sweep 无 token → 403', r.status === 403);
r = await call('internal/sweep', { method: 'POST', body: { token: 'internal-token' } });
check('internal/sweep payload token → 200', r.status === 200 && r.data.ok === true, JSON.stringify(r.data));

const failed = results.filter(x => !x.ok);
console.log(`\n结果: ${results.length - failed.length}/${results.length} 通过`);
if (failed.length) console.log('失败用例：\n' + failed.map(f => ' - ' + f.name).join('\n'));
process.exit(failed.length ? 1 : 0);

r = await call('manage/user', {
  method: 'POST', cookie: adminSess.cookie, csrf: adminSess.csrf,
  body: { target_user: 'user1', wrapped_priv_key: 'NEW', salt: 'S', pub_key: {}, login_hash: 'NEW' },
});
check('已有文件时禁止重置用户密钥', r.status === 409, `HTTP ${r.status}`);
