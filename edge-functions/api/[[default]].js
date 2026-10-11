// Edge Vault — API 总路由（catch-all）
// /api/* 全部在此分发。KV 为全局变量：state_kv / session_kv / audit_kv
// 胁迫模式：胁迫口令登录 → 会话标记 duress → 所有数据操作重定向到 decoy/ 隔离空间
//           真实数据在后台立即销毁（waitUntil），对胁迫者呈现"正常但空"的仓库
import {
  json, err, createSession, getSession, destroyAllSessions,
  audit, readAudit, getState, putState, getStorageConfig, getUsage,
  randId, nowSec, DEFAULT_QUOTA,
} from '../_lib/util.js';
import { presign, listAllObjects, deleteObjects } from '../_lib/r2.js';

const CHECKIN_SALT = 'edge-vault-checkin'; // 预留

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

// 对胁迫者呈现的"假状态"——一切正常、刚签到、空仓库
function fakeState() {
  return {
    ok: true, initialized: true, destroyed: false,
    last_checkin: nowSec(), checkin_timeout_hours: 72,
    quota: { vault_quota_bytes: DEFAULT_QUOTA, notes_excluded: true },
    usage: { used_bytes: 0 },
  };
}

// ---- 销毁流程：先删钥，后删密文 ----
// keepSessionToken：胁迫会话的 token——不删它，让胁迫者停留在假仓库里
async function destroyAll(env, reason, keepSessionToken = null) {
  // 1) 删密钥材料（密文立即变废料）；保留 hash:duress 以维持假仓库可复登
  for (const k of ['key:me', 'hash:checkin']) await state_kv.delete(k);
  // 2) 删 R2 真实密文（vault/ 与 notes/ 前缀，不动 decoy/）
  let r2Deleted = 0;
  for (const prefix of ['vault/', 'notes/']) {
    const keys = await listAllObjects(env, prefix);
    if (keys.length) r2Deleted += await deleteObjects(env, keys);
  }
  // 3) 清 KV（真实文件元数据、笔记、用量）
  for (const [kv, prefix] of [[state_kv, 'file:'], [state_kv, 'note:'], [state_kv, 'notes-index']]) {
    const res = await kv.list({ prefix });
    for (const k of res.keys) await kv.delete(k.name);
  }
  // 4) 删除其余会话（保留当前胁迫会话）
  const res = await session_kv.list({ prefix: 'sess:' });
  for (const k of res.keys) {
    if (keepSessionToken && k.name === `sess:${keepSessionToken}`) continue;
    await session_kv.delete(k.name);
  }
  await state_kv.delete('usage:vault');
  // 5) 墓碑（对胁迫者不可见：匿名/胁迫会话的 state 端点返回假状态）
  const st = await getState();
  await putState({ ...st, destroyed: true, destroyed_at: new Date().toISOString(), destroy_reason: reason });
  await audit(env, 'destroy', `${reason} r2_deleted=${r2Deleted}`);
  return r2Deleted;
}

export async function onRequest(context) {
  const { request, env, waitUntil } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/?/, '');
  const method = request.method;

  try {
    // ---------- 无需会话 ----------
    if (path === 'state' && method === 'GET') {
      const sess = await getSession(request);
      const st = await getState();
      const cfg = await getStorageConfig();
      const usage = await getUsage();
      // 胁迫会话 / 匿名访问：销毁状态不可见（胁迫者先看到登录页，登录后进假仓库）
      if ((sess?.duress) || (!sess && st.initialized && st.destroyed)) {
        return json(st.initialized && st.destroyed ? fakeState() : { ...fakeState() });
      }
      // overdue 仅对真实会话暴露（匿名不泄露"待销毁"状态）
      const overdue = !!sess && st.initialized && !st.destroyed && st.last_checkin > 0 &&
        (nowSec() - st.last_checkin > (st.checkin_timeout_hours || 72) * 3600);
      return json({
        ok: true,
        initialized: !!st.initialized,
        destroyed: !!st.destroyed,
        overdue,
        last_checkin: st.last_checkin || 0,
        checkin_timeout_hours: st.checkin_timeout_hours || 72,
        quota: cfg,
        usage,
      });
    }

    if (path === 'init' && method === 'POST') {
      const st = await getState();
      if (st.initialized && !st.destroyed) return err('已初始化，拒绝重复初始化', 403);
      const b = await body(request);
      for (const f of ['wrapped_priv_key', 'salt', 'pub_key', 'checkin_hash', 'duress_hash', 'checkin_timeout_hours']) {
        if (b[f] === undefined) return err(`缺少字段 ${f}`);
      }
      await putState({
        initialized: true,
        destroyed: false,
        created_at: nowSec(),
        last_checkin: nowSec(),
        checkin_timeout_hours: Number(b.checkin_timeout_hours) || 72,
      });
      await state_kv.put('hash:checkin', b.checkin_hash);
      await state_kv.put('hash:duress', b.duress_hash);
      await state_kv.put('key:me', JSON.stringify({ wrapped: b.wrapped_priv_key, salt: b.salt, pub: b.pub_key }));
      if (!(await state_kv.get('config:storage'))) await state_kv.put('config:storage', JSON.stringify({ vault_quota_bytes: 5368709120, notes_excluded: true }));
      await audit(env, 'init', 'system initialized');
      return json({ ok: true });
    }

    if (path === 'login' && method === 'POST') {
      const st = await getState();
      if (!st.initialized) return err('系统未初始化', 403);
      const b = await body(request);
      const hash = String(b.hash || '');
      const checkinHash = await state_kv.get('hash:checkin');
      const duressHash = await state_kv.get('hash:duress');
      let duress = false;
      if (checkinHash && timingSafeEq(hash, checkinHash)) duress = false;
      else if (duressHash && timingSafeEq(hash, duressHash)) duress = true; // 胁迫码
      else {
        await audit(env, 'login_fail');
        return err('口令错误', 401);
      }
      const { token, cookie } = await createSession(duress);
      if (duress) {
        // 胁迫登录：响应"正常"，真实数据在后台立即销毁（本请求内完成大部分删除）
        waitUntil(destroyAll(env, 'duress', token).catch(() => {}));
        return json({ ok: true, mode: 'decoy' }, 200, { 'Set-Cookie': cookie });
      }
      // 系统已销毁后真实口令已删，自然到不了这里
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

    // ---------- 需要会话 ----------
    const sess = await getSession(request);
    if (!sess && !['state', 'init', 'login'].includes(path)) {
      // 其余端点一律要求会话
      if (path !== 'internal/sweep' && path !== 'internal/archive') return err('未登录', 401);
    }
    const duress = !!sess?.duress;

    if (path === 'checkin' && method === 'POST') {
      if (duress) return json({ ok: true, last_checkin: nowSec() }); // 假签到
      const st = await getState();
      st.last_checkin = nowSec();
      await putState(st);
      return json({ ok: true, last_checkin: st.last_checkin });
    }

    if (path === 'logout' && method === 'POST') {
      const token = (request.headers.get('Cookie') || '').match(/ev_session=([^;]+)/)?.[1];
      if (token) await session_kv.delete(`sess:${token}`);
      return json({ ok: true });
    }

    // 存储配额（设置菜单）
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
        if (duress) return json({ ok: true }); // 假保存
        const b = await body(request);
        const q = Number(b.vault_quota_bytes);
        if (!Number.isFinite(q) || q < 1024 * 1024 || q > 1024 * 1024 * 1024 * 1024) return err('配额值无效');
        await state_kv.put('config:storage', JSON.stringify({ vault_quota_bytes: Math.floor(q), notes_excluded: true }));
        await audit(env, 'config_quota', String(q));
        return json({ ok: true });
      }
    }

    // 文件：登记元数据 + 预签名上传（真实→vault/，胁迫→decoy/ 隔离空间）
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
      const meta = {
        id, size, r2_key: `vault/${id}.aes`,
        name_enc: b.name_enc, wrapped_key: b.wrapped_key,
        created: nowSec(), status: 'uploading',
      };
      await state_kv.put(`file:${id}`, JSON.stringify(meta));
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
        ok: true,
        url: await presign(env, 'GET', meta.r2_key, 1800),
        name_enc: meta.name_enc,
        wrapped_key: meta.wrapped_key,
        size: meta.size,
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

    // ---------- 笔记（真实→KV note:，胁迫→decoy:note:）----------
    if (path === 'notes/list' && method === 'GET') {
      const prefix = duress ? 'decoy:notes-index' : 'notes-index';
      const index = (await state_kv.get(prefix, 'json')) || [];
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

    // 笔记附件：走 R2 预签名（不占保险库配额）
    if (path === 'notes/att/meta' && method === 'POST') {
      const attId = randId();
      const r2Key = duress ? `decoy/att/${attId}` : `notes/att/${attId}`;
      return json({ ok: true, att_id: attId, upload_url: await presign(env, 'PUT', r2Key, 3600) });
    }

    if (path.startsWith('notes/att/') && method === 'GET') {
      const attId = path.slice('notes/att/'.length);
      const r2Key = duress ? `decoy/att/${attId}` : `notes/att/${attId}`;
      return json({ ok: true, url: await presign(env, 'GET', r2Key, 1800) });
    }

    // ---------- 审计 ----------
    if (path === 'logs' && method === 'GET') {
      if (duress) return json({ ok: true, counter: 0, entries: [] }); // 假日志
      return json({ ok: true, ...(await readAudit(300)) });
    }

    // ---------- 手动销毁 ----------
    if (path === 'destroy' && method === 'POST') {
      if (duress) return json({ ok: true, deleted_r2_objects: 0 }); // 假销毁
      const deleted = await destroyAll(env, 'manual');
      return json({ ok: true, deleted_r2_objects: deleted });
    }

    // ---------- schedules 内部端点 ----------
    if (path === 'internal/sweep' && method === 'POST') {
      if (!internalAuthOk(request, env)) return err('forbidden', 403);
      const st = await getState();
      if (!st.initialized || st.destroyed) return json({ ok: true, skipped: 'not-active' });
      const timeoutH = st.checkin_timeout_hours || 72;
      const overdue = nowSec() - st.last_checkin > timeoutH * 3600;
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
