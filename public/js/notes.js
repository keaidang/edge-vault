// Edge Vault — 神盾笔记前端（独立密钥 / 独立笔记会话 / 敏感操作二次验口令）
import { loginHash, unwrapPrivateKey, wrapKeyWithPub, unwrapKeyWithPriv, fileEncrypt, fileDecrypt, encryptText, decryptText, newRawKey } from './crypto.js';

const $ = id => document.getElementById(id);
const show = (id, on = true) => { const el = $(id); if (el) el.classList.toggle('hidden', !on); };
const fmtSize = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

let authSalt = '';
let csrf = '';
let notePrivKey = null;   // 笔记密钥对私钥（仅内存）
let notePubJwk = null;
let activeNote = { id: null, rawKey: null, attachments: [] };
let unlocked = false;

async function api(path, { method = 'GET', body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (csrf && method !== 'GET') headers['x-csrf-token'] = csrf;
  const res = await fetch(`/api/${path}`, {
    method, headers, credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.ok === false) {
    const e = new Error(data.error || `HTTP ${res.status}`);
    e.status = res.status;
    throw e;
  }
  return data;
}

// 笔记页所有读写都要求 3 分钟内的笔记口令验证；窗口内不重复索要，页面上有行内口令框时优先使用
const VERIFY_CLIENT_MS = 170 * 1000;   // 服务端 180s，本地提前 10s 失效
let verifiedUntilNotes = 0;
const isVerifiedNotes = () => Date.now() < verifiedUntilNotes;
async function requireVerify(pass = '') {
  if (isVerifiedNotes()) return;
  let given = String(pass || '');
  if (!given) {
    const typed = window.prompt('请输入笔记密码以继续：');
    if (!typed) throw new Error('已取消');
    given = typed;
  }
  await api('verify', { method: 'POST', body: { scope: 'notes', hash: await loginHash(given, 'note', authSalt) } });
  verifiedUntilNotes = Date.now() + VERIFY_CLIENT_MS;
}

function status(msg, bad = false) {
  const el = $('noteStatus');
  if (!el) return;
  el.textContent = msg;
  el.classList.toggle('text-red-300', bad);
  el.classList.toggle('text-cyan-100/60', !bad);
}

// ---- 空闲自动锁定 ----
// 旧实现：60 秒无操作即 lock()，且 lock() 里还会 api('logout') 把笔记会话一起删掉；
// 现在放宽到 15 分钟，切后台不计时，锁定只清本地内存密钥（会话保留，输密码即可继续）。
const IDLE_LOCK_SEC = 900;
let idleDeadline = 0;
const idleLeft = () => Math.max(0, Math.ceil((idleDeadline - Date.now()) / 1000));
function renderIdle(v) {
  const el = $('idle-countdown');
  if (!el) return;
  el.textContent = `${String(Math.max(0, v)).padStart(2, '0')}s`;
  el.classList.toggle('is-warning', v <= 10);
}
function lock({ keepSession = false } = {}) {
  unlocked = false;
  notePrivKey = null;
  verifiedUntilNotes = 0;
  activeNote = { id: null, rawKey: null, attachments: [] };
  $('noteBody').value = '';
  $('noteTitle').value = '';
  show('notes-main', false);
  show('notes-gate', true);
  status('');
  if (!keepSession) {
    api('logout', { method: 'POST' }).catch(() => {});
    csrf = '';
  }
}
function resetIdle() {
  if (!unlocked) return;
  idleDeadline = Date.now() + IDLE_LOCK_SEC * 1000;
  renderIdle(IDLE_LOCK_SEC);
}
setInterval(() => {
  if (!unlocked || document.hidden) return;      // 切后台/别的窗口时不计时
  const left = idleLeft();
  renderIdle(left);
  if (left <= 0) lock({ keepSession: true });
}, 1000);
document.addEventListener('visibilitychange', () => {
  if (document.hidden || !unlocked) return;
  if (idleLeft() <= 0) lock({ keepSession: true }); else renderIdle(idleLeft());
});
['pointerdown', 'pointermove', 'keydown', 'scroll', 'touchstart', 'click'].forEach(e => window.addEventListener(e, resetIdle, { passive: true }));

// ==================== 解锁（笔记密码 → 笔记会话）====================
$('btnNotesUnlock').onclick = async () => {
  const pass = $('notesPass').value;
  if (!pass) return;
  try {
    const r = await api('login', { method: 'POST', body: { hash: await loginHash(pass, 'note', authSalt) } });
    if (r.mode !== 'notes') throw new Error('该密码不是笔记密码，请到保险库登录');
    csrf = r.csrf;
    if ($('notesUser')) $('notesUser').textContent = String(r.user || 'NOTES').toUpperCase();
    const info = await api('keyinfo?scope=notes');
    notePubJwk = info.note.pub;
    notePrivKey = await unwrapPrivateKey(info.note.wrapped, pass);
    unlocked = true;
    $('notesPass').value = '';
    show('notes-gate', false);
    show('notes-main', true);
    resetIdle();
    await loadList();
    await applyDeepLink();
  } catch (e) { alert(e.message); }
};
$('notesPass').addEventListener('keydown', e => { if (e.key === 'Enter') $('btnNotesUnlock').click(); });

// ==================== 列表 ====================
function fmtTime(ts) {
  if (!ts) return '--';
  // 原版以 UTC+8 展示
  const d = new Date((Number(ts) + 8 * 3600) * 1000);
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

async function decryptTitle(item) {
  if (!item?.title_enc || !notePrivKey) return '';
  try {
    const rawKey = await unwrapKeyWithPriv(notePrivKey, item.wrapped_key);
    return await decryptText(rawKey, item.title_enc);
  } catch { return ''; }
}

async function loadList() {
  const { notes } = await api('notes/list');
  const list = $('noteList');
  list.innerHTML = '';
  show('notesEmpty', notes.length === 0);
  for (const n of notes) {
    const title = (await decryptTitle(n)) || '加密笔记';
    const card = document.createElement('article');
    card.className = 'note-menu-card block no-underline text-inherit';
    card.dataset.noteId = n.id;
    card.innerHTML = `
      <div class="space-y-2">
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0 flex-1">
            <p class="section-title">Encrypted Note</p>
            <div class="mt-2 text-sm font-medium text-cyan-100">
              <span class="note-title-text" title="${escapeHtml(title)}">${escapeHtml(title)}</span>
            </div>
          </div>
        </div>
        <div class="text-xs leading-6 text-cyan-100/55">更新 ${escapeHtml(fmtTime(n.updated || n.created))}</div>
      </div>`;
    card.onclick = () => openNote(n.id, card);
    list.appendChild(card);
  }
  markActive();
}

function markActive() {
  const list = $('noteList');
  for (const el of list.querySelectorAll('[data-note-id]')) {
    el.classList.toggle('is-active', el.dataset.noteId === activeNote.id);
  }
}

// 原版笔记页用 /notes?note=<id>（新建为 ?note=create）表达"当前选中的笔记"，
// 刷新、收藏、从历史记录返回都能回到同一篇；这里用 replaceState 保持同一语义。
function syncUrl(id) {
  const query = id ? `?note=${encodeURIComponent(id)}` : '';
  try { history.replaceState(null, '', `${location.pathname}${query}`); } catch { /* file:// 等场景忽略 */ }
}

async function applyDeepLink() {
  const want = new URLSearchParams(location.search).get('note');
  if (!want) return;
  if (want === 'create') { startNewNote(); return; }
  const list = $('noteList');
  if (list && list.querySelector(`[data-note-id="${CSS.escape(want)}"]`)) await openNote(want);
  else syncUrl(null);
}

// ==================== 详细信息（原版 Details 面板）====================
function renderDetails(note) {
  const created = note?.created || 0;
  const updated = note?.updated || 0;
  if ($('noteCreated')) $('noteCreated').textContent = created ? fmtTime(created) : '--';
  if ($('noteUpdated')) $('noteUpdated').textContent = updated ? fmtTime(updated) : '--';
  const ol = $('noteHistory');
  if (!ol) return;
  ol.innerHTML = '';
  const hist = (note?.history || []).slice(-200).reverse();
  if (!hist.length) {
    const li = document.createElement('li');
    li.textContent = '暂无修改记录';
    ol.appendChild(li);
    return;
  }
  for (const ts of hist) {
    const li = document.createElement('li');
    li.textContent = `${fmtTime(ts)} (UTC+8)`;
    ol.appendChild(li);
  }
}

// ==================== 读取 / 新建 ====================
async function openNote(id, card) {
  try {
    await requireVerify();
    const { note } = await api(`notes/get/${id}`);
    activeNote = {
      id: note.id, rawKey: null, attachments: note.attachments || [],
      created: note.created || 0, updated: note.updated || 0, history: note.history || [],
    };
    if (note.wrapped_key) activeNote.rawKey = await unwrapKeyWithPriv(notePrivKey, note.wrapped_key);
    $('noteTitle').value = note.title_enc && activeNote.rawKey ? await decryptText(activeNote.rawKey, note.title_enc) : '';
    $('noteBody').value = note.body_enc && activeNote.rawKey ? await decryptText(activeNote.rawKey, note.body_enc) : '';
    renderDetails(activeNote);
    status('已解密显示');
    renderAttachments();
    markActive();
    syncUrl(activeNote.id);
    resetIdle();
  } catch (e) { status(e.message, true); alert(e.message); }
}

function startNewNote() {
  activeNote = { id: null, rawKey: null, attachments: [] };
  $('noteTitle').value = '';
  $('noteBody').value = '';
  renderDetails(null);
  status('新笔记：保存后生成独立文件密钥');
  renderAttachments();
  markActive();
  syncUrl('create');
  resetIdle();
}

$('btnNewNote').onclick = startNewNote;

// ==================== 保存 / 删除 ====================
$('btnSaveNote').onclick = async () => {
  const title = $('noteTitle').value;
  const body = $('noteBody').value;
  if (!body.trim()) { status('正文不能为空', true); return; }
  if (body.length > 750 * 1024) { status('正文过大（服务端上限约 750KB 明文），请用附件', true); return; }
  try {
    await requireVerify();
    if (!activeNote.rawKey) {
      activeNote.rawKey = newRawKey();
      activeNote.wrappedKey = await wrapKeyWithPub(notePubJwk, activeNote.rawKey);
    }
    const payload = {
      note_id: activeNote.id || undefined,
      title_enc: await encryptText(activeNote.rawKey, title),
      body_enc: await encryptText(activeNote.rawKey, body),
      wrapped_key: activeNote.wrappedKey || await wrapKeyWithPub(notePubJwk, activeNote.rawKey),
      attachments: activeNote.attachments,
    };
    const r = await api('notes/save', { method: 'POST', body: payload });
    activeNote.id = r.note_id;
    activeNote.created = activeNote.created || r.updated;
    activeNote.updated = r.updated;
    activeNote.history = [...(activeNote.history || []), r.updated].slice(-200);
    syncUrl(activeNote.id);
    renderDetails(activeNote);
    status(`已保存 ${new Date().toLocaleTimeString()}`);
    await loadList();
    markActive();
    resetIdle();
  } catch (e) { status(e.message, true); alert(e.message); }
};

$('btnDeleteNote').onclick = async () => {
  if (!activeNote.id) { status('当前没有已保存的笔记', true); return; }
  if (!window.confirm('删除该笔记及其全部附件？（不可恢复）')) return;
  const pass = $('noteDeletePass') ? $('noteDeletePass').value : '';
  try {
    await requireVerify(pass);
    await api(`notes/delete/${activeNote.id}`, { method: 'POST' });
    activeNote = { id: null, rawKey: null, attachments: [] };
    $('noteTitle').value = '';
    $('noteBody').value = '';
    if ($('noteDeletePass')) $('noteDeletePass').value = '';
    renderDetails(null);
    renderAttachments();
    syncUrl(null);
    status('笔记已删除');
    await loadList();
  } catch (e) { status(e.message, true); alert(e.message); }
};

// ==================== 附件 ====================
function renderAttachments() {
  const list = $('attList');
  list.innerHTML = '';
  const atts = activeNote.attachments || [];
  show('attEmpty', atts.length === 0);
  if ($('attCount')) $('attCount').textContent = String(atts.length);
  atts.forEach(a => {
    const card = document.createElement('article');
    card.className = 'attachment-card';
    const placeholder = `附件 ${String(a.id).slice(0, 6)}`;
    card.innerHTML = `
      <div class="space-y-3">
        <div class="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div class="min-w-0">
            <div class="text-sm font-medium text-cyan-100">
              <span class="file-name-text" data-att-name title="${escapeHtml(placeholder)}">${escapeHtml(placeholder)}</span>
            </div>
            <div class="mt-2 text-xs text-cyan-100/55">上传于 ${escapeHtml(fmtTime(a.created))} (UTC+8)</div>
          </div>
          <div class="status-pill">${escapeHtml(fmtSize(Number(a.size || 0)))}</div>
        </div>
        <div class="attachment-actions">
          <input type="password" autocomplete="off" placeholder="笔记密码" class="download-password-field secure-entry">
          <button type="button" class="btn-neon" data-att-dl="${escapeHtml(a.id)}">下载附件</button>
          <button type="button" class="btn-danger" data-att-del="${escapeHtml(a.id)}">删除附件</button>
        </div>
      </div>`;
    list.appendChild(card);
  });
  decryptAttachmentNames();
}

async function decryptAttachmentNames() {
  if (!activeNote.rawKey) return;
  for (const el of $('attList').querySelectorAll('[data-att-dl]')) {
    const id = el.dataset.attDl;
    const meta = (activeNote.attachments || []).find(a => String(a.id) === String(id));
    if (!meta || !meta.name_enc) continue;
    try {
      const name = await decryptText(activeNote.rawKey, meta.name_enc);
      const card = el.closest('.attachment-card');
      const label = card?.querySelector('[data-att-name]');
      if (label) { label.textContent = name; label.title = name; }
    } catch { /* 保持占位文本 */ }
  }
}

$('attList').onclick = async e => {
  const dl = e.target.closest('[data-att-dl]');
  const del = e.target.closest('[data-att-del]');
  const card = e.target.closest('.attachment-card');
  const pass = card && card.querySelector('[data-att-pass], .download-password-field')
    ? card.querySelector('.download-password-field').value : '';
  if (dl) await downloadAttachment(dl.dataset.attDl, pass);
  if (del) await deleteAttachment(del.dataset.attDel, pass);
};

async function downloadAttachment(attId, pass = '') {
  try {
    if (!activeNote.rawKey) throw new Error('请先打开笔记以获取文件密钥');
    await requireVerify(pass);
    const { url } = await api(`notes/att/${attId}?note_id=${encodeURIComponent(activeNote.id)}`);
    const ct = new Uint8Array(await (await fetch(url)).arrayBuffer());
    const plain = await fileDecrypt(activeNote.rawKey, ct);
    const meta = (activeNote.attachments || []).find(a => String(a.id) === String(attId));
    let name = `attachment-${String(attId).slice(0, 6)}`;
    if (meta?.name_enc) { try { name = await decryptText(activeNote.rawKey, meta.name_enc); } catch { /* 用默认名 */ } }
    const blobUrl = URL.createObjectURL(new Blob([plain]));
    const a = document.createElement('a');
    a.href = blobUrl; a.download = name; a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(blobUrl), 60000);
  } catch (e) { alert(e.message); }
}

async function deleteAttachment(attId, pass = '') {
  if (!window.confirm('删除该附件？')) return;
  try {
    await requireVerify(pass);
    await api('notes/att/delete', { method: 'POST', body: { note_id: activeNote.id, att_id: attId } });
    activeNote.attachments = (activeNote.attachments || []).filter(a => String(a.id) !== String(attId));
    renderAttachments();
    await loadList();
    markActive();
  } catch (e) { alert(e.message); }
}

$('btnAttUpload').onclick = async () => {
  const input = $('attInput');
  const file = input.files && input.files[0];
  if (!file) { status('请选择要上传的附件', true); return; }
  try {
    if (!activeNote.id) throw new Error('请先保存笔记再上传附件');
    if (!activeNote.rawKey) throw new Error('请先重新打开笔记以获取文件密钥');
    await requireVerify();
    const { att_id, upload_url } = await api('notes/att/meta', { method: 'POST', body: { note_id: activeNote.id } });
    const cipher = await fileEncrypt(activeNote.rawKey, new Uint8Array(await file.arrayBuffer()));
    const put = await fetch(upload_url, { method: 'PUT', body: cipher });
    if (!put.ok) throw new Error(`R2 上传失败 HTTP ${put.status}`);
    activeNote.attachments = [
      ...(activeNote.attachments || []),
      { id: att_id, name_enc: await encryptText(activeNote.rawKey, file.name), size: cipher.byteLength, created: Math.floor(Date.now() / 1000) },
    ];
    await api('notes/save', {
      method: 'POST',
      body: {
        note_id: activeNote.id,
        title_enc: await encryptText(activeNote.rawKey, $('noteTitle').value),
        body_enc: await encryptText(activeNote.rawKey, $('noteBody').value),
        wrapped_key: activeNote.wrappedKey || await wrapKeyWithPub(notePubJwk, activeNote.rawKey),
        attachments: activeNote.attachments,
      },
    });
    input.value = '';
    renderAttachments();
    status('附件已加密上传');
    await loadList();
    markActive();
  } catch (e) { status(e.message, true); alert(e.message); }
};

// ==================== 退出 / 启动 ====================
$('btnLogout').onclick = () => { lock(); location.href = '/'; };

function showBootError(e) {
  const gate = $('notes-gate');
  if (gate) gate.classList.remove('hidden');
  show('notes-main', false);
  status(`无法连接边缘服务：${e.message}`, true);
}

async function boot() {
  const st = await api('state');
  authSalt = st.auth_salt || '';
  if (st.destroyed || !st.initialized) {
    status('系统未初始化或已销毁，请先在保险库完成初始化', true);
    $('btnNotesUnlock').disabled = true;
    return;
  }
  // 会话即使存在也不保留私钥：每次进入笔记页都需重新输入笔记密码
  verifiedUntilNotes = st.verified && st.verified.notes ? Date.now() + 100 * 1000 : 0;
  show('notes-gate', true);
  show('notes-main', false);
}

boot().catch(showBootError);
