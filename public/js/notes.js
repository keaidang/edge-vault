// Edge Vault — 神盾笔记前端（原版风格：侧栏列表 + 编辑区 + 图片附件）
import { loginHash, unwrapPrivateKey, unwrapKeyWithPriv, encryptText, decryptText, deriveFileKey, b64 } from './crypto.js';

const $ = id => document.getElementById(id);
let privKey = null;
let decoyMode = false;
let decoyPass = null;
let currentNote = null; // {id, rawKey(Uint8Array), title}
let noteIndex = [];

async function api(path, opts = {}) {
  const res = await fetch(`/api/${path}`, { headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', ...opts });
  const data = await res.json();
  if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ---- 60s 空闲登出 ----
let idleRemaining = 60, idleSubmitting = false;
function renderIdle(v) {
  const el = $('idle-countdown');
  el.textContent = `${String(Math.max(0, v)).padStart(2, '0')}s`;
  el.classList.toggle('is-warning', v <= 10);
}
['pointerdown', 'pointermove', 'keydown', 'scroll', 'touchstart', 'click'].forEach(e => window.addEventListener(e, () => {
  if (idleSubmitting) return;
  idleRemaining = 60; renderIdle(60);
}, { passive: true }));
setInterval(() => {
  if (!privKey && !decoyMode) return;
  idleRemaining -= 1; renderIdle(idleRemaining);
  if (idleRemaining <= 0 && !idleSubmitting) { idleSubmitting = true; doLogout(); }
}, 1000);

async function noteKey(note) {
  if (decoyMode) return deriveFileKey(decoyPass, note.id);
  return new Uint8Array(await unwrapKeyWithPriv(privKey, note.wrapped_key));
}

async function loadList() {
  const { notes } = await api('notes/list');
  noteIndex = notes;
  const list = $('noteList');
  list.innerHTML = '';
  $('notesEmpty').classList.toggle('hidden', notes.length > 0);
  for (const n of notes) {
    const card = document.createElement('a');
    card.className = `note-menu-card block no-underline text-inherit cursor-pointer ${currentNote?.id === n.id ? 'is-active' : ''}`;
    card.dataset.open = n.id;
    let title = '🔒 加密笔记';
    if (currentNote?.id === n.id) { try { title = currentNote.title; } catch {} }
    card.innerHTML = `
      <div class="space-y-2">
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0 flex-1">
            <p class="section-title">Encrypted Note</p>
            <div class="mt-2 text-sm font-medium text-cyan-100"><span class="note-title-text">${title}</span></div>
          </div>
        </div>
        <div class="text-xs leading-6 text-cyan-100/55">更新 ${new Date(n.updated * 1000).toLocaleString('zh-CN')}</div>
      </div>`;
    list.appendChild(card);
  }
}

$('noteList').onclick = e => {
  const card = e.target.closest('[data-open]');
  if (card) openNote(card.dataset.open);
};

async function openNote(id) {
  const { note } = await api(`notes/get/${id}`);
  try {
    const rawKey = await noteKey(note);
    currentNote = { id, rawKey, title: await decryptText(rawKey, note.title_enc) };
    $('noteTitle').value = currentNote.title;
    $('noteBody').value = await decryptText(rawKey, note.body_enc);
    $('noteStatus').textContent = '';
    renderAttachments(note.attachments || [], rawKey);
    await loadList();
  } catch { alert('解密失败（密钥不匹配）'); }
}

function renderAttachments(atts, rawKey) {
  $('attCount').textContent = String(atts.length);
  $('attEmpty').classList.toggle('hidden', atts.length > 0);
  const list = $('attList');
  list.innerHTML = '';
  for (const a of atts) {
    const card = document.createElement('article');
    card.className = 'attachment-card';
    card.innerHTML = `
      <div class="space-y-3">
        <div class="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div class="min-w-0">
            <div class="text-sm font-medium text-cyan-100"><span class="file-name-text">${a.name}</span></div>
            <div class="mt-2 text-xs text-cyan-100/55">上传于 ${new Date(a.created * 1000).toLocaleString('zh-CN')}</div>
          </div>
          <div class="status-pill">${a.size} B</div>
        </div>
        <div class="attachment-actions">
          <button type="button" data-att-dl="${a.id}" data-att-name="${a.name}" class="btn-neon">下载附件</button>
          <button type="button" data-att-del="${a.id}" class="btn-danger">删除附件</button>
        </div>
      </div>`;
    list.appendChild(card);
  }
  list.onclick = async e => {
    const dl = e.target.closest('[data-att-dl]');
    const del = e.target.closest('[data-att-del]');
    if (!dl && !del) return;
    try {
      if (dl) {
        const { url } = await api(`notes/att/${dl.dataset.attDl}`);
        const ct = new Uint8Array(await (await fetch(url)).arrayBuffer());
        const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ct.slice(0, 12) }, await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']), ct.slice(12));
        const aEl = document.createElement('a');
        aEl.href = URL.createObjectURL(new Blob([plain]));
        aEl.download = dl.dataset.attName;
        aEl.click();
        URL.revokeObjectURL(aEl.href);
      }
      if (del) {
        if (!window.confirm('确认删除当前附件？')) return;
        await api('notes/att/delete', { method: 'POST', body: JSON.stringify({ att_id: del.dataset.attDel }) });
        const note = currentNote;
        note.attachments = (note.attachments || []).filter(x => x.id !== del.dataset.attDel);
        await saveNoteSilent();
      }
    } catch (err) { alert(err.message); }
  };
}

async function saveNoteSilent() {
  const { note } = await api(`notes/get/${currentNote.id}`);
  await api('notes/save', { method: 'POST', body: JSON.stringify({
    note_id: currentNote.id,
    title_enc: await encryptText(currentNote.rawKey, currentNote.title),
    body_enc: await encryptText(currentNote.rawKey, $('noteBody').value),
    wrapped_key: currentNote.wrapped_key || '',
    attachments: currentNote.attachments || [],
  }) });
  void note;
}

$('btnNewNote').onclick = () => {
  if (!privKey && !decoyMode) return;
  currentNote = null;
  $('noteTitle').value = '';
  $('noteBody').value = '';
  $('noteStatus').textContent = '';
  $('attCount').textContent = '0';
  $('attList').innerHTML = '';
  $('attEmpty').classList.remove('hidden');
};

$('btnSaveNote').onclick = async () => {
  const title = $('noteTitle').value, bodyText = $('noteBody').value;
  try {
    const id = currentNote?.id || crypto.randomUUID().replace(/-/g, '').slice(0, 16);
    let rawKey = currentNote?.rawKey;
    let wrappedKey = currentNote?.wrapped_key || '';
    if (!rawKey) rawKey = crypto.getRandomValues(new Uint8Array(32));
    if (!decoyMode) {
      const pub = (await api('keyinfo')).pub;
      const pubKey = await crypto.subtle.importKey('jwk', pub, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
      wrappedKey = b64.enc(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, rawKey));
    }
    await api('notes/save', { method: 'POST', body: JSON.stringify({
      note_id: id,
      title_enc: await encryptText(rawKey, title),
      body_enc: await encryptText(rawKey, bodyText),
      wrapped_key: wrappedKey,
      attachments: currentNote?.attachments || [],
    }) });
    currentNote = { id, rawKey, title, wrapped_key: wrappedKey, attachments: currentNote?.attachments || [] };
    $('noteStatus').textContent = `✅ 已保存 ${new Date().toLocaleTimeString('zh-CN')}`;
    await loadList();
  } catch (e) { $('noteStatus').textContent = `❌ ${e.message}`; }
};

$('btnDeleteNote').onclick = async () => {
  if (!currentNote) { alert('请先选择一篇笔记'); return; }
  if (!window.confirm('确认删除当前笔记？')) return;
  await api(`notes/delete/${currentNote.id}`, { method: 'POST' });
  currentNote = null;
  $('noteTitle').value = ''; $('noteBody').value = '';
  $('attList').innerHTML = ''; $('attEmpty').classList.remove('hidden');
  await loadList();
};

$('btnAttUpload').onclick = async () => {
  const file = $('attInput').files[0];
  if (!file) { alert('请选择图片'); return; }
  if (!currentNote) { alert('请先保存笔记再上传附件'); return; }
  try {
    const { att_id: attId, upload_url: uploadUrl } = await api('notes/att/meta', { method: 'POST', body: JSON.stringify({}) });
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey('raw', currentNote.rawKey, { name: 'AES-GCM' }, false, ['encrypt']);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new Uint8Array(await file.arrayBuffer()));
    const packed = new Uint8Array(12 + ct.byteLength);
    packed.set(iv); packed.set(new Uint8Array(ct), 12);
    const put = await fetch(uploadUrl, { method: 'PUT', body: packed });
    if (!put.ok) throw new Error(`R2 上传失败 HTTP ${put.status}`);
    currentNote.attachments = currentNote.attachments || [];
    currentNote.attachments.push({ id: attId, name: file.name, size: ct.byteLength, created: Math.floor(Date.now() / 1000) });
    await saveNoteSilent();
    $('attInput').value = '';
    renderAttachments(currentNote.attachments, currentNote.rawKey);
  } catch (e) { alert(`附件上传失败：${e.message}`); }
};

async function doLogout() {
  try { await api('logout', { method: 'POST' }); } catch {}
  sessionStorage.removeItem('ev_priv');
  sessionStorage.removeItem('ev_pass');
  sessionStorage.removeItem('ev_decoy');
  location.href = '/';
}
$('btnLogout').onclick = doLogout;

$('btnNotesUnlock').onclick = async () => {
  const pass = $('notesPass').value;
  try {
    // 确保会话有效（若主页面已登录则跳过登录）
    try { await api('keyinfo'); } catch {
      await api('login', { method: 'POST', body: JSON.stringify({ hash: await loginHash(pass, 'login') }) });
    }
    const info = await api('keyinfo');
    if (info.decoy) {
      decoyMode = true; decoyPass = sessionStorage.getItem('ev_decoy') || pass;
    } else {
      privKey = await unwrapPrivateKey(info.wrapped, pass);
      sessionStorage.setItem('ev_priv', JSON.stringify(await crypto.subtle.exportKey('jwk', privKey)));
    }
    $('notes-gate').classList.add('hidden');
    $('notes-main').classList.remove('hidden');
    await loadList();
  } catch (e) { alert(`解锁失败：${e.message}`); }
};

async function boot() {
  const jwkStr = sessionStorage.getItem('ev_priv');
  decoyPass = sessionStorage.getItem('ev_decoy');
  let ready = false;
  if (jwkStr) {
    try {
      privKey = await crypto.subtle.importKey('jwk', JSON.parse(jwkStr), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
      await api('keyinfo');
      ready = true;
    } catch {}
  } else if (decoyPass) {
    decoyMode = true;
    try { await api('keyinfo'); ready = true; } catch {}
  }
  if (!ready) { $('notes-main').classList.add('hidden'); $('notes-gate').classList.remove('hidden'); return; }
  $('notes-gate').classList.add('hidden');
  $('notes-main').classList.remove('hidden');
  await loadList();
}
boot();
