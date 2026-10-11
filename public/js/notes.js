// Edge Vault — 神盾笔记前端（真实模式 / 假仓库 decoy 模式）
import { unwrapPrivateKey, unwrapKeyWithPriv, encryptText, decryptText, deriveFileKey, b64 } from './crypto.js';

const $ = id => document.getElementById(id);
let privKey = null;         // 真实模式
let decoyMode = false;      // 假仓库模式
let decoyPass = null;
let currentNote = null;     // {id, rawKey(Uint8Array), title}

async function api(path, opts = {}) {
  const res = await fetch(`/api/${path}`, { headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', ...opts });
  const data = await res.json();
  if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// 60s 空闲返回主页
let idleTimer = null;
function resetIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => location.href = '/', 60000);
}
['mousemove', 'keydown', 'click', 'touchstart'].forEach(e => document.addEventListener(e, resetIdle));

// 取某笔记的原始密钥：真实模式 RSA 解包；decoy 模式按「口令+id」派生
async function noteKey(note) {
  if (decoyMode) return deriveFileKey(decoyPass, note.id);
  return new Uint8Array(await unwrapKeyWithPriv(privKey, note.wrapped_key));
}

async function loadList() {
  const { notes } = await api('notes/list');
  const tbody = $('noteList');
  tbody.innerHTML = '';
  if (!notes.length) { tbody.innerHTML = '<tr><td colspan="3" class="hint">暂无笔记，点「新建笔记」创建</td></tr>'; return; }
  for (const n of notes) {
    const tr = document.createElement('tr');
    let title = '🔒 加密笔记';
    if (currentNote && currentNote.id === n.id) {
      try { title = await decryptText(currentNote.rawKey, n.title_enc); } catch {}
    }
    tr.innerHTML = `<td data-open="${n.id}" style="cursor:pointer">${title}</td><td>${new Date(n.updated * 1000).toLocaleString()}</td>
      <td><button class="ghost" data-open2="${n.id}">打开</button> <button class="ghost danger" data-del="${n.id}">删除</button></td>`;
    tbody.appendChild(tr);
  }
}

$('noteList').onclick = async e => {
  const open = e.target.dataset.open || e.target.dataset.open2;
  const del = e.target.dataset.del;
  try {
    if (open) return await openNote(open);
    if (del) {
      if (!confirm('删除该笔记及其附件？')) return;
      await api(`notes/delete/${del}`, { method: 'POST' });
      if (currentNote?.id === del) { currentNote = null; $('editor').classList.add('hidden'); }
      await loadList();
    }
  } catch (err) { alert(err.message); }
};

async function openNote(id) {
  const { note } = await api(`notes/get/${id}`);
  try {
    const rawKey = await noteKey(note);
    currentNote = { id, rawKey, title: await decryptText(rawKey, note.title_enc) };
    $('noteTitle').value = currentNote.title;
    $('noteBody').value = await decryptText(rawKey, note.body_enc);
    $('editor').classList.remove('hidden');
    $('noteStatus').textContent = '';
  } catch { alert('解密失败（密钥不匹配）'); }
}

$('btnNew').onclick = () => {
  currentNote = null;
  $('editor').classList.remove('hidden');
  $('noteTitle').value = '';
  $('noteBody').value = '';
  $('noteStatus').textContent = '';
};

$('btnSaveNote').onclick = async () => {
  const title = $('noteTitle').value, bodyText = $('noteBody').value;
  try {
    const id = currentNote?.id || crypto.randomUUID().replace(/-/g, '').slice(0, 16);
    let rawKey = currentNote?.rawKey;
    let wrappedKey = currentNote ? null : '';
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
      wrapped_key: wrappedKey || '',
      attachments: [],
    }) });
    currentNote = { id, rawKey, title };
    $('noteStatus').textContent = `✅ 已保存 ${new Date().toLocaleTimeString()}`;
    await loadList();
  } catch (e) { $('noteStatus').textContent = `❌ ${e.message}`; }
};

$('btnCloseNote').onclick = () => { $('editor').classList.add('hidden'); currentNote = null; };
$('btnLogout').onclick = async () => {
  try { await api('logout', { method: 'POST' }); } catch {}
  sessionStorage.removeItem('ev_priv');
  sessionStorage.removeItem('ev_decoy');
  location.href = '/';
};

async function boot() {
  const jwkStr = sessionStorage.getItem('ev_priv');
  decoyPass = sessionStorage.getItem('ev_decoy');
  if (jwkStr) {
    try {
      privKey = await crypto.subtle.importKey('jwk', JSON.parse(jwkStr), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    } catch {}
  } else if (decoyPass) {
    decoyMode = true;
  } else {
    location.href = '/';
    return;
  }
  try { await api('notes/list'); } catch { location.href = '/'; return; }
  resetIdle();
  await loadList();
}
boot();
