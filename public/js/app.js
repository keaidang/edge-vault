// Edge Vault — 保险库前端（对齐 aegis-vault：四用户槽位 / 管理员管理 / 敏感操作二次验口令）
import { loginHash, generateMasterKeys, wrapPrivateKey, unwrapPrivateKey, wrapKeyWithPub, unwrapKeyWithPriv, fileEncrypt, fileDecrypt, encryptText, decryptText, newRawKey } from './crypto.js';

const $ = id => document.getElementById(id);
const show = (id, on = true) => { const el = $(id); if (el) el.classList.toggle('hidden', !on); };

let authSalt = '';
let csrf = '';
let users = [];
let session = null;      // { user, mode, csrf }
let privKey = null;      // 仅内存
let resetToken = '';

const nowSec = () => Math.floor(Date.now() / 1000);
const fmtSize = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(2)} GB`;
function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

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

// 敏感操作前的二次口令校验（服务端记录 3 分钟窗口）
async function requireVerify(scope) {
  const label = scope === 'notes' ? '笔记密码' : '访问密码';
  const pass = window.prompt(`请输入${label}以继续：`);
  if (!pass) throw new Error('已取消');
  await api('verify', { method: 'POST', body: { scope, hash: await loginHash(pass, scope === 'notes' ? 'note' : 'login', authSalt) } });
}

// ---- 状态胶囊 / 视图 ----
function pill(name) {
  for (const id of ['status-pill', 'status-pill-running', 'status-pill-destroyed']) show(id, false);
  if (name) show(name, true);
}
function setAuthChrome(on, user = '') {
  document.body.classList.toggle('auth-body', on);
  const main = document.querySelector('main');
  if (main) main.classList.toggle('auth-shell', on);
  const frame = $('app-frame');
  if (frame) frame.classList.toggle('auth-frame', on);
  show('idle-countdown', on);
  show('user-pill', on);
  if (user) {
    if ($('user-pill')) $('user-pill').textContent = user.toUpperCase();
    if ($('sessionUser')) $('sessionUser').textContent = user.toUpperCase();
  }
}

function showView(name) {
  for (const v of ['view-init', 'view-destroyed', 'view-login', 'view-vault']) show(v, false);
  show(name, true);
  const authed = name === 'view-vault';
  setAuthChrome(authed, session?.user || '');
  show('admin-controls', authed && session?.user === 'admin');
}

// ---- 60s 空闲登出 ----
let idleRemaining = 60;
let idleSubmitting = false;
function renderIdle(v) {
  const el = $('idle-countdown');
  if (!el) return;
  el.textContent = `${String(Math.max(0, v)).padStart(2, '0')}s`;
  el.classList.toggle('is-warning', v <= 10);
}
function resetIdle() {
  if (idleSubmitting) return;
  idleRemaining = 60;
  renderIdle(idleRemaining);
}
async function doLogout() {
  if (idleSubmitting) return;
  idleSubmitting = true;
  try { await api('logout', { method: 'POST' }); } catch { /* ignore */ }
  privKey = null; csrf = ''; session = null;
  location.reload();
}
setInterval(() => {
  if (!privKey) return;
  idleRemaining -= 1;
  renderIdle(idleRemaining);
  if (idleRemaining <= 0) doLogout();
}, 1000);
['pointerdown', 'pointermove', 'keydown', 'scroll', 'touchstart', 'click'].forEach(e => window.addEventListener(e, resetIdle, { passive: true }));
window.addEventListener('keydown', e => {
  const k = String(e.key || '').toLowerCase();
  if (k === 'f5' || (k === 'r' && (e.ctrlKey || e.metaKey))) {
    if (privKey) { e.preventDefault(); doLogout(); }
  }
});

// ---- 自毁倒计时 ----
let countdownTimer = null;
function renderCountdown(sec) {
  const el = $('countdown');
  if (!el) return;
  const s = Math.max(0, Math.floor(sec));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), ss = s % 60;
  el.textContent = [h, m, ss].map(x => String(x).padStart(2, '0')).join(':');
  el.classList.toggle('text-red-300', s <= 3600);
}
function startCountdown(lastCheckin, timeoutH) {
  clearInterval(countdownTimer);
  const deadline = (lastCheckin || nowSec()) + (timeoutH || 72) * 3600;
  renderCountdown(deadline - nowSec());
  countdownTimer = setInterval(() => renderCountdown(deadline - nowSec()), 1000);
}

// ==================== 启动 ====================
async function boot() {
  const st = await api('state');
  authSalt = st.auth_salt || '';
  users = st.users || [];
  if (st.session) { session = st.session; csrf = st.session.csrf; }
  if (st.destroyed) { pill('status-pill-destroyed'); showView('view-destroyed'); return; }
  if (!st.initialized) { pill('status-pill'); showView('view-init'); return; }
  pill('status-pill-running');
  startCountdown(st.last_checkin, st.checkin_timeout_hours);
  renderQuota(st.quota, st.usage);
  // 私钥不落存储：每次进入都要求重新输入口令
  showView('view-login');
}

function showBootError(e) {
  pill('status-pill');
  showView('view-init');
  const log = $('initProgress');
  if (log) {
    log.classList.remove('hidden');
    log.textContent = `❌ 无法连接边缘服务：${e.message}\n请检查边缘函数日志与 KV 绑定。`;
  }
}

function renderQuota(quota, usage) {
  const used = usage?.used_bytes || 0;
  const total = quota?.vault_quota_bytes || 0;
  const text = `${fmtSize(used)} / ${fmtSize(total)}`;
  for (const id of ['quotaText', 'quotaTextMobile']) {
    const el = $(id);
    if (el) el.textContent = text;
  }
}

// ==================== 初始化（admin 引导）====================
$('btnInit').onclick = async () => {
  const pass = $('initPass').value;
  const pass2 = $('initPass2').value;
  const checkin = $('initCheckin').value;
  const duress = $('initDuress').value;
  const timeoutH = Number($('initTimeout').value) || 72;
  const log = $('initProgress');
  const fail = msg => { log.classList.remove('hidden'); log.textContent += `\n❌ ${msg}`; };
  log.classList.remove('hidden');
  log.textContent = '';
  try {
    if (pass.length < 12) throw new Error('管理员密码至少 12 位');
    if (pass !== pass2) throw new Error('两次输入的管理员密码不一致');
    if (checkin.trim().length < 8) throw new Error('签到码至少 8 位');
    if (duress && duress.trim().length < 8) throw new Error('胁迫码至少 8 位');

    log.textContent += '[1/4] 生成 RSA-3072 密钥对…\n';
    const { privJwk, pubJwk } = await generateMasterKeys();
    log.textContent += '[2/4] 口令派生并包裹私钥…\n';
    const { wrapped, salt } = await wrapPrivateKey(privJwk, pass);
    log.textContent += '[3/4] 计算登录 / 签到 / 胁迫哈希…\n';
    const auth_salt = [...crypto.getRandomValues(new Uint8Array(16))].map(x => x.toString(16).padStart(2, '0')).join('');
    const body = {
      wrapped_priv_key: wrapped, salt, pub_key: pubJwk,
      login_hash: await loginHash(pass, 'login', auth_salt),
      checkin_hash: await loginHash(checkin.trim(), 'checkin', auth_salt),
      auth_salt, checkin_timeout_hours: timeoutH,
      reset_token: resetToken || undefined,
    };
    if (duress.trim()) {
      const d = duress.trim();
      // 胁迫码存两份：登录框用 login kind、签到框用 checkin kind
      body.duress_hash = await loginHash(d, 'login', auth_salt);
      body.duress_hash_checkin = await loginHash(d, 'checkin', auth_salt);
    }
    log.textContent += '[4/4] 写入边缘 KV…\n';
    await api('init', { method: 'POST', body });
    authSalt = auth_salt;
    log.textContent += '✅ 初始化完成，请使用管理员密码登录。';
    pill('status-pill-running');
    startCountdown(nowSec(), timeoutH);
    showView('view-login');
  } catch (e) { fail(e.message); }
};

// ==================== 登录（统一入口：保险库 / 笔记）====================
$('btnLogin').onclick = async () => {
  const pass = $('loginPass').value;
  if (!pass) return;
  try {
    const r = await api('login', { method: 'POST', body: { hash: await loginHash(pass, 'login', authSalt) } });
    csrf = r.csrf;
    session = { user: r.user, mode: r.mode, csrf: r.csrf };
    if (r.mode === 'notes') { location.href = '/notes.html'; return; }   // 笔记口令 → 笔记页
    const info = await api('keyinfo');
    privKey = await unwrapPrivateKey(info.user.wrapped, pass);
    pill('status-pill-running');
    showView('view-vault');
    await enterVault();
  } catch (e) {
    alert(e.message);
  }
};

// ==================== 忘记密码（需服务端 RESET_TOKEN）====================
$('btnForgot').onclick = async () => {
  if (!window.confirm('重置将清空全部密钥与数据，之后需要重新初始化。继续？')) return;
  resetToken = window.prompt('请输入服务端 RESET_TOKEN（EdgeOne 控制台临时设置）:') || '';
  if (!resetToken) return;
  pill('status-pill');
  showView('view-init');
};

// ==================== 签到 ====================
$('btnCheckin').onclick = async () => {
  try {
    const r = await api('checkin', { method: 'POST', body: { hash: await loginHash($('checkinCode').value, 'checkin', authSalt) } });
    startCountdown(r.last_checkin, r.checkin_timeout_hours);
    pill('status-pill-running');
    alert('签到成功，计时器已重置');
  } catch (e) { alert(e.message); }
};

// ==================== 保险库 ====================
async function enterVault() {
  await refreshFiles();
  resetIdle();
}

async function decodeFileName(f) {
  if (!f.name_enc) return '加密文件';
  try {
    const rawKey = await unwrapKeyWithPriv(privKey, f.wrapped_key);
    return await decryptText(rawKey, f.name_enc);
  } catch { return '加密文件（密钥不匹配）'; }
}

async function refreshFiles() {
  const { files } = await api('files');
  const cfg = await api('config/storage').catch(() => null);
  if (cfg) renderQuota(cfg, cfg.usage);

  const rows = $('fileRows');
  const mobile = $('filesMobile');
  rows.innerHTML = '';
  mobile.innerHTML = '';
  const none = files.length === 0;
  show('filesEmpty', none);

  const names = await Promise.all(files.map(decodeFileName));
  files.forEach((f, i) => {
    const safeName = escapeHtml(names[i]);
    const tr = document.createElement('tr');
    tr.className = 'border-b border-cyan-900/30 align-middle';
    tr.innerHTML = `
      <td class="file-name-cell py-4 pr-4 text-cyan-100/85"><span class="file-name-text" title="${safeName}">${safeName}</span></td>
      <td class="py-4 pr-4 text-cyan-100/70">${fmtSize(f.size || 0)}</td>
      <td class="py-4 text-right">
        <div class="inline-actions justify-end">
          <button type="button" data-dl="${escapeHtml(f.id)}" class="btn-neon px-4 py-2">解密下载</button>
          <button type="button" data-del="${escapeHtml(f.id)}" class="btn-danger px-4 py-2">删除</button>
        </div>
      </td>`;
    rows.appendChild(tr);

    const card = document.createElement('article');
    card.className = 'file-card';
    card.innerHTML = `
      <div class="space-y-3">
        <div>
          <p class="section-title">Encrypted File</p>
          <div class="mt-2 text-sm font-medium text-cyan-100"><span class="file-name-text" title="${safeName}">${safeName}</span></div>
          <div class="mt-2 text-xs text-cyan-100/55">${fmtSize(f.size || 0)}</div>
        </div>
        <div class="flex gap-2">
          <button type="button" data-dl="${escapeHtml(f.id)}" class="btn-neon flex-1">解密下载</button>
          <button type="button" data-del="${escapeHtml(f.id)}" class="btn-danger flex-1">删除</button>
        </div>
      </div>`;
    mobile.appendChild(card);
  });
}

async function downloadFile(id) {
  try {
    await requireVerify('vault');
    const d = await api(`download/${id}`);
    const ct = new Uint8Array(await (await fetch(d.url)).arrayBuffer());
    const rawKey = await unwrapKeyWithPriv(privKey, d.wrapped_key);
    const plain = await fileDecrypt(rawKey, ct);
    const name = await decryptText(rawKey, d.name_enc);
    const url = URL.createObjectURL(new Blob([plain]));
    const a = document.createElement('a');
    a.href = url; a.download = name; a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } catch (e) { alert(e.message); }
}

async function deleteFile(id) {
  if (!window.confirm('确认删除该文件？（不可恢复）')) return;
  try {
    await requireVerify('vault');
    await api(`files/delete/${id}`, { method: 'POST' });
    await refreshFiles();
  } catch (e) { alert(e.message); }
}

$('fileRows').onclick = e => {
  const dl = e.target.closest('[data-dl]');
  const del = e.target.closest('[data-del]');
  if (dl) downloadFile(dl.dataset.dl);
  if (del) deleteFile(del.dataset.del);
};
$('filesMobile').onclick = e => {
  const dl = e.target.closest('[data-dl]');
  const del = e.target.closest('[data-del]');
  if (dl) downloadFile(dl.dataset.dl);
  if (del) deleteFile(del.dataset.del);
};

$('btnUpload').onclick = () => $('fileInput').click();
$('fileInput').onchange = async e => {
  for (const file of e.target.files) {
    try {
      const rawKey = newRawKey();
      const { user } = await api('keyinfo');
      const wrappedKey = await wrapKeyWithPub(user.pub, rawKey);
      const cipher = await fileEncrypt(rawKey, new Uint8Array(await file.arrayBuffer()));
      const meta = { size: cipher.byteLength, name_enc: await encryptText(rawKey, file.name), wrapped_key: wrappedKey };
      const { id, upload_url } = await api('upload/meta', { method: 'POST', body: meta });
      const put = await fetch(upload_url, { method: 'PUT', body: cipher });
      if (!put.ok) throw new Error(`R2 上传失败 HTTP ${put.status}`);
      await api('upload/done', { method: 'POST', body: { id } });
    } catch (err) { alert(`上传 ${file.name} 失败：${err.message}`); }
  }
  e.target.value = '';
  await refreshFiles();
};

// ==================== 管理端：用户密钥 / 神盾笔记 / 协议码 / 配额 / 销毁 ====================
async function buildKeyMaterial(pass) {
  const { privJwk, pubJwk } = await generateMasterKeys();
  const { wrapped, salt } = await wrapPrivateKey(privJwk, pass);
  return { wrapped, salt, pub: pubJwk };
}

$('btnManageUser').onclick = async () => {
  const target = $('adminUserTarget').value;
  const pass = $('adminUserPass').value;
  const pass2 = $('adminUserPass2').value;
  try {
    if (pass.length < 12) throw new Error('密码至少 12 位');
    if (pass !== pass2) throw new Error('两次输入的密码不一致');
    if (!window.confirm(`为 ${target} 生成 / 重置密钥对？该槽位现有会话将失效。`)) return;
    const m = await buildKeyMaterial(pass);
    const r = await api('manage/user', {
      method: 'POST',
      body: {
        target_user: target, wrapped_priv_key: m.wrapped, salt: m.salt, pub_key: m.pub,
        login_hash: await loginHash(pass, 'login', authSalt),
      },
    });
    alert(`${target} 密钥${r.created ? '创建' : '更新'}成功`);
    $('adminUserPass').value = ''; $('adminUserPass2').value = '';
  } catch (e) { alert(e.message); }
};

$('btnEnableNotes').onclick = async () => {
  const target = $('adminNoteTarget').value;
  const pass = $('adminNotePass').value;
  const pass2 = $('adminNotePass2').value;
  try {
    if (pass.length < 12) throw new Error('笔记密码至少 12 位');
    if (pass !== pass2) throw new Error('两次输入的笔记密码不一致');
    const m = await buildKeyMaterial(pass);
    await api('manage/notes', {
      method: 'POST',
      body: {
        target_user: target, enabled: true,
        wrapped_note_key: m.wrapped, salt: m.salt, pub_key: m.pub,
        note_login_hash: await loginHash(pass, 'note', authSalt),
      },
    });
    alert(`${target} 已启用神盾笔记（请使用笔记密码登录笔记页）`);
    $('adminNotePass').value = ''; $('adminNotePass2').value = '';
  } catch (e) { alert(e.message); }
};

$('btnDisableNotes').onclick = async () => {
  const target = $('adminNoteTarget').value;
  if (!window.confirm(`关闭 ${target} 的神盾笔记？笔记将无法再访问（密钥保留，可再次启用）。`)) return;
  try {
    await api('manage/notes', { method: 'POST', body: { target_user: target, enabled: false } });
    alert(`${target} 的神盾笔记已关闭`);
  } catch (e) { alert(e.message); }
};

$('btnUpdateCheckin').onclick = async () => {
  const code = $('adminCheckinCode').value.trim();
  try {
    if (code.length < 8) throw new Error('签到码至少 8 位');
    await api('codes/checkin', { method: 'POST', body: { hash: await loginHash(code, 'checkin', authSalt) } });
    $('adminCheckinCode').value = '';
    alert('签到码已更新');
  } catch (e) { alert(e.message); }
};

$('btnUpdateDuress').onclick = async () => {
  const code = $('adminDuressCode').value.trim();
  try {
    if (code.length < 8) throw new Error('胁迫码至少 8 位');
    await api('codes/duress', { method: 'POST', body: {
      hash: await loginHash(code, 'login', authSalt),
      hash_checkin: await loginHash(code, 'checkin', authSalt),
    } });
    $('adminDuressCode').value = '';
    alert('胁迫码已更新');
  } catch (e) { alert(e.message); }
};

$('btnSaveQuota').onclick = async () => {
  const gb = Number($('quotaGB').value);
  try {
    if (!Number.isFinite(gb) || gb <= 0) throw new Error('请输入有效的配额');
    await api('config/storage', { method: 'POST', body: { vault_quota_bytes: Math.floor(gb * 1024 ** 3) } });
    await refreshFiles();
    alert('存储配额已保存');
  } catch (e) { alert(e.message); }
};

$('btnDestroy').onclick = async () => {
  if (!window.confirm('立即销毁全部密钥与密文？此操作不可恢复。')) return;
  try {
    await requireVerify('vault');
    await api('destroy', { method: 'POST' });
    alert('销毁完成');
    location.reload();
  } catch (e) { alert(e.message); }
};

$('btnLogout').onclick = doLogout;
$('btnResetSystem').onclick = () => showView('view-init');

$('loginPass').addEventListener('keydown', e => { if (e.key === 'Enter') $('btnLogin').click(); });

// ==================== 入口 ====================
boot().catch(showBootError);
