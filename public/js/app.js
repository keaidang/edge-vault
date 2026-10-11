// Edge Vault — 保险库前端（原版 Aegis Vault 风格）
import { loginHash, generateMasterKeys, wrapPrivateKey, unwrapPrivateKey, wrapKeyWithPub, unwrapKeyWithPriv, fileEncrypt, fileDecrypt, deriveFileKey, b64, newRawKey } from './crypto.js';

const $ = id => document.getElementById(id);
const show = (id, on = true) => $(id).classList.toggle('hidden', !on);
let privKey = null;        // 真实模式：RSA 私钥（仅内存）
let decoyMode = false;
let decoyPass = null;

// ---- 状态胶囊 / 视图切换 ----
function pill(name) {
  for (const id of ['status-pill', 'status-pill-running', 'status-pill-destroyed']) show(id, false);
  if (name) show(name, true);
}
function setAuthChrome(on) {
  document.body.classList.toggle('auth-body', on);
  document.querySelector('main').classList.toggle('auth-shell', on);
  show('idle-countdown', on);
  show('user-pill', on);
}

// ---- 60s 空闲登出（原版协议：倒计时胶囊 + F5/刷新即登出）----
let idleRemaining = 60;
let idleSubmitting = false;
function renderIdle(v) {
  const el = $('idle-countdown');
  if (!el) return;
  el.textContent = `${String(Math.max(0, v)).padStart(2, '0')}s`;
  el.classList.toggle('is-warning', v <= 10);
}
function submitIdleLogout() {
  if (idleSubmitting || (!privKey && !decoyMode)) return;
  idleSubmitting = true;
  doLogout();
}
function resetIdle() {
  if (idleSubmitting) return;
  idleRemaining = 60;
  renderIdle(idleRemaining);
}
setInterval(() => {
  if (!privKey && !decoyMode) return;
  idleRemaining -= 1;
  renderIdle(idleRemaining);
  if (idleRemaining <= 0) { submitIdleLogout(); }
}, 1000);
['pointerdown', 'pointermove', 'keydown', 'scroll', 'touchstart', 'click'].forEach(e => window.addEventListener(e, resetIdle, { passive: true }));
window.addEventListener('keydown', e => {
  const k = String(e.key || '').toLowerCase();
  if (k === 'f5' || (k === 'r' && (e.ctrlKey || e.metaKey))) {
    if (privKey || decoyMode) { e.preventDefault(); submitIdleLogout(); }
  }
});

async function api(path, opts = {}) {
  const res = await fetch(`/api/${path}`, { headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', ...opts });
  const data = await res.json();
  if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

// ---- 自毁倒计时（Dead Man's Switch）----
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
  const deadline = lastCheckin + timeoutH * 3600;
  renderCountdown(deadline - nowSec());
  countdownTimer = setInterval(() => {
    const remain = deadline - nowSec();
    renderCountdown(remain);
    if (remain <= 0) clearInterval(countdownTimer);
  }, 1000);
}
const nowSec = () => Math.floor(Date.now() / 1000);

// ---- 视图切换 ----
function showView(name) {
  for (const v of ['view-init', 'view-destroyed', 'view-login', 'view-vault']) show(v, false);
  show(name, true);
  const authed = name === 'view-vault';
  setAuthChrome(authed);
}

// ---- 启动 ----
async function boot() {
  const st = await api('state');
  if (st.destroyed) {
    pill('status-pill-destroyed');
    showView('view-destroyed');
    return;
  }
  if (!st.initialized) {
    pill('status-pill');
    showView('view-init');
    return;
  }
  pill('status-pill-running');
  startCountdown(st.last_checkin, st.checkin_timeout_hours);
  showView('view-login');
  // 已有会话（刷新/回访）→ 直接进保险库
  try {
    const info = await api('keyinfo');
    if (info.decoy) {
      decoyMode = true;
      decoyPass = sessionStorage.getItem('ev_decoy');
    } else {
      const pass = sessionStorage.getItem('ev_pass');
      if (pass) privKey = await unwrapPrivateKey(info.wrapped, pass).catch(() => null);
      if (privKey) sessionStorage.setItem('ev_priv', JSON.stringify(await crypto.subtle.exportKey('jwk', privKey)));
    }
    await enterVault(st);
  } catch { /* 停留在登录视图 */ }
}

async function enterVault(st) {
  showView('view-vault');
  if (st) startCountdown(st.last_checkin, st.checkin_timeout_hours);
  await refreshFiles();
  resetIdle();
}

async function refreshFiles() {
  const st = await api('state');
  $('vaultSize').textContent = `${fmtSize(st.usage.used_bytes)} / ${fmtSize(st.quota.vault_quota_bytes)}`;
  $('quotaGB').value = (st.quota.vault_quota_bytes / 1073741824).toFixed(2);
  const { files, decoy } = await api('files');
  const rows = $('fileRows');
  const mobile = $('filesMobile');
  rows.innerHTML = '';
  mobile.innerHTML = '';
  const none = !files.length;
  show('filesEmpty', none);
  show('filesTable', !none);
  show('filesMobile', !none);
  if (none) return;

  for (const f of files) {
    let name = f.name || '加密文件';
    if (!decoy && f.name_enc && privKey) {
      try { name = JSON.parse(new TextDecoder().decode(b64.dec(f.name_enc))); } catch {}
    }
    // 桌面表格行
    const tr = document.createElement('tr');
    tr.className = 'border-b border-cyan-900/30 align-middle';
    tr.innerHTML = `
      <td class="file-name-cell py-4 pr-4 text-cyan-100/85"><span class="file-name-text" title="${name}">${name}</span></td>
      <td class="py-4 text-right">
        <div class="inline-actions justify-end">
          <button type="button" data-dl="${f.id}" class="btn-neon px-4 py-2">解密下载</button>
          <button type="button" data-del="${f.id}" class="btn-danger px-4 py-2">删除</button>
        </div>
      </td>`;
    rows.appendChild(tr);
    // 移动端卡片
    const card = document.createElement('article');
    card.className = 'file-card';
    card.innerHTML = `
      <div class="space-y-3">
        <div>
          <p class="section-title">Encrypted File</p>
          <div class="mt-2 text-sm font-medium text-cyan-100"><span class="file-name-text" title="${name}">${name}</span></div>
        </div>
        <div class="flex gap-2">
          <button type="button" data-dl="${f.id}" class="btn-neon flex-1">解密下载</button>
          <button type="button" data-del="${f.id}" class="btn-danger flex-1">删除</button>
        </div>
      </div>`;
    mobile.appendChild(card);
  }

  const handler = async e => {
    const dl = e.target.closest('[data-dl]')?.dataset.dl;
    const del = e.target.closest('[data-del]')?.dataset.del;
    try {
      if (dl) return await downloadFile(dl);
      if (del) {
        if (!window.confirm('确认删除当前文件？')) return;
        await api(`files/delete/${del}`, { method: 'POST' });
        await refreshFiles();
      }
    } catch (err2) { alert(err2.message); }
  };
  rows.onclick = handler;
  mobile.onclick = handler;
}

async function downloadFile(id) {
  const d = await api(`download/${id}`);
  const ct = new Uint8Array(await (await fetch(d.url)).arrayBuffer());
  let plain, name;
  if (decoyMode) {
    plain = await fileDecrypt(await deriveFileKey(decoyPass, id), ct);
    name = d.name;
  } else {
    plain = await fileDecrypt(await unwrapKeyWithPriv(privKey, d.wrapped_key), ct);
    name = JSON.parse(new TextDecoder().decode(b64.dec(d.name_enc)));
  }
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([plain]));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ---- 初始化 ----
$('btnInit').onclick = async () => {
  const pass = $('initPass').value, pass2 = $('initPass2').value;
  const log = $('initProgress');
  try {
    if (pass.length < 10) throw new Error('管理员总密码至少 10 位');
    if (pass !== pass2) throw new Error('两次密码不一致');
    const checkinCode = $('initCheckin').value;
    if (checkinCode.length < 6) throw new Error('签到确认码至少 6 位');
    const duress = $('initDuress').value;
    const timeoutH = Number($('initTimeout').value) || 72;
    log.classList.remove('hidden');
    log.textContent = '[1/4] 生成 RSA-3072 密钥对…';
    const { privJwk, pubJwk } = await generateMasterKeys();
    log.textContent += '\n[2/4] 口令派生并包裹私钥…';
    const { wrapped, salt } = await wrapPrivateKey(privJwk, pass);
    log.textContent += '\n[3/4] 计算登录/签到/胁迫哈希…';
    const login_hash = await loginHash(pass, 'login');
    const checkin_hash = await loginHash(checkinCode, 'checkin');
    const duress_hash = await loginHash(duress || pass, 'duress');
    log.textContent += '\n[4/4] 写入服务端…';
    await api('init', { method: 'POST', body: JSON.stringify({
      wrapped_priv_key: wrapped, salt, pub_key: pubJwk,
      login_hash, checkin_hash, duress_hash, checkin_timeout_hours: timeoutH,
    }) });
    log.textContent += '\n✅ 初始化完成。';
    pill('status-pill-running');
    startCountdown(nowSec(), timeoutH);
    showView('view-login');
  } catch (e) { log.classList.remove('hidden'); log.textContent += `\n❌ ${e.message}`; }
};

// ---- 登录 ----
$('btnLogin').onclick = async () => {
  const pass = $('loginPass').value;
  try {
    const r = await api('login', { method: 'POST', body: JSON.stringify({ hash: await loginHash(pass, 'login') }) });
    if (r.mode === 'decoy') {
      decoyMode = true;
      decoyPass = pass;
      sessionStorage.setItem('ev_decoy', pass);
    } else {
      const info = await api('keyinfo');
      try {
        privKey = await unwrapPrivateKey(info.wrapped, pass);
        sessionStorage.setItem('ev_priv', JSON.stringify(await crypto.subtle.exportKey('jwk', privKey)));
        sessionStorage.setItem('ev_pass', pass);
      } catch { /* 表现为空库 */ }
    }
    pill('status-pill-running');
    showView('view-vault');
    await enterVault();
    if (!privKey && !decoyMode) $('filesEmpty').classList.remove('hidden');
  } catch (e) { alert(e.message); }
};

// ---- 签到（公开端点，签到码协议）----
$('btnCheckin').onclick = async () => {
  try {
    const r = await api('checkin', { method: 'POST', body: JSON.stringify({ hash: await loginHash($('checkinCode').value, 'checkin') }) });
    startCountdown(r.last_checkin, Number(r.checkin_timeout_hours) || 72);
    pill('status-pill-running');
    alert('计时器已重置。');
  } catch (e) { alert(e.message); }
};

// ---- 上传 ----
$('btnUpload').onclick = () => $('fileInput').click();
$('fileInput').onchange = async e => {
  for (const file of e.target.files) {
    try {
      let cipher, metaBody;
      if (decoyMode) {
        const cid = crypto.randomUUID().replace(/-/g, '').slice(0, 32);
        const fileKey = await deriveFileKey(decoyPass, cid);
        cipher = await fileEncrypt(fileKey, new Uint8Array(await file.arrayBuffer()));
        const { id, upload_url: uploadUrl } = await api('upload/meta', { method: 'POST', body: JSON.stringify({ size: cipher.byteLength, name: file.name, client_id: cid }) });
        const put = await fetch(uploadUrl, { method: 'PUT', body: cipher });
        if (!put.ok) throw new Error(`R2 上传失败 HTTP ${put.status}`);
        await api('upload/done', { method: 'POST', body: JSON.stringify({ id }) });
      } else {
        const rawKey = newRawKey();
        const wrappedKey = await wrapKeyWithPub((await api('keyinfo')).pub, rawKey);
        cipher = await fileEncrypt(rawKey, new Uint8Array(await file.arrayBuffer()));
        metaBody = { size: cipher.byteLength, name_enc: b64.enc(new TextEncoder().encode(JSON.stringify(file.name))), wrapped_key: wrappedKey };
        const { id, upload_url: uploadUrl } = await api('upload/meta', { method: 'POST', body: JSON.stringify(metaBody) });
        const put = await fetch(uploadUrl, { method: 'PUT', body: cipher });
        if (!put.ok) throw new Error(`R2 上传失败 HTTP ${put.status}`);
        await api('upload/done', { method: 'POST', body: JSON.stringify({ id }) });
      }
    } catch (err2) { alert(`上传 ${file.name} 失败：${err2.message}`); }
  }
  e.target.value = '';
  await refreshFiles();
};

// ---- 设置 / 销毁 ----
$('btnSaveQuota').onclick = async () => {
  try {
    await api('config/storage', { method: 'POST', body: JSON.stringify({ vault_quota_bytes: Number($('quotaGB').value) * 1073741824 }) });
    alert('配额已保存');
    await refreshFiles();
  } catch (e) { alert(e.message); }
};
$('btnDestroy').onclick = async () => {
  if (!window.confirm('⚠️ 此操作非常危险，可能导致不可逆的数据丢失！\n将删除全部密钥与密文（R2 + KV），不可恢复。确认？')) return;
  if (!window.confirm('再次确认：真的要销毁全部数据吗？')) return;
  await api('destroy', { method: 'POST' });
  sessionStorage.removeItem('ev_priv');
  sessionStorage.removeItem('ev_pass');
  location.reload();
};
$('btnResetSystem').onclick = async () => {
  // 已销毁后的重置 = 清空状态重新初始化（服务端 init 允许 destroyed 状态重建）
  location.reload();
};
async function doLogout() {
  try { await api('logout', { method: 'POST' }); } catch {}
  privKey = null; decoyMode = false; decoyPass = null;
  sessionStorage.removeItem('ev_priv');
  sessionStorage.removeItem('ev_pass');
  sessionStorage.removeItem('ev_decoy');
  location.reload();
}
$('btnLogout').onclick = doLogout;

boot();
