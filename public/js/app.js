// Edge Vault — 保险库前端逻辑（真实模式 / 假仓库 decoy 模式）
import { loginHash, generateMasterKeys, wrapPrivateKey, unwrapPrivateKey, wrapKeyWithPub, unwrapKeyWithPriv, fileEncrypt, fileDecrypt, deriveFileKey, b64, newRawKey } from './crypto.js';

const $ = id => document.getElementById(id);
const show = (id, on = true) => $(id).classList.toggle('hidden', !on);
let privKey = null;      // 真实模式：解包后的 RSA 私钥（仅内存）
let decoyMode = false;   // 胁迫模式：进入空仓库
let decoyPass = null;
let idleTimer = null;

// ---- 60s 空闲登出 + 每 5 分钟自动签到 ----
function resetIdle() {
  clearTimeout(idleTimer);
  if (privKey || decoyMode) idleTimer = setTimeout(logout, 60000);
}
['mousemove', 'keydown', 'click', 'touchstart'].forEach(e => document.addEventListener(e, resetIdle));

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

function renderQuota(usage, cfg) {
  const pct = Math.min(100, usage.used_bytes / cfg.vault_quota_bytes * 100);
  for (const [fill, text] of [['quotaFill', 'quotaText'], ['quotaFill2', 'quotaText2']]) {
    const f = $(fill), t = $(text);
    if (!f) continue;
    f.style.width = `${pct}%`;
    t.textContent = `${fmtSize(usage.used_bytes)} / ${fmtSize(cfg.vault_quota_bytes)}（${pct.toFixed(1)}%）`;
  }
  const badge = $('quotaBadge');
  if (badge) badge.textContent = fmtSize(usage.used_bytes);
}

// ---- 启动流程 ----
async function boot() {
  const st = await api('state');
  if (st.destroyed) return show('view-destroyed');
  if (!st.initialized) { show('view-init'); return; }
  if (st.overdue) { show('view-overdue'); return; }
  // 已初始化：尝试用现有会话进入（真会话 → 真仓库；胁迫会话 → 假仓库）
  try {
    const info = await api('keyinfo');
    if (!info.decoy) {
      const pass = sessionStorage.getItem('ev_pass');
      if (pass) {
        privKey = await unwrapPrivateKey(info.wrapped, pass).catch(() => null);
        if (privKey) sessionStorage.setItem('ev_priv', JSON.stringify(await crypto.subtle.exportKey('jwk', privKey)));
      }
    } else {
      decoyMode = true;
      decoyPass = sessionStorage.getItem('ev_decoy');
    }
    await enterVault();
  } catch { show('view-login'); }
}

async function enterVault() {
  show('view-init', false); show('view-login', false); show('view-destroyed', false);
  show('view-settings', false); show('view-overdue', false);
  show('view-vault'); show('nav');
  startCheckinPing();
  await refreshFiles();
  resetIdle();
}

async function refreshFiles() {
  const st = await api('state');
  renderQuota(st.usage, st.quota);
  const { files, decoy } = await api('files');
  const tbody = $('fileList');
  tbody.innerHTML = '';
  if (!files.length) { tbody.innerHTML = '<tr><td colspan="4" class="hint">暂无文件</td></tr>'; return; }
  for (const f of files) {
    const name = decoy ? f.name : '🔒 加密文件';
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${name}</td><td>${fmtSize(f.size)}</td><td>${new Date(f.created * 1000).toLocaleString()}</td>
      <td><button class="ghost" data-dl="${f.id}">下载</button> <button class="ghost danger" data-del="${f.id}">删除</button></td>`;
    tbody.appendChild(tr);
  }
  tbody.onclick = async e => {
    const dl = e.target.dataset.dl, del = e.target.dataset.del;
    try {
      if (dl) return await downloadFile(dl);
      if (del) {
        if (!confirm('删除该文件？')) return;
        await api(`files/delete/${del}`, { method: 'POST' });
        await refreshFiles();
      }
    } catch (err2) { alert(err2.message); }
  };
}

async function downloadFile(id) {
  const d = await api(`download/${id}`);
  const ct = new Uint8Array(await (await fetch(d.url)).arrayBuffer());
  let plain, name;
  if (decoyMode) {
    const fileKey = await deriveFileKey(decoyPass, id);
    plain = await fileDecrypt(fileKey, ct);
    name = d.name;
  } else {
    const rawKey = await unwrapKeyWithPriv(privKey, d.wrapped_key);
    plain = await fileDecrypt(rawKey, ct);
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
    if (pass.length < 8) throw new Error('主口令至少 8 位');
    if (pass !== pass2) throw new Error('两次口令不一致');
    const duress = $('initDuress').value;
    const timeoutH = Number($('initTimeout').value) || 72;
    log.textContent = '[1/4] 生成 RSA-3072 密钥对…';
    const { privJwk, pubJwk } = await generateMasterKeys();
    log.textContent += '\n[2/4] 口令派生并包裹私钥…';
    const { wrapped, salt } = await wrapPrivateKey(privJwk, pass);
    log.textContent += '\n[3/4] 计算签到/胁迫哈希…';
    const checkinHash = await loginHash(pass, 'checkin');
    const duressHash = duress ? await loginHash(duress, 'duress') : await loginHash(pass, 'duress');
    log.textContent += '\n[4/4] 写入服务端…';
    await api('init', { method: 'POST', body: JSON.stringify({
      wrapped_priv_key: wrapped, salt, pub_key: pubJwk,
      checkin_hash: checkinHash, duress_hash: duressHash, checkin_timeout_hours: timeoutH,
    }) });
    log.textContent += '\n✅ 初始化完成，请解锁。';
    show('view-init', false); show('view-login');
  } catch (e) { log.textContent += `\n❌ ${e.message}`; }
};

// ---- 登录 ----
$('btnLogin').onclick = async () => {
  const pass = $('loginPass').value;
  try {
    const hash = await loginHash(pass, 'checkin'); // checkin/duress 用同一输入，服务端判别
    const r = await api('login', { method: 'POST', body: JSON.stringify({ hash }) });
    if (r.mode === 'decoy') {
      // 假仓库：界面完全一致，数据在 decoy/ 隔离空间（真实仓库已在后台销毁）
      decoyMode = true;
      decoyPass = pass;
      sessionStorage.setItem('ev_decoy', pass);
    } else {
      const info = await api('keyinfo');
      try {
        privKey = await unwrapPrivateKey(info.wrapped, pass);
        sessionStorage.setItem('ev_priv', JSON.stringify(await crypto.subtle.exportKey('jwk', privKey)));
      } catch { /* 表现为空库 */ }
    }
    show('view-login', false);
    await enterVault();
    if (!privKey && !decoyMode) $('fileList').innerHTML = '<tr><td colspan="4" class="hint">⚠️ 无法解包密钥（口令已变更）</td></tr>';
  } catch (e) {
    $('loginHint').textContent = e.message;
  }
};

// ---- 上传 ----
$('btnUpload').onclick = () => $('fileInput').click();
$('fileInput').onchange = async e => {
  for (const file of e.target.files) {
    try {
      let cipher, metaBody;
      if (decoyMode) {
        // 客户端自带 id → 按「口令+id」派生密钥加密 → 一次上传成型
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
        const plain = new Uint8Array(await file.arrayBuffer());
        cipher = await fileEncrypt(rawKey, plain);
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

// ---- 签到 ----
async function checkin() {
  try {
    const r = await api('checkin', { method: 'POST' });
    const badge = $('checkinBadge');
    if (badge) badge.textContent = `✅ 已签到 ${new Date(r.last_checkin * 1000).toLocaleTimeString()}`;
  } catch {}
}
let checkinTimer = null;
function startCheckinPing() {
  clearInterval(checkinTimer);
  checkin();
  checkinTimer = setInterval(checkin, 5 * 60 * 1000);
}

// ---- 设置 / 销毁 / 登出 ----
$('btnSettings').onclick = async () => {
  const st = await api('config/storage');
  $('quotaGB').value = (st.vault_quota_bytes / 1073741824).toFixed(2);
  renderQuota(st.usage, st);
  show('view-vault', false); show('view-settings');
};
$('btnBack').onclick = () => { show('view-settings', false); show('view-vault'); };
$('btnSaveQuota').onclick = async () => {
  try {
    await api('config/storage', { method: 'POST', body: JSON.stringify({ vault_quota_bytes: Number($('quotaGB').value) * 1073741824 }) });
    alert('已保存');
    show('view-settings', false); show('view-vault');
    await refreshFiles();
  } catch (e) { alert(e.message); }
};
$('btnDestroy').onclick = async () => {
  if (!confirm('⚠️ 此操作非常危险，可能导致不可逆的数据丢失！\n将删除全部密钥与密文（R2 + KV），不可恢复。确认？')) return;
  if (!confirm('再次确认：真的要销毁全部数据吗？')) return;
  await api('destroy', { method: 'POST' });
  location.reload();
};
$('btnRescue').onclick = async () => {
  try {
    const pass = $('loginPass')?.value || prompt('输入主口令') || '';
    await api('login', { method: 'POST', body: JSON.stringify({ hash: await loginHash(pass, 'checkin') }) });
    location.reload();
  } catch (e) { alert(e.message); }
};
async function logout() {
  try { await api('logout', { method: 'POST' }); } catch {}
  privKey = null; decoyMode = false; decoyPass = null;
  clearTimeout(idleTimer); clearInterval(checkinTimer);
  sessionStorage.removeItem('ev_priv');
  sessionStorage.removeItem('ev_decoy');
  location.reload();
}
$('btnLogout').onclick = logout;

boot();
