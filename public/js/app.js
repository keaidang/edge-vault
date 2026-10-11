// Edge Vault — 保险库前端逻辑
import { loginHash, generateMasterKeys, wrapPrivateKey, unwrapPrivateKey, wrapKeyWithPub, unwrapKeyWithPriv, fileEncrypt, fileDecrypt, b64, newRawKey } from './crypto.js';

const $ = id => document.getElementById(id);
const show = (id, on = true) => $(id).classList.toggle('hidden', !on);
let privKey = null;   // 解包后的 RSA 私钥（仅内存）
let idleTimer = null;

// ---- 60s 空闲登出 + 每 5 分钟自动签到 ----
function resetIdle() {
  clearTimeout(idleTimer);
  if (privKey) idleTimer = setTimeout(logout, 60000);
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
  let st;
  try { st = await api('state'); } catch { return; }
  const overdue = st.initialized && !st.destroyed && st.last_checkin > 0 &&
    (Date.now() / 1000 - st.last_checkin > st.checkin_timeout_hours * 3600);

  if (st.destroyed) return show('view-destroyed');
  if (!st.initialized) { show('view-init'); return; }
  if (overdue) { show('view-overdue'); return; }
  // 已初始化未登录 → 登录页；已登录（有 cookie）→ 尝试进主界面
  try { await api('keyinfo'); await enterVault(); }
  catch { show('view-login'); }
}

async function enterVault() {
  privKey = null;
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
  const { files } = await api('files');
  const tbody = $('fileList');
  tbody.innerHTML = '';
  if (!files.length) { tbody.innerHTML = '<tr><td colspan="4" class="hint">暂无文件</td></tr>'; return; }
  for (const f of files) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="fname" data-id="${f.id}">🔒 加密文件</td><td>${fmtSize(f.size)}</td><td>${new Date(f.created * 1000).toLocaleString()}</td>
      <td><button class="ghost" data-dl="${f.id}">下载</button> <button class="ghost danger" data-del="${f.id}">删除</button></td>`;
    tbody.appendChild(tr);
  }
  tbody.onclick = async e => {
    const dl = e.target.dataset.dl, del = e.target.dataset.del;
    try {
      if (dl) return await downloadFile(dl);
      if (del) {
        if (!confirm('删除该文件？')) return;
        await api(`files/delete/${dl || del}`, { method: 'POST' });
        await refreshFiles();
      }
    } catch (err2) { alert(err2.message); }
  };
}

async function downloadFile(id) {
  const { url, wrapped_key: wrappedKey, name_enc: nameEnc } = await api(`download/${id}`);
  const ct = new Uint8Array(await (await fetch(url)).arrayBuffer());
  const rawKey = await unwrapKeyWithPriv(privKey, wrappedKey);
  const plain = await fileDecrypt(rawKey, ct);
  const name = JSON.parse(new TextDecoder().decode(b64.dec(nameEnc)));
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
    await api('login', { method: 'POST', body: JSON.stringify({ hash }) });
    const info = await api('keyinfo');
    try {
      privKey = await unwrapPrivateKey(info.wrapped, pass);
      // 会话级暂存解包后的私钥（供笔记页使用，登出/关标签即清）
      sessionStorage.setItem('ev_priv', JSON.stringify(await crypto.subtle.exportKey('jwk', privKey)));
    } catch { /* 胁迫口令或错误口令：表现为空库 */ }
    show('view-login', false);
    await enterVault();
    if (!privKey) $('fileList').innerHTML = '<tr><td colspan="4" class="hint">⚠️ 无法解包密钥（胁迫口令或口令已变更）</td></tr>';
  } catch (e) {
    $('loginHint').textContent = e.message;
    if (String(e.message).includes('销毁')) { show('view-login', false); show('view-destroyed'); }
  }
};

// ---- 上传 ----
$('btnUpload').onclick = () => $('fileInput').click();
$('fileInput').onchange = async e => {
  for (const file of e.target.files) {
    try {
      const rawKey = newRawKey();
      const wrappedKey = await wrapKeyWithPub((await api('keyinfo')).pub, rawKey);
      const plain = new Uint8Array(await file.arrayBuffer());
      const cipher = await fileEncrypt(rawKey, plain);
      const { id, upload_url: uploadUrl } = await api('upload/meta', { method: 'POST', body: JSON.stringify({
        size: cipher.byteLength,
        name_enc: b64.enc(new TextEncoder().encode(JSON.stringify(file.name))),
        wrapped_key: wrappedKey,
      }) });
      const put = await fetch(uploadUrl, { method: 'PUT', body: cipher });
      if (!put.ok) throw new Error(`R2 上传失败 HTTP ${put.status}`);
      await api('upload/done', { method: 'POST', body: JSON.stringify({ id }) });
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
    await api('login', { method: 'POST', body: JSON.stringify({ hash: await loginHash($('loginPass')?.value || prompt('输入主口令') || '', 'checkin') }) });
    location.reload();
  } catch (e) { alert(e.message); }
};
async function logout() {
  try { await api('logout', { method: 'POST' }); } catch {}
  privKey = null; clearTimeout(idleTimer); clearInterval(checkinTimer);
  sessionStorage.removeItem('ev_priv');
  location.reload();
}
$('btnLogout').onclick = logout;

boot();
