// R2 (S3 兼容) SigV4 签名与请求 —— 纯 WebCrypto，边缘函数可用
const enc = new TextEncoder();

const te = s => enc.encode(s);
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

async function hmac(keyBuf, msg) {
  const key = await crypto.subtle.importKey('raw', keyBuf, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return crypto.subtle.sign('HMAC', key, te(msg));
}
async function sha256Hex(data) {
  const buf = typeof data === 'string' ? te(data) : data;
  return hex(await crypto.subtle.digest('SHA-256', buf));
}

async function signingKey(secret, dateStamp) {
  const kDate = await hmac(te(`AWS4${secret}`), dateStamp);
  const kRegion = await hmac(kDate, 'auto');
  const kService = await hmac(kRegion, 's3');
  return hmac(kService, 'aws4_request');
}

function cfg(env) {
  const host = `${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  return { host, bucket: env.R2_BUCKET, accessKey: env.R2_ACCESS_KEY_ID, secret: env.R2_SECRET_ACCESS_KEY };
}

function amzDates() {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  return { amzDate, dateStamp: amzDate.slice(0, 8) };
}

// SigV4 要求查询参数按 key 字典序排序并 URI 编码
function canonicalQuery(params) {
  return Object.keys(params).sort()
    .map(k => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`)
    .join('&');
}

// 服务端签名请求（ListObjectsV2 / DeleteObjects 等）
export async function s3Request(env, method, path, params = {}, body = '') {
  const { host, bucket, accessKey, secret } = cfg(env);
  const { amzDate, dateStamp } = amzDates();
  const fullPath = `/${bucket}${path}`;
  const query = canonicalQuery(params);
  const payloadHash = await sha256Hex(body);
  const headers = {
    host,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': amzDate,
  };
  const hNames = Object.keys(headers).sort();
  const signedHeaders = hNames.join(';');
  const canonical = [method, fullPath, query, hNames.map(h => `${h}:${headers[h]}`).join('\n') + '\n', signedHeaders, payloadHash].join('\n');
  const scope = `${dateStamp}/auto/s3/aws4_request`;
  const sts = ['AWS4-HMAC-SHA256', amzDate, scope, await sha256Hex(canonical)].join('\n');
  const sig = hex(await hmac(await signingKey(secret, dateStamp), sts));
  const auth = `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${sig}`;
  const url = `https://${host}${fullPath}${query ? `?${query}` : ''}`;
  return fetch(url, { method, headers: { ...headers, Authorization: auth }, body: body || undefined });
}

// 预签名 URL（浏览器直传/直下用）
export async function presign(env, method, objectKey, expires = 3600) {
  const { host, bucket, accessKey, secret } = cfg(env);
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
  const sts = ['AWS4-HMAC-SHA256', amzDate, scope, await sha256Hex(canonical)].join('\n');
  const sig = hex(await hmac(await signingKey(secret, dateStamp), sts));
  qp.set('X-Amz-Signature', sig);
  return `https://${host}${fullPath}?${qp}`;
}

// 列出前缀下全部对象（自毁扫描用）
export async function listAllObjects(env, prefix) {
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
export async function deleteObjects(env, keys) {
  let deleted = 0;
  for (let i = 0; i < keys.length; i += 1000) {
    const batch = keys.slice(i, i + 1000);
    const body = `<Delete><Quiet>true</Quiet>${batch.map(k => `<Object><Key>${k}</Key></Object>`).join('')}</Delete>`;
    const res = await s3Request(env, 'POST', '', { delete: '' }, body);
    if (!res.ok) throw new Error(`DeleteObjects failed: ${res.status}`);
    deleted += batch.length;
  }
  return deleted;
}
