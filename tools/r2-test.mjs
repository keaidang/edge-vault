// Edge Vault — R2 (S3 兼容) 连通性测试
// 用法: node tools/r2-test.mjs
// 凭据从 .env 读取（.env 已被 .gitignore 排除，严禁提交）
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const env = Object.fromEntries(
  readFileSync(join(root, '.env'), 'utf8')
    .split(/\r?\n/).filter(l => l.includes('='))
    .map(l => [l.slice(0, l.indexOf('=')).trim(), l.slice(l.indexOf('=') + 1).trim()])
);

const ACCOUNT = env.R2_ACCOUNT_ID;
const ACCESS_KEY = env.R2_ACCESS_KEY_ID;
const SECRET_KEY = env.R2_SECRET_ACCESS_KEY;
const BUCKET = env.R2_BUCKET;
const HOST = `${ACCOUNT}.r2.cloudflarestorage.com`;
const REGION = 'auto';
const SERVICE = 's3';

const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
const sha256hex = d => crypto.createHash('sha256').update(d).digest('hex');

function sigv4Headers(method, path, body = '', extraHeaders = {}) {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256hex(body);

  const headers = {
    host: HOST,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': amzDate,
    ...extraHeaders,
  };
  const sortedHeaders = Object.keys(headers).sort()
    .map(h => `${h}:${String(headers[h]).trim()}`);
  const signedHeaderList = Object.keys(headers).sort().join(';');

  const canonicalRequest = [
    method, path, '',
    sortedHeaders.join('\n') + '\n',
    signedHeaderList, payloadHash,
  ].join('\n');

  const scope = `${dateStamp}/${REGION}/${SERVICE}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonicalRequest),
  ].join('\n');

  const kDate = hmac(`AWS4${SECRET_KEY}`, dateStamp);
  const kRegion = hmac(kDate, REGION);
  const kService = hmac(kRegion, SERVICE);
  const kSigning = hmac(kService, 'aws4_request');
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');

  return {
    ...headers,
    Authorization: `AWS4-HMAC-SHA256 Credential=${ACCESS_KEY}/${scope}, SignedHeaders=${signedHeaderList}, Signature=${signature}`,
  };
}

async function call(method, path, body = '', extraHeaders = {}) {
  const headers = sigv4Headers(method, path, body, extraHeaders);
  const res = await fetch(`https://${HOST}${path}`, { method, headers, body: body || undefined });
  return res;
}

const results = [];
const t = (name, ok, detail) => {
  results.push({ name, ok, detail });
  console.log(`${ok ? '✅' : '❌'} ${name}  ${detail}`);
};

// 1. ListBuckets（验证凭据有效性）
{
  const res = await call('GET', '/');
  const text = await res.text();
  const names = [...text.matchAll(/<Name>([^<]+)<\/Name>/g)].map(m => m[1]);
  t('ListBuckets（凭据验证）', res.ok, `HTTP ${res.status}，桶列表: ${names.join(', ') || '(无)'}`);
}

// 2. PutObject 写入测试密文
const testKey = `__edge_vault_test/connectivity-${Date.now()}.aes`;
const testBody = crypto.randomBytes(64); // 模拟 AES-GCM 密文
{
  const res = await call('PUT', `/${BUCKET}/${testKey}`, testBody);
  t('PutObject（写入密文）', res.ok, `HTTP ${res.status} ${res.ok ? '' : await res.text()}`);
}

// 3. GetObject 读回校验
{
  const res = await call('GET', `/${BUCKET}/${testKey}`);
  const buf = Buffer.from(await res.arrayBuffer());
  const match = res.ok && buf.equals(testBody);
  t('GetObject（读回比对）', match, `HTTP ${res.status}，${match ? `内容一致（${buf.length}B）` : '内容不一致!'}`);
}

// 4. HeadObject 元数据
{
  const res = await call('HEAD', `/${BUCKET}/${testKey}`);
  t('HeadObject（元数据）', res.ok, `HTTP ${res.status}，Content-Length: ${res.headers.get('content-length')}`);
}

// 5. DeleteObject 删除（自毁链路依赖）
{
  const res = await call('DELETE', `/${BUCKET}/${testKey}`);
  t('DeleteObject（删除）', res.ok, `HTTP ${res.status}`);
}

// 6. 复查删除结果（应为 404）
{
  const res = await call('HEAD', `/${BUCKET}/${testKey}`);
  t('复查删除（应 404）', res.status === 404, `HTTP ${res.status}`);
}

// 7. 预签名 GET URL 生成验证（模拟下载链路）
{
  const path = `/${BUCKET}/${testKey}`;
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/${REGION}/${SERVICE}/aws4_request`;
  const qp = new URLSearchParams({
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${ACCESS_KEY}/${scope}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': '3600',
    'X-Amz-SignedHeaders': 'host',
  });
  const canonicalRequest = ['GET', path, qp.toString(), `host:${HOST}\n`, 'host', 'UNSIGNED-PAYLOAD'].join('\n');
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonicalRequest)].join('\n');
  const kDate = hmac(`AWS4${SECRET_KEY}`, dateStamp);
  const kSigning = hmac(hmac(hmac(kDate, REGION), SERVICE), 'aws4_request');
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');
  qp.set('X-Amz-Signature', signature);
  const url = `https://${HOST}${path}?${qp}`;
  const res = await fetch(url);
  t('预签名 GET URL（应 404，对象已删）', res.status === 404, `HTTP ${res.status}（URL 签名有效，对象不存在符合预期）`);
}

const pass = results.filter(r => r.ok).length;
console.log(`\n结果: ${pass}/${results.length} 通过`);
process.exit(pass === results.length ? 0 : 1);
