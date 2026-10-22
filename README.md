# Edge Vault

边缘原生加密保险库与安全笔记 —— 基于腾讯 EdgeOne Makers 部署，明文永不出浏览器。

## 特性

- 🔐 **客户端加密**：AES-256-GCM 分块加密 + RSA-OAEP 密钥封装，口令派生与密钥生成全部在浏览器完成，边缘函数只见密文（文件名、笔记标题与附件名同样加密）
- ☁️ **Cloudflare R2 存储**：S3 兼容接口，预签名 URL 直传直下，零下行流量费
- 🗂️ **边缘状态存储**：EdgeOne KV 承载系统状态/会话/密钥元数据/审计日志/笔记密文与索引；R2 承载文件密文、笔记附件与审计归档
- ⏱️ **签到自毁**：任何访问触发"访问即检"（超时立即销毁）+ 每日 cron 兜底扫描，先删密钥后删密文，配合前端本地兜底，双重保险
- 🔗 **审计日志**：链式哈希防篡改，归档前校验链完整性
- 🥷 **胁迫防护**：胁迫码在登录框或签到框命中即静默全量销毁（先删密钥后清密文），对外只返回与他人完全一致的「身份验证失败」，60 秒空闲自动登出，私钥只留内存

## 平台限制（先说清楚哪些做不到）

完整清单见 [平台限制与降级说明](docs/平台限制与降级说明.md)，要点：

- **笔记正文约 750KB 明文上限**：Edge Functions 请求体 1MB，超限返回 413，大内容走附件
- **定时自毁降级为「访问即检 + 每日 cron 兜底」**：免费套餐 cron 最低 1 天/次，完全无人访问时最长 24h 才清理
- **KV 最终一致（边缘缓存最长 60s）**：会话撤销、限流不是瞬时的；不可恢复性由「先删密钥」保证
- **无法做安全擦除 / mlock**：只有客户端加密与删除对象，平台侧备份不在控制范围
- **服务端无法校验口令强度**：明文不出浏览器，强度校验只能在前端
- **没有服务端强校验 / 无锁并发**：签到码、胁迫码同样只在前端校验长度；KV 无事务，两个标签页并发保存同一笔记可能丢一次修改
- **必须使用现代浏览器**：密钥派生与加解密依赖 WebCrypto，禁用 JS 或旧浏览器完全不可用
- **单文件 64MB 上限**（与原版一致），不支持分片续传
- **必须手工配置 R2 CORS**：预签名直传直下由浏览器发起，桶策略无法由代码下发
- 初始化后**不要更换 `SESSION_SECRET`**：状态 HMAC 校验失败会被判定为篡改并触发自毁

## 架构

```
浏览器（加密/解密）→ EdgeOne 边缘函数（鉴权/签名/调度）→ R2（文件密文）+ KV（状态/笔记/审计）
```

## 项目结构

```
edge-vault/
├── public/              # 静态页面（index / notes / logs + 本地 CSS/JS + 自托管字体）
├── edge-functions/      # 边缘函数（/api/* catch-all 路由 + R2 SigV4 + 工具库）
├── docs/                # 方案文档 + 部署配置指南
├── tools/               # 本地脚本（R2 连通性、接口/加密回归、Tailwind 源文件）
├── tailwind.config.js   # Tailwind 扫描配置（内容源：public/**/*.html + public/js/**/*.js）
├── package.json         # 仅本地构建用（devDependency: tailwindcss）
└── edgeone.json         # Makers 项目配置（headers 安全头 + schedules 定时任务）
```

> 页面不加载任何第三方资源：Tailwind 已预编译成 `public/css/tailwind.css`（约 10KB），Orbitron 字体自托管在 `public/fonts/`。
> 首屏请求只有 7 个、全部同源（HTML/CSS×2/JS×2/字体/`/api/state`）。

## 本地开发

```bash
npm install            # 只装 tailwindcss
npm run build:css      # 改了 HTML/JS 里的 class 后重新生成 public/css/tailwind.css
npm run watch:css      # 开发时监听
```

## 本地回归

```bash
node tools/api-smoke-test.mjs   # 模拟 EdgeOne KV/R2 跑边缘函数全部端点，无需真实凭据（45 项）
node tools/crypto-test.mjs      # 浏览器加密库回归（哈希/密钥包裹/文件名加密/分块加解密，10 项）
node tools/r2-test.mjs          # R2 连通性 + DeleteObjects 批量删除（需要根目录 .env）
```

浏览器端 E2E（初始化 → 登录 → 上传/下载 → 笔记/附件 → 配额 → 销毁 → 胁迫码）需要本地桩服务器与 `playwright-core`，用例覆盖 31 + 9 项，详见 [平台限制与降级说明](docs/平台限制与降级说明.md) §4。

## 相关项目

前身：[aegis-vault](https://github.com/keaidang/aegis-vault)（Python/FastAPI 本地版）

## 文档

- [方案确认 v2.0](docs/方案确认-v2.md) —— 部署架构、密码学适配、存储分工、自毁机制设计
- [部署配置指南](docs/部署配置指南.md) —— 控制台配置、环境变量、定时任务、验证清单
- [平台限制与降级说明](docs/平台限制与降级说明.md) —— 哪些能力在边缘平台上做不到、如何补偿

## License

Apache-2.0
