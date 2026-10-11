# Edge Vault

边缘原生加密保险库与安全笔记 —— 基于腾讯 EdgeOne Makers 部署，明文永不出浏览器。

## 特性

- 🔐 **客户端加密**：AES-256-GCM 分块加密 + RSA-OAEP 密钥封装，口令派生与密钥生成全部在浏览器完成，边缘函数只见密文
- ☁️ **Cloudflare R2 存储**：S3 兼容接口，预签名 URL 直传直下，零下行流量费
- 🗂️ **边缘状态存储**：EdgeOne KV 承载系统状态/会话/密钥元数据/审计日志，Blob 存储笔记密文与附件
- ⏱️ **签到自毁**：定时任务每 5 分钟扫描签到超时，先删密钥后删密文，配合前端本地兜底，双重保险
- 🔗 **审计日志**：链式哈希防篡改，每日自动归档
- 🥷 **胁迫防护**：胁迫码触发静默销毁，60 秒空闲自动登出

## 架构

```
浏览器（加密/解密）→ EdgeOne 边缘函数（鉴权/签名/调度）→ R2（文件密文）+ KV/Blob（状态与笔记）
```

## 项目结构

```
edge-vault/
├── public/              # 静态页面（index / notes / logs + 本地 CSS/JS）
├── functions/           # 边缘函数（/api/* 路由，JS）
├── docs/                # 方案与设计文档
└── edgeone.json         # Makers 项目配置（schedules 定时任务等）
```

## 相关项目

前身：[aegis-vault](https://github.com/keaidang/aegis-vault)（Python/FastAPI 本地版）

## 文档

- [方案确认 v2.0](docs/方案确认-v2.md) —— 部署架构、密码学适配、存储分工、自毁机制设计

## License

Apache-2.0
