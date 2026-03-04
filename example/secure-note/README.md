# SecureNote — 安全笔记应用

> 示例项目一：演示认证全流程，覆盖本书第一、二部分核心知识点

## 📖 章节对照

| 功能模块 | 对应章节 |
|---------|---------|
| 密码 Argon2 哈希 + AES-GCM 加密存储 | ch02 密码学基础 |
| 自签 CA + mTLS 双向认证 | ch03 PKI 与 X.509, ch06 TLS |
| OAuth2 Authorization Code + PKCE | ch07 OAuth 2.0 |
| OIDC 第三方登录 (Google/GitHub) | ch08 OpenID Connect |
| JWT RS256 签发 / 刷新 / 吊销 | ch09 JWT |
| TOTP 二次验证 (MFA) | ch10 多因素认证 |
| FastAPI Security 集成 | ch25 安全框架 |

## 🏗️ 架构

```
┌─────────────┐     HTTPS/mTLS      ┌──────────────────┐
│   Vue.js 3  │ ◄──────────────────► │   FastAPI        │
│   Frontend  │                      │                  │
└─────────────┘                      │  ┌────────────┐  │
                                     │  │ Auth Module │  │
                                     │  │ - JWT       │  │
                                     │  │ - OAuth2    │  │
                                     │  │ - TOTP      │  │
                                     │  └────────────┘  │
                                     │  ┌────────────┐  │
                                     │  │ Crypto      │  │
                                     │  │ - AES-GCM   │  │
                                     │  │ - Argon2    │  │
                                     │  └────────────┘  │
                                     │  ┌────────────┐  │
                                     │  │ SQLite DB   │  │
                                     │  └────────────┘  │
                                     └──────────────────┘
```

## 🚀 快速开始

### 前置条件

- Python 3.11+
- Node.js 18+
- OpenSSL (用于生成证书)

### 1. 生成 mTLS 证书

```bash
cd backend/certs
./generate_certs.sh
```

### 2. 启动后端

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --ssl-keyfile certs/server.key --ssl-certfile certs/server.crt
```

### 3. 启动前端

```bash
cd frontend
npm install
npm run dev
```

### 4. Docker Compose (推荐)

```bash
docker-compose up -d
```

## 🧪 运行测试

```bash
cd backend
pytest tests/ -v --cov=. --cov-report=term-missing
```

## 📁 项目结构

```
secure-note/
├── backend/
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── jwt_handler.py      # JWT RS256 签发/验证/刷新
│   │   ├── oauth2.py           # OAuth2 Authorization Code + PKCE
│   │   ├── oidc.py             # OIDC 第三方登录
│   │   ├── password.py         # Argon2 密码哈希
│   │   ├── totp.py             # TOTP 二次验证
│   │   └── dependencies.py     # FastAPI 依赖注入
│   ├── crypto/
│   │   ├── __init__.py
│   │   └── encryption.py       # AES-256-GCM 笔记加密
│   ├── models/
│   │   ├── __init__.py
│   │   ├── database.py         # SQLite + SQLAlchemy
│   │   ├── user.py             # 用户模型
│   │   └── note.py             # 笔记模型
│   ├── certs/
│   │   └── generate_certs.sh   # CA + 服务端/客户端证书生成
│   ├── tests/
│   │   ├── conftest.py
│   │   ├── test_password.py
│   │   ├── test_jwt.py
│   │   ├── test_totp.py
│   │   ├── test_encryption.py
│   │   ├── test_auth_api.py
│   │   └── test_notes_api.py
│   ├── main.py
│   ├── config.py
│   └── requirements.txt
├── frontend/                   # Vue.js 3 SPA
├── docker-compose.yml
├── docs/
│   └── architecture.md         # 详细架构文档
└── README.md
```

## 🔑 安全特性详解

### 1. 密码存储 (ch02)
- 使用 Argon2id（内存硬函数），抵抗 GPU/ASIC 暴力破解
- 自动 salt，参数可配置 (time_cost, memory_cost, parallelism)

### 2. mTLS 双向认证 (ch03, ch06)
- 自签 Root CA → Server Cert + Client Cert
- 服务端验证客户端证书，客户端验证服务端证书
- 证书链：Root CA → Intermediate CA → End Entity

### 3. OAuth2 + OIDC (ch07, ch08)
- Authorization Code Flow + PKCE（防 CSRF + 防授权码拦截）
- 支持 Google / GitHub 作为 Identity Provider
- state + nonce 双重防护

### 4. JWT 令牌 (ch09)
- RS256 非对称签名（私钥签发，公钥验证）
- Access Token (15min) + Refresh Token (7d)
- Token 黑名单（吊销机制）

### 5. MFA / TOTP (ch10)
- RFC 6238 TOTP 实现
- QR Code 生成，兼容 Google Authenticator / Authy
- 恢复码 (Recovery Codes) 备份

### 6. 笔记加密存储 (ch02)
- AES-256-GCM 认证加密
- 每条笔记独立 IV/Nonce
- 用户主密钥派生 (HKDF)
