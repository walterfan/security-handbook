# SecureNote 架构文档

## 1. 系统概览

SecureNote 是一个安全笔记应用，演示了现代 Web 应用中认证与加密的最佳实践。

```
                    ┌─────────────────────────────────────────────┐
                    │              SecureNote Backend              │
                    │                                             │
  ┌──────────┐      │  ┌─────────┐  ┌──────────┐  ┌───────────┐  │
  │ Vue.js   │ HTTPS│  │ FastAPI │  │ Auth     │  │ Crypto    │  │
  │ Frontend │◄────►│  │ Router  │─►│ Module   │  │ Module    │  │
  └──────────┘      │  └────┬────┘  │          │  │           │  │
                    │       │       │ • JWT    │  │ • AES-GCM │  │
                    │       │       │ • OAuth2 │  │ • HKDF    │  │
                    │       │       │ • TOTP   │  │ • Argon2  │  │
                    │       │       │ • Argon2 │  │           │  │
                    │       │       └──────────┘  └───────────┘  │
                    │       │                                     │
                    │  ┌────▼────┐                                │
                    │  │ SQLite  │                                │
                    │  │ (加密存储)│                                │
                    │  └─────────┘                                │
                    └─────────────────────────────────────────────┘
```

## 2. 认证流程

### 2.1 密码登录 + JWT (ch02, ch09)

```
Client                          Server                         Database
  │                               │                               │
  │  POST /auth/register          │                               │
  │  {username, email, password}  │                               │
  │──────────────────────────────►│                               │
  │                               │  Argon2id(password) → hash    │
  │                               │──────────────────────────────►│
  │                               │  Store user + hash            │
  │  201 Created                  │◄──────────────────────────────│
  │◄──────────────────────────────│                               │
  │                               │                               │
  │  POST /auth/login             │                               │
  │  {username, password}         │                               │
  │──────────────────────────────►│                               │
  │                               │  Lookup user                  │
  │                               │──────────────────────────────►│
  │                               │  Argon2id.verify(password)    │
  │                               │                               │
  │  {access_token, refresh_token}│  Sign JWT with RS256          │
  │◄──────────────────────────────│  (private key)                │
  │                               │                               │
  │  GET /notes                   │                               │
  │  Authorization: Bearer <AT>   │                               │
  │──────────────────────────────►│                               │
  │                               │  Verify JWT (public key)      │
  │                               │  Check blacklist              │
  │  200 OK [notes]               │  Decrypt notes                │
  │◄──────────────────────────────│                               │
```

### 2.2 OAuth2 + PKCE (ch07, ch08)

```
Client              Server              Identity Provider
  │                   │                       │
  │ GET /auth/oauth/  │                       │
  │   google/authorize│                       │
  │──────────────────►│                       │
  │                   │ Generate:             │
  │                   │  • state (CSRF)       │
  │                   │  • code_verifier      │
  │                   │  • code_challenge     │
  │                   │    = SHA256(verifier)  │
  │ 302 Redirect      │                       │
  │◄──────────────────│                       │
  │                   │                       │
  │ Redirect to Google with code_challenge    │
  │──────────────────────────────────────────►│
  │                   │                       │
  │ User authenticates & consents             │
  │◄──────────────────────────────────────────│
  │                   │                       │
  │ GET /auth/callback│                       │
  │ ?code=xxx&state=yyy                       │
  │──────────────────►│                       │
  │                   │ Verify state          │
  │                   │ POST token endpoint   │
  │                   │ + code_verifier       │
  │                   │──────────────────────►│
  │                   │ Verify:               │
  │                   │ SHA256(verifier)==     │
  │                   │   code_challenge      │
  │                   │◄──────────────────────│
  │                   │ {access_token,        │
  │                   │  id_token}            │
  │                   │                       │
  │ {our JWT tokens}  │ Fetch userinfo        │
  │◄──────────────────│ Create/link user      │
```

### 2.3 MFA / TOTP (ch10)

```
── Setup Phase ──

Client                          Server
  │  POST /auth/mfa/setup        │
  │──────────────────────────────►│
  │                               │  Generate TOTP secret
  │                               │  Generate QR code
  │                               │  Generate recovery codes
  │  {secret, qr_code,           │
  │   recovery_codes}            │
  │◄──────────────────────────────│
  │                               │
  │  User scans QR with app      │
  │                               │
  │  POST /auth/mfa/enable       │
  │  {code: "123456"}            │
  │──────────────────────────────►│
  │                               │  Verify TOTP code
  │  {message: "MFA enabled"}    │  Enable MFA flag
  │◄──────────────────────────────│

── Login Phase (with MFA) ──

Client                          Server
  │  POST /auth/login             │
  │  {username, password}         │
  │──────────────────────────────►│
  │                               │  Password OK, MFA enabled
  │  {access_token (limited),    │
  │   mfa_required: true}        │
  │◄──────────────────────────────│
  │                               │
  │  POST /auth/mfa/verify       │
  │  {code: "654321"}            │
  │  Authorization: Bearer <limited_token>
  │──────────────────────────────►│
  │                               │  Verify TOTP code
  │  {access_token (full),       │  Issue full token pair
  │   refresh_token}             │  with mfa_verified=true
  │◄──────────────────────────────│
```

## 3. 加密架构 (ch02)

### 3.1 密钥层次

```
┌──────────────────────────────────────────┐
│           Master Key (256-bit)           │
│  来源: 环境变量 / KMS / Vault            │
└──────────────┬───────────────────────────┘
               │ HKDF (SHA-256)
               │ info = "securenote:user:{user_id}"
               ▼
┌──────────────────────────────────────────┐
│        Per-User Key (256-bit)            │
│  每个用户派生独立密钥                      │
└──────────────┬───────────────────────────┘
               │ AES-256-GCM
               │ nonce = random 96-bit (per note)
               ▼
┌──────────────────────────────────────────┐
│        Encrypted Note Content            │
│  ciphertext + auth_tag (128-bit)         │
└──────────────────────────────────────────┘
```

### 3.2 为什么选择 AES-GCM

| 特性 | AES-GCM | AES-CBC + HMAC | ChaCha20-Poly1305 |
|------|---------|----------------|-------------------|
| 认证加密 | ✅ 内置 | ❌ 需手动组合 | ✅ 内置 |
| 硬件加速 | ✅ AES-NI | ✅ AES-NI | ❌ 软件实现 |
| Nonce 重用风险 | ⚠️ 灾难性 | ⚠️ IV 重用泄露 | ⚠️ 灾难性 |
| 适用场景 | 服务端加密 | 遗留系统 | 移动端/无 AES-NI |

## 4. 数据模型

```
┌─────────────────────┐       ┌─────────────────────┐
│       users          │       │       notes          │
├─────────────────────┤       ├─────────────────────┤
│ id (PK)             │       │ id (PK)             │
│ username (UNIQUE)   │       │ title               │
│ email (UNIQUE)      │       │ encrypted_content   │
│ hashed_password     │◄──────│ nonce (96-bit)      │
│ totp_secret         │  1:N  │ tag (128-bit)       │
│ totp_enabled        │       │ owner_id (FK)       │
│ recovery_codes      │       │ created_at          │
│ oauth_provider      │       │ updated_at          │
│ oauth_sub           │       └─────────────────────┘
│ is_active           │
│ created_at          │       ┌─────────────────────┐
│ updated_at          │       │   revoked_tokens     │
└─────────────────────┘       ├─────────────────────┤
                              │ jti (PK)            │
                              │ revoked_at          │
                              │ expires_at          │
                              └─────────────────────┘
```

## 5. 安全设计决策

| 决策 | 理由 | 替代方案 |
|------|------|---------|
| Argon2id 而非 bcrypt | 内存硬函数，抗 GPU/ASIC | bcrypt (仍可接受) |
| RS256 而非 HS256 | 非对称签名，验证方无需密钥 | HS256 (单体应用可用) |
| PKCE 而非 plain code | 防授权码拦截攻击 | 无替代 (PKCE 是必须的) |
| AES-GCM 而非 CBC | 认证加密，防篡改 | CBC+HMAC (Encrypt-then-MAC) |
| HKDF 派生用户密钥 | 用户隔离，单用户泄露不影响他人 | 共享密钥 (不推荐) |
| Token 黑名单 | 支持即时吊销 | 短过期时间 (延迟吊销) |
