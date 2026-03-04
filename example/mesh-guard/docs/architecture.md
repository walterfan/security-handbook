# MeshGuard 架构文档

## 1. 零信任架构 (ch23)

MeshGuard 实现了 NIST 800-207 零信任架构的核心原则：

```
┌─────────────────────────────────────────────────────────────────┐
│                        零信任网络                                │
│                                                                 │
│  ┌──────────┐    mTLS     ┌──────────┐    mTLS    ┌──────────┐ │
│  │   API    │◄──────────►│  Order   │◄─────────►│ Payment  │ │
│  │ Gateway  │  X.509-SVID │ Service  │ X.509-SVID │ Service  │ │
│  └────┬─────┘            └────┬─────┘            └────┬─────┘ │
│       │                       │                       │       │
│       │ Workload API          │ Workload API          │       │
│       ▼                       ▼                       ▼       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    SPIRE Agent                          │   │
│  │  • 工作负载证明 (Unix selectors)                         │   │
│  │  • SVID 签发与轮换 (1h TTL)                              │   │
│  │  • 信任包分发                                            │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         │ Node Attestation                     │
│                         ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   SPIRE Server                          │   │
│  │  • 信任域: spiffe://mesh-guard                          │   │
│  │  • CA 管理 (24h TTL)                                    │   │
│  │  • 注册条目数据库                                        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────┐                                    ┌──────────┐  │
│  │   OPA    │ ← 服务间授权策略                    │  Vault   │  │
│  │ (Policy) │   (最小权限)                        │(Secrets) │  │
│  └──────────┘                                    └──────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## 2. SPIFFE 身份体系 (ch19)

### SPIFFE ID 分配

| 服务 | SPIFFE ID | 用途 |
|------|-----------|------|
| API Gateway | `spiffe://mesh-guard/api-gateway` | 接收外部请求，转发到内部服务 |
| Order Service | `spiffe://mesh-guard/order-service` | 处理订单，调用支付服务 |
| Payment Service | `spiffe://mesh-guard/payment-service` | 处理支付，访问 Vault 密钥 |

### X.509-SVID 证书结构

```
Certificate:
    Subject: O=SPIRE
    URI SAN: spiffe://mesh-guard/order-service
    Not Before: 2026-03-04 12:00:00 UTC
    Not After:  2026-03-04 13:00:00 UTC  ← 1小时 TTL
    Key Usage: Digital Signature, Key Encipherment
    Extended Key Usage: TLS Web Server Auth, TLS Web Client Auth
```

## 3. 服务调用图 (OPA 策略)

```
                    ┌──────────────┐
                    │  External    │
                    │  Client      │
                    └──────┬───────┘
                           │ HTTP (HMAC Auth)
                           ▼
                    ┌──────────────┐
                    │ API Gateway  │
                    └──────┬───────┘
                           │ GET /orders
                           │ GET /orders/{id}
                           ▼
                    ┌──────────────┐
                    │Order Service │
                    └──────┬───────┘
                           │ POST /payments/process
                           │ GET  /payments/{id}
                           ▼
                    ┌──────────────┐
                    │Payment Svc   │
                    └──────────────┘

  ✅ 允许的调用路径 (OPA 策略定义)
  ❌ 其他所有调用路径被拒绝
```

### OPA 策略规则

| 源服务 | 目标服务 | 允许方法 | 允许路径 |
|--------|---------|---------|---------|
| api-gateway | order-service | GET | /orders, /orders/* |
| order-service | payment-service | POST | /payments/process |
| order-service | payment-service | GET | /payments/* |
| * | * | GET | /health |

## 4. Vault 密钥管理 (ch27)

```
Vault Secret Paths:
├── secret/data/payment/
│   ├── stripe-key          # Stripe API 密钥
│   └── webhook-secret      # Webhook 签名密钥
├── secret/data/database/
│   ├── order-db-creds      # 订单数据库凭据
│   └── payment-db-creds    # 支付数据库凭据
└── pki/
    └── issue/mesh-guard    # 备用 TLS 证书签发
```

## 5. 安全层次总结

| 层次 | 技术 | 章节 | 作用 |
|------|------|------|------|
| L1: API 认证 | HMAC-SHA256 | ch12 | 外部客户端身份验证 |
| L2: 传输安全 | mTLS (X.509-SVID) | ch19, ch24 | 服务间加密和身份验证 |
| L3: 服务授权 | OPA Rego | ch15 | 服务间调用权限控制 |
| L4: 密钥管理 | Vault | ch27 | 敏感数据保护 |
| L5: 身份管理 | SPIRE | ch20 | 工作负载身份签发和轮换 |
| L6: 可观测性 | Envoy Access Log | ch24 | 审计和监控 |
