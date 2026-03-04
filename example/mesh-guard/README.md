# MeshGuard — 微服务安全网关

> 示例项目三：演示零信任 + 工作负载身份，覆盖本书第四部分核心知识点

## 📖 章节对照

| 功能模块 | 对应章节 |
|---------|---------|
| API 签名验证 (HMAC) | ch12 API 认证模式 |
| SPIRE Server/Agent 部署 | ch19 SPIFFE, ch20 SPIRE |
| X.509-SVID 工作负载身份 | ch19 SPIFFE |
| SPIFFE 联邦 (跨域信任) | ch21 SPIFFE 联邦 |
| WIMSE 工作负载令牌 | ch22 WIMSE |
| 零信任架构 (永不信任) | ch23 零信任架构 |
| Service Mesh (Envoy mTLS) | ch24 Service Mesh |
| API 安全 (Rate Limit, Validation) | ch26 API 安全 |
| Vault 密钥管理 | ch27 密钥管理 |

## 🏗️ 架构

```
                    ┌─────────────────────────────────────────────────┐
                    │              Docker Compose Network              │
                    │                                                 │
  Client            │  ┌──────────────┐  mTLS   ┌────────────────┐   │
  ─────────────────►│  │ API Gateway  │────────►│ Order Service  │   │
                    │  │ (Go + Envoy) │         │ (Go + Envoy)   │   │
                    │  └──────────────┘         └───────┬────────┘   │
                    │         │                         │ mTLS       │
                    │         │                         ▼            │
                    │         │                 ┌────────────────┐   │
                    │         │                 │Payment Service │   │
                    │         │                 │ (Go + Envoy)   │   │
                    │         │                 └────────────────┘   │
                    │         │                                      │
                    │  ┌──────▼──────┐  ┌──────────┐  ┌──────────┐  │
                    │  │ SPIRE Server│  │   OPA    │  │  Vault   │  │
                    │  │ + Agent     │  │ Sidecar  │  │ (Secrets)│  │
                    │  └─────────────┘  └──────────┘  └──────────┘  │
                    └─────────────────────────────────────────────────┘

  mTLS = Mutual TLS with X.509-SVID certificates from SPIRE
```

## 🚀 快速开始

```bash
# Start all services
docker-compose up -d

# Verify SPIRE is running
docker-compose exec spire-server /opt/spire/bin/spire-server healthcheck

# Register workload entries
./scripts/register_entries.sh

# Test the API
curl http://localhost:8080/api/orders
```

## 🧪 运行测试

```bash
# Unit tests (Go)
cd services/api-gateway && go test ./... -v
cd services/order-service && go test ./... -v
cd services/payment-service && go test ./... -v

# Integration tests
cd tests && python -m pytest -v
```

## 📁 项目结构

```
mesh-guard/
├── services/
│   ├── api-gateway/          # Go — 入口网关
│   │   ├── main.go
│   │   ├── middleware/
│   │   │   ├── hmac_auth.go  # HMAC API 签名验证 (ch12)
│   │   │   ├── rate_limit.go # 速率限制 (ch26)
│   │   │   └── validation.go # 输入验证 (ch26)
│   │   ├── main_test.go
│   │   ├── Dockerfile
│   │   └── go.mod
│   ├── order-service/        # Go — 订单服务
│   │   ├── main.go
│   │   ├── main_test.go
│   │   ├── Dockerfile
│   │   └── go.mod
│   └── payment-service/      # Go — 支付服务
│       ├── main.go
│       ├── main_test.go
│       ├── Dockerfile
│       └── go.mod
├── spire/
│   ├── server/
│   │   └── server.conf       # SPIRE Server 配置 (ch20)
│   └── agent/
│       └── agent.conf         # SPIRE Agent 配置 (ch20)
├── opa/
│   └── policies/
│       └── service_authz.rego # 服务间授权策略 (ch15)
├── vault/
│   └── config/
│       └── vault.hcl          # Vault 配置 (ch27)
├── envoy/
│   └── envoy.yaml             # Envoy sidecar 配置 (ch24)
├── scripts/
│   └── register_entries.sh    # SPIRE 工作负载注册
├── tests/
│   ├── test_mtls.py           # mTLS 连通性测试
│   ├── test_api_security.py   # API 安全测试
│   └── test_zero_trust.py     # 零信任场景测试
├── docker-compose.yml
├── docs/
│   └── architecture.md
└── README.md
```

## 🔑 零信任核心原则 (ch23)

1. **永不信任，始终验证** — 每次服务间调用都通过 mTLS 验证身份
2. **最小权限** — OPA 策略限制每个服务只能调用它需要的下游服务
3. **假设已被攻破** — 即使内网也加密，证书短期轮换 (1h TTL)
4. **持续验证** — SPIRE Agent 持续监控工作负载，证书自动轮换
