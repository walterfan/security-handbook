# 附录：安全工程实战指南

> 这份指南的目标只有一个：**拿到就能在项目中直接落地**。

## A. 安全工程十大原则

| # | 原则 | 一句话 | 反面案例 | 正确做法 |
|---|------|--------|---------|---------|
| 1 | **纵深防御** | 不要把鸡蛋放在一个篮子里 | 只靠 API Gateway 做认证 | Gateway + 服务端 JWT 验证 + 数据库行级权限 |
| 2 | **最小权限** | 只给刚好够用的权限 | 数据库连接用 root 账号 | 每个服务独立数据库账号，只授 SELECT/INSERT |
| 3 | **默认拒绝** | 没有明确允许的就是禁止的 | `if user.role == "blocked": deny()` | `if user.role in allowed_roles: allow(); else: deny()` |
| 4 | **零信任** | 永远验证，永不信任 | 内网服务之间不做认证 | 所有服务间通信走 mTLS |
| 5 | **安全左移** | 越早发现越便宜 | 上线前才做安全测试 | CI 流水线集成 SAST + SCA |
| 6 | **密码敏捷性** | 算法可以随时换 | 硬编码 `algorithm="RS256"` | 配置文件驱动，支持多算法并存 |
| 7 | **不造轮子** | 用审计过的库 | 自己实现 HMAC 签名 | 用 `cryptography` / `Bouncy Castle` / `crypto/*` |
| 8 | **失败安全** | 出错时拒绝而不是放行 | `catch(e) { return true; }` | `catch(e) { log(e); return false; }` |
| 9 | **可审计** | 所有安全操作留痕 | 只记 `login success` | 记录 who + when + what + where + result |
| 10 | **最小攻击面** | 不需要的就关掉 | 生产环境开着 debug 端口 | 只暴露必要端口，禁用 debug/swagger |

### 原则落地：代码对比

**原则 3 — 默认拒绝**：

```python
# ❌ 黑名单模式（容易遗漏）
def check_access(user, resource):
    if user.role == "blocked":
        raise Forbidden()
    return True  # 默认放行 — 危险！

# ✅ 白名单模式（默认拒绝）
ALLOWED = {
    "admin": ["read", "write", "delete"],
    "editor": ["read", "write"],
    "viewer": ["read"],
}
def check_access(user, resource, action):
    allowed_actions = ALLOWED.get(user.role, [])  # 未知角色 → 空列表
    if action not in allowed_actions:
        raise Forbidden(f"{user.role} cannot {action} on {resource}")
```

**原则 8 — 失败安全**：

```go
// ❌ 认证失败时放行
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _, err := validateToken(r)
        if err != nil {
            log.Printf("auth error: %v", err) // 只记日志，继续执行
        }
        next.ServeHTTP(w, r)
    })
}

// ✅ 认证失败时拒绝
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims, err := validateToken(r)
        if err != nil {
            log.Printf("auth failed: %v", err)
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return // 立即返回，不执行后续逻辑
        }
        ctx := context.WithValue(r.Context(), "claims", claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

**原则 9 — 可审计**：

```java
// ❌ 模糊的日志
logger.info("user logged in");

// ✅ 结构化审计日志
@Component
public class AuditLogger {
    private static final Logger audit = LoggerFactory.getLogger("AUDIT");

    public void log(AuditEvent event) {
        audit.info("action={} subject={} resource={} result={} ip={} timestamp={}",
            event.getAction(),      // "login" / "delete_user" / "export_data"
            event.getSubjectId(),   // "user-123"
            event.getResourceId(),  // "document-456"
            event.getResult(),      // "success" / "denied" / "error"
            event.getSourceIP(),    // "192.168.1.100"
            Instant.now()           // "2026-03-21T10:30:00Z"
        );
    }
}
```

## B. 八大安全设计模式

### B.1 Gateway 认证模式

**问题**：每个微服务都自己验证 JWT，重复且难维护。

**方案**：API Gateway 统一认证，向后端注入可信身份头。

```{mermaid}
sequenceDiagram
    participant C as 客户端
    participant G as API Gateway
    participant S as 后端服务
    
    C->>G: GET /api/orders (Authorization: Bearer xxx)
    G->>G: 验证 JWT
    alt JWT 有效
        G->>S: GET /api/orders<br/>X-User-Id: user-123<br/>X-User-Roles: admin
        S->>S: 信任 Gateway 注入的头<br/>（只接受内网来源）
        S->>G: 200 OK + data
        G->>C: 200 OK + data
    else JWT 无效
        G->>C: 401 Unauthorized
    end
```

**关键**：后端服务必须验证请求来自 Gateway（通过 mTLS 或内网 IP 白名单），否则攻击者可以伪造 `X-User-Id` 头。

```python
# FastAPI — 信任 Gateway 注入的身份头
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()
TRUSTED_PROXIES = {"10.0.0.0/8", "172.16.0.0/12"}  # 内网网段

def get_user_from_gateway(request: Request) -> dict:
    """从 Gateway 注入的头中提取用户身份"""
    # 验证请求来自可信 Gateway
    client_ip = request.client.host
    # 生产环境应使用 ipaddress 模块做 CIDR 匹配
    
    user_id = request.headers.get("X-User-Id")
    if not user_id:
        raise HTTPException(401, "Missing identity header")
    return {
        "user_id": user_id,
        "roles": request.headers.get("X-User-Roles", "").split(","),
    }

@app.get("/api/orders")
async def list_orders(request: Request):
    user = get_user_from_gateway(request)
    # 直接使用 user["user_id"]，不需要再验证 JWT
    return {"orders": [], "user": user["user_id"]}
```

### B.2 Sidecar 代理模式

**问题**：应用代码要处理 mTLS 证书、轮换、安全头……太复杂。

**方案**：Sidecar（Envoy/Istio）处理所有安全通信，应用只管业务逻辑。

```{mermaid}
flowchart LR
    subgraph Pod A
        A[应用 A<br/>:8080 HTTP] --- SA[Envoy Sidecar<br/>mTLS 终止]
    end
    subgraph Pod B
        SB[Envoy Sidecar<br/>mTLS 发起] --- B[应用 B<br/>:8080 HTTP]
    end
    SA <-->|mTLS| SB
    
    style A fill:#9f9
    style B fill:#9f9
    style SA fill:#99f
    style SB fill:#99f
```

**应用代码零改动**：应用只监听 `localhost:8080`（明文 HTTP），Sidecar 负责加密。

### B.3 Token 中继模式

**问题**：微服务 A 调用微服务 B 时，如何传递用户身份？

```{mermaid}
flowchart LR
    subgraph "方案一：JWT 透传"
        C1[客户端] -->|JWT| A1[服务 A]
        A1 -->|同一个 JWT| B1[服务 B]
    end
    
    subgraph "方案二：Token Exchange"
        C2[客户端] -->|User JWT| A2[服务 A]
        A2 -->|User JWT + 自身凭证| IDP[IdP]
        IDP -->|新 JWT<br/>sub=user, act=serviceA| A2
        A2 -->|新 JWT| B2[服务 B]
    end
```

| 方案 | 优点 | 缺点 | 适用场景 |
|------|------|------|---------|
| JWT 透传 | 简单，零开销 | 服务 B 无法区分"用户直接调用"和"服务 A 代理调用" | 简单微服务 |
| Token Exchange | 可审计，可限制权限 | 需要 IdP 支持，多一次网络调用 | 高安全要求 |

```go
// Go — Token Exchange 客户端（RFC 8693）
func exchangeToken(ctx context.Context, userToken string, targetAudience string) (string, error) {
    data := url.Values{
        "grant_type":          {"urn:ietf:params:oauth:grant-type:token-exchange"},
        "subject_token":       {userToken},
        "subject_token_type":  {"urn:ietf:params:oauth:token-type:access_token"},
        "audience":            {targetAudience},
        "requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
    }
    resp, err := http.PostForm("https://idp.example.com/oauth/token", data)
    if err != nil {
        return "", fmt.Errorf("token exchange failed: %w", err)
    }
    defer resp.Body.Close()
    
    var result struct {
        AccessToken string `json:"access_token"`
        TokenType   string `json:"token_type"`
    }
    json.NewDecoder(resp.Body).Decode(&result)
    return result.AccessToken, nil
}
```

### B.4 策略外置模式

**问题**：授权逻辑散落在各个服务的 if-else 里，改一个权限要改 N 个服务。

**方案**：授权决策交给外部策略引擎（OPA/OpenFGA），应用只做查询。

```{mermaid}
sequenceDiagram
    participant App as 应用服务
    participant PE as 策略引擎<br/>(OPA/OpenFGA)
    participant DB as 策略存储
    
    App->>PE: 检查权限<br/>{user: "alice", action: "delete", resource: "doc-123"}
    PE->>DB: 查询策略和关系
    DB->>PE: 策略数据
    PE->>PE: 评估策略
    PE->>App: {allowed: true/false, reason: "..."}
    
    Note over App: 应用不包含任何授权逻辑<br/>只根据 allowed 决定是否执行
```

```python
# Python — 策略外置模式（OPA 客户端）
import httpx

class PolicyClient:
    """OPA 策略查询客户端"""
    def __init__(self, opa_url: str = "http://localhost:8181"):
        self.opa_url = opa_url
        self.client = httpx.AsyncClient(timeout=2.0)
    
    async def check(self, user: str, action: str, resource: str) -> bool:
        """查询 OPA 授权决策"""
        resp = await self.client.post(
            f"{self.opa_url}/v1/data/authz/allow",
            json={"input": {
                "user": user,
                "action": action,
                "resource": resource,
            }},
        )
        return resp.json().get("result", False)

# 使用
policy = PolicyClient()

@app.delete("/api/documents/{doc_id}")
async def delete_document(doc_id: str, user: User = Depends(get_current_user)):
    # 应用代码里没有任何 if role == "admin" 的逻辑
    allowed = await policy.check(user.id, "delete", f"document:{doc_id}")
    if not allowed:
        raise HTTPException(403, "Policy denied")
    # 执行删除...
```

### B.5 密钥信封模式（Envelope Encryption）

**问题**：用一个密钥加密所有数据，密钥泄露就全完了。

**方案**：数据密钥（DEK）加密数据，主密钥（KEK）加密 DEK。

```{mermaid}
flowchart TB
    subgraph "加密流程"
        KMS[KMS / Vault] -->|生成| DEK[数据密钥 DEK<br/>AES-256]
        DEK -->|加密| DATA[明文数据]
        DATA --> EDATA[密文数据]
        KMS -->|用 KEK 加密| EDEK[加密的 DEK]
    end
    
    subgraph "存储"
        EDATA --> S[(数据库)]
        EDEK --> S
    end
    
    subgraph "解密流程"
        S --> EDEK2[加密的 DEK]
        EDEK2 -->|发送给 KMS| KMS2[KMS / Vault]
        KMS2 -->|用 KEK 解密| DEK2[明文 DEK]
        DEK2 -->|解密| EDATA2[密文数据]
        EDATA2 --> PLAIN[明文数据]
    end
```

```java
// Java — Envelope Encryption 实现
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.SecureRandom;
import java.util.Base64;

public class EnvelopeEncryption {
    
    /**
     * 生成数据密钥（DEK）
     */
    public static SecretKey generateDEK() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, new SecureRandom());
        return kg.generateKey();
    }
    
    /**
     * 用 DEK 加密数据
     */
    public static byte[] encryptData(byte[] plaintext, SecretKey dek) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, dek, new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);
        // iv + ciphertext
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return result;
    }
    
    /**
     * 用 KEK 加密 DEK（模拟 KMS 操作）
     */
    public static byte[] wrapDEK(SecretKey dek, SecretKey kek) throws Exception {
        Cipher cipher = Cipher.getInstance("AESWrap");
        cipher.init(Cipher.WRAP_MODE, kek);
        return cipher.wrap(dek);
    }
    
    /**
     * 用 KEK 解密 DEK
     */
    public static SecretKey unwrapDEK(byte[] wrappedDek, SecretKey kek) throws Exception {
        Cipher cipher = Cipher.getInstance("AESWrap");
        cipher.init(Cipher.UNWRAP_MODE, kek);
        return (SecretKey) cipher.unwrap(wrappedDek, "AES", Cipher.SECRET_KEY);
    }
}
```

### B.6 Circuit Breaker 安全模式

**问题**：认证服务挂了，所有请求都 503？还是全部放行？

**方案**：降级策略 — 短时间内用缓存的决策，超时后拒绝。

```{mermaid}
flowchart TD
    R[请求到达] --> C{认证服务<br/>可用？}
    C -->|是| N[正常验证]
    C -->|否| CB{熔断器状态}
    CB -->|CLOSED| RETRY[重试一次]
    RETRY -->|成功| N
    RETRY -->|失败| OPEN[打开熔断器]
    CB -->|OPEN| CACHE{本地缓存<br/>有有效 Token？}
    CACHE -->|是且未过期| ALLOW[允许<br/>标记为降级]
    CACHE -->|否| DENY[拒绝<br/>503 Service Unavailable]
    CB -->|HALF-OPEN| PROBE[探测请求]
    PROBE -->|成功| CLOSE[关闭熔断器]
    PROBE -->|失败| OPEN
```

### B.7 审计日志模式

```python
# Python — 结构化审计日志
import json
import logging
from datetime import datetime, timezone
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
handler = logging.FileHandler("audit.jsonl")
audit_logger.addHandler(handler)

class AuditMiddleware(BaseHTTPMiddleware):
    """记录所有 API 操作的审计日志"""
    
    SENSITIVE_PATHS = {"/api/admin", "/api/users", "/api/secrets"}
    
    async def dispatch(self, request: Request, call_next):
        start = datetime.now(timezone.utc)
        response = await call_next(request)
        
        # 只审计写操作和敏感路径
        if request.method in ("POST", "PUT", "DELETE", "PATCH") or \
           any(request.url.path.startswith(p) for p in self.SENSITIVE_PATHS):
            
            audit_entry = {
                "timestamp": start.isoformat(),
                "action": f"{request.method} {request.url.path}",
                "subject": getattr(request.state, "user_id", "anonymous"),
                "source_ip": request.client.host,
                "user_agent": request.headers.get("user-agent", ""),
                "status_code": response.status_code,
                "result": "success" if response.status_code < 400 else "failure",
                "duration_ms": (datetime.now(timezone.utc) - start).total_seconds() * 1000,
            }
            audit_logger.info(json.dumps(audit_entry))
        
        return response
```

### B.8 Secret Zero 模式

**问题**：应用启动时需要密钥来连接 Vault，但这个密钥本身怎么安全传递？

```{mermaid}
flowchart LR
    subgraph "方案一：平台注入"
        K8S[Kubernetes] -->|ServiceAccount Token| APP1[应用]
        APP1 -->|K8s Auth| V1[Vault]
    end
    
    subgraph "方案二：云 IAM"
        IAM[AWS IAM Role] -->|Instance Profile| APP2[应用]
        APP2 -->|IAM Auth| V2[Vault]
    end
    
    subgraph "方案三：AppRole"
        CI[CI/CD] -->|注入 Role ID + Secret ID| APP3[应用]
        APP3 -->|AppRole Auth| V3[Vault]
    end
```

| 方案 | 安全性 | 复杂度 | 适用场景 |
|------|--------|--------|---------|
| K8s ServiceAccount | ⭐⭐⭐⭐ | 低 | Kubernetes 环境 |
| 云 IAM Role | ⭐⭐⭐⭐ | 低 | AWS/GCP/Azure |
| Vault AppRole | ⭐⭐⭐ | 中 | 通用环境 |
| 环境变量 | ⭐⭐ | 低 | 开发环境 |
| 配置文件 | ⭐ | 低 | ❌ 不推荐 |

## C. 框架与库推荐

### C.1 Python 安全技术栈

| 类别 | 库 | 说明 | 安装 |
|------|-----|------|------|
| **JWT** | PyJWT | JWT 编解码，支持 RS256/ES256 | `pip install PyJWT[crypto]` |
| **JWT** | python-jose | JWT + JWK + JWS，OIDC 友好 | `pip install python-jose[cryptography]` |
| **OAuth/OIDC** | Authlib | OAuth 1/2 + OIDC 全家桶 | `pip install authlib` |
| **密码哈希** | passlib | bcrypt/argon2/scrypt 统一接口 | `pip install passlib[bcrypt]` |
| **密码学** | cryptography | OpenSSL 绑定，RSA/EC/AES | `pip install cryptography` |
| **授权** | casbin | RBAC/ABAC/ReBAC 策略引擎 | `pip install casbin` |
| **OPA** | opa-python-client | OPA REST API 客户端 | `pip install opa-python-client` |
| **OpenFGA** | openfga-sdk | OpenFGA 官方 SDK | `pip install openfga-sdk` |
| **Vault** | hvac | HashiCorp Vault 客户端 | `pip install hvac` |
| **Rate Limit** | slowapi | FastAPI 限流 | `pip install slowapi` |
| **SAST** | bandit | Python 安全静态分析 | `pip install bandit` |
| **SCA** | pip-audit | 依赖漏洞扫描 | `pip install pip-audit` |
| **WebAuthn** | py-webauthn | Passkey/FIDO2 服务端 | `pip install webauthn` |
| **TOTP** | pyotp | Google Authenticator 兼容 | `pip install pyotp` |

**最小示例 — 密码哈希**：

```python
from passlib.context import CryptContext

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

hashed = pwd_ctx.hash("my-password")        # 哈希
verified = pwd_ctx.verify("my-password", hashed)  # 验证
```

### C.2 Java 安全技术栈

| 类别 | 库 | 说明 | Maven |
|------|-----|------|-------|
| **框架** | Spring Security | 认证+授权+安全头全家桶 | `spring-boot-starter-security` |
| **JWT** | jjwt | JWT 签发/验证 | `io.jsonwebtoken:jjwt-api:0.12.5` |
| **JWT** | java-jwt | Auth0 出品 JWT 库 | `com.auth0:java-jwt:4.4.0` |
| **JWKS** | jwks-rsa | JWKS 公钥获取+缓存 | `com.auth0:jwks-rsa:0.22.1` |
| **OAuth/OIDC** | Spring OAuth2 Client | OIDC 登录+Token 管理 | `spring-boot-starter-oauth2-client` |
| **密码学** | Bouncy Castle | 全算法覆盖（含 PQC） | `org.bouncycastle:bcprov-jdk18on` |
| **密码学** | Tink | Google 出品，误用难 | `com.google.crypto.tink:tink` |
| **授权** | jCasbin | Casbin Java 版 | `org.casbin:jcasbin:1.55.0` |
| **Vault** | Spring Vault | Vault 集成 | `spring-vault-core` |
| **SAST** | SpotBugs | 字节码安全分析 | Maven/Gradle 插件 |
| **SCA** | OWASP Dep-Check | 依赖漏洞扫描 | Maven/Gradle 插件 |
| **WebAuthn** | java-webauthn-server | Yubico 出品 | `com.yubico:webauthn-server-core` |
| **TOTP** | totp-spring-boot | TOTP 集成 | `dev.samstevens.totp:totp` |

**最小示例 — JWT 签发**：

```java
// jjwt
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Date;

KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();

String jwt = Jwts.builder()
    .subject("user-123")
    .claim("roles", List.of("admin"))
    .issuedAt(Date.from(Instant.now()))
    .expiration(Date.from(Instant.now().plusSeconds(3600)))
    .signWith(kp.getPrivate())
    .compact();
```

### C.3 Go 安全技术栈

| 类别 | 库 | 说明 | 安装 |
|------|-----|------|------|
| **JWT** | golang-jwt/jwt/v5 | JWT 签发/验证 | `go get github.com/golang-jwt/jwt/v5` |
| **JWKS** | lestrrat-go/jwx | JWK/JWS/JWE 全家桶 | `go get github.com/lestrrat-go/jwx/v2` |
| **OIDC** | coreos/go-oidc/v3 | OIDC Discovery + 验证 | `go get github.com/coreos/go-oidc/v3` |
| **OAuth2** | golang.org/x/oauth2 | OAuth2 客户端 | `go get golang.org/x/oauth2` |
| **密码学** | crypto/* | 标准库，RSA/EC/AES | 内置 |
| **JOSE** | go-jose/go-jose/v4 | JOSE 全家桶 | `go get github.com/go-jose/go-jose/v4` |
| **授权** | casbin/casbin/v2 | RBAC/ABAC 策略引擎 | `go get github.com/casbin/casbin/v2` |
| **OPA** | open-policy-agent/opa | 嵌入式 OPA | `go get github.com/open-policy-agent/opa` |
| **Vault** | hashicorp/vault/api | Vault 客户端 | `go get github.com/hashicorp/vault/api` |
| **Web** | gin-gonic/gin | HTTP 框架 | `go get github.com/gin-gonic/gin` |
| **SAST** | securego/gosec | Go 安全静态分析 | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| **SCA** | govulncheck | 官方漏洞扫描 | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| **WebAuthn** | go-webauthn/webauthn | Passkey/FIDO2 | `go get github.com/go-webauthn/webauthn` |
| **TOTP** | pquerna/otp | TOTP/HOTP | `go get github.com/pquerna/otp` |

**最小示例 — JWT 签发**：

```go
import "github.com/golang-jwt/jwt/v5"

claims := jwt.MapClaims{
    "sub":   "user-123",
    "roles": []string{"admin"},
    "exp":   time.Now().Add(time.Hour).Unix(),
}
token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
signed, _ := token.SignedString(privateKey)
```

## D. 三个可直接落地的项目模板

### D.1 安全 REST API — Python FastAPI

```python
"""secure_api.py — 可直接落地的安全 API 模板"""
import os
import time
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from jose import jwt, JWTError
import httpx
from slowapi import Limiter
from slowapi.util import get_remote_address

# ============================================================
# 配置
# ============================================================
JWKS_URL = os.getenv("JWKS_URL", "https://auth.example.com/.well-known/jwks.json")
ISSUER = os.getenv("JWT_ISSUER", "https://auth.example.com")
AUDIENCE = os.getenv("JWT_AUDIENCE", "my-api")
ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "https://app.example.com").split(",")

# ============================================================
# 日志
# ============================================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("api")
audit = logging.getLogger("audit")

# ============================================================
# JWKS 缓存
# ============================================================
_jwks_cache = {"keys": None, "expires": 0}

async def get_jwks() -> dict:
    if _jwks_cache["keys"] and time.time() < _jwks_cache["expires"]:
        return _jwks_cache["keys"]
    async with httpx.AsyncClient() as client:
        resp = await client.get(JWKS_URL, timeout=5)
        resp.raise_for_status()
        _jwks_cache["keys"] = resp.json()
        _jwks_cache["expires"] = time.time() + 3600  # 缓存 1 小时
    return _jwks_cache["keys"]

# ============================================================
# 认证
# ============================================================
security = HTTPBearer()

class User(BaseModel):
    id: str
    email: str | None = None
    roles: list[str] = []

async def get_current_user(
    cred: HTTPAuthorizationCredentials = Depends(security),
) -> User:
    try:
        jwks = await get_jwks()
        payload = jwt.decode(
            cred.credentials,
            jwks,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
        )
        return User(
            id=payload["sub"],
            email=payload.get("email"),
            roles=payload.get("roles", []),
        )
    except JWTError as e:
        raise HTTPException(401, f"Invalid token: {e}")

def require_role(*roles: str):
    async def checker(user: User = Depends(get_current_user)):
        if not any(r in user.roles for r in roles):
            raise HTTPException(403, f"Requires role: {roles}")
        return user
    return checker

# ============================================================
# 应用
# ============================================================
limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting secure API")
    yield
    logger.info("Shutting down")

app = FastAPI(title="Secure API", lifespan=lifespan)
app.state.limiter = limiter

# 安全中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    allow_credentials=True,
    max_age=3600,
)

from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ============================================================
# 端点
# ============================================================
@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/api/profile")
@limiter.limit("30/minute")
async def get_profile(request: Request, user: User = Depends(get_current_user)):
    audit.info(f"action=get_profile user={user.id} ip={request.client.host}")
    return {"user_id": user.id, "email": user.email, "roles": user.roles}

class CreateItemRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field("", max_length=2000)

@app.post("/api/items")
@limiter.limit("10/minute")
async def create_item(
    request: Request,
    item: CreateItemRequest,
    user: User = Depends(get_current_user),
):
    audit.info(f"action=create_item user={user.id} item={item.name}")
    return {"id": "item-001", "name": item.name, "created_by": user.id}

@app.delete("/api/admin/users/{user_id}")
@limiter.limit("5/minute")
async def delete_user(
    request: Request,
    user_id: str,
    admin: User = Depends(require_role("admin")),
):
    audit.info(f"action=delete_user admin={admin.id} target={user_id} ip={request.client.host}")
    return {"message": f"User {user_id} deleted"}
```

**配套文件**：

```text
# requirements.txt
fastapi==0.115.0
uvicorn[standard]==0.30.0
python-jose[cryptography]==3.3.0
httpx==0.27.0
slowapi==0.1.9
pydantic==2.9.0
passlib[bcrypt]==1.7.4
```

```dockerfile
# Dockerfile
FROM python:3.12-slim AS base
RUN groupadd -r app && useradd -r -g app app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER app
EXPOSE 8000
CMD ["uvicorn", "secure_api:app", "--host", "0.0.0.0", "--port", "8000"]
```

### D.2 安全微服务 — Go Gin

```go
// main.go — 可直接落地的安全微服务模板
package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// ============================================================
// 配置
// ============================================================
type Config struct {
	Port        string
	JWKSUrl     string
	Issuer      string
	Audience    string
	CORSOrigins []string
}

func loadConfig() Config {
	return Config{
		Port:        getEnv("PORT", "8080"),
		JWKSUrl:     getEnv("JWKS_URL", "https://auth.example.com/.well-known/jwks.json"),
		Issuer:      getEnv("JWT_ISSUER", "https://auth.example.com"),
		Audience:    getEnv("JWT_AUDIENCE", "my-api"),
		CORSOrigins: strings.Split(getEnv("CORS_ORIGINS", "https://app.example.com"), ","),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ============================================================
// 审计日志
// ============================================================
var auditLog = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
	Level: slog.LevelInfo,
}))

func audit(action, userID, resource, result, ip string) {
	auditLog.Info("audit",
		"action", action,
		"user", userID,
		"resource", resource,
		"result", result,
		"ip", ip,
		"timestamp", time.Now().UTC().Format(time.RFC3339),
	)
}

// ============================================================
// JWT 认证中间件
// ============================================================
type Claims struct {
	jwt.RegisteredClaims
	Roles []string `json:"roles"`
	Email string   `json:"email"`
}

func authMiddleware(publicKey *rsa.PublicKey, cfg Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(401, gin.H{"error": "missing bearer token"})
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")

		token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return publicKey, nil
		},
			jwt.WithIssuer(cfg.Issuer),
			jwt.WithAudience(cfg.Audience),
		)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
			return
		}

		claims := token.Claims.(*Claims)
		c.Set("user_id", claims.Subject)
		c.Set("roles", claims.Roles)
		c.Set("email", claims.Email)
		c.Next()
	}
}

// ============================================================
// 授权中间件
// ============================================================
func requireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRoles, _ := c.Get("roles")
		for _, required := range roles {
			for _, has := range userRoles.([]string) {
				if has == required {
					c.Next()
					return
				}
			}
		}
		userID, _ := c.Get("user_id")
		audit("access_denied", userID.(string), c.Request.URL.Path, "denied", c.ClientIP())
		c.AbortWithStatusJSON(403, gin.H{"error": "insufficient permissions"})
	}
}

// ============================================================
// 安全响应头中间件
// ============================================================
func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Next()
	}
}

// ============================================================
// 路由
// ============================================================
func setupRouter(cfg Config, publicKey *rsa.PublicKey) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), securityHeaders())

	// 公开端点
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "timestamp": time.Now().UTC()})
	})

	// 认证端点
	api := r.Group("/api", authMiddleware(publicKey, cfg))
	{
		api.GET("/profile", func(c *gin.Context) {
			userID, _ := c.Get("user_id")
			email, _ := c.Get("email")
			roles, _ := c.Get("roles")
			audit("get_profile", userID.(string), "/api/profile", "success", c.ClientIP())
			c.JSON(200, gin.H{"user_id": userID, "email": email, "roles": roles})
		})
	}

	// 管理端点
	admin := r.Group("/api/admin", authMiddleware(publicKey, cfg), requireRole("admin"))
	{
		admin.DELETE("/users/:id", func(c *gin.Context) {
			targetID := c.Param("id")
			userID, _ := c.Get("user_id")
			audit("delete_user", userID.(string), targetID, "success", c.ClientIP())
			c.JSON(200, gin.H{"message": fmt.Sprintf("User %s deleted", targetID)})
		})
	}

	return r
}

// ============================================================
// 主函数（Graceful Shutdown）
// ============================================================
func main() {
	cfg := loadConfig()
	slog.Info("starting secure API", "port", cfg.Port)

	// TODO: 从 JWKS 加载公钥（这里用占位符）
	var publicKey *rsa.PublicKey // = loadFromJWKS(cfg.JWKSUrl)

	router := setupRouter(cfg, publicKey)
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "err", err)
	}
	slog.Info("server stopped")
}

func init() {
	_ = json.Marshal // 确保 import 不报错
}
```

**配套 Dockerfile**：

```dockerfile
# Go 安全 Dockerfile — 多阶段构建
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /secure-api .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /secure-api /secure-api
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/secure-api"]
```

### D.3 安全微服务 — Java Spring Boot

```java
// SecurityConfig.java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/health", "/actuator/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").authenticated()
                .anyRequest().denyAll()  // 默认拒绝
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwkSetUri(jwkSetUri)
                    .jwtAuthenticationConverter(jwtAuthConverter())
                )
            )
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfig()))
            .headers(headers -> headers
                .contentTypeOptions(ct -> {})
                .frameOptions(fo -> fo.deny())
                .httpStrictTransportSecurity(hsts -> hsts
                    .maxAgeInSeconds(31536000)
                    .includeSubDomains(true))
            )
            .sessionManagement(sm -> sm
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    private JwtAuthenticationConverter jwtAuthConverter() {
        var converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            var roles = jwt.getClaimAsStringList("roles");
            if (roles == null) return List.of();
            return roles.stream()
                .map(r -> new SimpleGrantedAuthority("ROLE_" + r.toUpperCase()))
                .collect(Collectors.toList());
        });
        return converter;
    }

    private CorsConfigurationSource corsConfig() {
        var config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("https://app.example.com"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
```

```yaml
# application.yml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: https://auth.example.com/.well-known/jwks.json
          issuer-uri: https://auth.example.com

server:
  port: 8080
  servlet:
    context-path: /
  # 安全配置
  error:
    include-stacktrace: never    # 不暴露堆栈
    include-message: never       # 不暴露内部错误消息

management:
  endpoints:
    web:
      exposure:
        include: health,info     # 只暴露必要的 actuator 端点
```

## E. 安全检查清单

### E.1 设计阶段

| # | 检查项 | 优先级 | 参考章节 |
|---|--------|--------|---------|
| 1 | 完成威胁建模（STRIDE） | 🔴 必须 | ch04 |
| 2 | 确定认证方案（JWT/Session/mTLS） | 🔴 必须 | ch06-ch12 |
| 3 | 确定授权模型（RBAC/ABAC/ReBAC） | 🔴 必须 | ch13 |
| 4 | 设计密钥管理方案 | 🔴 必须 | ch27 |
| 5 | 定义 API 安全规范 | 🔴 必须 | ch26 |
| 6 | 规划审计日志方案 | 🟡 推荐 | 附录 B.7 |
| 7 | 评估第三方依赖安全性 | 🟡 推荐 | ch29 |
| 8 | 设计安全降级策略 | 🟡 推荐 | 附录 B.6 |
| 9 | 规划密码敏捷性 | 🟢 可选 | ch30 |
| 10 | 考虑合规要求（GDPR/SOC2） | 🟢 可选 | ch30 |

### E.2 编码阶段

| # | 检查项 | 优先级 |
|---|--------|--------|
| 1 | 所有输入都做验证和清洗 | 🔴 必须 |
| 2 | 使用参数化查询防 SQL 注入 | 🔴 必须 |
| 3 | 密码用 bcrypt/argon2 哈希，不用 MD5/SHA | 🔴 必须 |
| 4 | JWT 验证 iss/aud/exp，明确指定算法 | 🔴 必须 |
| 5 | 敏感数据不写日志 | 🔴 必须 |
| 6 | 错误信息不暴露内部细节 | 🔴 必须 |
| 7 | 使用 HTTPS，设置安全响应头 | 🔴 必须 |
| 8 | CORS 白名单，不用 `*` | 🔴 必须 |
| 9 | API Rate Limiting | 🟡 推荐 |
| 10 | 结构化审计日志 | 🟡 推荐 |
| 11 | 依赖版本锁定 | 🟡 推荐 |
| 12 | 密钥不硬编码，用环境变量或 Vault | 🔴 必须 |
| 13 | 文件上传验证类型和大小 | 🟡 推荐 |
| 14 | 使用 CSP 防 XSS | 🟡 推荐 |
| 15 | 定期更新依赖 | 🟡 推荐 |

### E.3 部署阶段

| # | 检查项 | 优先级 |
|---|--------|--------|
| 1 | 容器以非 root 用户运行 | 🔴 必须 |
| 2 | 使用最小基础镜像（distroless/scratch） | 🔴 必须 |
| 3 | 镜像扫描通过（无 HIGH/CRITICAL） | 🔴 必须 |
| 4 | TLS 证书配置正确（TLS 1.2+） | 🔴 必须 |
| 5 | 生产环境禁用 debug/swagger | 🔴 必须 |
| 6 | K8s NetworkPolicy 限制 Pod 通信 | 🟡 推荐 |
| 7 | Pod Security Standards: Restricted | 🟡 推荐 |
| 8 | 密钥通过 Vault/KMS 注入 | 🟡 推荐 |
| 9 | 镜像签名验证 | 🟢 可选 |
| 10 | SBOM 生成并存档 | 🟢 可选 |

### E.4 运维阶段

| # | 检查项 | 优先级 |
|---|--------|--------|
| 1 | 安全告警监控（异常登录、权限提升） | 🔴 必须 |
| 2 | 定期轮换密钥和证书 | 🔴 必须 |
| 3 | 依赖漏洞扫描（每周） | 🔴 必须 |
| 4 | 审计日志保留和分析 | 🟡 推荐 |
| 5 | 渗透测试（每季度） | 🟡 推荐 |
| 6 | 安全事件响应演练 | 🟡 推荐 |
| 7 | 备份加密和恢复测试 | 🟡 推荐 |
| 8 | 访问权限定期审查 | 🟡 推荐 |
| 9 | 安全指标仪表盘 | 🟢 可选 |
| 10 | 红蓝对抗演练 | 🟢 可选 |

---

*这份指南会随着安全实践的演进持续更新。如果你在落地过程中遇到问题，欢迎反馈。*
