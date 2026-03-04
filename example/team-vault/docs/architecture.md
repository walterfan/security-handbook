# TeamVault 架构文档

## 1. 双层授权架构 (ch17)

TeamVault 实现了 PEP/PDP/PIP/PAP 分离的授权架构，使用两个策略引擎：

```
                         ┌─────────────────────────────────────┐
                         │          请求处理流程                 │
                         │                                     │
  HTTP Request           │  ┌──────────┐    ┌──────────────┐   │
  ──────────────────────►│  │ Layer 1   │    │  Layer 2      │   │
                         │  │ OPA       │───►│  OpenFGA      │   │
                         │  │ (粗粒度)   │    │  (细粒度)      │   │
                         │  │           │    │              │   │
                         │  │ • IP 检查  │    │ • 文档权限    │   │
                         │  │ • 角色检查  │    │ • 继承关系    │   │
                         │  │ • 速率限制  │    │ • 共享传播    │   │
                         │  └──────────┘    └──────────────┘   │
                         │       │                │            │
                         │       ▼                ▼            │
                         │  ┌──────────────────────────┐       │
                         │  │     Route Handler         │       │
                         │  │     (业务逻辑)             │       │
                         │  └──────────────────────────┘       │
                         └─────────────────────────────────────┘
```

### 组件映射

| 架构组件 | 实现 | 文件 |
|---------|------|------|
| **PAP** (策略管理) | OpenFGA Model DSL + OPA Rego | `openfga/model.fga`, `opa/policies/` |
| **PDP** (策略决策) | OpenFGA Server + OPA Server | Docker 容器 |
| **PEP** (策略执行) | FastAPI Middleware | `authz/middleware.py` |
| **PIP** (策略信息) | PostgreSQL + JWT Claims | `models/`, JWT payload |

## 2. OpenFGA 权限模型 (ch14)

### 实体关系图

```
┌──────────────┐     owner/admin/member     ┌──────────────┐
│     User     │◄──────────────────────────►│ Organization │
└──────┬───────┘                            └──────┬───────┘
       │                                           │
       │ lead/member                               │ org
       ▼                                           ▼
┌──────────────┐                            ┌──────────────┐
│     Team     │                            │    Folder    │
└──────────────┘                            └──────┬───────┘
                                                   │ parent
                                                   ▼
                                            ┌──────────────┐
                                            │   Document   │
                                            └──────────────┘
```

### 权限继承链

```
Organization (owner)
  └─► admin (implied)
       └─► Folder (editor, via "admin from org")
            └─► Document (editor, via "editor from parent")
                 └─► can_edit (implied)
                      └─► can_view (implied)
```

**示例**：Alice 是 Acme 的 owner → 自动成为所有 Acme 文件夹的 editor → 自动成为所有文档的 editor → 可以编辑和查看所有文档。

### 权限矩阵

| 角色 | can_view | can_edit | can_share | delete |
|------|----------|----------|-----------|--------|
| Organization Owner | ✅ | ✅ | ❌ (需直接 owner) | ❌ |
| Organization Admin | ✅ | ✅ | ❌ | ❌ |
| Organization Member | ✅ | ❌ | ❌ | ❌ |
| Document Owner | ✅ | ✅ | ✅ | ✅ |
| Document Editor | ✅ | ✅ | ❌ | ❌ |
| Document Viewer | ✅ | ❌ | ❌ | ❌ |
| Blocked User | ❌ | ❌ | ❌ | ❌ |

## 3. OPA 策略设计 (ch15, ch16)

### 策略层次

```
api_policy.rego
├── default deny (所有请求默认拒绝)
├── public endpoints (无需认证)
│   ├── /health
│   ├── /auth/login
│   └── /auth/register
├── authenticated access (需要有效 JWT)
│   └── 非 admin 端点 + 非封禁 IP
├── admin access (需要 admin 角色 + IP 白名单)
│   ├── /admin/* 路径
│   └── DELETE /organizations
└── rate limit tier (信息性，供 PEP 使用)
    ├── standard (member)
    ├── elevated (admin/owner)
    └── unlimited (service_account)
```

## 4. 数据流示例

### 场景：Bob 编辑 Alice 的文档

```
1. Bob → POST /documents/doc-123 {"content": "new text"}
   │
2. │→ PEP Middleware (authz/middleware.py)
   │   ├── 解析 JWT → {sub: "bob", role: "member"}
   │   └── 调用 OPA
   │       └── OPA 评估 api_policy.rego
   │           ├── 路径 /documents/doc-123 不是 admin 端点 ✓
   │           ├── Bob 有有效 JWT ✓
   │           ├── IP 不在封禁列表 ✓
   │           └── 返回 {allow: true, rate_limit_tier: "standard"}
   │
3. │→ Route Handler (routers/documents.py)
   │   └── 调用 OpenFGA
   │       └── check(user:bob, can_edit, document:doc-123)
   │           ├── Bob 是 document:doc-123 的 editor? → 否
   │           ├── Bob 是 document:doc-123 的 owner? → 否
   │           ├── document:doc-123 的 parent 是 folder:project-docs
   │           ├── Bob 是 folder:project-docs 的 editor? → 否
   │           ├── folder:project-docs 的 org 是 organization:acme
   │           ├── Bob 是 organization:acme 的 admin? → 是!
   │           └── 返回 allowed: true ✓
   │
4. │→ 更新数据库，返回 200 OK
```
