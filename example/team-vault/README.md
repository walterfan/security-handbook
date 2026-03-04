# TeamVault — 团队权限管理平台

> 示例项目二：演示 RBAC → ReBAC 的演进，覆盖本书第三部分核心知识点

## 📖 章节对照

| 功能模块 | 对应章节 |
|---------|---------|
| IAM 身份管理 (Organization/Team/Member) | ch05 IAM 概述 |
| SSO 模拟 (SAML-like federation) | ch11 SSO 与联邦身份 |
| 经典 RBAC 实现 (Owner/Admin/Editor/Viewer) | ch13 访问控制模型 |
| OpenFGA 细粒度授权 (文档级权限) | ch14 OpenFGA |
| OPA Rego 策略 (API 级策略) | ch15 OPA |
| Policy as Code (策略版本控制) | ch16 策略即代码 |
| 授权架构 (PEP/PDP/PIP/PAP) | ch17 授权架构 |
| OpenFGA + FastAPI 实战 | ch18 OpenFGA 实战 |

## 🏗️ 架构

```
┌──────────────┐                    ┌──────────────────────────────────┐
│   Vue.js 3   │     HTTP/JSON      │          FastAPI Backend          │
│   Frontend   │◄──────────────────►│                                  │
└──────────────┘                    │  ┌────────────┐  ┌────────────┐  │
                                    │  │ PEP        │  │ Routers    │  │
                                    │  │ Middleware  │──│ • org      │  │
                                    │  └─────┬──────┘  │ • team     │  │
                                    │        │         │ • document │  │
                                    │   ┌────▼────┐    └────────────┘  │
                                    │   │ PDP     │                    │
                                    │   │ Router  │                    │
                                    │   └──┬───┬──┘                    │
                                    │      │   │                       │
                                    └──────┼───┼───────────────────────┘
                                           │   │
                              ┌────────────┘   └────────────┐
                              ▼                              ▼
                    ┌──────────────────┐          ┌──────────────────┐
                    │    OpenFGA       │          │      OPA         │
                    │  (ReBAC Engine)  │          │  (Policy Engine) │
                    │                  │          │                  │
                    │  细粒度资源授权    │          │  粗粒度 API 策略  │
                    │  • 文档权限       │          │  • IP 限制       │
                    │  • 继承关系       │          │  • 速率限制       │
                    │  • 共享传播       │          │  • 时间窗口       │
                    └───────┬──────────┘          └──────────────────┘
                            │
                    ┌───────▼──────────┐
                    │   PostgreSQL     │
                    │  (OpenFGA Store) │
                    └──────────────────┘
```

## 🚀 快速开始

### Docker Compose (推荐)

```bash
docker-compose up -d
```

这将启动：
- FastAPI 后端 (port 8000)
- OpenFGA 服务器 (port 8080, playground: 3000)
- OPA 服务器 (port 8181)
- PostgreSQL (port 5432)
- Vue.js 前端 (port 5173)

### 手动启动

```bash
# 1. 启动 OpenFGA
docker run -d -p 8080:8080 openfga/openfga run

# 2. 启动 OPA
docker run -d -p 8181:8181 -v $(pwd)/opa/policies:/policies \
    openpolicyagent/opa run --server /policies

# 3. 启动后端
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --reload

# 4. 初始化授权模型
python -m scripts.init_openfga
```

## 🧪 运行测试

```bash
cd backend
pytest tests/ -v --cov=. --cov-report=term-missing
```

## 📁 项目结构

```
team-vault/
├── backend/
│   ├── authz/
│   │   ├── __init__.py
│   │   ├── openfga_client.py   # OpenFGA SDK 封装
│   │   ├── opa_client.py       # OPA REST API 客户端
│   │   ├── middleware.py       # PEP 授权中间件
│   │   └── models.py          # 授权请求/响应模型
│   ├── models/
│   │   ├── __init__.py
│   │   ├── database.py
│   │   ├── organization.py
│   │   ├── team.py
│   │   └── document.py
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── organizations.py
│   │   ├── teams.py
│   │   └── documents.py
│   ├── tests/
│   │   ├── conftest.py
│   │   ├── test_openfga_client.py
│   │   ├── test_opa_client.py
│   │   ├── test_rbac.py
│   │   ├── test_rebac.py
│   │   └── test_documents_api.py
│   ├── main.py
│   ├── config.py
│   └── requirements.txt
├── openfga/
│   ├── model.fga              # OpenFGA 授权模型 (DSL)
│   ├── model.json             # 授权模型 (JSON)
│   └── tuples.json            # 初始关系数据
├── opa/
│   └── policies/
│       ├── api_policy.rego    # API 级策略
│       └── data.json          # 策略数据
├── frontend/
├── docker-compose.yml
├── docs/
│   └── architecture.md
└── README.md
```

## 🔑 核心概念

### 双层授权架构 (ch17)

```
请求 → [OPA: 粗粒度] → [OpenFGA: 细粒度] → 资源

Layer 1 (OPA):  "这个 API 调用是否被允许？"
  - IP 白名单
  - 请求频率限制
  - 工作时间窗口
  - API 版本策略

Layer 2 (OpenFGA): "这个用户对这个资源有什么权限？"
  - 文档级读写权限
  - 组织层级继承
  - 共享链传播
```

### OpenFGA 授权模型 (ch14)

模拟 Google Drive 式权限系统：
- **Organization** → owner, admin, member
- **Team** → org (parent), lead, member
- **Folder** → org, owner, editor, viewer (继承自 org)
- **Document** → parent (folder), owner, editor, viewer, can_share

### PEP/PDP/PIP/PAP 分离 (ch17)

| 组件 | 实现 | 职责 |
|------|------|------|
| **PAP** (Policy Admin Point) | OpenFGA Model + OPA Policies | 策略定义与管理 |
| **PDP** (Policy Decision Point) | OpenFGA Server + OPA Server | 策略评估与决策 |
| **PEP** (Policy Enforcement Point) | FastAPI Middleware | 拦截请求，执行决策 |
| **PIP** (Policy Info Point) | PostgreSQL + API Context | 提供决策所需数据 |
