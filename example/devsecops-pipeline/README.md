# DevSecOps Pipeline — 安全流水线

> 示例项目四：演示 DevSecOps 安全扫描流水线，覆盖本书第五部分核心知识点

## 📖 章节对照

| 功能模块 | 对应章节 |
|---------|---------|
| Spring Security / FastAPI 安全配置 | ch25 安全框架 |
| OWASP API Top 10 检查 | ch26 API 安全 |
| Vault 密钥扫描 | ch27 密钥管理 |
| 容器镜像扫描 (4C 模型) | ch28 云原生安全 |
| SAST / SCA / DAST / 容器扫描 | ch29 DevSecOps |
| 未来趋势 (Passkey, DID, ZKP) | ch30 未来展望 |

## 🏗️ 架构

```
  ┌─────────────────────────────────────────────────────────────┐
  │                    DevSecOps Pipeline                        │
  │                                                             │
  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌──────────────┐  │
  │  │  SAST   │  │  SCA    │  │  DAST   │  │  Container   │  │
  │  │ (Bandit │  │(Safety/ │  │ (ZAP   │  │  Scan        │  │
  │  │  Semgrep│  │ pip-    │  │  Proxy) │  │  (Trivy)     │  │
  │  │  )      │  │ audit)  │  │         │  │              │  │
  │  └────┬────┘  └────┬────┘  └────┬────┘  └──────┬───────┘  │
  │       │            │            │               │          │
  │       ▼            ▼            ▼               ▼          │
  │  ┌─────────────────────────────────────────────────────┐   │
  │  │              Report Aggregator                       │   │
  │  │  • SARIF format output                              │   │
  │  │  • Severity classification                          │   │
  │  │  • Quality gate (pass/fail)                         │   │
  │  └─────────────────────────────────────────────────────┘   │
  │                         │                                   │
  │                         ▼                                   │
  │  ┌─────────────────────────────────────────────────────┐   │
  │  │              GitHub Actions / CI                     │   │
  │  │  • PR check (block merge on critical findings)      │   │
  │  │  • Nightly full scan                                │   │
  │  │  • Release gate                                     │   │
  │  └─────────────────────────────────────────────────────┘   │
  └─────────────────────────────────────────────────────────────┘
```

## 🚀 快速开始

```bash
# Install dependencies
pip install -r requirements.txt

# Run all scans on the sample app
python -m pipeline.runner --target ./sample-app --output ./reports

# Run individual scanners
python -m scanners.sast.bandit_scanner --target ./sample-app/src
python -m scanners.sca.dependency_scanner --target ./sample-app
python -m scanners.container.trivy_scanner --image sample-app:latest

# View report
cat reports/summary.json
```

## 🧪 运行测试

```bash
pytest tests/ -v
```

## 📁 项目结构

```
devsecops-pipeline/
├── pipeline/
│   ├── runner.py              # 流水线编排器
│   ├── quality_gate.py        # 质量门禁 (pass/fail 判定)
│   ├── report_aggregator.py   # 报告聚合 (SARIF)
│   └── stages/
│       ├── __init__.py
│       ├── sast_stage.py      # SAST 阶段
│       ├── sca_stage.py       # SCA 阶段
│       ├── dast_stage.py      # DAST 阶段
│       └── container_stage.py # 容器扫描阶段
├── scanners/
│   ├── sast/
│   │   └── bandit_scanner.py  # Bandit (Python SAST)
│   ├── sca/
│   │   └── dependency_scanner.py  # pip-audit / Safety
│   ├── dast/
│   │   └── zap_scanner.py     # OWASP ZAP
│   └── container/
│       └── trivy_scanner.py   # Trivy 容器扫描
├── sample-app/                # 示例被扫描应用
│   ├── src/
│   │   └── app.py             # 包含故意的安全问题
│   ├── tests/
│   │   └── test_app.py
│   ├── requirements.txt
│   └── Dockerfile
├── tests/
│   ├── test_quality_gate.py
│   ├── test_report_aggregator.py
│   └── test_scanners.py
├── .github/
│   └── workflows/
│       └── security-scan.yml  # GitHub Actions 工作流
├── requirements.txt
├── docs/
│   └── architecture.md
└── README.md
```

## 🔒 扫描类型说明 (ch29)

| 扫描类型 | 工具 | 检测内容 | 阶段 |
|---------|------|---------|------|
| **SAST** | Bandit, Semgrep | SQL 注入、硬编码密钥、不安全函数 | 编码/PR |
| **SCA** | pip-audit, Safety | 已知漏洞依赖 (CVE) | 编码/构建 |
| **DAST** | OWASP ZAP | XSS、CSRF、认证绕过 | 测试/预发布 |
| **Container** | Trivy | 镜像漏洞、配置错误 | 构建/部署 |
| **Secret** | detect-secrets | 泄露的密钥、Token | 编码/PR |
