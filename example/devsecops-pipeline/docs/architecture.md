# DevSecOps Pipeline 架构文档

## 1. 概述

DevSecOps Pipeline 是一个自动化安全扫描流水线，将安全检查集成到 CI/CD 流程中，
实现"安全左移"(Shift-Left Security)。

## 2. 扫描阶段 (ch29)

```
  代码提交 → PR 创建 → 安全扫描 → 质量门禁 → 合并/拒绝
                          │
                          ▼
              ┌───────────────────────┐
              │    Pipeline Runner    │
              │   (编排器)             │
              └───────────┬───────────┘
                          │
          ┌───────┬───────┼───────┬───────┐
          ▼       ▼       ▼       ▼       ▼
       ┌──────┐┌──────┐┌──────┐┌──────┐┌──────┐
       │ SAST ││ SCA  ││Secret││Docker││ DAST │
       │      ││      ││ Det. ││ Scan ││      │
       └──┬───┘└──┬───┘└──┬───┘└──┬───┘└──┬───┘
          │       │       │       │       │
          ▼       ▼       ▼       ▼       ▼
       ┌─────────────────────────────────────┐
       │       Report Aggregator (SARIF)     │
       └──────────────┬──────────────────────┘
                      │
                      ▼
       ┌─────────────────────────────────────┐
       │         Quality Gate                │
       │  • 0 Critical (阻断)               │
       │  • ≤5 High (警告)                  │
       │  • ≤20 Medium (记录)               │
       └──────────────┬──────────────────────┘
                      │
              ┌───────┴───────┐
              ▼               ▼
          ✅ PASS          ❌ FAIL
          允许合并          阻断合并
```

## 3. 扫描类型详解

### 3.1 SAST — 静态应用安全测试

| 工具 | 语言 | 检测能力 |
|------|------|---------|
| Bandit | Python | SQL注入、eval/exec、硬编码密钥、不安全哈希 |
| Semgrep | 多语言 | 自定义规则、OWASP Top 10 |
| 内置扫描器 | Python | 基础模式匹配 (无需外部工具) |

**检测示例**:
```python
# B307: Use of eval() — CWE-95
result = eval(user_input)  # ❌ 危险

# B608: SQL Injection — CWE-89
query = f"SELECT * FROM users WHERE id = '{user_id}'"  # ❌ 危险

# 安全写法
result = ast.literal_eval(user_input)  # ✅
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # ✅
```

### 3.2 SCA — 软件成分分析

| 工具 | 数据源 | 特点 |
|------|--------|------|
| pip-audit | OSV/PyPI | 官方推荐，准确率高 |
| Safety | Safety DB | 商业数据库，覆盖广 |

**工作原理**:
1. 解析 requirements.txt / pyproject.toml
2. 查询 CVE 数据库 (NVD, OSV, GitHub Advisory)
3. 匹配已安装版本与已知漏洞
4. 建议升级版本

### 3.3 Secret Detection — 密钥检测

检测模式:
- API Key: `api_key = "sk-..."`
- AWS Key: `AKIA...` (20字符)
- Private Key: `-----BEGIN PRIVATE KEY-----`
- Password: `password = "..."`

**最佳实践** (ch27):
- 使用 Vault 管理密钥
- 环境变量注入
- .gitignore 排除敏感文件
- pre-commit hook 阻止提交

### 3.4 Container Scan — 容器扫描

| 检查项 | 规则ID | 严重性 |
|--------|--------|--------|
| 使用 latest 标签 | DS001 | Medium |
| 以 root 运行 | DS002 | High |
| 缺少 HEALTHCHECK | DS004 | Low |
| ADD 代替 COPY | DS005 | Low |
| OS 包漏洞 | CVE-* | Varies |

**4C 安全模型** (ch28):
```
Cloud (云平台安全)
  └── Cluster (集群安全)
       └── Container (容器安全) ← 本扫描器
            └── Code (代码安全) ← SAST/SCA
```

### 3.5 DAST — 动态应用安全测试

| 检查项 | 对应 OWASP API Top 10 |
|--------|----------------------|
| SQL 注入 | API8: Security Misconfiguration |
| XSS | API8: Security Misconfiguration |
| 认证绕过 | API2: Broken Authentication |
| 过度数据暴露 | API3: Excessive Data Exposure |
| 缺少速率限制 | API4: Lack of Resources & Rate Limiting |

## 4. 质量门禁配置

```python
# 默认配置
QualityGateConfig(
    max_critical=0,    # 零容忍：任何 Critical 都阻断
    max_high=5,        # 允许最多 5 个 High
    max_medium=20,     # 允许最多 20 个 Medium
    max_low=-1,        # Low 不限制
)

# 严格模式 (发布前)
QualityGateConfig(
    max_critical=0,
    max_high=0,
    max_medium=5,
    max_low=10,
)
```

## 5. SARIF 报告格式

所有扫描结果统一输出为 SARIF v2.1.0 格式：
- GitHub Security Tab 原生支持
- Azure DevOps 原生支持
- VS Code SARIF Viewer 插件支持

```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "bandit"}},
    "results": [{
      "ruleId": "B307",
      "level": "error",
      "message": {"text": "Use of eval()"},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "src/app.py"},
          "region": {"startLine": 42}
        }
      }]
    }]
  }]
}
```

## 6. CI/CD 集成

### GitHub Actions
- PR 检查：每次 PR 自动触发
- 夜间全量扫描：每天 UTC 2:00
- 发布门禁：手动触发，严格模式

### 本地开发
```bash
# pre-commit hook
pip install pre-commit
pre-commit install

# 手动扫描
python -m pipeline.runner --target . --output ./reports
```
