# 安全工程手册：从身份认证到零信任架构

* [中文版](./README_cn.md) | [English Version](./README.md)
* 在线阅读: [Security Handbook](https://walterfan.github.io/security-handbook)

> 本书系统性地探讨现代软件安全工程的核心主题。从基础的密码学和威胁建模，到身份认证协议（OAuth2、OIDC、JWT），
> 再到细粒度授权（OpenFGA、OPA），以及云原生时代的工作负载身份（SPIFFE/SPIRE）和零信任架构，
> 帮助每一位工程师构建安全可靠的系统。

| 属性 | 值 |
|------|------|
| **作者** | Walter Fan |
| **分类** | Security Engineering |
| **状态** | WIP |
| **许可** | CC-BY-NC-ND |

---

## 构建与发布

本书使用 Poetry 管理 Sphinx/MyST 文档依赖：

```bash
poetry install --only docs --no-root
make html
make serve
```

`make publish` 会生成 GitHub Pages artifact 到 `doc/build/html`。推送到 `master` 或 `main` 后，GitHub Actions 会自动发布到 <https://walterfan.github.io/security-handbook/>。

---

## 📖 目录

### 第一部分：安全基础

| 章节 | 标题 |
|------|------|
| 第一章 | [安全工程概论](doc/source/chapters/ch01.md) |
| 第二章 | [密码学基础](doc/source/chapters/ch02.md) |
| 第三章 | [PKI 与证书体系](doc/source/chapters/ch03.md) |
| 第四章 | [威胁建模与风险评估](doc/source/chapters/ch04.md) |
| 第五章 | [身份与访问管理（IAM）概论](doc/source/chapters/ch05.md) |

### 第二部分：身份认证 (Authentication)

| 章节 | 标题 |
|------|------|
| 第六章 | [TLS 协议深入解析](doc/source/chapters/ch06.md) |
| 第七章 | [OAuth 2.0 授权框架](doc/source/chapters/ch07.md) |
| 第八章 | [OpenID Connect 身份认证](doc/source/chapters/ch08.md) |
| 第九章 | [JWT 深入解析](doc/source/chapters/ch09.md) |
| 第十章 | [多因素认证（MFA）](doc/source/chapters/ch10.md) |
| 第十一章 | [单点登录（SSO）与联邦身份](doc/source/chapters/ch11.md) |
| 第十二章 | [API 认证模式](doc/source/chapters/ch12.md) |

### 第三部分：访问授权 (Authorization)

| 章节 | 标题 |
|------|------|
| 第十三章 | [访问控制模型](doc/source/chapters/ch13.md) |
| 第十四章 | [OpenFGA — 细粒度授权引擎](doc/source/chapters/ch14.md) |
| 第十五章 | [OPA — 通用策略引擎](doc/source/chapters/ch15.md) |
| 第十六章 | [策略即代码（Policy as Code）](doc/source/chapters/ch16.md) |
| 第十七章 | [授权架构模式](doc/source/chapters/ch17.md) |
| 第十八章 | [授权系统实战 — OpenFGA + FastAPI](doc/source/chapters/ch18.md) |

### 第四部分：工作负载身份与零信任

| 章节 | 标题 |
|------|------|
| 第十九章 | [SPIFFE — 通用工作负载身份框架](doc/source/chapters/ch19.md) |
| 第二十章 | [SPIRE — SPIFFE 的参考实现](doc/source/chapters/ch20.md) |
| 第二十一章 | [SPIFFE 联邦与跨域信任](doc/source/chapters/ch21.md) |
| 第二十二章 | [WIMSE — 多系统环境中的工作负载身份](doc/source/chapters/ch22.md) |
| 第二十三章 | [零信任架构](doc/source/chapters/ch23.md) |
| 第二十四章 | [Service Mesh 安全](doc/source/chapters/ch24.md) |

### 第五部分：实战与展望

| 章节 | 标题 |
|------|------|
| 第二十五章 | [安全框架与库实战](doc/source/chapters/ch25.md) |
| 第二十六章 | [API 安全设计](doc/source/chapters/ch26.md) |
| 第二十七章 | [密钥与凭证管理](doc/source/chapters/ch27.md) |
| 第二十八章 | [云原生安全](doc/source/chapters/ch28.md) |
| 第二十九章 | [DevSecOps — 安全左移](doc/source/chapters/ch29.md) |
| 第三十章 | [安全工程的未来](doc/source/chapters/ch30.md) |

### 附录：专题笔记

| 附录 | 标题 |
|------|------|
| 附录 | [医疗器械网络安全](doc/source/appendix/medical_software_cybersecurity.md) |

---

## 🛠️ 实战项目

本书配套 4 个实战项目，覆盖各部分核心知识点：

| 项目 | 名称 | 技术栈 | 覆盖章节 |
|------|------|--------|----------|
| [secure-note](./example/secure-note/) | SecureNote 安全笔记 | FastAPI + JWT + TOTP + AES | 第 1-12 章（密码学、TLS、OAuth2、JWT、MFA） |
| [team-vault](./example/team-vault/) | TeamVault 团队权限平台 | FastAPI + OpenFGA + OPA | 第 13-18 章（RBAC → ReBAC、双引擎授权） |
| [mesh-guard](./example/mesh-guard/) | MeshGuard 微服务安全网关 | Go + SPIRE + Envoy + Vault + OPA | 第 19-24 章（零信任、SPIFFE、Service Mesh） |
| [devsecops-pipeline](./example/devsecops-pipeline/) | DevSecOps 安全流水线 | Python + Bandit + Trivy + ZAP | 第 25-30 章（SAST、SCA、DAST、容器扫描） |

---

## 📚 核心概念

### 安全三要素 (CIA)

- **Confidentiality** — 保密性
- **Integrity** — 完整性
- **Availability** — 可用性

### 关键术语

| 术语 | 说明 |
|------|------|
| **Authentication (AuthN)** | 身份认证 — 验证用户是否为合法用户 |
| **Authorization (AuthZ)** | 访问授权 — 验证用户是否有权访问特定资源 |
| **Audit** | 审计 — 用户的访问和操作是否可追溯 |
| **Asset** | 资产 — 需要防护机制保护的关键实体 |
| **Vulnerability** | 漏洞 — 系统中可能危及安全的薄弱环节 |
| **Threat** | 威胁 — 利用漏洞危害系统安全的潜在负面行为 |
| **Risk** | 风险 — 威胁利用漏洞造成影响的可能性组合 |
| **SAST** | 静态应用安全测试 — 通过分析源代码识别潜在漏洞 |
| **DAST** | 动态应用安全测试 — 通过运行应用识别潜在漏洞 |

---

## 🔗 参考资源

### 安全测试平台

- [OWASP Benchmark](https://github.com/OWASP/Benchmark) — Java 安全测试套件
- [WebGoat](https://github.com/WebGoat/WebGoat) — Web 应用安全教学平台
- [OWASP Juice Shop](https://github.com/bkimminich/juice-shop) — 包含 OWASP Top 10 漏洞的练习应用
- [DVWA](https://github.com/digininja/DVWA) — Damn Vulnerable Web Application
- [Juliet Test Suites](https://samate.nist.gov/SARD/test-suites) — NIST 安全测试用例集

### 安全工具

- [Burp Suite](https://portswigger.net/burp) — Web 安全测试平台
- [OWASP ZAP](https://www.zaproxy.org/) — 开源 Web 应用安全扫描器
- [Kali Linux](https://www.kali.org/) — 渗透测试 Linux 发行版
- [Dependency-Check](https://jeremylong.github.io/DependencyCheck/) — 依赖漏洞检测
- [Talisman](https://github.com/thoughtworks/talisman) — Git 预提交钩子，防止敏感信息泄露

### 标准与规范

- [NIST Computer Security Resource Center](https://csrc.nist.gov/projects)
- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/)
- [CWE Top 25 (2023)](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)

---

## 📝 License

CC-BY-NC-ND

---

*作者：Walter Fan | 2026 年*
