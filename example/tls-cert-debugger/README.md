# TLS Cert Debugger

> 一个用于排查 HTTPS 证书链、CA trust store、Python `requests` / `ssl` 验证失败的小工具箱。

这个示例项目对应《安全工程手册》里与 PKI / X.509 / TLS 相关的几章，目标很朴素：

- 当你看到 `certificate verify failed`
- 尤其是 `unable to get local issuer certificate`
- 不要一上来就怀疑 Python、SDK、网关、人生

先把证书链看清楚。

## 📖 章节对照

| 脚本 / 主题 | 对应章节 |
|------------|---------|
| 证书链获取与拆解 | ch03 PKI 与证书体系 |
| TLS 握手与服务端证书校验 | ch06 TLS 协议深入解析 |
| Python 运行时 CA / `requests` 排查 | ch25 安全框架与库实战 |

## 🧰 脚本清单

### 1. `inspect_cert_chain.sh`

用 `openssl s_client` 拉取服务端返回的证书链，拆出每张 PEM，并打印详细字段：

- `subject`
- `issuer`
- `serial`
- `notBefore / notAfter`
- `SHA256 fingerprint`
- `subjectAltName`
- `authorityKeyIdentifier`
- `subjectKeyIdentifier`
- `basicConstraints`
- `keyUsage`
- `extendedKeyUsage`
- `authorityInfoAccess`

适合回答这些问题：

- 服务端到底发了几张证书？
- 有没有发 intermediate CA？
- leaf cert 的 `issuer` 是谁？
- SAN 里有没有目标域名？
- 证书有没有过期？

### 2. `tls_probe.py`

用 Python 标准库 `ssl` 和可选的 `requests` 做一次真实 TLS 连接，打印：

- Python 默认 CA 路径
- 环境变量里的 CA 覆盖项
- `certifi.where()`
- TLS 版本
- cipher suite
- peer certificate
- 可选 HTTP 响应首行

适合回答这些问题：

- Python 当前到底信哪份 CA？
- 是系统 trust store，还是 `certifi`？
- 为什么本机能通、容器不通？
- 为什么 `curl` 能通，`requests` 不通？

### 3. `unable-local-issuer-repro/`

这是一个更完整的本地复现实验，专门演示：

- 失败场景：服务端只发 leaf cert，客户端即使信任 root CA 也会失败
- 成功场景：服务端改成发送 full chain，客户端立刻恢复正常

适合教学、写书、做 demo，也适合拿来解释“为什么 `unable to get local issuer certificate` 往往不是客户端代码本身的锅”。

## 🚀 快速开始

### 先用 Poetry 安装依赖

```bash
cd example/tls-cert-debugger
poetry install
```

这个目录现在用 Poetry 管理 Python 依赖。默认会在项目内创建 `.venv/`，方便你在 `security-handbook` 里单独维护这一组脚本。

### 前置条件

- macOS / Linux
- OpenSSL 1.1.1+ 或 3.x
- Python 3.10+
- Poetry 2.x

### 给脚本执行权限

```bash
chmod +x inspect_cert_chain.sh
```

### 场景一：先看服务端到底发了什么证书

```bash
bash inspect_cert_chain.sh internal.example.com
```

如果目标不是 443：

```bash
bash inspect_cert_chain.sh internal.example.com 8443
```

如果你想把输出落到固定目录：

```bash
bash inspect_cert_chain.sh internal.example.com 443 /tmp/my-cert-debug
```

### 场景二：从 Python 侧检查 TLS 和 CA

如果你想看默认 trust store：

```bash
poetry run python tls_probe.py \
  --host internal.example.com \
  --port 443 \
  --path /
```

如果你想指定 CA bundle：

```bash
poetry run python tls_probe.py \
  --host internal.example.com \
  --port 443 \
  --path /api/v1/health \
  --cafile /path/to/custom-ca-bundle.pem \
  --requests-check
```

### 场景三：跑一个完整的本地 failure vs success 复现实验

```bash
cd unable-local-issuer-repro
bash generate_test_certs.sh
poetry run python compare_success_vs_failure.py
```

如果你想手工分两步演示，也可以：

```bash
cd unable-local-issuer-repro
bash generate_test_certs.sh
poetry run python https_server.py
```

然后在另一个终端：

```bash
poetry run python reproduce_ssl_error.py
```

切到修复场景：

```bash
poetry run python https_server.py --certfile certs/server-fullchain.pem
poetry run python reproduce_ssl_error.py --expect-success
```

## 🔍 推荐排查顺序

我更推荐按这个顺序查：

1. **先跑 `inspect_cert_chain.sh`**  
   看服务端是不是把证书链发完整了。

2. **再跑 `tls_probe.py`**  
   看 Python 运行时到底在信哪份 CA。

3. **最后才去翻业务 SDK 或应用代码**  
   不然很容易在错误的层级里打转。

一句话说：

> 先证书链，后 trust store，再看业务代码。  
> 别倒过来。

## ✅ 排查检查点

### 证书链检查点

- `cert-1` 通常是 leaf cert
- `issuer(cert-1)` 是否等于 `subject(cert-2)`
- 服务端有没有发 intermediate CA
- 服务端不发 root CA 并不一定有问题，root 往往应由客户端本地信任
- 证书顺序是不是 `leaf -> intermediate -> ...`

### 证书内容检查点

- `subjectAltName` 里有没有目标域名
- `notAfter` 有没有过期
- leaf 是否 `CA:FALSE`
- intermediate 是否 `CA:TRUE`
- leaf 是否包含 `serverAuth`
- `Authority Key Identifier` 与上一级 `Subject Key Identifier` 是否大致对应

### 客户端环境检查点

- Python 默认 CA 路径是什么
- `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` 有没有覆盖
- `certifi.where()` 指向哪份 CA bundle
- 本机与容器是不是用了不同的 trust store

### 结论判断检查点

- 只发 leaf，不发 intermediate：优先记服务端的账
- 服务端链完整，但指定自家 CA bundle 后才成功：客户端不认识 root CA
- 本机成功、容器失败：运行环境 trust store 不一致
- `verify=False` 成功不等于修好了，只能说明验证链路有问题

## ⚠️ 安全提醒

- 不要把 `verify=False` 当正式修复
- 不要在日志里打印敏感域名、路径、token 或完整证书内容
- 不要把临时下载的 CA 文件四处拷来拷去，最好纳入配置管理

## 📁 目录结构

```text
tls-cert-debugger/
├── pyproject.toml          # Poetry project definition
├── poetry.toml             # Poetry local config (.venv in project)
├── inspect_cert_chain.sh   # 拉取并查看服务端证书链详情
├── tls_probe.py            # 从 Python 运行时视角做 TLS / CA 诊断
├── unable-local-issuer-repro/
│   ├── generate_test_certs.sh
│   ├── https_server.py
│   ├── reproduce_ssl_error.py
│   ├── compare_success_vs_failure.py
│   └── README.md
└── README.md
```

## 📚 参考资料

- Python 官方文档：[`ssl` module](https://docs.python.org/3/library/ssl.html)
- Requests 官方文档：[`SSL Cert Verification`](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification)
- urllib3 官方文档：[`Custom TLS Certificates`](https://urllib3.readthedocs.io/en/stable/advanced-usage.html#custom-ssl-certificates)
- OpenSSL 文档：[`openssl s_client`](https://docs.openssl.org/3.4/man1/openssl-s_client/)
- 项目作者的安全工程手册：[walterfan/security-handbook](https://github.com/walterfan/security-handbook)
