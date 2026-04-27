# TLS Cert Debugger

> 一个用于排查 HTTPS 证书链、CA trust store、Python `requests` / `ssl` 验证失败的小工具箱。

- 当你看到 `certificate verify failed`
- 尤其是 `unable to get local issuer certificate`
- 不要一上来就怀疑 Python、SDK、网关、人生

先把证书链看清楚。

## 🧰 脚本清单

### 1. `inspect_cert_chain.sh`

用 `openssl s_client` 拉取服务端返回的证书链，拆出每张 PEM，并打印详细字段。

默认是直连目标服务；如果你配置了显式 HTTP `CONNECT` 代理，也可以带 `--proxy host:port` 去看“代理路径上客户端实际拿到的链”：

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
- 经过显式代理后，客户端实际看到的是源站链还是代理重签链？

### 2. `tls_probe.py`

用 Python 标准库 `ssl` 和可选的 `requests` 做一次真实 TLS 连接，打印：

- Python 默认 CA 路径
- 环境变量里的 CA 覆盖项
- `certifi.where()`
- TLS 版本
- cipher suite
- peer certificate
- 可选 HTTP 响应首行

如果你传 `--proxy`，脚本会先显式建代理隧道，再在隧道上做 TLS 握手。这样 `ssl` 探针和 `requests` 探针可以尽量对齐到同一条代理路径，而不是一个走代理、一个直连。

适合回答这些问题：

- Python 当前到底信哪份 CA？
- 是系统 trust store，还是 `certifi`？
- 为什么本机能通、容器不通？
- 为什么 `curl` 能通，`requests` 不通？
- 为什么直连成功，但走代理就报 `unable to get local issuer certificate`？

### 3. `unable-local-issuer-repro/`

这是一个更完整的本地复现实验，专门演示：

- 失败场景：服务端只发 leaf cert，客户端即使信任 root CA 也会失败
- 成功场景：服务端改成发送 full chain，客户端立刻恢复正常

### 4. `mitm-proxy-repro/`

这是另一组本地复现实验，专门演示：

- 失败场景：显式 HTTPS 代理重签后，客户端不信任 proxy CA
- 失败场景：客户端已经信任 proxy root，但代理自己只发 leaf、不发 intermediate
- 成功场景：客户端信任 proxy root，代理也发 full chain，请求恢复正常

它适合解释另一类经常被误判的情况：

> 源站证书可能没问题，但客户端真正看到的是代理链，不是源站链。

## 快速开始

### 先用 Poetry 安装依赖

```bash
cd project/tls-cert-debugger
poetry install
```

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

如果你想看经过显式代理后的证书链：

```bash
bash inspect_cert_chain.sh internal.example.com 443 /tmp/my-cert-debug \
  --proxy proxy.example.com:8080
```

如果只是想先确认实际会调用什么 `openssl` 命令：

```bash
bash inspect_cert_chain.sh internal.example.com 443 /tmp/my-cert-debug \
  --proxy proxy.example.com:8080 \
  --dry-run
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

如果你想让 `ssl` 和 `requests` 都走同一个显式代理路径：

```bash
poetry run python tls_probe.py \
  --host internal.example.com \
  --port 443 \
  --path /api/v1/health \
  --proxy http://proxy.example.com:8080 \
  --requests-check
```

如果你的代理入口本身也是 TLS：

```bash
poetry run python tls_probe.py \
  --host internal.example.com \
  --proxy https://proxy.example.com:8443 \
  --requests-check
```

> 提示：`requests` 自己会吃 `HTTPS_PROXY` / `HTTP_PROXY` 环境变量，但 `tls_probe.py` 里的原生 `ssl` 探针只有在你显式传 `--proxy` 时才会走代理。  
> 如果你想对比同一条链路，最好显式传 `--proxy`，不要只依赖环境变量。

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

### 场景四：跑一个 MITM 代理重签复现实验

```bash
cd mitm-proxy-repro
bash generate_proxy_certs.sh
poetry run python compare_proxy_cases.py
```

如果你想手工演示，也可以分别启动：

- `poetry run python origin_https_server.py`
- `poetry run python mitm_https_proxy.py --certfile certs/proxy-leaf.pem --mode leaf-only`
- `poetry run python reproduce_proxy_ssl_error.py --proxy http://127.0.0.1:8081 --verify certs/proxy-root-ca.pem`

## 推荐排查顺序

我更推荐按这个顺序查：

1. **先跑 `inspect_cert_chain.sh`**  
   看当前路径上对客户端发证书的那一跳，是不是把证书链发完整了。

2. **再跑 `tls_probe.py`**  
   看 Python 运行时到底在信哪份 CA，以及 `ssl` / `requests` 是不是走了同一条代理路径。

3. **最后才去翻业务 SDK 或应用代码**  
   不然很容易在错误的层级里打转。

一句话说：

> 先证书链，后 trust store，再看业务代码。  
> 别倒过来。

## 经过代理时怎么判断问题归属

看到 `unable to get local issuer certificate` 时，关键不是先问“有没有代理”，而是先问：

> 当前到底是谁在给客户端发证书？

### 场景 A：直连，或者代理只是纯 `CONNECT` 隧道

- 客户端最终看到的仍然是源站证书链
- `issuer` 通常还是公网 CA 或你原本预期的内部 CA
- 这时如果报 `unable to get local issuer certificate`，更常见是：
  - 源站没把 intermediate CA 发完整
  - 客户端本地 trust store 不认识对应 root CA

### 场景 B：代理做了 TLS 解密 / 重签名 / SSL inspection

- 客户端实际校验的是代理发出的证书链，不再是源站原始链
- `issuer` 往往会变成公司内部 Proxy CA / Web Proxy CA
- 这时报错通常优先记代理路径的账：
  - 代理重签 CA 不在客户端 trust store 里
  - 代理只发了 leaf，没有把 intermediate 一起发出来
  - 代理链顺序不对，或者代理本身证书配置有问题

### 场景 C：只有某些客户端失败

- 本机成功、容器失败
- `requests` 成功、原生 `ssl` 失败
- 这通常说明“链路本身”未必有问题，而是不同运行时看到的 trust store、代理配置或环境变量不一致

一句话总结：

- 不解密的代理，通常还是记源站或客户端 trust store 的账
- 做 MITM 重签的代理，通常优先记代理节点的账
- 想下判断前，先抓“客户端实际收到的链”，不要只看你以为的源站链

## 排查检查点

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
- 配了代理后 `issuer` 变成公司 Proxy CA：客户端实际在校验代理链，不是源站链
- 直连成功、走代理失败：优先检查代理重签 CA 是否受信任，以及代理是否发了 full chain
- `verify=False` 成功不等于修好了，只能说明验证链路有问题

## 安全提醒

- 不要把 `verify=False` 当正式修复
- 不要为了临时排查把代理账号密码直接粘到共享终端或日志里
- 不要在日志里打印敏感域名、路径、token 或完整证书内容
- 不要把临时下载的 CA 文件四处拷来拷去，最好纳入配置管理

## 目录结构

```text
tls-cert-debugger/
├── pyproject.toml          # Poetry project definition
├── poetry.toml             # Poetry local config (.venv in project)
├── inspect_cert_chain.sh   # 拉取并查看服务端证书链详情
├── tls_probe.py            # 从 Python 运行时视角做 TLS / CA 诊断
├── mitm-proxy-repro/
│   ├── generate_proxy_certs.sh
│   ├── origin_https_server.py
│   ├── mitm_https_proxy.py
│   ├── reproduce_proxy_ssl_error.py
│   ├── compare_proxy_cases.py
│   └── README.md
├── unable-local-issuer-repro/
│   ├── generate_test_certs.sh
│   ├── https_server.py
│   ├── reproduce_ssl_error.py
│   ├── compare_success_vs_failure.py
│   └── README.md
└── README.md
```

## 参考资料

- Python 官方文档：[`ssl` module](https://docs.python.org/3/library/ssl.html)
- Requests 官方文档：[`SSL Cert Verification`](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification)
- urllib3 官方文档：[`Custom TLS Certificates`](https://urllib3.readthedocs.io/en/stable/advanced-usage.html#custom-ssl-certificates)
- OpenSSL 文档：[`openssl s_client`](https://docs.openssl.org/3.4/man1/openssl-s_client/)
- 项目作者的安全工程手册：[walterfan/security-handbook](https://github.com/walterfan/security-handbook)
