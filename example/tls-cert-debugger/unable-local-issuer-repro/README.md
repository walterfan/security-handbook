# Reproduce `unable to get local issuer certificate`

这个示例用一个最小本地实验，把下面这件事演清楚：

> 客户端明明信任 root CA，为什么访问 HTTPS 服务时，还是会报  
> `certificate verify failed: unable to get local issuer certificate`

核心原因是：

- 证书链是 `root CA -> intermediate CA -> server cert`
- 客户端信任的是 `root CA`
- 但服务端如果只发送 leaf certificate，不把 intermediate certificate 一起带上
- 客户端就没法从 leaf 一路走到 root
- 验证失败

这不是 Python 矫情，也不是 `requests` 故障。  
很多时候，就是服务端证书链没发全。

## 📁 文件说明

- `generate_test_certs.sh`：生成演示用 `root / intermediate / server` 证书链
- `https_server.py`：启动本地 HTTPS 服务，默认只发送 leaf cert
- `reproduce_ssl_error.py`：用 `requests` 访问本地服务，稳定复现错误
- `compare_success_vs_failure.py`：一键对比失败场景和修复场景
- `.gitignore`：忽略生成的 `certs/`、`__pycache__/`

## 🔗 证书链关系

```text
root CA
  └── intermediate CA
        └── server cert (localhost / 127.0.0.1)
```

## 🚀 快速开始

这组脚本位于上一级 `tls-cert-debugger` Poetry 项目中。先在项目根目录安装依赖：

```bash
cd example/tls-cert-debugger
poetry install
```

然后再进入这个子目录运行示例。  
`requests` 会由 Poetry 安装；即便某个环境里没有它，脚本也能自动退回到 Python 标准库。

### 1. 生成证书

```bash
cd example/tls-cert-debugger/unable-local-issuer-repro
bash generate_test_certs.sh
```

生成后会得到：

- `certs/root-ca.pem`
- `certs/intermediate-ca.pem`
- `certs/server.pem`
- `certs/server-fullchain.pem`
- `certs/server.key`

### 2. 启动错误场景：服务端只发 leaf cert

```bash
poetry run python https_server.py
```

默认行为就是加载：

- `certs/server.pem`

也就是只发 leaf certificate，不带 intermediate。

### 3. 在另一个终端复现错误

```bash
poetry run python reproduce_ssl_error.py
```

客户端会：

- 请求 `https://127.0.0.1:4443/api/v1/demo-secret`
- 使用 `certs/root-ca.pem` 作为受信任 CA

预期结果是：

```text
SSLCertVerificationError: unable to get local issuer certificate
```

这就证明了一件事：

> **客户端认识 root CA，不代表链一定能验通。**

如果中间那张 intermediate cert 没拿到，链还是断的。

## ✅ 证明修复：改成 full chain

### 方式一：手工切换服务端证书

先停掉当前服务，再启动：

```bash
poetry run python https_server.py --certfile certs/server-fullchain.pem
```

这次服务端会发：

- leaf cert
- intermediate cert

然后再跑：

```bash
poetry run python reproduce_ssl_error.py --expect-success
```

这次应该成功返回 `HTTP 200`。

## 🧪 一键对比 failure vs success

如果你不想手工开两个终端，直接跑：

```bash
poetry run python compare_success_vs_failure.py
```

这个脚本会顺序做两件事：

1. 启动一个 leaf-only 服务端，证明客户端失败
2. 启动一个 fullchain 服务端，证明客户端成功

如果两步都符合预期，脚本返回 `0`。

## 🔍 建议你观察的检查点

### 错误场景

- 服务端只发送一张 cert
- leaf cert 的 `issuer` 是 intermediate CA
- 客户端信任 root CA，但看不到 intermediate CA
- `requests` 报 `unable to get local issuer certificate`

### 修复场景

- 服务端发送 leaf + intermediate
- 客户端仍然只信任 root CA
- 这次能从 leaf -> intermediate -> root 走完整条链
- 请求成功

## 🔧 配合 `inspect_cert_chain.sh` 一起看更直观

如果你想把服务端实际发出来的证书看得更清楚，可以配合上一级目录里的脚本：

```bash
cd ..
bash inspect_cert_chain.sh 127.0.0.1 4443
```

你会很直观地看到：

- 失败场景只发了 leaf cert
- 成功场景发了 full chain

## ⚠️ 安全提醒

- 这里生成的是本地教学证书，只用于演示
- 不要把 `verify=False` 当修复方案
- 不要把这个 demo 里的证书生成方式直接照搬到生产

## 📚 适合配合阅读的资料

- Python 官方文档：[`ssl` module](https://docs.python.org/3/library/ssl.html)
- Requests 官方文档：[`SSL Cert Verification`](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification)
- OpenSSL 文档：[`openssl s_client`](https://docs.openssl.org/3.4/man1/openssl-s_client/)
- 安全工程手册项目主页：[walterfan/security-handbook](https://github.com/walterfan/security-handbook)
