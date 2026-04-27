# Reproduce MITM Proxy TLS Failures

这个本地实验专门演示一类很容易被误判的问题：

> 源站证书也许完全正常，但显式 HTTPS 代理做了 TLS interception / 重签名后，  
> 客户端实际校验的是代理发出来的证书链。  
> 这时出现 `certificate verify failed: unable to get local issuer certificate`，问题可能根本不在源站。

它和上一级的 `unable-local-issuer-repro/` 是两种不同教学模型：

- `unable-local-issuer-repro/` 讲的是“源站自己没把 intermediate 发全”
- `mitm-proxy-repro/` 讲的是“代理重签后，客户端看到的是代理链，不再是源站链”

## 这个实验演示什么

一条本地链路里会有两个独立的证书体系：

```text
client
  -> explicit CONNECT proxy
       -> origin HTTPS server
```

### Origin 证书体系

```text
origin root CA
  └── origin intermediate CA
        └── origin server cert
```

### Proxy 证书体系

```text
proxy root CA
  └── proxy intermediate CA
        └── proxy leaf cert
```

客户端通过显式代理访问源站时，真正看到的是 **proxy leaf / proxy intermediate / proxy root** 这条链，而不是 origin 那条链。

## 三个场景

### 失败场景 1：proxy CA 不受信

- 代理发的是完整 proxy chain
- 客户端却只信 `origin-root-ca.pem`
- 结果：TLS 在代理这一跳就失败，根本没走到“信任源站”的阶段

### 失败场景 2：proxy 只发 leaf，不发 intermediate

- 客户端已经信任 `proxy-root-ca.pem`
- 但代理只发 `proxy-leaf.pem`
- 结果：客户端拿不到 `proxy intermediate`，照样会报 `unable to get local issuer certificate`

### 成功场景：proxy full chain + client 信任 proxy root

- 客户端信任 `proxy-root-ca.pem`
- 代理发 `proxy-leaf-fullchain.pem`
- 请求成功返回 `HTTP 200`

## 文件说明

- `generate_proxy_certs.sh`：生成 origin/proxy 两套本地证书链
- `origin_https_server.py`：本地源站 HTTPS 服务
- `mitm_https_proxy.py`：本地显式 `CONNECT` MITM 代理
- `reproduce_proxy_ssl_error.py`：通过代理访问源站，复现或验证结果
- `compare_proxy_cases.py`：一键按顺序跑三种场景
- `.gitignore`：忽略 `certs/`、`__pycache__/`

## 快速开始

先在上一级 Poetry 项目里安装依赖：

```bash
cd project/tls-cert-debugger
poetry install
```

然后进入这个目录：

```bash
cd mitm-proxy-repro
```

### 1. 生成证书

```bash
bash generate_proxy_certs.sh
```

会生成这些关键文件：

- `certs/origin-root-ca.pem`
- `certs/origin-intermediate-ca.pem`
- `certs/origin-server.pem`
- `certs/origin-server-fullchain.pem`
- `certs/origin-server.key`
- `certs/proxy-root-ca.pem`
- `certs/proxy-intermediate-ca.pem`
- `certs/proxy-leaf.pem`
- `certs/proxy-leaf-fullchain.pem`
- `certs/proxy-leaf.key`

### 2. 一键跑完三种场景

```bash
poetry run python compare_proxy_cases.py
```

预期会按顺序看到：

1. `Failure case: proxy CA not trusted`
2. `Failure case: proxy leaf only`
3. `Success case: proxy full chain`

最后输出：

```text
Comparison finished successfully.
```

## 手工分步演示

如果你想自己开几个终端看得更清楚，可以分步跑。

### 步骤 1：启动 origin server

```bash
poetry run python origin_https_server.py
```

默认监听：

- `https://127.0.0.1:4443`

### 步骤 2：启动 leaf-only 代理

```bash
poetry run python mitm_https_proxy.py \
  --target-host 127.0.0.1 \
  --target-port 4443 \
  --certfile certs/proxy-leaf.pem \
  --mode leaf-only
```

### 步骤 3：客户端通过代理访问

```bash
poetry run python reproduce_proxy_ssl_error.py \
  --url https://127.0.0.1:4443/api/v1/demo-secret \
  --proxy http://127.0.0.1:8081 \
  --verify certs/proxy-root-ca.pem
```

预期会失败，并看到：

```text
unable to get local issuer certificate
```

### 切换到成功场景

停掉当前代理，改为：

```bash
poetry run python mitm_https_proxy.py \
  --target-host 127.0.0.1 \
  --target-port 4443 \
  --certfile certs/proxy-leaf-fullchain.pem \
  --mode fullchain
```

然后再跑：

```bash
poetry run python reproduce_proxy_ssl_error.py \
  --url https://127.0.0.1:4443/api/v1/demo-secret \
  --proxy http://127.0.0.1:8081 \
  --verify certs/proxy-root-ca.pem \
  --expect-success
```

这次应该返回 `HTTP 200`。

## 建议观察的检查点

### 失败场景 1：proxy CA 不受信

- 代理对客户端发的是 proxy 证书
- 客户端却只信 origin root
- 失败点发生在“client -> proxy”这条 TLS 链路

### 失败场景 2：proxy leaf only

- 客户端已经信 proxy root
- 但代理没把 proxy intermediate 发出来
- 失败点是 proxy 自己的链不完整

### 成功场景

- client 信 proxy root
- proxy 发 full chain
- 同一个 origin、同一个 URL、同一条代理路径就可以成功

## 它和源站缺链实验的区别

如果你把这个实验和上一级 `unable-local-issuer-repro/` 放在一起看，会更容易区分：

- 一个是 **源站** 没发 intermediate
- 一个是 **代理** 重签后链不受信或没发完整

同样是 `unable to get local issuer certificate`，责任点完全可以不一样。

## 安全提醒

- 这里生成的是本地教学证书，只用于演示
- 代理默认只建议绑定在 loopback 地址
- 不要把 `verify=False` 当修复方案
- 不要把这套证书或代理代码直接搬到生产环境
