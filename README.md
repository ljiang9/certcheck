# certcheck

查域名 TLS 证书还有多少天过期的小工具。域名进，剩余天数出。

纯 Python 标准库（`ssl` / `socket` / `argparse` / `json` / `datetime`），零依赖，离线逻辑、只做网络握手。

## 安装

```bash
git clone https://github.com/ljiang9/certcheck.git
cd certcheck
python3 -m certcheck --help   # 无需安装，直接跑
```

## 用法

```bash
# 查一个或多个域名
python3 -m certcheck example.com github.com

# 从文件批量查（每行一个，# 开头是注释）
python3 -m certcheck --file examples/domains.txt

# 自定义告警阈值：剩余 <= 14 天标 ⚠️
python3 -m certcheck example.com --warn 14

# JSON 输出（给脚本/监控用）
python3 -m certcheck example.com --json

# 连接超时 5 秒
python3 -m certcheck example.com --timeout 5

# 内网非标端口的服务
python3 -m certcheck 10.0.0.5 --port 8443
```

输出示例：

```
  域名           颁发者          过期时间            剩余天数  状态
  ------------------------------------------------------------
  example.com   DigiCert ...  2027-01-13 23:59 UTC     465 天  ✅ ok
  github.com    DigiCert ...  2026-12-23 23:59 UTC      79 天  ✅ ok

共检查 2 个域名：2 正常，0 异常
```

## 退出码（给 CI / Nagios 用）

| 退出码 | 含义 |
|---|---|
| 0 | 全部正常（剩余天数都大于阈值） |
| 1 | 有证书已过期 / 连不上 / 剩余天数触及阈值 |
| 2 | 用法错误（没给域名、文件读不到、参数非法） |

## 设计说明

- **SNI**：握手时带 `server_hostname`，CDN 后面的多域名主机也能查对证书。
- **IPv6 回退**：`getaddrinfo` 返回的地址逐个尝试，v6 不通自动换 v4。
- **代理感知**：直连失败时，若环境里有 `HTTPS_PROXY`/`https_proxy`，自动改走 HTTP CONNECT 隧道（带代理鉴权），公司内网/沙箱出口也能用。
- **只查叶子证书**：取 TLS 握手时对方出示的 DER 证书，用纯标准库的最小 DER 解析器提取颁发者 CN 和 `notAfter`（不依赖 `getpeercert()` 的 dict 形式——关闭校验时它可能是空的），不验证完整证书链。
- **默认不校验证书有效性**：已过期/自签名的证书也能读出颁发者和过期时间——这正是过期检查工具该有的行为（`openssl s_client` 同理）。本工具只"读出示的证书"，不做身份认证。

## 诚实说明（局限）

- 只检查**叶子证书**的过期时间，不检查中间证书/根证书是否过期，也不做 **OCSP/CRL** 吊销检查——证书被吊销了这里查不出来。
- 只走 **HTTPS(443)**，不支持 SMTP/IMAP 的 STARTTLS。
- 某些做了客户端证书或特殊 TLS 指纹策略的站点可能握手失败，会被记为"不可达"，不代表证书真的有问题。
- 剩余天数按 UTC 计算，精确到 0.1 天；表格里显示整数天。
- 注意：如果你的出口有做 TLS 中间人检查的代理/网关（如公司上网行为管理），你看到的将是**代理签发的证书**而不是源站的——剩余天数以源站直连为准。
