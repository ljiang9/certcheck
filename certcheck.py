#!/usr/bin/env python3
"""certcheck —— TLS 证书过期检查：域名进，剩余天数出。

纯标准库，零依赖。只做 HTTPS(443) 握手，不检查完整证书链、不做 OCSP。

用法：
    python -m certcheck example.com github.com
    python -m certcheck --file domains.txt
    python -m certcheck example.com --warn 14 --json
"""

import argparse
import base64
import datetime as dt
import json
import os
import socket
import ssl
import sys
from urllib.parse import urlparse

VERSION = "0.1.0"


def _proxy_from_env():
    """从环境变量读 HTTPS 代理（urllib 风格），返回 (host, port, auth_header) 或 None。"""
    for key in ("HTTPS_PROXY", "https_proxy"):
        raw = os.environ.get(key)
        if raw:
            u = urlparse(raw if "://" in raw else "http://" + raw)
            auth = ""
            if u.username:
                creds = u.username + (":" + u.password if u.password else "")
                auth = "Proxy-Authorization: Basic " + base64.b64encode(
                    creds.encode()).decode() + "\r\n"
            return u.hostname, u.port or 8080, auth
    return None


def _tunnel(sock, host, port, timeout):
    """经 HTTP 代理做 CONNECT 隧道，返回已连通到目标的 socket。"""
    proxy = _proxy_from_env()
    if not proxy:
        raise ConnectionError("无可用代理")
    phost, pport, auth = proxy
    sock.settimeout(timeout)
    sock.connect((phost, pport))
    req = (f"CONNECT {host}:{port} HTTP/1.1\r\n"
           f"Host: {host}:{port}\r\n{auth}Connection: close\r\n\r\n")
    sock.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
    if " 200" not in status:
        raise ConnectionError(f"代理 CONNECT 被拒绝: {status}")
    return sock


def _raw_sockets(host, port, timeout):
    """按优先级产生候选裸连接：各直连地址在前，代理 CONNECT 隧道在后。"""
    try:
        addrs = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ConnectionError(f"DNS 解析失败: {e}") from e
    for family, socktype, proto, _canon, sockaddr in addrs:
        yield ("直连", sockaddr, family, socktype, proto)
    if _proxy_from_env():
        yield ("代理", None, None, None, None)


def fetch_cert(host, port=443, timeout=10):
    """握手并返回证书 dict。失败抛异常（带中文语境的调用方负责翻译）。"""
    ctx = ssl.create_default_context()
    # 刻意关闭校验：本工具的任务是"读出对方出示的证书"（包括已过期/自签名的），
    # 而不是确认对方身份。openssl s_client 同理默认只展示不校验。
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    last_err = None
    n = 0
    for kind, sockaddr, family, socktype, proto in _raw_sockets(host, port, timeout):
        n += 1
        raw = None
        try:
            if kind == "直连":
                raw = socket.socket(family, socktype, proto)
                raw.settimeout(timeout)
                raw.connect(sockaddr)  # 直连优先
            else:
                raw = _tunnel(socket.socket(), host, port, timeout)
            tls = ctx.wrap_socket(raw, server_hostname=host)  # SNI
            try:
                # CERT_NONE 下 dict 形式可能为空，DER 一定有：直接解析 DER
                der = tls.getpeercert(binary_form=True)
            finally:
                tls.close()
            if not der:
                raise ConnectionError("握手成功但未拿到证书")
            issuer, not_after = parse_der_cert(der)
            return {"issuer": issuer, "notAfter": not_after}
        except Exception as e:  # 建连/TLS 任一环节失败 → 换下一条路径
            last_err = e
            try:
                if raw is not None:
                    raw.close()
            except OSError:
                pass
            continue
    raise ConnectionError(f"无法与 {host}:{port} 建立 TLS（试过 {n} 条路径）: {last_err}")


def _tlv(buf, off):
    """读一个 DER TLV，返回 (tag, value_offset, next_offset)。"""
    tag = buf[off]
    off += 1
    lb = buf[off]
    off += 1
    if lb & 0x80:
        n = lb & 0x7F
        if n == 0 or n > 4:
            raise ValueError("DER 长度字段异常")
        length = int.from_bytes(buf[off:off + n], "big")
        off += n
    else:
        length = lb
    return tag, off, off + length


def _children(buf, off, end):
    """SEQUENCE/SET 的直接子元素：返回 [(tag, val_off, val_end)]。"""
    out = []
    while off < end:
        tag, voff, nxt = _tlv(buf, off)
        out.append((tag, voff, nxt))
        off = nxt
    return out


_OID_CN = b"\x55\x04\x03"  # 2.5.4.3


def _name_cn(buf, off, end):
    """从 RDNSequence 里找第一个 CN。"""
    for _t, soff, send in _children(buf, off, end):      # RDN (SET)
        for _t2, aoff, aend in _children(buf, soff, send):  # AttributeTypeAndValue (SEQ)
            atv = _children(buf, aoff, aend)
            if len(atv) < 2:
                continue
            otag, ooff, oend = atv[0]
            vtag, voff, vend = atv[1]
            if otag == 0x06 and buf[ooff:oend] == _OID_CN:
                raw = buf[voff:vend]
                if vtag == 0x1E:  # BMPString
                    return raw.decode("utf-16-be", "replace")
                return raw.decode("utf-8", "replace")
    return None


def _time(buf, tag, off, end):
    s = buf[off:end].decode("ascii")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
        year = int(s[0:2])
        year += 2000 if year < 50 else 1900
        s = f"{year}{s[2:]}"
    # GeneralizedTime: YYYYMMDDHHMMSSZ
    return dt.datetime(int(s[0:4]), int(s[4:6]), int(s[6:8]),
                       int(s[8:10]), int(s[10:12]), int(s[12:14]),
                       tzinfo=dt.timezone.utc)


def parse_der_cert(der):
    """最小 X.509 DER 解析：返回 (issuer_cn, not_after)。只够本工具用，不是通用解析器。"""
    buf = bytes(der)
    tag, off, end = _tlv(buf, 0)
    if tag != 0x30:
        raise ValueError("不是 DER 证书")
    tbs = _children(buf, off, end)[0]  # tbsCertificate
    if tbs[0] != 0x30:
        raise ValueError("tbsCertificate 缺失")
    items = _children(buf, tbs[1], tbs[2])
    i = 0
    if items[i][0] == 0xA0:  # [0] version（可选）
        i += 1
    i += 1  # serialNumber (INTEGER)
    i += 1  # signature (AlgorithmIdentifier)
    itag, ioff, iend = items[i]
    i += 1
    vtag, voff, vend = items[i]
    issuer = _name_cn(buf, ioff, iend) if itag == 0x30 else None
    validity = _children(buf, voff, vend) if vtag == 0x30 else []
    not_after = None
    if len(validity) >= 2:
        ttag, toff, tend = validity[1]
        not_after = _time(buf, ttag, toff, tend)
    if not_after is None:
        raise ValueError("证书里找不到 notAfter")
    return issuer or "?", not_after


def check_one(host, port, timeout, warn_days):
    now = dt.datetime.now(dt.timezone.utc)
    try:
        cert = fetch_cert(host, port=port, timeout=timeout)
        expires = cert["notAfter"]
        days = (expires - now).total_seconds() / 86400
        if days < 0:
            status = "expired"
            mark = "❌"
        elif days <= warn_days:
            status = "warning"
            mark = "⚠️"
        else:
            status = "ok"
            mark = "✅"
        return {
            "domain": host, "ok": status == "ok", "status": status, "mark": mark,
            "issuer": cert["issuer"],
            "expires": expires.strftime("%Y-%m-%d %H:%M UTC"),
            "days_left": round(days, 1),
            "error": None,
        }
    except Exception as e:  # 连接/DNS/TLS 失败统一记为不可达
        return {
            "domain": host, "ok": False, "status": "unreachable", "mark": "❌",
            "issuer": None, "expires": None, "days_left": None,
            "error": str(e),
        }


def render_table(results):
    w_dom = max(len(r["domain"]) for r in results)
    w_iss = max(len(r["issuer"] or "-") for r in results)
    print(f"  {'域名'.ljust(w_dom)}  {'颁发者'.ljust(w_iss)}  {'过期时间'.ljust(18)}  {'剩余天数':>8}  状态")
    print("  " + "-" * (w_dom + w_iss + 42))
    for r in results:
        if r["error"]:
            print(f"  {r['domain'].ljust(w_dom)}  {'-'.ljust(w_iss)}  {'-'.ljust(18)}  {'-':>8}  {r['mark']} {r['error'][:60]}")
        else:
            days = f"{r['days_left']:.0f} 天"
            print(f"  {r['domain'].ljust(w_dom)}  {r['issuer'].ljust(w_iss)}  "
                  f"{r['expires'].ljust(18)}  {days:>8}  {r['mark']} {r['status']}")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="certcheck",
        description="检查域名的 TLS 证书还有多少天过期（只查叶子证书，不查证书链/OCSP）。")
    ap.add_argument("domains", nargs="*", help="要检查的域名，可多个")
    ap.add_argument("--file", "-f", help="从文件逐行读取域名（# 开头为注释）")
    ap.add_argument("--warn", type=int, default=30, metavar="DAYS",
                    help="剩余天数 <= DAYS 标为警告（默认 30）")
    ap.add_argument("--timeout", type=int, default=10, metavar="SEC", help="连接超时秒数（默认 10）")
    ap.add_argument("--port", type=int, default=443, metavar="PORT",
                    help="TLS 端口（默认 443，可查内网非标端口服务）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--version", action="version", version=f"certcheck {VERSION}")
    args = ap.parse_args(argv)

    domains = list(args.domains)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        domains.append(line)
        except OSError as e:
            print(f"error: 读不到域名文件 {args.file}：{e}", file=sys.stderr)
            return 2
    if not domains:
        print("error: 请给出至少一个域名，或用 --file 指定文件", file=sys.stderr)
        return 2
    if args.warn < 0 or args.timeout <= 0 or not (1 <= args.port <= 65535):
        print("error: --warn 不能为负，--timeout 必须为正，--port 取值 1-65535", file=sys.stderr)
        return 2

    results = [check_one(d, args.port, args.timeout, args.warn) for d in domains]

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        render_table(results)
        n_bad = sum(1 for r in results if not r["ok"])
        print(f"\n共检查 {len(results)} 个域名：{len(results) - n_bad} 正常，{n_bad} 异常")

    return 0 if all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
