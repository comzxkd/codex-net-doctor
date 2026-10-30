"""单点探测：对一个域名做解析、连 TCP、做 TLS 握手、发一次 HTTP 请求。

只用标准库，不装任何依赖。
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import ssl
import time

# ---------------------------------------------------------------------------
# 域名表
#
# 这张表是整个工具的输入，全部端点都从 openai/codex 上游源码与发布二进制核对过：
#   codex-rs/codex-api/src/lib.rs   -> RESPONSES_PATH = "/responses"
#   账号模式 base  https://chatgpt.com/backend-api/codex
#   API Key 模式 base https://api.openai.com/v1
#
# critical=True 表示这个域名不通，Codex 就一定用不了。
# ---------------------------------------------------------------------------
DOMAINS = [
    {
        "host": "api.openai.com",
        "path": "/v1/models",
        "method": "GET",
        "role": "API Key 模式的接口",
        "critical": True,
        "core": True,
        "note": "不带 token 请求，401 说明地区没问题，403 才是地区被拒",
    },
    {
        "host": "chatgpt.com",
        "path": "/cdn-cgi/trace",
        "method": "GET",
        "role": "Cloudflare 对你这颗 IP 的国家判定",
        "critical": True,
        "core": False,
        "note": "返回纯文本，loc= 就是国家码",
    },
    {
        "host": "chatgpt.com",
        "path": "/backend-api/codex/responses",
        "method": "POST",
        "role": "账号模式真正干活的地方",
        "critical": True,
        "core": True,
        "note": "Codex 每一轮对话都打这里",
    },
    {
        "host": "chatgpt.com",
        "path": "/backend-api/codex/responses",
        "method": "WS",
        "role": "同一个地址的 WebSocket 长连接",
        "critical": True,
        "core": True,
        "note": "Codex 会用 WebSocket 复用连接；分流规则漏写 ws 时这里会断",
    },
    {
        "host": "auth.openai.com",
        "path": "/",
        "method": "GET",
        "role": "登录与换 token",
        "critical": True,
        "core": True,
        "note": "登录失败多半是这里不通",
    },
    {
        "host": "ab.chatgpt.com",
        "path": "/otlp/v1/metrics",
        "method": "POST",
        "role": "遥测上报",
        "critical": False,
        "core": False,
        "note": "不通不影响使用，只影响统计",
    },
    {
        "host": "persistent.oaistatic.com",
        "path": "/",
        "method": "GET",
        "role": "静态资源 CDN",
        "critical": False,
        "core": False,
        "note": "网页版加载资源用，CLI 基本不依赖",
    },
    {
        "host": "api.github.com",
        "path": "/repos/openai/codex/releases/latest",
        "method": "GET",
        "role": "检查 Codex 版本更新",
        "critical": False,
        "core": False,
        "note": "不通只会导致版本检查失败",
    },
]

# ---------------------------------------------------------------------------
# 特殊地址段
#
# 解析结果落进这些段，说明请求根本没走到真正的公网服务，
# 而是被本机某层接管了。这是排查时最容易被忽略的一类问题。
#
# 这里不用 ipaddress 模块做网段判断，改成手工算整数：
# 需求只是「这个地址在不在这个网段」，自己算最直观，也便于逐行核对。
# ---------------------------------------------------------------------------
V4_RANGES = [
    ("fake-ip（代理软件接管 DNS）", ["198.18.0.0/15"]),
    ("本机回环（疑似 hosts 劫持）", ["127.0.0.0/8"]),
    ("保留地址（DNS 被替换或被拦截）", [
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
    ]),
    ("运营商级 NAT", ["100.64.0.0/10"]),
    ("内网地址", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]),
]

V6_PREFIXES = [
    ("本机回环（疑似 hosts 劫持）", ["::1"]),
    ("保留地址（DNS 被替换或被拦截）", ["2001:db8:"]),
    ("内网地址", ["fe80:", "fd", "fc"]),
]

DEFAULT_TIMEOUT = 8.0
USER_AGENT = "codex-net-doctor/0.1"


def _v4_to_int(text: str) -> int | None:
    """把 a.b.c.d 算成一个 32 位整数。不合法返回 None。"""
    parts = text.split(".")
    if len(parts) != 4:
        return None
    value = 0
    for part in parts:
        if not part.isdigit():
            return None
        octet = int(part)
        if octet > 255:
            return None
        value = (value << 8) | octet
    return value


def _v4_net(cidr: str) -> tuple[int, int]:
    """把 a.b.c.d/n 算成（网段整数, 掩码整数）。"""
    addr, _, bits_text = cidr.partition("/")
    bits = int(bits_text)
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF if bits else 0
    return (_v4_to_int(addr) or 0) & mask, mask


def classify_ip(ip_text: str) -> str | None:
    """判断一个 IP 是否落在特殊段，返回人话描述或 None。"""
    text = (ip_text or "").strip()
    if not text:
        return "空地址"

    if ":" in text:
        lowered = text.lower()
        for label, prefixes in V6_PREFIXES:
            for prefix in prefixes:
                if lowered == prefix or lowered.startswith(prefix):
                    return label
        return None

    value = _v4_to_int(text)
    if value is None:
        return "无法解析为 IP"

    for label, cidrs in V4_RANGES:
        for cidr in cidrs:
            net, mask = _v4_net(cidr)
            if value & mask == net:
                return label
    return None


def resolve(host: str) -> dict:
    """分别查 A 和 AAAA 记录。

    分开查很重要：如果 A 记录走代理、AAAA 记录绕开代理，
    就会出现「有时候能用有时候不能用」这种最烦人的症状。
    """
    out = {"ipv4": [], "ipv6": [], "errors": []}
    for family, key in ((socket.AF_INET, "ipv4"), (socket.AF_INET6, "ipv6")):
        try:
            infos = socket.getaddrinfo(host, 443, family, socket.SOCK_STREAM)
            seen = []
            for info in infos:
                addr = info[4][0]
                if addr not in seen:
                    seen.append(addr)
            out[key] = seen
        except socket.gaierror as exc:
            out["errors"].append(f"{key}: {exc}")
    return out


def _read_response(sock: socket.socket, limit: int = 65536, headers_only: bool = False) -> bytes:
    """读够 limit 字节或读空为止。够解析小响应了。

    headers_only 给 WebSocket 用：握手成功的响应没有响应体，对面也
    不会关连接，不看到空行就停就会一直等到超时。
    """
    buf = b""
    while len(buf) < limit:
        try:
            chunk = sock.recv(8192)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
        if b"\r\n\r\n" in buf and (headers_only or len(buf) > 512):
            break
    return buf


def _parse_status(raw: bytes) -> dict:
    """从原始响应里抠出状态行和关心的几个头。"""
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1", "replace").split("\r\n")
    info = {"status": None, "headers": {}, "body_head": ""}
    if not lines or not lines[0]:
        return info

    parts = lines[0].split(" ", 2)
    if len(parts) >= 2 and parts[1].isdigit():
        info["status"] = int(parts[1])

    wanted = {
        "server", "cf-ray", "content-type", "x-request-id",
        "cf-cache-status", "location", "retry-after",
        "sec-websocket-accept", "upgrade",
    }
    for line in lines[1:]:
        name, _, value = line.partition(":")
        key = name.strip().lower()
        if key in wanted:
            info["headers"][key] = value.strip()

    info["body_head"] = body[:1200].decode("utf-8", "replace")
    return info


def _connect_tls(host: str, family: int | None, timeout: float, result: dict):
    """解析 → TCP → TLS，把每一步的耗时写进 result。

    成功返回 (socket, None)，失败返回 (None, 错误信息)。
    HTTP 和 WebSocket 两种探测共用这一段，免得改一处漏一处。
    """
    dns_started = time.perf_counter()
    try:
        infos = socket.getaddrinfo(
            host, 443, family if family is not None else socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        return None, f"DNS 解析失败: {exc}"
    result["dns_ms"] = round((time.perf_counter() - dns_started) * 1000, 1)
    if not infos:
        return None, "DNS 解析结果为空"

    # IPv6 的地址元组是 4 元组，IPv4 是 2 元组，切片取前两位才能通用
    target = infos[0][4][:2]
    result["remote_ip"] = target[0]

    tcp_started = time.perf_counter()
    try:
        raw_sock = socket.create_connection(target, timeout=timeout)
    except OSError as exc:
        return None, f"TCP 连接失败: {exc}"
    result["tcp_ms"] = round((time.perf_counter() - tcp_started) * 1000, 1)

    ctx = ssl.create_default_context()
    try:
        tls_started = time.perf_counter()
        sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        result["tls_ms"] = round((time.perf_counter() - tls_started) * 1000, 1)
        result["tls_version"] = sock.version()
        cert = sock.getpeercert() or {}
        for field in cert.get("issuer", ()):
            for key, value in field:
                if key == "organizationName":
                    result["cert_issuer"] = value
    except (ssl.SSLError, OSError) as exc:
        try:
            raw_sock.close()
        except OSError:
            pass
        return None, f"TLS 握手失败: {exc}"

    return sock, None


def http_probe(
    host: str,
    path: str = "/",
    method: str = "GET",
    timeout: float = DEFAULT_TIMEOUT,
    family: int | None = None,
) -> dict:
    """直连探测：自己解析、自己连、自己握手、自己发请求。

    绕开一切 HTTP 库和环境变量，拿到的是「这条路上真实发生了什么」。
    如果开着 TUN，即便这里是直连写法，流量照样会被虚拟网卡接管，
    所以它测出来的仍然是用户实际走的那条路。
    """
    result = {
        "host": host,
        "path": path,
        "method": method,
        "ok": False,
        "remote_ip": None,
        "dns_ms": None,
        "tcp_ms": None,
        "tls_ms": None,
        "total_ms": None,
        "tls_version": None,
        "cert_issuer": None,
        "status": None,
        "headers": {},
        "body_head": "",
        "error": None,
    }

    started = time.perf_counter()

    sock, error = _connect_tls(host, family, timeout, result)
    if sock is None:
        result["error"] = error
        return result


    # 4) 发一个最小请求
    body_bytes = b""
    if method == "POST":
        body_bytes = b'{"model":"gpt-5-codex","input":[],"stream":false}'
    request = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Accept: */*\r\n"
        f"Accept-Encoding: identity\r\n"
        f"Connection: close\r\n"
    )
    if body_bytes:
        request += (
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
        )
    request += "\r\n"

    try:
        sock.settimeout(timeout)
        sock.sendall(request.encode("ascii") + body_bytes)
        raw = _read_response(sock)
    except OSError as exc:
        result["error"] = f"收发失败: {exc}"
        try:
            sock.close()
        except OSError:
            pass
        return result
    finally:
        try:
            sock.close()
        except OSError:
            pass

    parsed = _parse_status(raw)
    result.update(parsed)
    result["ok"] = parsed["status"] is not None
    result["total_ms"] = round((time.perf_counter() - started) * 1000, 1)
    if parsed["status"] is None:
        result["error"] = "收到了连接但没有拿到有效的 HTTP 响应"
    return result


# RFC 6455 规定的固定 GUID，算 Sec-WebSocket-Accept 用
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ws_probe(
    host: str,
    path: str = "/",
    timeout: float = DEFAULT_TIMEOUT,
    family: int | None = None,
) -> dict:
    """发一次 WebSocket 握手，看能不能升级成功。

    为什么单独测：Codex 是拿 WebSocket 跑 Responses 的，很多分流规则
    只写了普通 HTTPS，没写 ws。症状是「能聊天、能登录，但跑一阵就断」，
    用普通 HTTPS 探测完全看不出来。

    判读方式：
      101 + Sec-WebSocket-Accept 对得上   → 真的升级成功了
      401 / 403 且带 cf-ray              → 走到了 Cloudflare，只是没凭据，链路通
      超时 / 502 / 没有 cf-ray 的错误页   → WebSocket 这条路没通
    """
    result = {
        "host": host,
        "path": path,
        "method": "WS",
        "kind": "ws",
        "ok": False,
        "upgrade": False,
        "remote_ip": None,
        "dns_ms": None,
        "tcp_ms": None,
        "tls_ms": None,
        "total_ms": None,
        "tls_version": None,
        "cert_issuer": None,
        "status": None,
        "headers": {},
        "body_head": "",
        "error": None,
    }

    started = time.perf_counter()
    sock, error = _connect_tls(host, family, timeout, result)
    if sock is None:
        result["error"] = error
        return result

    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    )

    try:
        sock.settimeout(timeout)
        sock.sendall(request.encode("ascii"))
        raw = _read_response(sock, headers_only=True)
    except OSError as exc:
        result["error"] = f"握手收发失败: {exc}"
        return result
    finally:
        try:
            sock.close()
        except OSError:
            pass

    parsed = _parse_status(raw)
    result.update(parsed)
    result["total_ms"] = round((time.perf_counter() - started) * 1000, 1)

    if parsed["status"] is None:
        result["error"] = "握手没拿到有效的 HTTP 响应"
        return result

    result["ok"] = True
    expected = base64.b64encode(
        hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
    ).decode("ascii")
    result["upgrade"] = (
        parsed["status"] == 101
        and parsed["headers"].get("sec-websocket-accept", "") == expected
    )
    return result


def trace_fields(body: str) -> dict:
    """把 Cloudflare /cdn-cgi/trace 的纯文本拆成键值。

    其中有用的几个：
      loc    这颗 IP 被判定成哪个国家
      colo   Cloudflare 用哪个机房接的你这单
      warp   WARP 是否开启
      sni    SNI 是否被改写
    """
    out = {}
    for line in body.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key.strip()] = value.strip()
    return out
