"""环境探测：本机代理设置与出口网卡的线索。

原则：只读。不改注册表、不改 env、不写 hosts、不动任何代理软件配置。
"""

from __future__ import annotations

import os
import socket
import sys

PROXY_ENV_KEYS = [
    "HTTPS_PROXY", "https_proxy",
    "HTTP_PROXY", "http_proxy",
    "ALL_PROXY", "all_proxy",
    "NO_PROXY", "no_proxy",
]


def proxy_env() -> dict:
    """读环境变量里的代理设置。

    Codex 是 Rust 写的，底层 reqwest 会读这些变量，所以有值就说明
    Codex 自己会走代理；没有值则完全依赖 TUN 或其他系统级接管。

    Windows 上常见大写小写成对出现且值相同，这里去重，只保留先出现的一个。
    如果同名两种写法值不一样，两个都留着——那本身就是个问题。
    """
    seen = set()
    out = {}
    for key in PROXY_ENV_KEYS:
        if key not in os.environ:
            continue
        value = os.environ[key]
        marker = (key.lower(), value)
        if marker in seen:
            continue
        seen.add(marker)
        out[key] = value
    return out


def system_proxy() -> dict:
    """读 Windows 系统代理（Internet 选项里那一栏）。只读注册表。"""
    if sys.platform != "win32":
        return {"available": False, "reason": "非 Windows，跳过"}

    try:
        import winreg
    except ImportError:
        return {"available": False, "reason": "拿不到 winreg"}

    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
    except OSError as exc:
        return {"available": False, "reason": str(exc)}

    try:
        enabled = 0
        server = ""
        try:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
        except FileNotFoundError:
            pass
        try:
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
        except FileNotFoundError:
            pass
        return {"available": True, "enabled": bool(enabled), "server": server or ""}
    finally:
        winreg.CloseKey(key)


def egress_interface_ip() -> dict:
    """不发包测出「去公网会从哪个本地地址出去」。

    UDP connect 不会真的发包，只让内核选路，所以很便宜。
    返回的本地地址能反推走了哪块网卡：
    192.168.x / 10.x 一般是真实局域网网卡，
    198.18.x 这类是代理软件的虚拟网卡（TUN）。
    """
    result = {"ipv4": None, "ipv6": None}
    for family, target, key in (
        (socket.AF_INET, ("1.1.1.1", 53), "ipv4"),
        (socket.AF_INET6, ("2606:4700:4700::1111", 53), "ipv6"),
    ):
        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            sock.connect(target)
            result[key] = sock.getsockname()[0]
        except OSError:
            result[key] = None
        finally:
            if sock is not None:
                sock.close()
    return result


def guess_tun(egress: dict, fake_ip_seen: bool) -> dict:
    """推测是否处于 TUN 模式。

    这不是权威判定，只是把两条线索合起来估计，所以标成推测。
    线索一：解析结果落在 198.18.0.0/15（代理软件常用 fake-ip 段）。
    线索二：出口本地地址不是常见局域网段，而是虚拟网卡段。
    """
    reasons = []
    ip4 = egress.get("ipv4") or ""

    if fake_ip_seen:
        reasons.append("有域名解析到 198.18.x.x（fake-ip 段），说明有代理在本地接管 DNS")
    if ip4.startswith("198.18."):
        reasons.append(f"出口本地地址是 {ip4}，属于虚拟网卡段，不是真实局域网网卡")

    if len(reasons) >= 2:
        verdict = "很可能开着"
    elif reasons:
        verdict = "可能有"
    else:
        verdict = "没发现迹象"

    return {"verdict": verdict, "reasons": reasons}


def scan_env() -> dict:
    """一次性收齐环境信息。"""
    return {
        "proxy_env": proxy_env(),
        "system_proxy": system_proxy(),
        "egress": egress_interface_ip(),
        "python": sys.version.split()[0],
        "platform": sys.platform,
    }
