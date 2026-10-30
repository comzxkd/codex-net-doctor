"""生成给用户自己的 agent 用的排查提示词。

为什么要有这个东西：工具只能告诉你「哪一段断了」，真正要改的是代理软件的
分流规则，那得看用户的配置文件。让用户自己去翻文档、或者在对话里一段段
描述现状，成本很高。所以直接给一段可以复制的提示词，粘给他自己的 agent。

写提示词的三条原则：
1. 自带上下文。对方的 agent 没有我们这边的任何信息，结论、断点、原始错误、
   环境参数都得写进去，否则它要重新问一遍。
2. 不写死步骤。只说要查什么、判断标准是什么，不写「第一步执行 X」这种。
   真正的排查要按现场情况走。
3. 结尾必须收住。默认只读排查，改配置前把要改的内容先给用户看。
"""

from __future__ import annotations

# Codex 会连的地址，写进提示词让对方 agent 知道排查范围
ENDPOINT_FACTS = """\
Codex 会连这些地址（已核对 openai/codex 上游源码）：
- api.openai.com            API Key 模式的接口，POST /v1/responses
- chatgpt.com               账号模式的主接口，POST /backend-api/codex/responses
- chatgpt.com               同一个地址还会用 WebSocket 复用连接
- auth.openai.com           登录与换 token
- ab.chatgpt.com            遥测上报，不通不影响使用
- persistent.oaistatic.com  静态资源 CDN"""

STAGE_TASKS = {
    "dns": """\
请帮我定位为什么这些域名解析不到地址。重点看：
1. 系统的 hosts 文件里有没有和这些域名相关的条目。
2. 代理软件的 DNS 设置：是否关掉了 DNS、是否用了 fake-ip 或 redir-host、
   上游 DNS 是什么、有没有单独的 DNS 分流规则。
3. 如果我用了 TUN 模式，DNS 是被代理接管的，这一层的配置在哪。""",
    "tcp": """\
请帮我定位这些域名为什么连不上。重点看：
1. 我用的是什么代理软件（大概率是 Clash/Mihomo、sing-box 或同类），
   它的分流规则配置文件在哪。
2. 上面这些域名分别会命中哪一条规则，是被分到了直连还是代理。
3. 是「被分到了走不通的路」，还是「节点本身不通」——你可以对同一个域名，
   走代理和不走代理各连一次对比结果，这样能区分这两件事。""",
    "tls": """\
请帮我定位为什么 TCP 能连上但 TLS 谈不成。重点看：
1. 链路上有没有东西在做 TLS 解密或证书替换（代理软件的 MITM、抓包工具、
   安全软件都可能是）。
2. 代理软件的 SNI 相关设置、有没有对这个域名做特殊处理。
3. 换个节点再试一次，排除是节点侧的问题。""",
    "http": """\
请帮我定位为什么连接都通了却拿不到 HTTP 响应。重点看：
1. 这个域名是不是被某条规则重写到了别的地址。
2. 代理软件里有没有对这个域名的 rewrite / host 映射。
3. 中间层有没有在超时前掐断连接。""",
}

KIND_TASKS = {
    "region": """\
请帮我解决「出口 IP 被判成不支持的地区」。重点看：
1. 我当前用的节点落地在哪个国家/地区。可以打开 chatgpt.com/cdn-cgi/trace
   看返回里的 loc 字段，那就是对方对我这颗 IP 的国家判定。
2. 我订阅里的节点，哪些的落地国家是 OpenAI 提供服务的地区。
3. 分流规则里，上面这些域名走的是哪个节点组，是不是被分到了不合适的出口。""",
    "ws": """\
请帮我定位「WebSocket 不通但普通请求能通」。这是一个很具体的症状，
基本可以断定是分流规则只覆盖了 http/https，漏了 ws/wss。重点看：
1. 规则里这个域名的条目，有没有把网络类型限定成 tcp 或者只写了 http。
2. 如果用的是 Clash/Mihomo，看有没有 network 字段、有没有单独的 ws 处理。
3. 如果用的是 sing-box，看出站配置是否支持 WebSocket 传输。
这个问题的表现是：能登录、能对话，但 Codex 用一阵子会断。""",
    "dns_special": """\
请帮我查清这些域名为什么解析到了非公网地址。重点看：
1. hosts 文件有没有被写过。
2. 代理软件的 fake-ip 设置，以及它的 fake-ip 网段是多少。
3. 如果确实是代理接管 DNS，那这个现象本身不一定是问题，
   需要确认的是这些假地址最终有没有被正确转发出去。""",
}

COMMON_TAIL = """\
## 约束

- 先只读排查。不要直接改我的网络适配器、路由表、系统 DNS 或代理软件配置。
- 找到要改的地方之后，把具体改哪一行、改成什么贴给我，我确认了你再动手。
- 信息不够就问我，不要猜着改。
- 我这个体检工具只测链路通不通，不评价节点质量好不好，别把这两件事混在一起。"""


def _proxy_summary(env: dict) -> list[str]:
    lines = []
    proxy_env = env.get("proxy_env") or {}
    https_proxy = proxy_env.get("HTTPS_PROXY") or proxy_env.get("https_proxy")
    if https_proxy:
        lines.append(f"- 环境变量代理：{https_proxy}（Codex 会读这个变量）")
    else:
        lines.append("- 环境变量代理：没有设置")

    sys_proxy = env.get("system_proxy") or {}
    if sys_proxy.get("available"):
        if sys_proxy.get("enabled"):
            lines.append(f"- 系统代理：已开启，{sys_proxy.get('server') or '地址未读取到'}")
        else:
            lines.append("- 系统代理：未开启")
    else:
        lines.append("- 系统代理：无法读取")

    tun = env.get("tun_guess") or {}
    lines.append(f"- TUN 模式：{tun.get('verdict', '未判定')}")

    egress = env.get("egress") or {}
    if egress.get("ipv4"):
        lines.append(f"- 出口网卡地址（IPv4）：{egress['ipv4']}")
    if egress.get("ipv6"):
        lines.append(f"- 出口网卡地址（IPv6）：{egress['ipv6']}")
    return lines


def _broken_lines(endpoints: list[dict], stage: str | None = None) -> list[str]:
    from .diagnose import _first_broken_stage  # 避免循环导入

    lines = []
    for item in endpoints:
        if item.get("verdict") not in ("unreachable", "region_blocked", "unknown", "server_error"):
            continue
        # 定了断点就只看关键项：结论本来就是按关键项汇总的，
        # 把非关键项列进来会跟结论对不上。
        if stage is not None:
            if not item.get("critical"):
                continue
            if _first_broken_stage(item.get("stages") or {}) != stage:
                continue
        label = f"{item['host']}{item['path']}"
        if item.get("kind") == "ws":
            label += "（WebSocket）"
        if not stage and not item.get("critical"):
            label += "（非关键）"
        reason = item.get("error") or item.get("verdict_text") or ""
        lines.append(f"- {label} —— {reason}" if reason else f"- {label}")
    return lines


def build_prompt(finding: dict, context: dict) -> str:
    """按问题类型拼一段可以直接复制的提示词。"""
    env = context.get("env") or {}
    trace = context.get("trace") or {}
    endpoints = context.get("endpoints") or []
    summary = context.get("summary") or {}

    kind = finding.get("kind") or "generic"
    stage = finding.get("stage")

    platform = {"win32": "Windows", "darwin": "macOS", "linux": "Linux"}.get(
        env.get("platform", ""), env.get("platform", "未知系统")
    )

    parts: list[str] = []
    parts.append(
        f"我在 {platform} 上用 Codex，遇到了网络问题。下面是我刚跑的一次链路体检结果，"
        "请基于这些信息帮我定位并修复。"
    )

    reach = (summary.get("reach") or {}).get("text", "")
    stability = (summary.get("stability") or {}).get("text", "")
    parts.append(
        "## 体检结论\n"
        f"- 通不通：{reach}\n"
        f"- 稳不稳：{stability}"
    )

    problem = f"## 需要解决的问题\n{finding.get('title', '')}"
    if finding.get("detail"):
        problem += f"\n{finding['detail']}"
    parts.append(problem)

    broken = _broken_lines(endpoints, stage)
    if broken:
        parts.append("## 具体断在这里\n" + "\n".join(broken[:12]))

    env_lines = _proxy_summary(env)
    if trace.get("loc"):
        env_lines.append(f"- 出口国家判定：{trace['loc']}（Cloudflare 的判定）")
    if trace.get("colo"):
        env_lines.append(f"- Cloudflare 机房：{trace['colo']}")
    parts.append("## 我这台机器的网络环境\n" + "\n".join(env_lines))

    parts.append(ENDPOINT_FACTS)

    task = KIND_TASKS.get(kind) or STAGE_TASKS.get(stage or "")
    if task is None:
        task = (
            "请帮我判断上面这条问题是否真的会影响 Codex 使用，"
            "如果会，该从哪里入手排查。"
        )
    parts.append("## 请你做什么")
    parts.append(task)

    parts.append(COMMON_TAIL)
    return "\n\n".join(parts)
