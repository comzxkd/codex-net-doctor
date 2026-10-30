"""把一堆探测结果翻译成人能看懂的结论。

这一层只做判断，不发请求。判断依据按可靠性排序：

1. 接口返回的 HTTP 状态码和错误码 —— 最权威，这是 OpenAI 自己的回答
2. 解析到的地址、连上的地址、TLS 是否正常 —— 说明链路有没有被改道
3. Cloudflare 给的 loc 国家码 —— 只是旁证，不能当结论
"""

from __future__ import annotations

import concurrent.futures
import datetime
import socket

from . import envscan
from .probe import DOMAINS, classify_ip, http_probe, resolve, trace_fields, ws_probe
from .prompts import build_prompt

# 第一轮用较长超时，后面几轮可以短一点：
# 采样关心的是「通不通」，不是「慢到什么程度」。
ROUND_TIMEOUT = 8.0
RETRY_TIMEOUT = 5.0
DEFAULT_ROUNDS = 5

# OpenAI 明确不提供服务的国家/地区（参考列表，随时可能变）。
# 只用来做「值得怀疑」的提示，不作为最终结论；
# 最终结论一律看接口自己返回的状态码。
SUSPECT_LOCS = {
    "CN": "中国大陆",
    "HK": "中国香港",
    "MO": "中国澳门",
    "RU": "俄罗斯",
    "IR": "伊朗",
    "KP": "朝鲜",
    "SY": "叙利亚",
    "CU": "古巴",
}

LEVEL_ORDER = {"bad": 0, "warn": 1, "ok": 2, "info": 3}

# 断在哪一段，就说哪一段该查什么。
# 三条一模一样的建议等于没给建议，所以这里必须分开写。
STAGE_ORDER = ["dns", "tcp", "tls", "http"]
STAGE_ADVICE = {
    "dns": (
        "解析",
        "这个域名没解析出地址。先看 hosts 文件是不是被写过，"
        "再看代理软件的 DNS 有没有关掉、有没有被改成 fake-ip 以外的模式。",
    ),
    "tcp": (
        "连接",
        "地址拿到了但连不上。这个域名大概率被分流到了直连，"
        "或者当前节点本身不通。先去规则里搜这个域名。",
    ),
    "tls": (
        "加密",
        "TCP 通了但 TLS 没谈成。可能是链路中间有东西在解 TLS，"
        "也可能是节点对这个 SNI 做了拦截。换个节点试着排除。",
    ),
    "http": (
        "应答",
        "连接都通了，但对面没回 HTTP 响应。中间层可能在掐连接，"
        "或者这个域名被规则改到了别的地址。",
    ),
}


def _first_broken_stage(stages: dict) -> str:
    """从左往右找第一个没过的段。全过了就返回空串。"""
    for key in STAGE_ORDER:
        if not (stages.get(key) or {}).get("ok"):
            return key
    return ""


def _finding(
    level: str,
    title: str,
    detail: str,
    advice: str,
    kind: str = "generic",
    stage: str | None = None,
) -> dict:
    """一条结论。

    kind 和 stage 是给提示词生成器用的：靠标题字符串去猜问题类型太脆，
    所以生成的时候就标清楚。
    """
    return {
        "level": level,
        "title": title,
        "detail": detail,
        "advice": advice,
        "kind": kind,
        "stage": stage,
    }


def _probe_one(spec: dict, timeout: float) -> dict:
    """按 method 分派。WS 走握手，其余走普通 HTTP 请求。"""
    if spec.get("method") == "WS":
        return ws_probe(spec["host"], spec["path"], timeout=timeout)
    return http_probe(spec["host"], spec["path"], spec.get("method", "GET"), timeout=timeout)


def _run_safe(spec: dict, timeout: float) -> dict:
    try:
        result = _probe_one(spec, timeout)
    except Exception as exc:  # 单个域名出意外不能拖垮整次体检
        result = {
            "host": spec["host"],
            "path": spec["path"],
            "method": spec.get("method", "GET"),
            "kind": spec.get("kind", "http"),
            "ok": False,
            "status": None,
            "total_ms": None,
            "dns_ms": None,
            "tcp_ms": None,
            "tls_ms": None,
            "tls_version": None,
            "remote_ip": None,
            "cert_issuer": None,
            "headers": {},
            "body_head": "",
            "error": f"探测过程异常: {type(exc).__name__}: {exc}",
        }
    result["role"] = spec["role"]
    result["critical"] = spec["critical"]
    result["note"] = spec["note"]
    result["core"] = spec.get("core", False)
    result.setdefault("kind", spec.get("kind", "http"))
    return result


def _probe_all(rounds: int = DEFAULT_ROUNDS, on_progress=None) -> list[dict]:
    """所有域名并发探测，跑多轮算稳定性。

    第一轮的结果带完整细节（四段耗时、响应头、响应体）；
    后面几轮只要「通不通」和耗时，用来判断稳不稳定。
    """
    rounds = max(1, int(rounds))
    workers = len(DOMAINS)

    def report(done: int) -> None:
        if on_progress is not None:
            try:
                on_progress(done, rounds)
            except Exception:
                pass  # 报进度出错不能影响体检本身

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        report(1)
        primary = list(pool.map(lambda s: _run_safe(s, ROUND_TIMEOUT), DOMAINS))
        later = []
        for index in range(rounds - 1):
            report(index + 2)
            later.append(list(pool.map(lambda s: _run_safe(s, RETRY_TIMEOUT), DOMAINS)))

    for index, item in enumerate(primary):
        collected = [item] + [rnd[index] for rnd in later]
        samples = [
            {
                "ok": s.get("status") is not None,
                "status": s.get("status"),
                "total_ms": s.get("total_ms"),
            }
            for s in collected
        ]
        item["samples"] = samples
        item["rounds_total"] = len(samples)
        item["rounds_ok"] = sum(1 for s in samples if s["ok"])

    return primary


def _judge_endpoint(item: dict) -> dict:
    """给单个域名下一个判定：通 / 地区受限 / 不通 / 未知。"""
    status = item.get("status")
    body = (item.get("body_head") or "").lower()
    has_cf_ray = "cf-ray" in (item.get("headers") or {})

    if item.get("error") and status is None:
        item["verdict"] = "unreachable"
        item["verdict_text"] = item["error"]
        return item

    # WebSocket 单独判。它没有 200 这回事，也不带业务响应体。
    if item.get("kind") == "ws":
        if item.get("upgrade"):
            item["verdict"] = "reachable"
            item["verdict_text"] = "握手成功（101），WebSocket 这条路通"
            return item
        if status == 404:
            item["verdict"] = "unknown"
            item["verdict_text"] = "路径返回 404，可能端点已经改过，本项结论不可靠"
            return item
        if status in (400, 401, 403):
            via = "（响应头里有 cf-ray，确实到了 Cloudflare）" if has_cf_ray else "（没有 cf-ray，可能被中间层挡了）"
            item["verdict"] = "reachable" if has_cf_ray else "unknown"
            item["verdict_text"] = f"服务端回过 {status}，没凭据所以没升成 101{via}"
            return item
        if status is not None and status >= 500:
            item["verdict"] = "server_error"
            item["verdict_text"] = f"握手阶段对面出错 {status}"
            return item
        item["verdict"] = "unreachable"
        item["verdict_text"] = f"握手没成功，返回 {status}"
        return item

    if "unsupported_country" in body or "country, region, or territory not supported" in body:
        item["verdict"] = "region_blocked"
        item["verdict_text"] = "接口明确回答：这个地区不支持"
        return item

    if status in (401, 403):
        # 401 是没带 token，403 也可能是没登录。
        # 只有 body 里出现 unsupported_country 才算地区问题，上面已经拦掉了。
        item["verdict"] = "reachable"
        item["verdict_text"] = f"通，返回 {status}（正常，说明只是没带凭据）"
        return item

    if status is not None and 200 <= status < 500:
        item["verdict"] = "reachable"
        item["verdict_text"] = f"通，返回 {status}"
        return item

    if status is not None and status >= 500:
        item["verdict"] = "server_error"
        item["verdict_text"] = f"对面服务器出错 {status}，跟你的网络无关"
        return item

    item["verdict"] = "unknown"
    item["verdict_text"] = "没拿到明确结果"
    return item


def _build_findings(env: dict, endpoints: list[dict], trace: dict, ip_classes: dict) -> list[dict]:
    findings: list[dict] = []
    by_stage: dict[str, list[str]] = {}

    by_host = {}
    for item in endpoints:
        by_host.setdefault(item["host"], []).append(item)

    # ---- 1. 环境线索 ----
    proxy_env = env.get("proxy_env") or {}
    has_env_proxy = any(k.lower().endswith("_proxy") and not k.lower().startswith("no_") and proxy_env[k]
                        for k in proxy_env)
    if has_env_proxy:
        values = {k: v for k, v in proxy_env.items() if not k.lower().startswith("no_")}
        findings.append(_finding(
            "info",
            "环境变量里配了代理",
            f"检测到 {values}。Codex 底层会读这些变量，所以它会走这个代理。",
            "这条本身没问题，只是说明排查对象是这条链路。",
        ))
    else:
        findings.append(_finding(
            "info",
            "环境变量里没有代理",
            "没检测到 HTTPS_PROXY 之类的变量。如果你开着 TUN，这是正常的；"
            "如果你靠系统代理上网，Codex 可能完全没走代理。",
            "靠系统代理的话，把代理地址写进 HTTPS_PROXY 更稳。",
        ))

    tun = env.get("tun_guess") or {}
    findings.append(_finding(
        "info",
        f"TUN 模式：{tun.get('verdict', '未判定')}",
        "；".join(tun.get("reasons") or ["没有发现 TUN 相关迹象"]),
        "TUN 开着时，程序读不读代理变量都能出去，排查重点要放在分流规则上。",
    ))

    # ---- 2. 解析结果落在特殊地址段 ----
    # fake-ip 是代理接管 DNS 的正常表现，不能当问题报。
    # 刚开 TUN 的人一跑就四条红字，会以为工具坏了。
    fake_ip_hosts = []
    odd_hosts: dict[str, set[str]] = {}

    for host, classes in ip_classes.items():
        names = {c for c in classes if c}
        if not names:
            continue
        if names == {"fake-ip（代理软件接管 DNS）"}:
            fake_ip_hosts.append(host)
            continue
        bad = {c for c in names if c not in ("内网地址", "fake-ip（代理软件接管 DNS）")}
        if bad:
            odd_hosts[host] = bad

    if fake_ip_hosts:
        findings.append(_finding(
            "info",
            f"{len(fake_ip_hosts)} 个域名解析到了 fake-ip 地址",
            "、".join(sorted(fake_ip_hosts))
            + "。这是代理软件接管 DNS 的正常表现，不是毛病。",
            "开着 TUN 或 fake-ip 时本来就是这样，不用处理。",
            kind="fake_ip",
        ))

    for host, bad in sorted(odd_hosts.items()):
        findings.append(_finding(
            "warn",
            f"{host} 解析到了非公网地址",
            f"命中：{'、'.join(sorted(bad))}。"
            "说明这个域名的请求在本机就被接管或拦下了，没有直接去公网。",
            "检查 hosts 文件有没有被写过，以及 DNS 设置是不是被改过。",
            kind="dns_special",
        ))

    # ---- 3. 地区判定 ----
    loc = (trace.get("loc") or "").upper()
    trace_reachable = any(
        item["host"] == "chatgpt.com"
        and item["path"] == "/cdn-cgi/trace"
        and item.get("status") is not None
        for item in endpoints
    )
    if loc:
        if loc in SUSPECT_LOCS:
            findings.append(_finding(
                "bad",
                f"Cloudflare 把你这颗 IP 判成了 {loc}（{SUSPECT_LOCS[loc]}）",
                "这个国家/地区不在 OpenAI 的服务范围内，接口会直接拒绝。",
                "换一个落地节点，或者检查分流是不是让这个域名走到了国内出口。",
            ))
        else:
            findings.append(_finding(
                "ok",
                f"出口国家判定为 {loc}",
                f"Cloudflare 用 {trace.get('colo', '未知')} 机房接的请求，warp={trace.get('warp', 'off')}。",
                "这一项没问题。",
            ))
    elif trace_reachable:
        findings.append(_finding(
            "warn",
            "拿不到出口国家判定",
            "chatgpt.com 的 trace 接口有响应，但没返回 loc 字段，可能被中间层改写了。",
            "以 api.openai.com 的返回码为准。",
        ))
    # trace 接口本身就连不上时不重复报，上面「连不上」那条已经说过了

    # ---- 4. 逐个关键域名的真实返回 ----
    for host, items in by_host.items():
        for item in items:
            verdict = item.get("verdict")
            label = f"{host}{item['path']}"
            if item.get("kind") == "ws":
                label += "（WebSocket）"
            if verdict == "region_blocked":
                findings.append(_finding(
                    "bad",
                    f"{label} 被地区限制",
                    item["verdict_text"],
                    "这就是报错的直接来源。先解决出口 IP 的归属，别动账号配置。",
                    kind="region",
                ))
            elif verdict == "unreachable" and item["critical"]:
                stage = _first_broken_stage(item.get("stages") or {}) or "tcp"
                by_stage.setdefault(stage, []).append((label, item.get("error") or ""))
            elif verdict == "unreachable" and not item["critical"]:
                findings.append(_finding(
                    "warn",
                    f"{label} 不通（非关键）",
                    item["verdict_text"],
                    "不影响 Codex 正常使用，可以先不管。",
                    kind="noncritical",
                ))

    # 同断点的域名合并成一条。
    # 分开列三个一模一样的建议，读起来像复读，也不告诉用户它们其实是同一个毛病。
    for stage in STAGE_ORDER:
        entries = by_stage.get(stage)
        if not entries:
            continue
        stage_cn, stage_advice = STAGE_ADVICE[stage]
        labels = [label for label, _ in entries]
        raw_error = next((err for _, err in entries if err), "")

        if len(labels) == 1:
            title = f"{labels[0]} 断在「{stage_cn}」"
            detail = raw_error
        else:
            title = f"{len(labels)} 个检查项都断在「{stage_cn}」"
            detail = "、".join(labels) + (f"（{raw_error}）" if raw_error else "")
        findings.append(_finding("bad", title, detail, stage_advice, kind="stage", stage=stage))

    # ---- 4.5 WebSocket 与同址普通请求的对比 ----
    # 这是 ws 检查最有价值的产出：同一个地址，普通请求能到、WebSocket 不行，
    # 基本可以断定是分流规则只写了 http/https。
    for item in endpoints:
        if item.get("kind") != "ws" or item.get("verdict") == "reachable":
            continue
        twin = next(
            (
                e for e in endpoints
                if e.get("kind") != "ws"
                and e["host"] == item["host"]
                and e["path"] == item["path"]
                and e.get("verdict") == "reachable"
            ),
            None,
        )
        if twin:
            findings.append(_finding(
                "bad",
                "WebSocket 不通，但同一个地址的普通请求通",
                f"{item['host']}{item['path']} 用普通请求能到，用 WebSocket 握手不行：{item['verdict_text']}。",
                "分流规则里只写了 http/https，没写 ws/wss。"
                "把同一个域名的 WebSocket 规则补上。这种症状就是「能登录、能聊，但 Codex 跑一阵就断」。",
                kind="ws",
            ))

    # ---- 5. 证书签发方 ----
    issuers = {i.get("cert_issuer") for i in endpoints if i.get("cert_issuer")}
    if issuers:
        findings.append(_finding(
            "info",
            "TLS 证书签发方",
            "、".join(sorted(x for x in issuers if x)),
            "如果出现陌生的签发方，说明链路中间有人在解密流量。",
        ))

    return findings


def _headline(findings: list[dict], endpoints: list[dict]) -> dict:
    bad = [f for f in findings if f["level"] == "bad"]
    warn = [f for f in findings if f["level"] == "warn"]

    region = [f for f in bad if "地区" in f["title"]]
    if region:
        return {"level": "bad", "text": "出口 IP 被判成不支持的地区，这是报错的直接原因。"}

    dead = [f for f in bad if "断在" in f["title"]]
    if dead:
        return {"level": "bad", "text": "关键域名连不上，Codex 现在肯定用不了。"}

    if not bad and not warn:
        return {"level": "ok", "text": "没发现问题：出口归属正常，关键域名都通。"}

    if warn:
        return {"level": "warn", "text": "核心链路通，但有值得看一眼的地方。"}

    return {"level": "bad", "text": "发现了问题，看下面逐项说明。"}


def _stages_of(item: dict) -> dict:
    """把一个域名的探测结果拆成四段，界面靠这个画矩阵。

    这四段是真实测过的，不是推演出来的：
      解析  域名能不能变成地址
      连接  TCP 能不能握上手
      加密  TLS 能不能谈成
      应答  对面有没有真的回一个 HTTP 状态码

    哪一段先断，后面的段就不用看。
    """
    stages = {}

    resolved = item.get("resolved") or {}
    v4 = resolved.get("ipv4") or []
    v6 = resolved.get("ipv6") or []
    if v4 and v6:
        dns_label = f"A{len(v4)}+{len(v6)}"
    elif v4:
        dns_label = f"A{len(v4)}"
    elif v6:
        dns_label = f"AAAA{len(v6)}"
    else:
        dns_label = "—"
    stages["dns"] = {"ok": bool(v4 or v6), "label": dns_label}

    tcp_ms = item.get("tcp_ms")
    stages["tcp"] = {
        "ok": tcp_ms is not None,
        "label": f"{tcp_ms:g}ms" if tcp_ms is not None else "—",
    }

    tls_ms = item.get("tls_ms")
    tls_version = (item.get("tls_version") or "").replace("TLSv", "")
    stages["tls"] = {
        "ok": tls_ms is not None,
        "label": tls_version if tls_version else "—",
    }

    status = item.get("status")
    stages["http"] = {
        "ok": status is not None,
        "label": str(status) if status is not None else "—",
    }

    return stages


def _stage_summary(endpoints: list[dict]) -> list[dict]:
    """四个阶段各自的通过数，界面顶部那一条用这个。"""
    names = [
        ("dns", "解析", "域名能不能变成地址"),
        ("tcp", "连接", "TCP 能不能握上手"),
        ("tls", "加密", "TLS 能不能谈成"),
        ("http", "应答", "对面有没有真的回话"),
    ]
    total = len(endpoints)
    out = []
    for key, title, hint in names:
        passed = sum(1 for e in endpoints if (e.get("stages") or {}).get(key, {}).get("ok"))
        if passed == total:
            level = "ok"
        elif passed == 0:
            level = "bad"
        else:
            level = "warn"
        out.append({"key": key, "title": title, "hint": hint, "passed": passed, "total": total, "level": level})
    return out


# 挑「问题在哪」时的优先级。数字大的先说。
# 不能拿「第一条」充数：同级别几条同时存在时，插入顺序是随机的。
FINDING_WEIGHT = [
    (lambda f: "地区" in f["title"], 100),
    (lambda f: "断在" in f["title"], 80),
    (lambda f: "WebSocket" in f["title"], 70),
    (lambda f: True, 50),
]


def _weigh(finding: dict) -> int:
    for test, score in FINDING_WEIGHT:
        if test(finding):
            # 同类里命中的检查项越多越先说
            return score + finding.get("detail", "").count("、")
    return 0


# 两种接入方式各自靠哪些地址。
# core 的条目才算数：cdn-cgi/trace 只是医生用的体温计，不是病人必需。
MODE_DEFS = [
    {
        "key": "chatgpt",
        "title": "账号登录",
        "hint": "登录 ChatGPT 账号后用 Codex",
        "needs": [
            ("chatgpt.com", "/backend-api/codex/responses"),
            ("auth.openai.com", "/"),
        ],
    },
    {
        "key": "apikey",
        "title": "API Key",
        "hint": "用 sk- 开头的密钥",
        "needs": [("api.openai.com", "/v1/models")],
    },
]


def _modes(endpoints: list[dict]) -> list[dict]:
    """把「哪个地址通不通」翻译成「哪种用法能不能用」。

    用户真正想知道的是后者。前面那张表是证据，这里的两个结论才是答案。
    """
    out = []
    for spec in MODE_DEFS:
        required = [
            e for e in endpoints
            if e.get("core") and (e["host"], e["path"]) in spec["needs"]
        ]
        broken = [e for e in required if e.get("verdict") in ("unreachable", "region_blocked")]
        available = bool(required) and not broken

        if available:
            detail = "用得到的关键地址都通。"
        elif broken:
            names = []
            for item in broken:
                label = f"{item['host']}{item['path']}"
                if item.get("kind") == "ws":
                    label += "（WebSocket）"
                names.append(label)
            detail = "卡在：" + "、".join(names)
        else:
            detail = "没有可用的检查结果。"

        out.append({
            "key": spec["key"],
            "title": spec["title"],
            "hint": spec["hint"],
            "available": available,
            "detail": detail,
        })
    return out


def _summary(endpoints: list[dict], findings: list[dict]) -> dict:
    """把四件事说清楚：通不通、稳不稳、问题在哪、怎么办。

    这四个问题是用户真正要的答案。上面的 findings 是给愿意看细节的人看的，
    这里是给只想看一眼就走的人看的。
    """
    critical = [e for e in endpoints if e.get("critical")]
    broken = [e for e in endpoints if e.get("verdict") in ("unreachable", "region_blocked")]
    critical_broken = [e for e in broken if e.get("critical")]
    modes = _modes(endpoints)
    usable = [m for m in modes if m["available"]]

    # 通不通：直接回答「能不能用」，不是「几个检查项红了」
    if len(usable) == len(modes):
        reach_level = "ok"
        reach_text = "Codex 应该能正常用，两种接入方式都通。"
    elif usable:
        reach_level = "warn"
        reach_text = f"Codex 只能用「{usable[0]['title']}」，另一种用不了。"
    elif modes:
        reach_level = "bad"
        reach_text = "Codex 现在用不了：账号登录和 API Key 两条路都断了。"
    else:
        reach_level, reach_text = "warn", "没有拿到可用的检查结果。"

    # 稳不稳
    rounds = max((e.get("rounds_total") or 1) for e in endpoints) if endpoints else 1
    flaky = [
        e for e in endpoints
        if (e.get("rounds_total") or 1) > 1
        and (e.get("rounds_ok") or 0) < (e.get("rounds_total") or 1)
    ]
    if rounds == 1:
        stab_level = "unknown"
        stab_text = "只跑了一轮，没有采样，判断不了稳不稳定。"
    elif not flaky:
        stab_level = "ok"
        stab_text = f"跑了 {rounds} 轮，全部成功，没有间歇失败。"
    else:
        worst = min(flaky, key=lambda e: e.get("rounds_ok") or 0)
        stab_level = "bad" if (worst.get("rounds_ok") or 0) == 0 or len(flaky) > len(endpoints) // 2 else "warn"
        stab_text = (
            f"跑了 {rounds} 轮，有 {len(flaky)} 个检查项出现过失败。"
            f"最差的是 {worst['host']}{worst['path']}，{worst.get('rounds_ok')}/{rounds} 成功。"
        )

    # 问题在哪 / 怎么办
    urgent = [f for f in findings if f["level"] == "bad"]
    if not urgent:
        urgent = [f for f in findings if f["level"] == "warn"]
    top = max(urgent, key=_weigh) if urgent else None

    if top is None:
        cause = "没有发现明确的问题。"
        fix = "不需要处理。但如果你还是用不了，问题可能在账号或额度，不在网络这一层。"
    else:
        cause = f"{top['title']}。{top['detail']}" if top["detail"] else f"{top['title']}。"
        fix = top["advice"]
        # 标记出来，界面就不用把它在下面的列表里再列一遍
        top["primary"] = True

    return {
        "reach": {"level": reach_level, "text": reach_text},
        "modes": modes,
        "stability": {"level": stab_level, "text": stab_text},
        "cause": {"level": "bad" if top and top["level"] == "bad" else ("warn" if top else "ok"), "text": cause},
        "fix": {"level": "ok", "text": fix},
        "rounds": rounds,
    }


def run_scan(rounds: int = DEFAULT_ROUNDS, on_progress=None) -> dict:
    """跑完整一次检查。这是唯一对外入口。

    on_progress(done, total) 会在每一轮开始时被叫一次，
    给界面报进度用。不传就什么也不做。
    """
    env = envscan.scan_env()

    endpoints = _probe_all(rounds, on_progress)
    endpoints = [_judge_endpoint(item) for item in endpoints]

    # 拿 chatgpt.com 的 trace 当出口身份旁证
    trace_raw = ""
    for item in endpoints:
        if item["host"] == "chatgpt.com" and item["path"] == "/cdn-cgi/trace":
            trace_raw = item.get("body_head") or ""
            break
    trace = trace_fields(trace_raw)

    # 解析结果里的特殊地址归类
    ip_classes = {}
    fake_ip_seen = False
    for host in {spec["host"] for spec in DOMAINS}:
        resolved = resolve(host)
        classes = []
        for ip_text in resolved["ipv4"] + resolved["ipv6"]:
            label = classify_ip(ip_text)
            classes.append(label)
            if label and "fake-ip" in label:
                fake_ip_seen = True
        resolved["classes"] = classes
        ip_classes[host] = classes
        for item in endpoints:
            if item["host"] == host:
                item["resolved"] = resolved

    # 四段结构要等 resolved 挂上去之后再算
    for item in endpoints:
        item["stages"] = _stages_of(item)

    env["tun_guess"] = envscan.guess_tun(env.get("egress") or {}, fake_ip_seen)

    findings = _build_findings(env, endpoints, trace, ip_classes)
    findings.sort(key=lambda f: LEVEL_ORDER.get(f["level"], 9))
    summary = _summary(endpoints, findings)

    # 给能动手修的问题配一段可以复制走用的提示词。
    # 信息级的条目不需要，它们不是要修的东西。
    context = {"env": env, "trace": trace, "endpoints": endpoints, "summary": summary}
    for item in findings:
        item["prompt"] = "" if item["level"] == "info" else build_prompt(item, context)

    return {
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "env": env,
        "trace": trace,
        "endpoints": endpoints,
        "stages": _stage_summary(endpoints),
        "findings": findings,
        "headline": _headline(findings, endpoints),
        "summary": summary,
        "rounds": rounds,
    }


def main_cli(rounds: int = DEFAULT_ROUNDS) -> int:
    """命令行模式，不启服务，直接把结果打出来。"""
    data = run_scan(rounds=rounds)
    summary = data["summary"]

    print()
    print("=" * 72)
    print(f"Codex 链路体检  {data['generated_at']}")
    print("=" * 72)
    print()

    print()
    print("  通不通    " + summary["reach"]["text"])
    print("  稳不稳    " + summary["stability"]["text"])
    print("  问题在哪  " + summary["cause"]["text"])
    print("  怎么解决  " + summary["fix"]["text"])
    print()

    print("-" * 72)
    print("逐域名结果")
    print("-" * 72)
    for item in data["endpoints"]:
        status = item.get("status")
        status_text = "—" if status is None else str(status)
        ms = item.get("total_ms")
        ms_text = "—" if ms is None else f"{ms}ms"
        tag = "关键" if item["critical"] else "次要"
        rounds_ok = item.get("rounds_ok")
        rounds_total = item.get("rounds_total")
        stable = f"{rounds_ok}/{rounds_total}" if rounds_total else "—"
        kind = " WS " if item.get("kind") == "ws" else ""
        print(f"  {item['host']}{item['path']}{kind}")
        print(
            f"    [{tag}] 状态 {status_text:>4}  耗时 {ms_text:>8}  "
            f"稳定 {stable:>6}  {item['verdict_text']}"
        )
    print()

    mark = {"ok": "[正常]", "warn": "[注意]", "bad": "[问题]", "info": "[信息]"}
    print("-" * 72)
    print("逐项说明")
    print("-" * 72)
    for item in data["findings"]:
        print(f"{mark.get(item['level'], '[?]')} {item['title']}")
        if item["detail"]:
            print(f"       {item['detail']}")
        print(f"       -> {item['advice']}")
        print()

    return 0 if summary["reach"]["level"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main_cli())
