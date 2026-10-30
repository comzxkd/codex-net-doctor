"""提示词生成的单元测试。"""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from netdoctor.prompts import build_prompt  # noqa: E402


def context(**kw):
    base = {
        "env": {
            "platform": "win32",
            "proxy_env": {"HTTPS_PROXY": "http://127.0.0.1:7897"},
            "system_proxy": {"available": True, "enabled": False, "server": ""},
            "tun_guess": {"verdict": "没发现迹象", "reasons": []},
            "egress": {"ipv4": "192.168.1.20", "ipv6": None},
        },
        "trace": {"loc": "JP", "colo": "NRT"},
        "endpoints": [],
        "summary": {
            "reach": {"text": "关键检查项里有 2 个走不通。"},
            "stability": {"text": "跑了 5 轮，有 2 个检查项出现过失败。"},
        },
    }
    base.update(kw)
    return base


def finding(**kw):
    base = {
        "level": "bad",
        "title": "2 个检查项都断在「连接」",
        "detail": "api.openai.com/v1/models、chatgpt.com/cdn-cgi/trace",
        "advice": "去看看分流规则",
        "kind": "stage",
        "stage": "tcp",
    }
    base.update(kw)
    return base


class TestBuildPrompt(unittest.TestCase):
    def test_carries_verdict_and_environment(self):
        text = build_prompt(finding(), context())
        self.assertIn("2 个检查项都断在「连接」", text)
        self.assertIn("关键检查项里有 2 个走不通", text)
        self.assertIn("127.0.0.1:7897", text)
        self.assertIn("192.168.1.20", text)
        self.assertIn("JP", text)

    def test_names_platform(self):
        self.assertIn("Windows", build_prompt(finding(), context()))
        mac = context(env={**context()["env"], "platform": "darwin"})
        self.assertIn("macOS", build_prompt(finding(), mac))

    def test_includes_codex_endpoint_facts(self):
        text = build_prompt(finding(), context())
        self.assertIn("api.openai.com", text)
        self.assertIn("backend-api/codex/responses", text)

    def test_always_ends_with_read_only_constraint(self):
        text = build_prompt(finding(), context())
        self.assertIn("先只读排查", text)
        self.assertIn("我确认了你再动手", text)

    def test_ws_prompt_mentions_ws_rules(self):
        text = build_prompt(finding(kind="ws", title="WebSocket 不通"), context())
        self.assertIn("ws/wss", text)
        self.assertIn("network 字段", text)

    def test_region_prompt_talks_about_exit_node(self):
        text = build_prompt(finding(kind="region", title="被地区限制"), context())
        self.assertIn("落地在哪个国家", text)
        self.assertIn("cdn-cgi/trace", text)

    def test_stage_prompt_differs_by_stage(self):
        dns = build_prompt(finding(stage="dns"), context())
        tls = build_prompt(finding(stage="tls"), context())
        self.assertIn("hosts", dns)
        self.assertIn("证书替换", tls)
        self.assertNotEqual(dns, tls)

    def test_unknown_kind_still_produces_something(self):
        text = build_prompt(finding(kind="whatever", stage=None), context())
        self.assertIn("请帮我判断", text)

    def test_no_proxy_reported_honestly(self):
        env = {**context()["env"], "proxy_env": {}}
        text = build_prompt(finding(), context(env=env))
        self.assertIn("没有设置", text)


if __name__ == "__main__":
    unittest.main()
