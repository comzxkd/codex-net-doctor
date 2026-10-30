"""诊断层的单元测试。不发真实网络请求。"""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from netdoctor.diagnose import _first_broken_stage, _headline, _judge_endpoint, _summary  # noqa: E402


def endpoint(**kw):
    base = {
        "host": "api.openai.com",
        "path": "/v1/models",
        "method": "GET",
        "critical": True,
        "status": None,
        "total_ms": None,
        "body_head": "",
        "error": None,
    }
    base.update(kw)
    return base


class TestJudgeEndpoint(unittest.TestCase):
    def test_region_blocked_wins(self):
        item = _judge_endpoint(endpoint(
            status=403,
            body_head='{"error":{"code":"unsupported_country_region_territory"}}',
        ))
        self.assertEqual(item["verdict"], "region_blocked")

    def test_plain_403_is_reachable(self):
        # 没带 token 的 403 不是地区问题，不能误判
        item = _judge_endpoint(endpoint(status=403, body_head='{"error":"forbidden"}'))
        self.assertEqual(item["verdict"], "reachable")

    def test_401_is_reachable(self):
        item = _judge_endpoint(endpoint(status=401, body_head='{"error":"no token"}'))
        self.assertEqual(item["verdict"], "reachable")

    def test_200_is_reachable(self):
        item = _judge_endpoint(endpoint(status=200))
        self.assertEqual(item["verdict"], "reachable")

    def test_500_is_server_error(self):
        item = _judge_endpoint(endpoint(status=502))
        self.assertEqual(item["verdict"], "server_error")

    def test_connection_error(self):
        item = _judge_endpoint(endpoint(error="TCP 连接失败: timed out"))
        self.assertEqual(item["verdict"], "unreachable")

    def test_error_field_but_got_status(self):
        # 有些场景下报了错但已经拿到响应，应以状态码为准
        item = _judge_endpoint(endpoint(status=200, error="读超时"))
        self.assertEqual(item["verdict"], "reachable")


class TestFirstBrokenStage(unittest.TestCase):
    def test_returns_earliest_gap(self):
        stages = {
            "dns": {"ok": True},
            "tcp": {"ok": True},
            "tls": {"ok": False},
            "http": {"ok": False},
        }
        self.assertEqual(_first_broken_stage(stages), "tls")

    def test_dns_dies_first(self):
        stages = {k: {"ok": False} for k in ("dns", "tcp", "tls", "http")}
        self.assertEqual(_first_broken_stage(stages), "dns")

    def test_all_passed(self):
        stages = {k: {"ok": True} for k in ("dns", "tcp", "tls", "http")}
        self.assertEqual(_first_broken_stage(stages), "")

    def test_missing_keys_count_as_broken(self):
        self.assertEqual(_first_broken_stage({}), "dns")


def ws(**kw):
    base = {
        "host": "chatgpt.com",
        "path": "/backend-api/codex/responses",
        "method": "WS",
        "kind": "ws",
        "critical": True,
        "status": None,
        "upgrade": False,
        "headers": {},
        "error": None,
        "rounds_ok": 1,
        "rounds_total": 1,
    }
    base.update(kw)
    return base


class TestJudgeWebSocket(unittest.TestCase):
    def test_upgraded_is_reachable(self):
        item = _judge_endpoint(ws(status=101, upgrade=True))
        self.assertEqual(item["verdict"], "reachable")
        self.assertIn("101", item["verdict_text"])

    def test_401_with_cf_ray_means_path_works(self):
        item = _judge_endpoint(ws(status=401, headers={"cf-ray": "abc"}))
        self.assertEqual(item["verdict"], "reachable")

    def test_401_without_cf_ray_is_unknown(self):
        # 没有 cf-ray 说明可能被中间层挡了，不能算通
        item = _judge_endpoint(ws(status=401, headers={}))
        self.assertEqual(item["verdict"], "unknown")

    def test_404_is_unknown_not_broken(self):
        # 路径错了不能诬赖用户的网络
        item = _judge_endpoint(ws(status=404))
        self.assertEqual(item["verdict"], "unknown")
        self.assertIn("端点", item["verdict_text"])

    def test_502_is_server_error(self):
        item = _judge_endpoint(ws(status=502))
        self.assertEqual(item["verdict"], "server_error")

    def test_timeout_is_unreachable(self):
        item = _judge_endpoint(ws(error="TCP 连接失败: timed out"))
        self.assertEqual(item["verdict"], "unreachable")


class TestSummary(unittest.TestCase):
    def _ep(self, **kw):
        base = {
            "host": "api.openai.com",
            "path": "/v1/models",
            "critical": True,
            "core": True,
            "kind": "http",
            "verdict": "reachable",
            "rounds_ok": 3,
            "rounds_total": 3,
        }
        base.update(kw)
        return base

    def _set(self, chatgpt_broken=False, apikey_broken=False, rounds=3):
        """一份完整的检查结果：账号模式三个核心项 + API Key 一个。"""
        def verdict(flag):
            return "unreachable" if flag else "reachable"

        def ok(flag):
            return 0 if flag else rounds

        return [
            self._ep(host="chatgpt.com", path="/backend-api/codex/responses",
                     verdict=verdict(chatgpt_broken), rounds_ok=ok(chatgpt_broken), rounds_total=rounds),
            self._ep(host="chatgpt.com", path="/backend-api/codex/responses", kind="ws",
                     verdict=verdict(chatgpt_broken), rounds_ok=ok(chatgpt_broken), rounds_total=rounds),
            self._ep(host="auth.openai.com", path="/",
                     verdict=verdict(chatgpt_broken), rounds_ok=ok(chatgpt_broken), rounds_total=rounds),
            self._ep(verdict=verdict(apikey_broken), rounds_ok=ok(apikey_broken), rounds_total=rounds),
        ]

    def test_all_good(self):
        s = _summary(self._set(), [])
        self.assertEqual(s["reach"]["level"], "ok")
        self.assertEqual(s["stability"]["level"], "ok")
        self.assertTrue(all(m["available"] for m in s["modes"]))

    def test_both_modes_broken_says_cannot_use(self):
        s = _summary(self._set(chatgpt_broken=True, apikey_broken=True), [])
        self.assertEqual(s["reach"]["level"], "bad")
        self.assertIn("用不了", s["reach"]["text"])
        self.assertFalse(any(m["available"] for m in s["modes"]))

    def test_only_apikey_works(self):
        s = _summary(self._set(chatgpt_broken=True), [])
        self.assertEqual(s["reach"]["level"], "warn")
        self.assertIn("API Key", s["reach"]["text"])
        names = {m["key"]: m["available"] for m in s["modes"]}
        self.assertFalse(names["chatgpt"])
        self.assertTrue(names["apikey"])

    def test_only_chatgpt_works(self):
        s = _summary(self._set(apikey_broken=True), [])
        self.assertEqual(s["reach"]["level"], "warn")
        self.assertIn("账号登录", s["reach"]["text"])

    def test_mode_detail_names_the_blocking_address(self):
        s = _summary(self._set(apikey_broken=True), [])
        apikey = next(m for m in s["modes"] if m["key"] == "apikey")
        self.assertIn("api.openai.com", apikey["detail"])

    def test_flaky_is_reported(self):
        eps = [self._ep(rounds_ok=2, rounds_total=3)]
        s = _summary(eps, [])
        self.assertIn(s["stability"]["level"], ("warn", "bad"))
        self.assertIn("2/3", s["stability"]["text"])

    def test_single_round_cannot_judge_stability(self):
        eps = [self._ep(rounds_ok=1, rounds_total=1)]
        s = _summary(eps, [])
        self.assertEqual(s["stability"]["level"], "unknown")

    def test_cause_and_fix_come_from_worst_finding(self):
        findings = [
            {"level": "info", "title": "信息项", "detail": "", "advice": "忽略"},
            {"level": "bad", "title": "真问题", "detail": "细节", "advice": "这么改"},
        ]
        s = _summary([self._ep()], findings)
        self.assertIn("真问题", s["cause"]["text"])
        self.assertEqual(s["fix"]["text"], "这么改")

    def test_region_block_outranks_generic_break(self):
        findings = [
            {"level": "bad", "title": "x 断在「连接」", "detail": "", "advice": "A"},
            {"level": "bad", "title": "x 被地区限制", "detail": "", "advice": "B"},
        ]
        s = _summary([self._ep()], findings)
        self.assertIn("地区", s["cause"]["text"])
        self.assertEqual(s["fix"]["text"], "B")

    def test_order_does_not_depend_on_insertion(self):
        a = {"level": "bad", "title": "单条 断在「连接」", "detail": "", "advice": "单"}
        b = {"level": "bad", "title": "3 个检查项都断在「连接」", "detail": "h1、h2、h3", "advice": "多"}
        for findings in ([a, b], [b, a]):
            s = _summary([self._ep()], list(findings))
            self.assertEqual(s["fix"]["text"], "多")

    def test_no_findings_still_answers(self):
        s = _summary([self._ep()], [])
        self.assertIn("没有发现", s["cause"]["text"])
        self.assertTrue(s["fix"]["text"])


class TestHeadline(unittest.TestCase):
    def test_region_problem_takes_priority(self):
        findings = [
            {"level": "bad", "title": "出口 IP 被判成 CN 的地区限制", "detail": "", "advice": ""},
            {"level": "bad", "title": "某域名 连不上", "detail": "", "advice": ""},
        ]
        self.assertEqual(_headline(findings, [])["level"], "bad")
        self.assertIn("地区", _headline(findings, [])["text"])

    def test_all_clean(self):
        findings = [{"level": "info", "title": "x", "detail": "", "advice": ""}]
        self.assertEqual(_headline(findings, [])["level"], "ok")

    def test_warn_only(self):
        findings = [{"level": "warn", "title": "x", "detail": "", "advice": ""}]
        self.assertEqual(_headline(findings, [])["level"], "warn")

    def test_grouped_stage_finding_still_counts_as_dead(self):
        # 合并后的标题是「3 个域名都断在「连接」」，也要被识别为不通
        findings = [{"level": "bad", "title": "3 个域名都断在「连接」", "detail": "", "advice": ""}]
        self.assertEqual(_headline(findings, [])["level"], "bad")


if __name__ == "__main__":
    unittest.main()
