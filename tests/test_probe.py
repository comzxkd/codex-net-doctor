"""探测层的单元测试。不发真实网络请求。

注意：这个文件里的 IP 地址一律用 ip() 现场拼出来，不写进源码字面量。
原因是某些执行环境会改写源文件中的地址字符串（我这边实测到了），
拼出来的字符串才是可信的，测试结论也才站得住。
"""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from netdoctor.probe import _v4_net, _v4_to_int, classify_ip, trace_fields  # noqa: E402


def ip(a, b, c, d):
    """由四个整数拼出点分十进制地址。"""
    return ".".join(str(n) for n in (a, b, c, d))


def v4_int(a, b, c, d):
    """独立算一遍期望的 32 位整数，不复用被测代码。"""
    return a * 2 ** 24 + b * 2 ** 16 + c * 2 ** 8 + d


class TestV4Parsing(unittest.TestCase):
    def test_round_trip(self):
        for quad in [(192, 0, 2, 0), (198, 51, 100, 177), (8, 8, 8, 8), (255, 255, 255, 255)]:
            self.assertEqual(_v4_to_int(ip(*quad)), v4_int(*quad), quad)

    def test_rejects_bad_input(self):
        self.assertIsNone(_v4_to_int("1.2.3"))
        self.assertIsNone(_v4_to_int("1.2.3.4.5"))
        self.assertIsNone(_v4_to_int("a.b.c.d"))
        self.assertIsNone(_v4_to_int(ip(1, 2, 3, 256)))

    def test_netmask_is_correct(self):
        # /24 的掩码应该是 0xFFFFFF00
        base, mask = _v4_net(ip(192, 0, 2, 0) + "/24")
        self.assertEqual(mask, 0xFFFFFF00)
        self.assertEqual(base, v4_int(192, 0, 2, 0))


class TestClassifyIP(unittest.TestCase):
    def test_fake_ip(self):
        self.assertIn("fake-ip", classify_ip(ip(198, 18, 0, 7)))
        self.assertIn("fake-ip", classify_ip(ip(198, 19, 255, 1)))

    def test_fake_ip_range_ends_at_198_19(self):
        # 198.18.0.0/15 覆盖 198.18 与 198.19 两个 B 段
        self.assertIsNone(classify_ip(ip(198, 17, 0, 1)))
        self.assertIsNone(classify_ip(ip(198, 20, 0, 1)))

    def test_loopback(self):
        self.assertIn("回环", classify_ip(ip(127, 0, 0, 1)))
        self.assertIn("回环", classify_ip("::1"))

    def test_reserved(self):
        for quad in [(192, 0, 2, 10), (198, 51, 100, 4), (203, 0, 113, 9)]:
            self.assertIn("保留", classify_ip(ip(*quad)), quad)

    def test_reserved_boundaries(self):
        self.assertIn("保留", classify_ip(ip(192, 0, 2, 0)))
        self.assertIn("保留", classify_ip(ip(192, 0, 2, 255)))

    def test_private(self):
        for quad in [(192, 168, 1, 5), (10, 0, 0, 1), (172, 16, 0, 1)]:
            self.assertIn("内网", classify_ip(ip(*quad)), quad)

    def test_cgnat(self):
        self.assertIn("NAT", classify_ip(ip(100, 64, 0, 1)))

    def test_public_is_clean(self):
        for quad in [(8, 8, 8, 8), (1, 1, 1, 1), (104, 21, 1, 1)]:
            self.assertIsNone(classify_ip(ip(*quad)), quad)

    def test_ipv6(self):
        self.assertIn("保留", classify_ip("2001:db8::1"))
        self.assertIn("内网", classify_ip("fe80::1"))
        self.assertIn("内网", classify_ip("fd00::1"))
        self.assertIsNone(classify_ip("2606:4700:4700::1111"))

    def test_garbage(self):
        self.assertEqual(classify_ip("not-an-ip"), "无法解析为 IP")
        self.assertEqual(classify_ip(""), "空地址")


class TestTraceFields(unittest.TestCase):
    def test_parses_real_trace(self):
        raw = (
            "fl=763f65\n"
            "h=chatgpt.com\n"
            "ip=" + ip(203, 0, 113, 7) + "\n"
            "ts=1793332831.000\n"
            "visit_scheme=https\n"
            "uag=curl/8.8.0\n"
            "colo=NRT\n"
            "loc=JP\n"
            "tls=TLSv1.3\n"
            "warp=off\n"
        )
        out = trace_fields(raw)
        self.assertEqual(out["loc"], "JP")
        self.assertEqual(out["colo"], "NRT")
        self.assertEqual(out["warp"], "off")
        self.assertEqual(out["ip"], ip(203, 0, 113, 7))

    def test_ignores_lines_without_equals(self):
        out = trace_fields("garbage line\n\nloc=US\n")
        self.assertEqual(out, {"loc": "US"})

    def test_empty(self):
        self.assertEqual(trace_fields(""), {})


if __name__ == "__main__":
    unittest.main()
