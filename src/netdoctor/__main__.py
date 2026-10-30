"""入口：命令行或本地界面，二选一。"""

from __future__ import annotations

import argparse

from .diagnose import DEFAULT_ROUNDS, main_cli
from .server import DEFAULT_PORT, serve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="codex-net-doctor",
        description="检查 Codex / GPT 相关域名在你这台机器上到底走不通哪一段。",
    )
    parser.add_argument("--cli", action="store_true", help="不开界面，直接在终端打印结果")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"界面端口，默认 {DEFAULT_PORT}")
    parser.add_argument("--no-browser", action="store_true", help="启动界面但不自动开浏览器")
    parser.add_argument(
        "--rounds",
        type=int,
        default=DEFAULT_ROUNDS,
        help=f"采样轮数，用来判断稳不稳定，默认 {DEFAULT_ROUNDS}。设成 1 会快很多但看不出间歇故障",
    )
    args = parser.parse_args(argv)

    if args.cli:
        return main_cli(rounds=args.rounds)

    serve(port=args.port, open_browser=not args.no_browser, rounds=args.rounds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
