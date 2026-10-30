#!/usr/bin/env python3
"""双击或 `py run.py` 就能跑。不需要安装任何依赖。"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "src"))

from netdoctor.__main__ import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
