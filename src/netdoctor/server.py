"""本地 HTTP 服务：一个页面 + 一个接口。

只监听 127.0.0.1，不对外。不收集、不上传任何东西。
"""

from __future__ import annotations

import json
import pathlib
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .diagnose import DEFAULT_ROUNDS, run_scan

UI_FILE = pathlib.Path(__file__).parent / "ui" / "index.html"
HOST = "127.0.0.1"
DEFAULT_PORT = 8787

# 一次扫描大概二十几秒，加锁避免同时跑两次把节点打爆
_scan_lock = threading.Lock()

# 扫描进度。同步阻塞的探测拿不到中间态，只能由服务端记下来给页面轮询。
PROGRESS = {"running": False, "done": 0, "total": 0, "started_at": None}
_progress_lock = threading.Lock()


def _on_progress(done: int, total: int) -> None:
    with _progress_lock:
        PROGRESS["done"] = done
        PROGRESS["total"] = total


def _progress_snapshot() -> dict:
    with _progress_lock:
        snap = dict(PROGRESS)
    if snap["started_at"]:
        snap["elapsed"] = round(time.time() - snap["started_at"], 1)
    else:
        snap["elapsed"] = 0
    return snap


class Handler(BaseHTTPRequestHandler):
    server_version = "codex-net-doctor"

    def log_message(self, fmt, *args):  # 静音，别刷屏
        return

    def _send(self, code: int, body: bytes, content_type: str):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path in ("/", "/index.html"):
            try:
                html = UI_FILE.read_bytes()
            except OSError as exc:
                self._send(500, f"读不到界面文件: {exc}".encode(), "text/plain; charset=utf-8")
                return
            self._send(200, html, "text/html; charset=utf-8")
            return

        if path == "/api/scan":
            rounds = DEFAULT_ROUNDS
            if "?" in self.path:
                from urllib.parse import parse_qs

                query = parse_qs(self.path.split("?", 1)[1])
                try:
                    rounds = int(query.get("rounds", [DEFAULT_ROUNDS])[0])
                except ValueError:
                    rounds = DEFAULT_ROUNDS
            try:
                with _scan_lock:
                    with _progress_lock:
                        PROGRESS.update(
                            {
                                "running": True,
                                "done": 0,
                                "total": rounds,
                                "started_at": time.time(),
                            }
                        )
                    try:
                        data = run_scan(rounds=rounds, on_progress=_on_progress)
                    finally:
                        with _progress_lock:
                            PROGRESS["running"] = False
            except Exception as exc:  # 兜底，别让页面白屏
                payload = json.dumps(
                    {"error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False
                ).encode()
                self._send(500, payload, "application/json; charset=utf-8")
                return
            payload = json.dumps(data, ensure_ascii=False).encode()
            self._send(200, payload, "application/json; charset=utf-8")
            return

        if path == "/api/progress":
            payload = json.dumps(_progress_snapshot(), ensure_ascii=False).encode()
            self._send(200, payload, "application/json; charset=utf-8")
            return

        self._send(404, b"not found", "text/plain; charset=utf-8")


def serve(port: int = DEFAULT_PORT, open_browser: bool = True, rounds: int = DEFAULT_ROUNDS) -> None:
    try:
        httpd = ThreadingHTTPServer((HOST, port), Handler)
    except OSError as exc:
        print()
        print(f"端口 {port} 用不了：{exc}")
        print("最常见的原因是已经有一个窗口在跑这个程序。")
        print("先关掉那个窗口；或者换个端口：")
        print(f"    py run.py --port {port + 1}")
        print()
        return

    url = f"http://{HOST}:{port}/"
    print(f"界面已就绪：{url}")
    print(f"每轮采样 {rounds} 次。按 Ctrl+C 停止。")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        httpd.server_close()
