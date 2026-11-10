# -*- coding: utf-8 -*-
"""把线上面板原样搬到本地端口（自动带 basic auth），用于真实浏览器截图验证。

    python tools/mirror.py 8791
"""
import base64
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import os

# 面板地址与 basic auth 从环境变量读，例如：
#   HOMEWATCH_UP=http://192.168.1.10:8088 HOMEWATCH_AUTH=admin:密码 python tools/mirror.py 8791
UP = os.environ.get("HOMEWATCH_UP", "http://127.0.0.1:8088").rstrip("/")
AUTH = "Basic " + base64.b64encode(
    os.environ.get("HOMEWATCH_AUTH", "").encode()).decode()
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8791


class H(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        try:
            req = urllib.request.Request(UP + self.path, headers={"Authorization": AUTH})
            with urllib.request.urlopen(req, timeout=10) as r:
                body = r.read()
                ctype = r.headers.get("Content-Type", "text/html; charset=utf-8")
                code = r.status
        except Exception as e:  # noqa: BLE001
            body = ("MIRROR ERROR: %s" % e).encode()
            ctype = "text/plain; charset=utf-8"
            code = 502
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


print("mirror %s -> http://127.0.0.1:%d" % (UP, PORT))
ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
