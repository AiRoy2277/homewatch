# -*- coding: utf-8 -*-
"""管理接口（只监听 Unix socket）。

为什么不用 TCP：Unix socket 不占端口、不需要额外的防火墙规则，
而且文件权限就能限制"只有 nginx 的 worker 能连"。
公网到不了这里，nginx 之外的本机进程也连不上。

鉴权在 nginx 层做（basic auth），所以到这里的请求已经认证过。
但代码仍然按"可能被本机任意进程访问"来写：
  - 只接受 POST + JSON + 自定义头，跨站请求伪造不出来；
  - 动作走白名单，没有执行任意命令的入口；
  - 每次写操作落审计日志。
"""

import http.server
import json
import os
import signal
import socketserver
import sys
import time

from .. import config as config_mod
from . import actions, audit, overview

SOCK_PATH = os.environ.get("HOMEWATCH_ADMIN_SOCK", "/run/homewatch/admin.sock")
MAX_BODY = 64 * 1024
REQUIRED_HEADER = "X-Requested-With"
REQUIRED_VALUE = "HomeWatch"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "HomeWatch"
    sys_version = ""
    timeout = 15

    # ---- 基础设施 ----

    def log_message(self, fmt, *args):
        sys.stderr.write("[admin] %s %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _client_ip(self):
        return (self.headers.get("X-Real-IP")
                or self.headers.get("X-Forwarded-For")
                or "local").split(",")[0].strip()[:64]

    def _path(self):
        return self.path.split("?")[0].rstrip("/") or "/"

    def _query(self):
        q = {}
        if "?" in self.path:
            for kv in self.path.split("?", 1)[1].split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    q[k] = v
        return q

    def _db(self):
        from .. import db as db_mod
        return db_mod.connect(config_mod.load()["paths"]["db"])

    def _series(self):
        """态势页的时间范围曲线。range 取 report.RANGES 里的 key。"""
        from .. import report as report_mod
        q = self._query()
        try:
            cfg = config_mod.load()
            conn = self._db()
            try:
                data = report_mod.series(conn, cfg, q.get("range"))
            finally:
                conn.close()
            data["ranges"] = report_mod.range_list()
            self._send(200, {"ok": True, "data": data})
        except Exception as exc:  # noqa: BLE001
            self.log_message("series 失败: %s", exc)
            self._send(500, {"ok": False, "error": "读取时间线失败"})

    def _range(self):
        """一次取回三个视图都需要的范围数据，切范围时只发一个请求。"""
        from .. import report as report_mod
        q = self._query()
        key = q.get("range")
        try:
            cfg = config_mod.load()
            conn = self._db()
            try:
                data = {
                    "series": report_mod.series(conn, cfg, key),
                    "snap": report_mod.snapshot(conn, cfg, key),
                    "ranges": report_mod.range_list(),
                }
            finally:
                conn.close()
            # 两份数据各自算过一遍范围，以 series 的为准，前端只读一份
            data["snap"]["label"] = data["series"]["label"]
            data["snap"]["step"] = data["series"]["step"]
            data["snap"]["window"] = data["series"]["window"]
            data["snap"]["truncated"] = data["series"]["truncated"]
            data["snap"]["covered"] = data["series"]["covered"]
            self._send(200, {"ok": True, "data": data})
        except Exception as exc:  # noqa: BLE001
            self.log_message("range 失败: %s", exc)
            self._send(500, {"ok": False, "error": "读取区间数据失败"})

    def _ip(self):
        """单个 IP 的档案：弹窗用。"""
        from .. import ipinfo
        q = self._query()
        try:
            cfg = config_mod.load()
            conn = self._db()
            try:
                data = ipinfo.detail(conn, cfg, q.get("ip", ""), q.get("hours"))
            finally:
                conn.close()
            self._send(200, {"ok": True, "data": data})
        except ValueError as exc:
            self._send(400, {"ok": False, "error": "IP 格式不正确：%s" % str(exc)[:40]})
        except Exception as exc:  # noqa: BLE001
            self.log_message("ip 失败: %s", exc)
            self._send(500, {"ok": False, "error": "读取 IP 档案失败"})

    def _anomaly(self):
        """某类异常来自哪些 IP：异常类型弹窗用。"""
        from .. import report as report_mod
        q = self._query()
        try:
            cfg = config_mod.load()
            conn = self._db()
            try:
                data = report_mod.anomaly_ips(conn, cfg, q.get("kind"), q.get("range"))
            finally:
                conn.close()
            self._send(200, {"ok": True, "data": data})
        except ValueError as exc:
            self._send(400, {"ok": False, "error": str(exc)[:80]})
        except Exception as exc:  # noqa: BLE001
            self.log_message("anomaly 失败: %s", exc)
            self._send(500, {"ok": False, "error": "读取异常来源失败"})

    def _fw(self):
        """规则 + 生成的 nft 片段，用于面板里"看看实际下发了什么"。"""
        from ..ops import fw as fw_ops
        try:
            cfg = config_mod.load()
            data = fw_ops.list_rules(cfg)
            data["nft"] = fw_ops.preview(cfg)
            self._send(200, {"ok": True, "data": data})
        except Exception as exc:  # noqa: BLE001
            self.log_message("fw 失败: %s", exc)
            self._send(500, {"ok": False, "error": "读取防火墙规则失败"})

    def _bans(self):
        """只读封禁状态。比 /api/state 轻，专门给"点完封禁刷标签"用。"""
        from .. import banmap as banmap_mod
        try:
            cfg = config_mod.load()
            self._send(200, {"ok": True, "data": {"banned": banmap_mod.build(cfg),
                                                  "sum": banmap_mod.summary(cfg)}})
        except Exception as exc:  # noqa: BLE001
            self.log_message("bans 失败: %s", exc)
            self._send(500, {"ok": False, "error": "读取封禁状态失败"})

    def _geo(self):
        """地域封锁状态 + 实际下发的规则文本。"""
        from ..ops import geoblock as geo_ops
        try:
            cfg = config_mod.load()
            data = geo_ops.status(cfg)
            data["nft"] = geo_ops.preview(cfg)
            self._send(200, {"ok": True, "data": data})
        except Exception as exc:  # noqa: BLE001
            self.log_message("geo 失败: %s", exc)
            self._send(500, {"ok": False, "error": "读取地域封锁状态失败"})

    # ---- GET ----

    def do_GET(self):
        p = self._path()
        if p in ("/api/series", "/series"):
            self._series()
            return
        if p in ("/api/range", "/range"):
            self._range()
            return
        if p in ("/api/ip", "/ip"):
            self._ip()
            return
        if p in ("/api/anomaly", "/anomaly"):
            self._anomaly()
            return
        if p in ("/api/fw", "/fw"):
            self._fw()
            return
        if p in ("/api/bans", "/bans"):
            self._bans()
            return
        if p in ("/api/geo", "/geo"):
            self._geo()
            return
        if p in ("/api/state", "/state"):
            try:
                cfg = config_mod.load()
                self._send(200, {"ok": True, "data": overview.build(cfg, force=True)})
            except Exception as exc:  # noqa: BLE001
                self.log_message("state 失败: %s", exc)
                self._send(500, {"ok": False, "error": "读取状态失败"})
            return
        if p in ("/api/health", "/health"):
            self._send(200, {"ok": True, "service": "homewatch-admin"})
            return
        self._send(404, {"ok": False, "error": "not found"})

    # ---- POST ----

    def do_POST(self):
        if self._path() not in ("/api/action", "/action"):
            self._send(404, {"ok": False, "error": "not found"})
            return

        # CSRF：跨站表单发不出自定义头；跨域 fetch 会先发 preflight，我们不回 CORS 头
        if self.headers.get(REQUIRED_HEADER) != REQUIRED_VALUE:
            self._send(403, {"ok": False, "error": "缺少请求标记"})
            return

        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype != "application/json":
            self._send(415, {"ok": False, "error": "只接受 application/json"})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._send(400, {"ok": False, "error": "请求体为空或过大"})
            return

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"ok": False, "error": "JSON 解析失败"})
            return
        if not isinstance(payload, dict):
            self._send(400, {"ok": False, "error": "请求体必须是对象"})
            return

        name = payload.get("action")
        params = payload.get("params") or {}
        if not isinstance(name, str) or not isinstance(params, dict):
            self._send(400, {"ok": False, "error": "action / params 格式不正确"})
            return

        ip = self._client_ip()
        started = time.time()
        cfg = config_mod.load()

        try:
            result = actions.run(cfg, name, params, {"ip": ip})
        except actions.ActionError as exc:
            audit.write(cfg, ip, name, params, ok=False, msg=str(exc),
                        ms=(time.time() - started) * 1000)
            self._send(400, {"ok": False, "error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001
            # 内部错误只记服务端日志，不回给前端细节
            self.log_message("动作 %s 失败: %r", name, exc)
            audit.write(cfg, ip, name, params, ok=False, msg="内部错误",
                        ms=(time.time() - started) * 1000)
            self._send(500, {"ok": False, "error": "执行失败：%s" % exc})
            return

        audit.write(cfg, ip, name, params, ok=True,
                    msg=result.get("msg", ""), ms=(time.time() - started) * 1000)
        overview.invalidate()

        try:
            state = overview.build(config_mod.load(), force=True)
        except Exception:  # noqa: BLE001
            state = None
        self._send(200, {"ok": True, "result": result, "data": state})


class UnixHTTPServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def get_request(self):
        conn, _ = super().get_request()
        return conn, ("unix", 0)


def _prepare_socket(path):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    if os.path.exists(path):
        os.remove(path)


def _set_perms(path, group="www-data"):
    """让 nginx 的 worker 能连，其他用户不能。"""
    try:
        import grp
        gid = grp.getgrnam(group).gr_gid
        os.chown(path, 0, gid)
    except (KeyError, PermissionError, OSError):
        pass
    try:
        os.chmod(path, 0o660)
    except OSError:
        pass


def serve(path=None):
    path = path or SOCK_PATH
    _prepare_socket(path)

    server = UnixHTTPServer(path, Handler)
    _set_perms(path)

    def _bye(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _bye)
    sys.stderr.write("[admin] listening on %s\n" % path)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("[admin] shutting down\n")
    finally:
        server.server_close()
        try:
            os.remove(path)
        except OSError:
            pass


if __name__ == "__main__":
    serve()
