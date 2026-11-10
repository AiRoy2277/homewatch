# -*- coding: utf-8 -*-
"""生成一份带假数据的面板，用来本地看视觉与交互（不参与部署）。

用法：python tools/preview.py   -> 输出目录打印在最后
"""
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
_out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, ".preview")
os.makedirs(_out, exist_ok=True)
os.environ["HOMEWATCH_ROOT"] = _out

from homewatch import config as C  # noqa: E402
from homewatch import db as D  # noqa: E402
from homewatch.web import render as R  # noqa: E402

cfg = C.load(os.path.join(ROOT, "config.example.json"))
cfg["title"] = "HomeWatch"
cfg["cloudflare"].update({"enabled": True, "api_token": "x" * 40,
                          "zone_name": "example.com"})

conn = D.connect(cfg["paths"]["db"])
for _t in ("hits", "paths", "net", "sshfail", "sshseen", "meta",
           "bans", "anomaly", "agent", "geo"):
    try:
        conn.execute("DELETE FROM %s" % _t)
    except Exception:  # noqa: BLE001
        pass
conn.commit()

now = int(time.time())
now -= now % 60

ips = [
    ("203.0.113.45", 4120, "Mozilla/5.0 (compatible; Baiduspider/2.0)"),
    ("203.0.113.77", 980, "python-requests/2.31"),
    ("203.0.113.31", 640, "Mozilla/5.0 zgrab/0.x"),
    ("203.0.113.55", 220, "curl/8.4.0"),
    ("1.1.1.1", 120, "Mozilla/5.0 (Macintosh)"),
]
for i, (ip, n, ua) in enumerate(ips):
    conn.execute("INSERT OR REPLACE INTO hits VALUES(?,?,?,?)", (now, ip, 402, n))
    conn.execute("INSERT OR REPLACE INTO hits VALUES(?,?,?,?)", (now, ip, 200, max(1, n // 40)))
    conn.execute("INSERT OR REPLACE INTO agent VALUES(?,?,?,?)", (now, ip, ua, n))

# 近 3 小时的分钟级曲线，让图表有形状
import math
for m in range(180):
    ts = now - m * 60 - (now % 60)
    total = int(28 + 22 * math.sin(m / 14.0) + (m % 7) * 3
                + (95 if 40 < m < 52 else 0))
    blocked = int(total * (0.72 if 40 < m < 52 else 0.18))
    conn.execute("INSERT OR REPLACE INTO hits VALUES(?,?,?,?)",
                 (ts, "203.0.113.45", 402, max(0, blocked)))
    conn.execute("INSERT OR REPLACE INTO hits VALUES(?,?,?,?)",
                 (ts, "1.1.1.1", 200, max(0, total - blocked)))

# 近 3 小时的分钟级曲线，让图表有形状
import math
for m in range(180):
    ts = now - m * 60 - (now % 60)
    total = int(28 + 22 * math.sin(m / 14.0) + (m % 7) * 3
                + (95 if 40 < m < 52 else 0))
    blocked = int(total * (0.72 if 40 < m < 52 else 0.18))
    conn.execute("INSERT OR REPLACE INTO hits VALUES(?,?,?,?)",
                 (ts, "203.0.113.45", 402, max(0, blocked)))
    conn.execute("INSERT OR REPLACE INTO hits VALUES(?,?,?,?)",
                 (ts, "1.1.1.1", 200, max(0, total - blocked)))

for path, n in [("/wp-login.php", 320), ("/.env", 180), ("/admin", 96),
                ("/phpmyadmin", 64), ("/api/v1/../etc/passwd", 21)]:
    conn.execute("INSERT OR REPLACE INTO paths VALUES(?,?,?,?,?,?)",
                 (now, "203.0.113.45", path, 402, 0, n))

conn.execute("INSERT OR REPLACE INTO sshfail VALUES(?,?,?)", (now, "203.0.113.77", 87))
conn.execute("INSERT OR REPLACE INTO net VALUES(?,?,?,?)", (now, 143, 22, 8))

for ip, kind, n, vmax in [("203.0.113.45", "long_uri", 12, 2140),
                          ("203.0.113.45", "honeypot", 5, 0),
                          ("203.0.113.31", "big_req", 3, 98304),
                          ("203.0.113.77", "bad_ua", 9, 0)]:
    conn.execute("INSERT OR REPLACE INTO anomaly VALUES(?,?,?,?,?)", (now, ip, kind, n, vmax))

for ip, geo in [("203.0.113.45", ("中国台湾", "TW", "臺北", "Google LLC")),
                ("203.0.113.77", ("荷兰", "NL", "阿姆斯特丹", "AS-CHOOPA")),
                ("203.0.113.31", ("美国", "US", "洛杉矶", "Shodan")),
                ("203.0.113.55", ("德国", "DE", "柏林", "Tor Exit")),
                ("1.1.1.1", ("澳大利亚", "AU", "悉尼", "Cloudflare"))]:
    conn.execute("INSERT OR REPLACE INTO geo VALUES(?,?,?,?,?,?,?,?,?)",
                 (ip, "ok", geo[0], geo[1], "", geo[2], geo[3], "", now))

conn.execute("INSERT OR REPLACE INTO bans VALUES(?,?,?,?,?,?,?,?)",
             (now - 300, "203.0.113.45", 24, "both", "ip_rate",
              "自动封禁：单 IP 高频请求", "auto", 120))
conn.execute("INSERT OR REPLACE INTO bans VALUES(?,?,?,?,?,?,?,?)",
             (now - 900, "203.0.113.77", 12, "both", "ssh_brute",
              "自动封禁：SSH 爆破", "auto", 87))
conn.commit()

R.render(conn, cfg)
conn.close()

# 管理页 / 策略页的数据来自 /api/state，静态预览里没法真跑后端，
# 这里挂一层 fetch 兜底，让这两页也能看到真实排版（只是动作不会真的执行）。
MOCK = {
    "ports": [
        {"port": 22, "label": "SSH", "desc": "远程管理", "closed": False,
         "listening": True, "readonly": False,
         "ctrl": {"in": "lan", "out": "allow", "proto": "tcp"}},
        {"port": 8443, "label": "源站", "desc": "Cloudflare 回源", "closed": False,
         "listening": True, "readonly": False,
         "ctrl": {"in": "cf", "out": "allow", "proto": "tcp"}},
        {"port": 8088, "label": "监控面板", "desc": "本页自身", "closed": False,
         "listening": True, "readonly": True,
         "ctrl": {"in": "lan", "out": "allow", "proto": "tcp"}},
        {"port": 7000, "label": "frps 控制口", "desc": "frp 服务端", "closed": False,
         "listening": True, "readonly": False,
         "ctrl": {"in": "allow", "out": "lan", "proto": "tcp"}},
        {"port": 28006, "label": "PVE 控制台", "desc": "frp 转发", "closed": True,
         "listening": False, "readonly": False,
         "ctrl": {"in": "deny", "out": "allow", "proto": "tcp"}},
    ],
    "fw": {
        "policy": {"in": "drop", "out": "accept"},
        "container": True, "counters": True, "max": 200,
        "rules": [
            {"id": "fw01a1", "name": "面板白名单", "note": "只允许内网打开面板",
             "dir": "in", "dir_label": "入站", "proto": "tcp", "proto_label": "TCP",
             "port": "8088", "port_label": "8088",
             "src": ["192.168.1.0/24"], "src_label": "192.168.1.0/24",
             "action": "accept", "action_label": "放行", "enabled": True,
             "priority": 10, "hits": 18422, "bytes": 2411720},
            {"id": "fw01a2", "name": "SSH 仅内网 + 我的出口", "note": "",
             "dir": "in", "dir_label": "入站", "proto": "tcp", "proto_label": "TCP",
             "port": "22", "port_label": "22",
             "src": ["192.168.1.0/24", "203.0.113.9/32"],
             "src_label": "192.168.1.0/24 等 2 个",
             "action": "accept", "action_label": "放行", "enabled": True,
             "priority": 20, "hits": 96, "bytes": 184320},
            {"id": "fw01a3", "name": "拒绝 MySQL", "note": "没有这台数据库，直接挡掉",
             "dir": "in", "dir_label": "入站", "proto": "tcp", "proto_label": "TCP",
             "port": "3306", "port_label": "3306", "src": [], "src_label": "任意",
             "action": "drop", "action_label": "拒绝", "enabled": True,
             "priority": 30, "hits": 0, "bytes": 0},
            {"id": "fw01a4", "name": "Cloudflare 回源", "note": "",
             "dir": "in", "dir_label": "入站", "proto": "tcp", "proto_label": "TCP",
             "port": "8443", "port_label": "8443",
             "src": ["173.245.48.0/20", "103.21.244.0/22"],
             "src_label": "173.245.48.0/20 等 2 个",
             "action": "accept", "action_label": "放行", "enabled": True,
             "priority": 40, "hits": 3110, "bytes": 912340},
            {"id": "fw01a5", "name": "禁止本机外发 25", "note": "防垃圾邮件外发",
             "dir": "out", "dir_label": "出站", "proto": "tcp", "proto_label": "TCP",
             "port": "25", "port_label": "25", "src": [], "src_label": "任意",
             "action": "drop", "action_label": "拒绝", "enabled": False,
             "priority": 50, "hits": 0, "bytes": 0},
        ],
    },
    "fw_ctx": {
        "lan": ["192.168.1.0/24"], "own": ["203.0.113.9"],
        "cf": ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22"],
        "admin_port": 8088, "ssh_port": 22,
    },
    "geo_lock": {
        "in": {"enabled": True, "scope": "web", "scope_label": "只挡 Web 端口",
               "ports": [80, 443, 8088, 8443]},
        "out": {"enabled": False},
        "container": True,
        "allow": ["198.18.0.0/15"],
        "cn": {"v4": 4339, "v6": 1688, "updated": int(time.time()) - 86400 * 6,
               "source": "clang.cn", "age_days": 6},
        "exempt": {"lan": ["192.168.1.0/24"], "own": ["203.0.113.9/32"],
                   "cf": 22, "dns": ["192.168.1.1"],
                   "allow": ["198.18.0.0/15"]},
        "hits": {"in": {"packets": 18422, "bytes": 2411720},
                 "out": {"packets": 0, "bytes": 0}},
        "counters": True, "on": True, "loaded": True,
    },
    "banned": {
        "203.0.113.45": {"ip": "203.0.113.45", "nft": True, "nginx": True,
                          "cf": True, "until": int(time.time()) + 86400,
                          "reason": "自动封禁：单 IP 高频请求", "auto": True,
                          "layers": ["nft", "nginx", "cf"],
                          "label": "nft、nginx、Cloudflare"},
        "203.0.113.77": {"ip": "203.0.113.77", "nft": True, "nginx": True,
                         "cf": False, "until": 0,
                         "reason": "自动封禁：SSH 爆破", "auto": True,
                         "layers": ["nft", "nginx"], "label": "nft、nginx"},
    },
    "listen": [
        {"port": 22, "procs": ["sshd"], "addr": "*", "container": None},
        {"port": 5000, "procs": ["python"], "addr": "0.0.0.0", "container": None},
        {"port": 7000, "procs": ["frps"], "addr": "*", "container": None},
        {"port": 7500, "procs": ["frps"], "addr": "127.0.0.1", "container": None},
        {"port": 8088, "procs": ["nginx"], "addr": "192.168.1.50", "container": None},
        {"port": 8443, "procs": ["nginx"], "addr": "0.0.0.0", "container": None},
        {"port": 9000, "procs": ["docker-proxy"],
         "addr": "0.0.0.0", "container": {"name": "home-assistant", "image": "ghcr.io/home-assistant"}},
    ],
    "ssh": {"socket_active": True, "service_active": True, "port": 22,
            "listening": True, "password_age": 21, "pending": None},
    "auth": {"path": "/etc/nginx/.htpasswd.homewatch", "exists": True,
             "user": "admin", "users": ["admin"], "age_days": 21,
             "mtime": int(time.time()) - 86400 * 21, "backup": False,
             "mode": "0640", "warnings": []},
    "blocked_nft": [
        {"ip": "203.0.113.45", "until": int(time.time()) + 86400,
         "reason": "自动封禁：单 IP 高频请求", "auto": True,
         "geo": "中国台湾·臺北", "cc": "TW"},
        {"ip": "203.0.113.77", "until": 0, "reason": "自动封禁：SSH 爆破",
         "auto": True, "geo": "荷兰·阿姆斯特丹", "cc": "NL"},
    ],
    "blocked_nginx": ["203.0.113.45", "203.0.113.77", "203.0.113.31"],
    "cf": {"updated": int(time.time()), "v4": 15, "v6": 7,
           "api": {"enabled": True, "configured": True, "auto_sync": True,
                   "zone": "example.com", "zone_id": "", "token": "cfat…b31e",
                   "has_token": True, "note": "HomeWatch", "timeout": 8},
           "last": {"at": int(time.time()) - 120, "ok": True,
                    "msg": "边缘规则：已存在 4", "added": [], "failed": []},
           "synced_at": int(time.time()) - 120},
    "policy": {
        "enabled": True, "auto_ban": True, "dry_run": False,
        "ban_mode": "silent", "ban_mode_label": "444 静默断开", "silent_log": True,
        "wiring": {"mode": "silent", "mode_label": "444 静默断开", "want_code": 444,
                   "wired": True, "log_wired": True, "via": "include",
                   "reply_code": 444, "ready": True, "files": [], "warnings": []},
        "max_bans_per_run": 3, "max_hours": 720, "repeat_window_hours": 72,
        "whitelist": ["198.51.100.7"],
        "limits": {"uri_len": 1024, "req_bytes": 65536, "ua_len": 400},
        "allowed_methods": ["GET", "HEAD"], "trusted_bots": ["googlebot", "bingbot"],
        "warnings": [], "log_fields": {"request_length": False, "user_agent": True},
        "rules": [
            {"id": "ssh_brute", "name": "SSH 爆破", "source": "ssh_fail",
             "window": 300, "threshold": 5, "hours": 24, "layer": "both", "enabled": True},
            {"id": "honeypot", "name": "蜜罐路径", "source": "honeypot",
             "window": 3600, "threshold": 1, "hours": 72, "layer": "both", "enabled": True},
            {"id": "ip_rate", "name": "单 IP 高频请求", "source": "http_total",
             "window": 120, "threshold": 120, "hours": 12, "layer": "both", "enabled": True},
            {"id": "long_uri", "name": "超长 URL", "source": "long_uri",
             "window": 300, "threshold": 3, "hours": 12, "layer": "both", "enabled": True},
            {"id": "big_req", "name": "超大请求报文", "source": "big_req",
             "window": 300, "threshold": 3, "hours": 12, "layer": "nginx", "enabled": True},
        ],
        "last": {"at": int(time.time()) - 60, "msg": "已自动封禁 2 个 IP",
                 "banned": [
                     {"ip": "203.0.113.45", "hours": 24, "geo": "中国台湾·臺北",
                      "reason": "自动封禁：单 IP 高频请求"},
                     {"ip": "203.0.113.77", "hours": 24, "geo": "荷兰·阿姆斯特丹",
                      "reason": "自动封禁：SSH 爆破"}],
                 "candidates": 2, "dry_run": False},
        "bans": [
            {"ts": int(time.time()) - 300, "ip": "203.0.113.45", "hours": 24,
             "layer": "both", "rule": "ip_rate", "reason": "自动封禁：单 IP 高频请求",
             "mode": "auto", "hits": 120, "geo": "中国台湾·臺北", "cc": "TW"},
            {"ts": int(time.time()) - 900, "ip": "203.0.113.77", "hours": 24,
             "layer": "both", "rule": "ssh_brute", "reason": "自动封禁：SSH 爆破",
             "mode": "auto", "hits": 87, "geo": "荷兰·阿姆斯特丹", "cc": "NL"},
        ],
    },
    "units": {
        "guard": {"on": True, "file": "/etc/systemd/system/homewatch-admin.service.d/10-homewatch-guard.conf",
                  "restart": "always"},
        "last_collect": int(time.time()) - 40, "lag": 40, "checked_at": int(time.time()),
        "warnings": [],
        "units": [
            {"name": "homewatch.timer", "label": "采集定时器", "desc": "每分钟唤一次采集",
             "kind": "timer", "readonly": False, "active": "active", "sub": "waiting",
             "enabled": True, "unit_state": "enabled", "pid": 0, "restarts": 0,
             "result": "success", "memory": "", "since": int(time.time()) - 86400 * 3,
             "description": "采集定时器", "next": int(time.time()) + 25},
            {"name": "homewatch.service", "label": "采集任务", "desc": "读日志写库",
             "kind": "oneshot", "readonly": False, "active": "inactive", "sub": "dead",
             "enabled": True, "unit_state": "static", "pid": 0, "restarts": 0,
             "result": "success", "memory": "", "since": 0,
             "description": "采集任务", "next": 0},
            {"name": "homewatch-admin.service", "label": "管理接口", "desc": "面板背后的接口",
             "kind": "daemon", "readonly": False, "active": "active", "sub": "running",
             "enabled": True, "unit_state": "enabled", "pid": 812,
             "restarts": 2, "result": "success", "memory": "24.1 MB",
             "since": int(time.time()) - 3600 * 5, "description": "管理接口", "next": 0},
            {"name": "nginx.service", "label": "Nginx", "desc": "站点入口",
             "kind": "daemon", "readonly": True, "active": "active", "sub": "running",
             "enabled": True, "unit_state": "enabled", "pid": 604,
             "restarts": 0, "result": "success", "memory": "38.6 MB",
             "since": int(time.time()) - 86400 * 9, "description": "Nginx", "next": 0},
        ],
    },
    "limits": {"red_threshold_10m": 50, "yellow_threshold_10m": 1, "retention_days": 30},
    "geo": {"enabled": True, "provider": "auto"},
    "own_ips": ["203.0.113.9"],
    "audit": [
        {"at": "2026-11-09 22:40", "action": "policy.run", "args": {"apply": True},
         "ok": True, "msg": "已自动封禁 2 个 IP"},
        {"at": "2026-11-09 22:31", "action": "auth.password", "args": {},
         "ok": True, "msg": "面板登录密码已更新"},
    ],
}

idx = os.path.join(cfg["paths"]["out_dir"], "index.html")
html = open(idx, encoding="utf-8").read()

JS = r"""
window.__MOCK__ = __MOCKDATA__;
(function () {
  var f = window.fetch;
  function ok(d) {
    return Promise.resolve(new Response(JSON.stringify(d),
      {headers: {'Content-Type': 'application/json'}}));
  }
  var RG = __RGDATA__;
  function key(k) { return RG[k] ? k : '1h'; }
  function now() { return Math.floor(Date.now() / 1000); }

  function series(k) {
    k = key(k);
    var w = RG[k][0], s = RG[k][1], n = Math.floor(w / s);
    var t1 = now(), end = t1 - t1 % s, pts = [], tot = 0, blk = 0;
    for (var i = n; i > 0; i--) {
      var t = end - i * s;
      var v = Math.round(22 + 16 * Math.sin(i / 7) + ((i % 23) < 4 ? 70 : 0));
      var b = Math.round(v * 0.28);
      pts.push({t: t, b: b, p: v - b}); tot += v; blk += b;
    }
    return {
      range: k, label: RG[k][2], step: s, window: w, points: pts,
      sum: {total: tot, blocked: blk, passed: tot - blk, ips: 5},
      top: [{ip: '203.0.113.45', n: 4120, blocked: 3800},
            {ip: '203.0.113.77', n: 980, blocked: 920},
            {ip: '203.0.113.31', n: 640, blocked: 600},
            {ip: '1.1.1.1', n: 120, blocked: 0}],
      oldest: t1 - 30 * 86400,
      covered: (k === '90d' || k === '365d') ? 30 * 86400 : w,
      truncated: (k === '90d' || k === '365d')
    };
  }

  function snap(k) {
    k = key(k);
    var t1 = now();
    return {
      range: k, label: RG[k][2], window: RG[k][0], step: RG[k][1],
      start: t1 - RG[k][0], end: t1,
      ips: [
        {ip: '203.0.113.45', n: 4120, blocked: 3800, last: t1 - 30,
         ua: 'Mozilla/5.0 (compatible; Baiduspider/2.0)', own: false,
         label: '中国台湾·臺北', geo: {cc: 'TW', label: '中国台湾·臺北'}},
        {ip: '203.0.113.77', n: 980, blocked: 920, last: t1 - 120,
         ua: 'python-requests/2.31', own: false,
         label: '荷兰·阿姆斯特丹', geo: {cc: 'NL', label: '荷兰·阿姆斯特丹'}},
        {ip: '203.0.113.31', n: 640, blocked: 600, last: t1 - 300,
         ua: 'Mozilla/5.0 zgrab/0.x', own: false,
         label: '美国·洛杉矶', geo: {cc: 'US', label: '美国·洛杉矶'}},
        {ip: '203.0.113.55', n: 220, blocked: 210, last: t1 - 900,
         ua: 'curl/8.4.0', own: false,
         label: '德国·柏林', geo: {cc: 'DE', label: '德国·柏林'}},
        {ip: '1.1.1.1', n: 120, blocked: 0, last: t1 - 60,
         ua: 'Mozilla/5.0 (Macintosh)', own: true,
         label: '澳大利亚·悉尼', geo: {cc: 'AU', label: '澳大利亚·悉尼'}}
      ],
      geo: [{cc: 'TW', country: '中国台湾', n: 4120},
            {cc: 'NL', country: '荷兰', n: 980},
            {cc: 'US', country: '美国', n: 640},
            {cc: 'DE', country: '德国', n: 220},
            {cc: 'AU', country: '澳大利亚', n: 120}],
      geo_known: 6080,
      paths: [{path: '/wp-login.php', n: 320, ips: 3},
              {path: '/.env', n: 180, ips: 2},
              {path: '/admin', n: 96, ips: 4},
              {path: '/phpmyadmin', n: 64, ips: 1},
              {path: '/api/v1/../etc/passwd', n: 21, ips: 1},
              {path: '/actuator/env', n: 18, ips: 1},
              {path: '/.git/config', n: 12, ips: 2}],
      status: [{code: 402, n: 5530}, {code: 200, n: 1280},
               {code: 404, n: 260}, {code: 444, n: 120}],
      anomaly: [
        {kind: 'long_uri', label: '超长 URL', n: 312, ips: 3, vmax: 2140,
         top: [{ip: '203.0.113.45', n: 210, last: t1 - 30},
               {ip: '203.0.113.77', n: 88, last: t1 - 120},
               {ip: '203.0.113.31', n: 14, last: t1 - 900}]},
        {kind: 'honeypot', label: '蜜罐路径', n: 155, ips: 2, vmax: 0,
         top: [{ip: '203.0.113.45', n: 143, last: t1 - 60},
               {ip: '203.0.113.55', n: 12, last: t1 - 800}]},
        {kind: 'big_req', label: '超大请求报文', n: 43, ips: 1, vmax: 98304,
         top: [{ip: '203.0.113.31', n: 43, last: t1 - 300}]},
        {kind: 'bad_ua', label: '恶意 User-Agent', n: 29, ips: 2, vmax: 0,
         top: [{ip: '203.0.113.77', n: 21, last: t1 - 200},
               {ip: '203.0.113.55', n: 8, last: t1 - 1000}]}],
      ssh: {total: 87, top: [{ip: '203.0.113.77', n: 87, last: t1 - 400}]},
      leak: [{path: '/.env', ip: '203.0.113.45', ts: t1 - 700, sz: 2048}],
      banned: window.__MOCK__.banned,
      oldest: t1 - 30 * 86400, covered: RG[k][0], truncated: false
    };
  }

  function ipprof(raw, hours) {
    hours = hours || 24;
    var t1 = now(), pts = [], n = 24;
    for (var i = n; i > 0; i--) {
      var v = Math.round(30 + 26 * Math.sin(i / 3));
      var b = Math.round(v * 0.8);
      pts.push({t: t1 - i * 3600, b: b, p: v - b});
    }
    return {
      ip: raw, geo: {cc: 'TW', label: '中国台湾·臺北'},
      geo_label: '中国台湾·臺北', private: false, own: false, whitelisted: false,
      window: {hours: hours, start: t1 - hours * 3600, step: 3600},
      points: pts,
      sum: {total: 4120, blocked: 3800, passed: 320,
            first: t1 - 86400 * 6, last: t1 - 30,
            w_total: 1480, w_blocked: 1390, w_paths: 46, ssh: 0, ssh_all: 0},
      first_str: '11-04 09:12', last_str: '刚刚',
      paths: [{path: '/wp-login.php', n: 320, status: 402, sz: 0, last: t1 - 60},
              {path: '/.env', n: 180, status: 402, sz: 0, last: t1 - 120},
              {path: '/phpmyadmin', n: 64, status: 402, sz: 0, last: t1 - 300},
              {path: '/', n: 12, status: 200, sz: 4210, last: t1 - 900}],
      status: [{code: 402, n: 1390}, {code: 200, n: 90}],
      anomaly: [{kind: 'long_uri', label: '超长 URL', n: 12, vmax: 2140, last: t1 - 200}],
      agents: [{ua: 'Mozilla/5.0 (compatible; Baiduspider/2.0)', n: 1400, last: t1 - 30}],
      sensitive: [{path: '/.env', status: 402, sz: 0, ts: t1 - 120, real: false}],
      ban: {nft: false, until: 0, reason: '', auto: false,
            nginx: false, cf: false, active: false},
      bans: [{ts: t1 - 86400, hours: 24, layer: 'both', mode: 'auto',
              reason: '自动封禁：单 IP 高频请求', rule: 'ip_rate'}],
      generated_at: t1
    };
  }

  window.fetch = function (u, o) {
    u = String(u);
    var m = u.match(/range=([^&]+)/);
    var k = m ? decodeURIComponent(m[1]) : '1h';
    if (u.indexOf('data.json') >= 0) {
      /* 深拷贝一份：render() 会就地改这份数据，复用同一个对象会把下一次轮询搞坏 */
      return ok(JSON.parse(JSON.stringify(__LIVEDATA__)));
    }
    if (u.indexOf('/api/range') >= 0) {
      return ok({ok: true, data: {series: series(k), snap: snap(k), ranges: []}});
    }
    if (u.indexOf('/api/series') >= 0) return ok({ok: true, data: series(k)});
    if (u.indexOf('/api/ip') >= 0) {
      var im = u.match(/ip=([^&]+)/);
      var hm = u.match(/hours=(\d+)/);
      return ok({ok: true, data: ipprof(im ? decodeURIComponent(im[1]) : '1.1.1.1',
                                        hm ? parseInt(hm[1], 10) : 24)});
    }
    if (u.indexOf('/api/anomaly') >= 0) {
      var km = u.match(/kind=([^&]+)/);
      var kind = km ? decodeURIComponent(km[1]) : 'long_uri';
      var meta = (snap('1h').anomaly.filter(function (x) { return x.kind === kind; })[0])
        || {label: kind, n: 0, ips: 0};
      return ok({ok: true, data: {
        kind: kind, label: meta.label, range: '1h', range_label: '1 小时',
        window: 3600, start: now() - 3600, end: now(),
        n: meta.n, ip_count: meta.ips, ips: (meta.top || []).map(function (x, i) {
          var geo = [
            {cc: 'TW', label: '中国台湾·臺北'},
            {cc: 'NL', label: '荷兰·阿姆斯特丹'},
            {cc: 'US', label: '美国·洛杉矶'}][i] || {cc: '', label: ''};
          return {ip: x.ip, n: x.n, vmax: 0, last: x.last, geo: geo, label: geo.label};
        }),
        paths: [{path: '/wp-login.php', n: 120, ips: 2},
                {path: '/.env', n: 64, ips: 2},
                {path: '/actuator/env', n: 18, ips: 1}],
        banned: window.__MOCK__.banned
      }});
    }
    if (u.indexOf('/api/fw') >= 0) {
      return ok({ok: true, data: {
        nft: '    chain fw_in {\n' +
             '        tcp dport 8088 ip saddr { 192.168.1.0/24 } counter comment "hw:fw01a1" accept\n' +
             '        tcp dport 22 ip saddr { 192.168.1.0/24, 203.0.113.9 } counter comment "hw:fw01a2" accept\n' +
             '        tcp dport 3306 counter comment "hw:fw01a3" drop\n' +
             '    }\n    chain fw_out {\n    }\n    chain fw_fwd {\n' +
             '        tcp dport 3306 counter comment "hw:fw01a3" drop\n    }'
      }});
    }
    if (u.indexOf('/api/bans') >= 0) {
      return ok({ok: true, data: {banned: window.__MOCK__.banned,
        sum: {total: Object.keys(window.__MOCK__.banned).length}}});
    }
    if (u.indexOf('/api/geo') >= 0) {
      var d = JSON.parse(JSON.stringify(window.__MOCK__.geo_lock));
      d.nft = 'set cn4 / cn6：IPv4 4339 段 / IPv6 1688 段（来源 clang.cn）\n\n' +
        'tcp dport { 80, 443, 8088, 8443 } ip saddr @geo_on4 ip saddr != @cn4 ' +
        'ip saddr != @geo_allow4 counter drop comment "hw:geo-in"\n' +
        'udp dport { 80, 443, 8088, 8443 } ip saddr @geo_on4 ip saddr != @cn4 ' +
        'ip saddr != @geo_allow4 counter drop comment "hw:geo-in"';
      return ok({ok: true, data: d});
    }
    if (u.indexOf('/api/state') >= 0) return ok({ok: true, data: window.__MOCK__});
    if (u.indexOf('/api/action') >= 0) {
      return ok({ok: true, result: {msg: '预览模式，动作未执行'}, data: window.__MOCK__});
    }
    return f(u, o);
  };
})();
"""

RG = {
    "10m": [600, 60, "10 分钟"], "30m": [1800, 60, "30 分钟"],
    "1h": [3600, 60, "1 小时"], "2h": [7200, 120, "2 小时"],
    "6h": [21600, 300, "6 小时"], "12h": [43200, 600, "12 小时"],
    "3d": [259200, 1800, "3 天"], "7d": [604800, 3600, "周"],
    "30d": [2592000, 7200, "月"], "90d": [7776000, 21600, "季度"],
    "365d": [31536000, 86400, "年"],
}
inject = "<script>" + JS.replace("__MOCKDATA__", json.dumps(MOCK, ensure_ascii=False)) \
    .replace("__RGDATA__", json.dumps(RG, ensure_ascii=False)) \
    .replace("__LIVEDATA__", open(os.path.join(cfg["paths"]["out_dir"], "data.json"),
                                  encoding="utf-8").read().strip()) + "</script>"
html = html.replace('<div class="toast"', inject + '<div class="toast"')
open(idx, "w", encoding="utf-8").write(html)

print(idx)
