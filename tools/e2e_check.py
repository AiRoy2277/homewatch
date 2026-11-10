# -*- coding: utf-8 -*-
"""沙箱端到端验证：站点 patch + Cloudflare mock + 策略评估。

不碰系统目录、不发真实请求：nginx/systemctl 用桩替换，CF API 起在本地端口。
跑法：python tools/e2e_check.py
"""
import ipaddress
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="hw_e2e_")
SITES = os.path.join(TMP, "sites-enabled")
os.makedirs(SITES)
BLOCK = os.path.join(TMP, "00-blocklist.conf")

VHOST = """server {
    listen 8443 ssl;
    server_name home.example.com;
    access_log /var/log/nginx/home-access.log combined;

    # 扫描源就地拒绝
    if ($blocked_scanner) { return 402; }

    location / { proxy_pass http://127.0.0.1:3000; }
}
"""
OTHER = """server {
    listen 8088;
    server_name _;
    access_log /var/log/nginx/panel.log;
    location / { root /var/www; }
}
"""

cfg = {
    "title": "HW", "admin_port": 8088, "own_ips": ["203.0.113.9"],
    "red_threshold_10m": 50, "yellow_threshold_10m": 1, "retention_days": 30,
    "blocked_status": [402, 403, 444],
    "paths": {"db": os.path.join(TMP, "hw.db"),
              "out_dir": os.path.join(TMP, "www"),
              "config": os.path.join(TMP, "config.json"),
              "nginx_log": os.path.join(TMP, "access.log"),
              "nginx_blocklist": BLOCK,
              "nginx_sites": SITES,
              "audit_log": os.path.join(TMP, "audit.log")},
    "policy": {"enabled": True, "auto_ban": True, "dry_run": False,
               "ban_mode": "silent", "silent_log": True,
               "max_bans_per_run": 3, "max_hours": 720,
               "repeat_window_hours": 72, "whitelist": ["198.51.100.7"],
               "limits": {"uri_len": 1024, "req_bytes": 65536, "ua_len": 400},
               "allowed_methods": ["GET", "HEAD"],
               "trusted_bots": ["googlebot"],
               "rules": [
                   {"id": "honeypot", "name": "蜜罐路径", "enabled": True,
                    "source": "honeypot", "window": 3600, "threshold": 1,
                    "hours": 72, "layer": "both"},
                   {"id": "ip_rate", "name": "单 IP 高频请求", "enabled": True,
                    "source": "http_total", "window": 120, "threshold": 100,
                    "hours": 12, "layer": "both"},
               ]},
    "cloudflare": {"enabled": True, "api_token": "T" * 40, "zone_name": "example.com",
                   "auto_sync": True, "note": "HomeWatch", "timeout": 5},
}

from homewatch import cloudflare as cf
from homewatch import config as config_mod
from homewatch import db as db_mod
from homewatch import policy as policy_mod
from homewatch.ops import nginx as nginx_ops
from homewatch.ops import nft as nft_ops

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  ✓ " if cond else "  ✗ ") + name + (("  " + str(extra)) if extra and not cond else ""))


# ---------- 1. 站点 patch ----------
print("\n[1] 站点配置 patch")
open(os.path.join(SITES, "home.conf"), "w", encoding="utf-8").write(VHOST)
open(os.path.join(SITES, "panel.conf"), "w", encoding="utf-8").write(OTHER)
nginx_ops._reload = lambda: None          # 沙箱没有 nginx
nginx_ops._reload_quiet = lambda: None

info = nginx_ops.scan(cfg)
check("扫描到 1 个接线站点", len(info["files"]) == 1, info["files"])
check("当前 return 是 402", info["files"] and info["files"][0]["return"] == 402)
check("当前未接线（期望 444）", info["wired"] is False)

res = nginx_ops.apply_sites(cfg)
text = open(os.path.join(SITES, "home.conf"), encoding="utf-8").read()
panel = open(os.path.join(SITES, "panel.conf"), encoding="utf-8").read()
check("patch 改了 return 444", "return 444;" in text)
check("patch 挂了 access_log 条件", "if=$blocked_loggable" in text)
check("另一个 server 一字未动", panel == OTHER)
check("名单文件已生成", os.path.exists(BLOCK))
blk = open(BLOCK, encoding="utf-8").read()
check("blocklist 含 loggable map", "map $blocked_scanner $blocked_loggable" in blk)
check("记日志时 map 没有 0 分支", "1       0;" not in blk)

info2 = nginx_ops.scan(cfg)
check("重新扫描：已接线", info2["wired"] is True and info2["log_wired"] is True)

res2 = nginx_ops.apply_sites(cfg)
check("二次 apply 幂等", res2["changed"] == [], res2["notes"])

# 切到不记日志
res3 = nginx_ops.apply_sites(cfg, mode="silent_nolog", log=False)
blk = open(BLOCK, encoding="utf-8").read()
check("不记日志时 map 产出 0 分支", "1       0;" in blk)
check("切换模式不动站点（已接好线）", res3["changed"] == [])
info3 = nginx_ops.scan(cfg)
check("静默+不记日志判定 ready", info3["ready"] is True, info3)

# 切回 visible：站点要改回 402
cfg["policy"]["ban_mode"] = "visible"
nginx_ops.apply_sites(cfg)
text = open(os.path.join(SITES, "home.conf"), encoding="utf-8").read()
check("切回 visible 恢复 402", "return 402;" in text)
cfg["policy"]["ban_mode"] = "silent"

# 回滚能力：nginx -t 失败要还原
open(os.path.join(SITES, "home.conf"), "w", encoding="utf-8").write(VHOST)
before = VHOST


def boom():
    raise nginx_ops.NginxError("模拟 nginx -t 失败")


nginx_ops._reload = boom
try:
    nginx_ops.apply_sites(cfg)
    check("nginx -t 失败应当抛错", False)
except nginx_ops.NginxError:
    after = open(os.path.join(SITES, "home.conf"), encoding="utf-8").read()
    check("nginx -t 失败自动还原站点", after == before)
nginx_ops._reload = lambda: None

# ---------- 2. Cloudflare mock ----------
print("\n[2] Cloudflare API")


class FakeCF(BaseHTTPRequestHandler):
    rules = {}
    seq = [0]
    calls = []

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        if self.headers.get("Authorization") != "Bearer " + "T" * 40:
            self._json({"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]}, 403)
            return False
        return True

    def do_GET(self):
        FakeCF.calls.append(("GET", self.path))
        if not self._auth():
            return
        if self.path.startswith("/zones?"):
            return self._json({"success": True, "result": [{"id": "zone123", "name": "example.com"}]})
        if self.path == "/user/tokens/verify":
            return self._json({"success": True, "result": {"status": "active"}})
        if "/firewall/access_rules/rules" in self.path:
            return self._json({"success": True, "result": list(FakeCF.rules.values())})
        self._json({"success": False, "errors": [{"code": 7003, "message": "not found"}]}, 404)

    def do_POST(self):
        if not self._auth():
            return
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        if "/firewall/access_rules/rules" in self.path:
            FakeCF.seq[0] += 1
            rid = "r%d" % FakeCF.seq[0]
            ip = body["configuration"]["value"]
            FakeCF.rules[rid] = {"id": rid, "configuration": {"target": "ip", "value": ip},
                                 "mode": body.get("mode"), "notes": body.get("notes"),
                                 "created_on": "2026-11-09T12:00:00Z"}
            return self._json({"success": True, "result": FakeCF.rules[rid]})
        if "purge_cache" in self.path:
            return self._json({"success": True, "result": {"id": "p1"}})
        self._json({"success": False, "errors": [{"code": 7000, "message": "nope"}]}, 400)

    def do_DELETE(self):
        if not self._auth():
            return
        rid = self.path.rsplit("/", 1)[-1]
        FakeCF.rules.pop(rid, None)
        self._json({"success": True, "result": {"id": rid}})


srv = HTTPServer(("127.0.0.1", 0), FakeCF)
threading.Thread(target=srv.serve_forever, daemon=True).start()
cf.API = "http://127.0.0.1:%d" % srv.server_port

v = cf.verify(cfg)
check("token 校验通过", v.get("ok") is True, v)
check("拿到 zone 名", v.get("zone") == "example.com")

r = cf.block(cfg, "203.0.113.45", "auto")
check("建规则返回 id", r.get("id") == "r1", r)
r2 = cf.rules(cfg)
check("规则列表 1 条", len(r2) == 1 and r2[0]["ip"] == "203.0.113.45")

s = cf.sync(cfg, ["203.0.113.45", "45.1.2.3"])
check("同步：1 已存在 + 1 新增", len(s["exists"]) == 1 and s["added"] == ["45.1.2.3"], s)
check("同步摘要可读", "新增 1" in s["msg"], s["msg"])

n = cf.unblock(cfg, "45.1.2.3")
check("删除自己建的规则", n == 1 and len(cf.rules(cfg)) == 1)

# 手工规则不能被误删
FakeCF.rules["manual1"] = {"id": "manual1", "configuration": {"target": "ip", "value": "1.1.1.1"},
                           "mode": "block", "notes": "手工加的", "created_on": ""}
n2 = cf.unblock(cfg, "1.1.1.1")
check("不删非本程序规则", n2 == 0 and "manual1" in FakeCF.rules)

dead = cf.prune(cfg, keep_ips=[])
check("prune 只清自己建的", dead == ["203.0.113.45"] and "manual1" in FakeCF.rules, dead)

# token 错误时的错误文案
bad = dict(cfg, cloudflare=dict(cfg["cloudflare"], api_token="X" * 40))
vb = cf.verify(bad)
check("错误 token 给出人话", vb.get("ok") is False and "Token" in vb.get("msg", ""), vb)

srv.shutdown()

# ---------- 3. 策略评估 ----------
print("\n[3] 策略评估 + CF 同步")
cfg["cloudflare"]["enabled"] = False          # 本地阶段先关掉，避免真发请求
conn = db_mod.connect(cfg["paths"]["db"])
now = int(time.time())
now -= now % 60
rows = [
    ("10.0.0.1", 200, 1), ("45.9.9.9", 200, 60), ("45.9.9.9", 404, 50),
]
for ip, st, n in rows:
    conn.execute("INSERT OR REPLACE INTO hits(ts,ip,status,n) VALUES(?,?,?,?)", (now, ip, st, n))
conn.execute("INSERT OR REPLACE INTO anomaly(ts,ip,kind,n,vmax) VALUES(?,?,?,?,?)",
             (now - 60, "77.88.99.1", "honeypot", 1, 0))
conn.execute("INSERT OR REPLACE INTO anomaly(ts,ip,kind,n,vmax) VALUES(?,?,?,?,?)",
             (now - 60, "192.0.2.5", "honeypot", 1, 0))   # 白名单
conn.commit()

nft_ops.block_many = lambda *a, **k: None
nginx_ops._reload = lambda: None

res = policy_mod.evaluate(conn, cfg, apply=True)
ips = [b["ip"] for b in res["banned"]]
check("封了高频 IP", "45.9.9.9" in ips, ips)
check("封了蜜罐 IP", "77.88.99.1" in ips, ips)
check("白名单被跳过", "192.0.2.5" not in ips)
check("自己的 IP 被跳过", "10.0.0.1" not in ips)
check("返回 wiring 信息", res.get("wiring", {}).get("mode") == "silent", res.get("wiring"))
check("未启用 CF 时不报错", res.get("cf") is None)

# 打开 CF，验证自动同步
FakeCF.rules.clear()
cfg["cloudflare"]["enabled"] = True
srv2 = HTTPServer(("127.0.0.1", 0), FakeCF)
threading.Thread(target=srv2.serve_forever, daemon=True).start()
cf.API = "http://127.0.0.1:%d" % srv2.server_port

conn.execute("DELETE FROM bans")
conn.commit()
res2 = policy_mod.evaluate(conn, cfg, apply=True)
check("评估结果带 CF 摘要", bool(res2.get("cf")), res2.get("cf"))
check("CF 里有规则了", len(FakeCF.rules) >= 1, len(FakeCF.rules))
check("消息里带 CF 结果", "Cloudflare" in (res2.get("msg") or ""), res2.get("msg"))

# CF 挂掉不影响本地封禁
cfg["cloudflare"]["api_token"] = "Y" * 40
conn.execute("DELETE FROM bans")
conn.execute("DELETE FROM paths")
conn.commit()
conn.execute("INSERT OR REPLACE INTO anomaly(ts,ip,kind,n,vmax) VALUES(?,?,?,?,?)",
             (now - 60, "66.77.88.99", "honeypot", 1, 0))
conn.commit()
res3 = policy_mod.evaluate(conn, cfg, apply=True)
check("CF 失败仍完成本地封禁", any(b["ip"] == "66.77.88.99" for b in res3["banned"]), res3["banned"])
check("CF 失败写进 cf 字段", res3.get("cf") and res3["cf"].get("ok") is False, res3.get("cf"))
check("本地错误计数不受 CF 影响", res3["errors"] == [])
srv2.shutdown()

# ---------- 4. 面板数据 ----------
print("\n[4] 面板数据")
cfg["cloudflare"]["api_token"] = "T" * 40
from homewatch.admin import overview
data = overview.build(cfg, force=True)
check("输出 cf.api", data["cf"]["api"]["configured"] is True)
check("token 已脱敏", ("T" * 40) not in data["cf"]["api"]["token"], data["cf"]["api"]["token"])
check("输出 ban_mode", data["policy"]["ban_mode"] == "silent")
check("输出 wiring", "wired" in data["policy"]["wiring"])
check("输出 cf.last", data["cf"]["last"] is not None, data["cf"]["last"])

# ---------- 5. include 回包片段 ----------
print("\n[5] include 回包片段（线上实际形态）")
SNIP = os.path.join(TMP, "snippets")
os.makedirs(SNIP, exist_ok=True)
REPLY = os.path.join(SNIP, "blocked-msg.conf")
SNIP_SITE = os.path.join(TMP, "subdomains.conf")
ORIG_REPLY = ('# 原版\nif ($blocked_scanner) {\n'
              '    return 402 "别扫了\\n你的 IP：$remote_addr\\n";\n}\n')

with open(REPLY, "w", encoding="utf-8") as fh:
    fh.write(ORIG_REPLY)
with open(SNIP_SITE, "w", encoding="utf-8") as fh:
    fh.write('server {\n    listen 8443 ssl http2;\n    server_name example.com;\n'
             '    include %s;\n}\n' % REPLY)

cfg2 = dict(cfg)
cfg2["paths"] = dict(cfg["paths"])
SNIP_SITES = os.path.join(TMP, "snip-sites")
os.makedirs(SNIP_SITES, exist_ok=True)
shutil.copy(SNIP_SITE, os.path.join(SNIP_SITES, "subdomains.conf"))
cfg2["paths"].update({"nginx_sites": SNIP_SITES, "nginx_reply": REPLY,
                      "nginx_blocklist": os.path.join(SNIP_SITES, "00-blocklist2.conf")})
cfg2["policy"] = dict(cfg["policy"], ban_mode="silent")
with open(cfg2["paths"]["nginx_blocklist"], "w", encoding="utf-8") as fh:
    fh.write(nginx_ops.render(["203.0.113.45"], "silent", True))

nginx_ops._reload = lambda: None
nginx_ops._reload_quiet = lambda: None
nginx_ops._smoke = lambda c: "200"

st = nginx_ops.scan(cfg2)
check("识别 include 形态", st.get("via") == "include", st.get("via"))
check("读到当前回包 402", st.get("reply_code") == 402)
check("402 时判定未接线", st.get("wired") is False)
check("该形态不支持按请求掐日志", st.get("log_supported") is False)

nginx_ops.apply_sites(cfg2, "silent")
body = open(REPLY, encoding="utf-8").read()
check("保留 if 判断", "if ($blocked_scanner)" in body)
check("回包改为 444", "return 444;" in body)
check("原文案存进注释", "原文案：" in body and "$remote_addr" in body)
check("切换后接线完成", nginx_ops.scan(cfg2)["wired"] is True)
check("重复切换不再改动", nginx_ops.apply_sites(cfg2, "silent")["changed"] == [])

nginx_ops.apply_sites(cfg2, "visible")
back = open(REPLY, encoding="utf-8").read()
check("切回 402 文案无损", 'return 402 "别扫了\\n你的 IP：$remote_addr\\n";' in back, back[-120:])

# 去掉 if 判断的片段必须被拒绝，绝不能写出"全员 444"
with open(REPLY, "w", encoding="utf-8") as fh:
    fh.write('return 402 "x";\n')
try:
    nginx_ops.apply_sites(cfg2, "silent")
    check("无判断的片段被拒绝", False)
except nginx_ops.NginxError:
    check("无判断的片段被拒绝", True)
check("被拒绝时文件没被改", open(REPLY, encoding="utf-8").read().strip() == 'return 402 "x";')

print("\n[6] 端口出入站类型")
CTRL_CFG = {
    "admin_port": 8088,
    "managed_ports": [{"port": 22}, {"port": 8443}, {"port": 8088},
                      {"port": 7000}, {"port": 28006}],
    "firewall": {"lan_cidrs": ["192.168.1.0/24"],
                 "rules": [{"port": 22, "allow": "lan"},
                           {"port": 8443, "allow": "cf"}]},
}
CTRL_STATE = {"cf_ips4": ["173.245.48.0/20"], "cf_ips6": [],
              "denied_ports": ["28006"], "blocked_ips": []}

ctrl = nft_ops.ensure_ctrl(CTRL_CFG, dict(CTRL_STATE))
check("老配置迁移：22 保持仅内网", ctrl["22"]["in"] == "lan", ctrl.get("22"))
check("老配置迁移：8443 保持仅 CF", ctrl["8443"]["in"] == "cf", ctrl.get("8443"))
check("没写过的端口默认放行", ctrl["7000"]["in"] == "allow", ctrl.get("7000"))
check("denied_ports 转成 in=deny", ctrl["28006"]["in"] == "deny", ctrl.get("28006"))
check("出站默认放行", all(v["out"] == "allow" for v in ctrl.values()))

st = dict(CTRL_STATE)
st["port_ctrl"] = dict(ctrl, **{"7000": {"in": "allow", "out": "lan", "proto": "tcp"},
                                "22": {"in": "lan", "out": "allow", "proto": "both"}})
text = nft_ops.render(st, CTRL_CFG)
check("入站仅内网生成 lan4 取反", "tcp dport 22 ip saddr != @lan4 counter drop" in text)
check("入站仅 CF 用 cf 网段", "tcp dport 8443 ip saddr != @cf_ips4 counter drop" in text)
check("入站禁止是整口丢弃", "tcp dport 28006 counter drop" in text)
check("协议 both 同时出 tcp/udp", "udp dport 22 ip saddr != @lan4" in text)
check("出站限制带 daddr 取反",
      'oif != "lo" tcp dport 7000 ip daddr != @lan4 counter drop' in text)
check("出站限制绕开回环", 'oif != "lo"' in text)
check("只限制出站的端口没有入站规则", "tcp dport 7000 ip saddr" not in text)

# 防呆：面板端口禁止入站 = 把自己锁在门外
bad = dict(CTRL_STATE)
bad["port_ctrl"] = dict(ctrl, **{"8088": {"in": "deny", "out": "allow", "proto": "tcp"}})
try:
    nft_ops.render(bad, CTRL_CFG)
    check("面板端口禁止入站被拒", False)
except nft_ops.NftError:
    check("面板端口禁止入站被拒", True)

# 防呆：要按 CF 网段过滤但网段是空的 → 规则恒真，等于全封
nocf = dict(CTRL_STATE)
nocf["cf_ips4"] = []
nocf["port_ctrl"] = ctrl
try:
    nft_ops.render(nocf, CTRL_CFG)
    check("CF 网段为空时拒绝生成", False)
except nft_ops.NftError:
    check("CF 网段为空时拒绝生成", True)

# 改类型落盘：假 nft + 假 state 文件，只验证状态与重建调用
from homewatch.ops import state as state_ops

calls = []
nft_ops.rebuild = lambda s, c: calls.append(json.loads(json.dumps(s.get("port_ctrl", {}))))
nft_ops.write_config = lambda s, c: None
memory = {"data": json.loads(json.dumps(dict(CTRL_STATE, port_ctrl=ctrl)))}
state_ops.load = lambda c: json.loads(json.dumps(memory["data"]))
state_ops.save = lambda c, s: memory.__setitem__("data", json.loads(json.dumps(s)))

nft_ops.set_port_ctrl(CTRL_CFG, 7000, "out", "deny")
saved = memory["data"]
check("改出站类型写进状态", saved["port_ctrl"]["7000"]["out"] == "deny", saved["port_ctrl"].get("7000"))
check("改类型触发整表重建", len(calls) == 1 and calls[-1]["7000"]["out"] == "deny", calls)

nft_ops.set_port_ctrl(CTRL_CFG, 28006, "in", "allow")
check("解除禁止后 denied_ports 同步移除", 28006 not in saved["denied_ports"],
      saved.get("denied_ports"))
nft_ops.set_port_ctrl(CTRL_CFG, 22, "in", "deny")
check("禁止入站后 denied_ports 同步加入", 22 in memory["data"]["denied_ports"],
      memory["data"].get("denied_ports"))
try:
    nft_ops.set_port_ctrl(CTRL_CFG, 7000, "out", "cf")
    check("出站不支持 cf 类型", False)
except nft_ops.NftError:
    check("出站不支持 cf 类型", True)
try:
    nft_ops.set_port_ctrl(CTRL_CFG, 7000, "in", "any")
    check("非法类型被拒", False)
except nft_ops.NftError:
    check("非法类型被拒", True)

# 状态文件读回来必须还带着 port_ctrl（load 只保留 EMPTY 里有的键，
# 漏了就会"改完看着生效、重启后又变回去"）
from homewatch.ops import state as state_file

saver = {"paths": {"db": os.path.join(TMP, "probe.db")}}
state_file.save(saver, {"port_ctrl": {"7000": {"in": "allow", "out": "lan", "proto": "tcp"}}})
roundtrip = state_file.load(saver)
check("port_ctrl 能落盘再读回", roundtrip.get("port_ctrl", {}).get("7000", {}).get("out") == "lan",
      roundtrip.get("port_ctrl"))

# ---------- 7. 防火墙规则表 + 异常来源 ----------
print("\n[7] 防火墙规则表")
from homewatch.ops import fw as fw_ops

FW_CFG = {
    "admin_port": 8088,
    "managed_ports": [{"port": 22, "label": "SSH"}, {"port": 8088, "label": "面板"},
                      {"port": 8443, "label": "源站"}],
    "watch_ports": {"ssh": "22", "panel": "8088"},
    "firewall": {"lan_cidrs": ["192.168.1.0/24"],
                 "rules": [{"port": 22, "allow": "lan"},
                           {"port": 8443, "allow": "cf"}]},
}
base_state = {
    "port_ctrl": {}, "denied_ports": [], "blocked_ips": [],
    "cf_ips4": ["173.245.48.0/20"], "cf_ips6": [], "cf_last": {},
    "fw": {"rules": [], "policy": {"in": "accept", "out": "accept"},
           "container": True, "seq": 0},
}
fk = {"data": json.loads(json.dumps(base_state))}
state_ops.load = lambda c: json.loads(json.dumps(fk["data"]))
state_ops.save = lambda c, s: fk.__setitem__("data", json.loads(json.dumps(s)))
nft_ops.rebuild = lambda s, c: None
nft_ops.write_config = lambda s, c: None
fw_ops.state_mod = state_ops

# 地址/端口归一化
r = fw_ops.add(FW_CFG, {"name": "面板白名单", "dir": "in", "proto": "tcp",
                        "port": "8088", "src": "192.168.1.0/24, 203.0.113.9"})
check("规则保存成功", r.get("id") and len(fk["data"]["fw"]["rules"]) == 1, fk["data"]["fw"])
rule = fk["data"]["fw"]["rules"][0]
check("多地址拆成列表", rule["src"] == ["192.168.1.0/24", "203.0.113.9/32"], rule["src"])
check("单 IP 归一成 /32", "203.0.113.9/32" in rule["src"])

fr = fw_ops.add(FW_CFG, {"name": "任意来源", "dir": "in", "port": "8080",
                         "src": "0.0.0.0/0"})
check("0.0.0.0/0 归一成任意", fk["data"]["fw"]["rules"][-1]["src"] == [], fr)

try:
    fw_ops.add(FW_CFG, {"name": "坏端口", "port": "70000"})
    check("越界端口被拒", False)
except fw_ops.FwError:
    check("越界端口被拒", True)
try:
    fw_ops.add(FW_CFG, {"name": "坏地址", "port": "80", "src": "1.2.3.999"})
    check("非法地址被拒", False)
except fw_ops.FwError:
    check("非法地址被拒", True)

# 端口范围 + 动作
fw_ops.add(FW_CFG, {"name": "拒绝 MySQL", "dir": "in", "port": "3306",
                    "action": "drop"})
fw_ops.add(FW_CFG, {"name": "出站 25", "dir": "out", "port": "25",
                    "action": "drop"})
check("规则按加入顺序排优先级",
      [x["priority"] for x in fk["data"]["fw"]["rules"]] ==
      sorted(x["priority"] for x in fk["data"]["fw"]["rules"]))

text = nft_ops.render(fk["data"], FW_CFG)
check("主链在端口基线之前跳自定义链", "jump fw_in" in text and
      text.index("jump fw_in") < text.index("tcp dport 8443 ip saddr != @cf_ips4"))
check("放行规则带来源集合与计数",
      'tcp dport 8088 ip saddr { 192.168.1.0/24, 203.0.113.9/32 } '
      'counter accept comment "hw:' in text)
check("拒绝规则按端口整段丢", "tcp dport 3306 counter drop" in text)
fw_lines = [l.strip() for l in text.splitlines()
            if 'comment "hw:' in l and "default-deny" not in l]
check("comment 挂在判决之后（nft 语法要求）",
      bool(fw_lines) and all(('accept comment "hw:' in l or 'drop comment "hw:' in l)
                             for l in fw_lines))
check("出站规则保护回环", 'tcp dport 25 oif != "lo" counter' in text)
check("容器转发只镜像拒绝规则", "chain fw_fwd" in text and
      text.count('comment "hw:') >= 4)

# 防呆：拒绝规则连面板一起挡 = 锁死
try:
    fw_ops.add(FW_CFG, {"name": "锁死", "dir": "in", "port": "8088",
                        "action": "drop"})
    check("宽泛拒绝面板端口被拒", False)
except fw_ops.FwError as exc:
    check("宽泛拒绝面板端口被拒", "面板端口" in str(exc), str(exc))

# 只封某个外部 IP 是合理需求，不能拦
ok = fw_ops.add(FW_CFG, {"name": "封某个 IP", "dir": "in", "port": "8088",
                         "src": "203.0.113.77", "action": "drop"})
check("只封单个 IP 不拦", bool(ok.get("id")))

# 默认拒绝：先停掉 8088 的白名单规则，此时必须拒绝切换
first = fk["data"]["fw"]["rules"][0]["id"]
fw_ops.toggle(FW_CFG, first, False)
try:
    fw_ops.set_policy(FW_CFG, "in", "drop")
    check("默认拒绝要求面板白名单", False)
except fw_ops.FwError as exc:
    check("默认拒绝要求面板白名单", "面板端口" in str(exc), str(exc))
fw_ops.toggle(FW_CFG, first, True)

# 恢复白名单后可以切
pol = fw_ops.set_policy(FW_CFG, "in", "drop")
check("补白名单后可以切默认拒绝", fk["data"]["fw"]["policy"]["in"] == "drop", pol)
text = nft_ops.render(fk["data"], FW_CFG)
check("默认拒绝生成兜底丢包", 'counter drop comment "hw:default-deny-in"' in text)
check("默认拒绝放行已建立连接", "ct state established,related counter accept" in text)
pol2 = fw_ops.set_policy(FW_CFG, "in", "accept")
check("可以切回默认放行", fk["data"]["fw"]["policy"]["in"] == "accept" and
      "hw:default-deny-in" not in nft_ops.render(fk["data"], FW_CFG))

# 停用 / 排序 / 删除
fw_ops.toggle(FW_CFG, first, False)
check("停用后不参与渲染", first not in nft_ops.render(fk["data"], FW_CFG))
fw_ops.toggle(FW_CFG, first, True)
order_before = [x["id"] for x in fk["data"]["fw"]["rules"]]
fw_ops.move(FW_CFG, order_before[-1], -1)
check("上移改变顺序", [x["id"] for x in fk["data"]["fw"]["rules"]][-2] == order_before[-1],
      [x["id"] for x in fk["data"]["fw"]["rules"]])
fw_ops.remove(FW_CFG, order_before[-1])
check("删除规则", order_before[-1] not in
      [x["id"] for x in fk["data"]["fw"]["rules"]])

# 按端口页生成白名单规则
fw_ops.seed_from_ports(FW_CFG)
names = [x["name"] for x in fk["data"]["fw"]["rules"]]
check("按端口页生成放行规则", any("SSH" in n for n in names), names)
ports_rule = [x for x in fk["data"]["fw"]["rules"] if x["port"] == "8443"]
check("CF 端口用 Cloudflare 网段", ports_rule and ports_rule[0]["src"] == ["173.245.48.0/20"],
      ports_rule)

# state.load 要保住 fw（EMPTY 漏键会让规则重启即失效）
state_file.save(saver, {"fw": fk["data"]["fw"]})
check("fw 能落盘再读回", state_file.load(saver)["fw"]["rules"] == fk["data"]["fw"]["rules"])
check("geo_lock 也在 EMPTY 里", "geo_lock" in state_file.EMPTY)

# ---- 地域封锁 ----
print("\n[9] 地域封锁（境内 / 境外）")
from homewatch.ops import geoblock as geo_ops

# 网段解析：合并相邻、跳过垃圾行
v4, v6 = geo_ops.parse_cidrs("10.0.0.0/25\n10.0.0.128/25\n# 注释\n\n2400:da00::/32\n乱写\n")
check("相邻网段会合并", v4 == ["10.0.0.0/24"], v4)
check("IPv6 单独归类", v6 == ["2400:da00::/32"], v6)

apn4, apn6 = geo_ops.parse_apnic(
    "apnic|CN|ipv4|1.0.1.0|256|20110414|allocated\n"
    "apnic|JP|ipv4|1.0.16.0|4096|20110412|allocated\n"
    "apnic|CN|ipv6|2400:da00::|32|20110414|allocated\n")
check("APNIC 委派格式能解析", apn4 == ["1.0.1.0/24"] and apn6 == ["2400:da00::/32"],
      (apn4, apn6))

GEO_CFG = dict(FW_CFG)
GEO_CFG["own_ips"] = ["203.0.113.9", "192.168.1.9"]
GEO_CFG["paths"] = {"db": os.path.join(TMP, "geo.db")}
gstate = {"port_ctrl": {}, "denied_ports": [], "blocked_ips": [],
          "cf_ips4": ["173.245.48.0/20"], "cf_ips6": [],
          "fw": {"rules": [], "policy": {"in": "accept", "out": "accept"},
                 "container": True, "seq": 0},
          "geo_lock": {"in": {"enabled": False, "scope": "web"},
                       "out": {"enabled": False}, "allow": []}}
gk = {"data": json.loads(json.dumps(gstate))}
state_ops.load = lambda c: json.loads(json.dumps(gk["data"]))
state_ops.save = lambda c, s: gk.__setitem__("data", json.loads(json.dumps(s)))

# 没有国内清单时不许开
try:
    geo_ops.set_lock(GEO_CFG, "in", True, client=None)
    check("没有网段清单时拒绝开启", False)
except geo_ops.GeoError as exc:
    check("没有网段清单时拒绝开启", "国内网段" in str(exc), str(exc))
check("拒绝后状态没被改脏", gk["data"]["geo_lock"]["in"]["enabled"] is False)

geo_ops.save_cn(GEO_CFG, ["1.0.1.0/24", "1.0.2.0/24"], ["2400:da00::/32"], "test")
res = geo_ops.set_lock(GEO_CFG, "in", True, client=None)
check("刷新清单后可以开启外来封锁", gk["data"]["geo_lock"]["in"]["enabled"], res)

text = nft_ops.render(gk["data"], GEO_CFG)
check("生成 cn4 / cn6 集合", "set cn4 {" in text and "set cn6 {" in text)
# 6000 多个网段塞不进一次 nft 批处理（内核回 Message too long），
# 所以文件里只建空集合，元素由 fill_lines() 分批下发。
check("国内网段不写进 nft 文件",
      "1.0.1.0/24" not in text and "1.0.2.0/24" not in text)
check("空集合声明里没有 elements",
      "elements" not in text.split("set cn4 {")[1].split("}")[0])
check("有闸门集合", "set geo_on4 {" in text and "set geo_on6 {" in text)
check("集合声明在链之前",
      text.index("set cn4 {") < text.index("chain input {"))
check("地域拦截在规则表之后", text.index("jump fw_in") < text.index("hw:geo-in"))
check("地域拦截在端口基线之前",
      text.index("hw:geo-in") < text.index("tcp dport 8443 ip saddr != @cf_ips4"))
geo_in = [l for l in text.splitlines() if 'hw:geo-in' in l]
check("Web 范围按端口挡",
      bool(geo_in) and all("dport {" in l for l in geo_in) and
      any("8088" in l for l in geo_in), geo_in[:2])
check("Web 范围不含 SSH",
      "tcp dport { 22," not in text and ", 22 }" not in text, geo_in[:2])
check("豁免集合含内网/我的 IP/CF",
      "192.168.1.0/24" in text.split("set geo_allow4 {")[1].split("}")[0] and
      "203.0.113.9/32" in text.split("set geo_allow4 {")[1].split("}")[0])

# nft 的 interval 集合不允许元素重叠（内网段里再列出自己的 IP 会直接
# "conflicting intervals specified"，整份规则加载失败），合并逻辑要顶住。
def _set_nets(block):
    out = []
    for tok in block.replace("elements = {", " ").replace(",", " ").split():
        try:
            out.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            continue
    return sorted(out)


_al4 = _set_nets(text.split("set geo_allow4 {")[1].split("}")[0])
_over = [(str(a), str(b)) for a, b in zip(_al4, _al4[1:])
         if int(b.network_address) <= int(a.broadcast_address)]
check("豁免集合无重叠（否则 nft 报 conflicting intervals）",
      bool(_al4) and not _over, _over[:3])
check("落在内网段里的自有 IP 被合并掉",
      "192.168.1.9/32" not in text.split("set geo_allow4 {")[1].split("}")[0],
      [str(n) for n in _al4])
# 分批下发：先关闸 → 灌网段 → 最后开闸（一条命令，原子生效）
_scripts = geo_ops.fill_lines(gk["data"], GEO_CFG, chunk=1)
check("灌网段前先关闸",
      len(_scripts) >= 2 and all("flush set inet filter geo_on" in x
                                 for x in _scripts[:2]), _scripts[:2])
check("按 chunk 分批 add element",
      sum(1 for x in _scripts if "add element inet filter cn4" in x) == 2,
      [x.split("\n")[0] for x in _scripts])
check("开闸放在最后",
      "0.0.0.0/0" in _scripts[-2] and "::/0" in _scripts[-1]
      and all("add element" in x for x in _scripts[-2:]), _scripts[-2:])

check("未开对外时不生成出站规则", "hw:geo-out" not in text)
check("容器转发也镜像", text.count("hw:geo-in") >= 2)

# 全部端口
geo_ops.set_scope(GEO_CFG, "all")
text = nft_ops.render(gk["data"], GEO_CFG)
check("全部端口范围不带 dport",
      'ip saddr @geo_on4 ip saddr != @cn4 ip saddr != @geo_allow4 '
      'counter drop comment "hw:geo-in"' in text)

# 对外
res = geo_ops.set_lock(GEO_CFG, "out", True, client=None)
check("对外封锁能开启", gk["data"]["geo_lock"]["out"]["enabled"], res)
check("开启对外时给出影响面提示", any("apt" in w for w in (res.get("warnings") or [])),
      res.get("warnings"))
text = nft_ops.render(gk["data"], GEO_CFG)
check("出站先放行已建立连接",
      "ct state established,related counter accept comment" in text and
      text.index("hw:geo-out-est") < text.index('comment "hw:geo-out"'))
check("出站规则排除回环",
      'oif != "lo" ip saddr @geo_on4 ip daddr != @cn4' in text)

# 自定义放行
geo_ops.set_allow(GEO_CFG, "add", "198.18.0.0/15")
check("自定义放行进了集合",
      "198.18.0.0/15" in nft_ops.render(gk["data"], GEO_CFG))

# 关掉之后不再有地域规则
geo_ops.set_lock(GEO_CFG, "in", False, client=None)
geo_ops.set_lock(GEO_CFG, "out", False, client=None)
text = nft_ops.render(gk["data"], GEO_CFG)
check("关闭后不生成地域规则", "hw:geo-" not in text and "set cn4" not in text)

# 状态接口只读
st = geo_ops.status(GEO_CFG, with_hits=False)
check("状态里带国内段数与豁免", st["cn"]["v4"] == 2 and st["exempt"]["allow"] == ["198.18.0.0/15"], st)

# ---- 封禁状态 ----
print("\n[10] 封禁状态与一键封禁")
from homewatch import banmap as banmap_mod

bk = {"data": {"blocked_ips": [
    {"ip": "203.0.113.45", "until": 0, "reason": "自动封禁：蜜罐", "auto": True},
    {"ip": "203.0.113.77", "until": int(time.time()) - 10, "reason": "过期了"},
], "cf_rules": {"203.0.113.31": {"id": "r1"}}}}
state_ops.load = lambda c: json.loads(json.dumps(bk["data"]))
state_ops.save = lambda c, s: bk.__setitem__("data", json.loads(json.dumps(s)))
open(BLOCK, "w", encoding="utf-8").write(
    "map $remote_addr $blocked_scanner {\n  203.0.113.45 1;\n  203.0.113.55 1;\n}\n")

bm = banmap_mod.build(cfg)
check("nft 封禁带 layers", bm.get("203.0.113.45", {}).get("layers") == ["nft", "nginx"],
      bm.get("203.0.113.45"))
check("nginx 独有封禁也在表里", bm.get("203.0.113.55", {}).get("nginx") is True)
check("CF 规则算一层", bm.get("203.0.113.31", {}).get("cf") is True)
check("过期封禁被清掉", "203.0.113.77" not in bm, list(bm))
check("概览统计", banmap_mod.summary(cfg)["total"] == len(bm))


# ---- 异常来源 IP ----
print("\n[8] 异常来源")
from homewatch import report as report_mod

conn = db_mod.connect(cfg["paths"]["db"])
now_ts = int(time.time())
for ip, kind, n in [("203.0.113.45", "long_uri", 7), ("203.0.113.77", "long_uri", 3),
                    ("203.0.113.31", "honeypot", 5)]:
    conn.execute("INSERT OR REPLACE INTO anomaly VALUES(?,?,?,?,?)",
                 (now_ts, ip, kind, n, 2000))
conn.commit()
detail = report_mod.anomaly_ips(conn, cfg, "long_uri", "1h")
by_ip = {x["ip"]: x for x in detail["ips"]}
check("按类型取到来源 IP",
      "203.0.113.45" in by_ip and "203.0.113.77" in by_ip, detail["ips"])
check("带每 IP 次数", by_ip["203.0.113.45"]["n"] == 7, by_ip.get("203.0.113.45"))
check("带总数与 IP 数", detail["n"] >= 10 and detail["ip_count"] >= 2, detail)
snap = report_mod.snapshot(conn, cfg, "1h")
long_uri = next((x for x in snap["anomaly"] if x["kind"] == "long_uri"), {})
check("快照里带 top IP", long_uri.get("top") and long_uri["top"][0]["ip"] == "203.0.113.45",
      long_uri)
conn.close()

print("\n==== 通过 %d / 失败 %d ====" % (len(PASS), len(FAIL)))
if FAIL:
    print("失败项：" + "、".join(FAIL))
shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
