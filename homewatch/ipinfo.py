# -*- coding: utf-8 -*-
"""单个 IP 的档案：面板上点任意 IP 弹出的那张卡。

数据全部来自本地库和本地状态文件，不发网络请求：
  - hits / paths / agent / anomaly / sshfail / bans 六张表；
  - state.json（nft 封禁、nginx 名单、Cloudflare 规则）；
  - geo 缓存（没有就留空，采集下一轮会补）。

时间窗按 hours 收窄，但"首次出现"始终是建库以来的值——
判断一个 IP 是"老熟人"还是"今天刚冒出来"，看的是这个。
"""

import ipaddress

from . import geo as geo_mod
from . import policy as policy_mod
from .ops import nginx as nginx_ops
from .ops import state as state_mod
from .report import _blocked, _not_blocked, _spa_fingerprints
from .utils import fmt_ts, now
from .patterns import SENSITIVE

WIN_CHOICES = (1, 6, 24, 72, 168, 720, 24 * 365)
DEFAULT_WIN = 24


def normalize(raw):
    """校验并归一化 IP，非法时抛 ValueError。"""
    addr = ipaddress.ip_address(str(raw).strip())
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def _private(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _step_for(hours):
    """点数控制在 24~180 之间：既看得出形状，也不会把分钟点全画出来。"""
    if hours <= 6:
        return 300
    if hours <= 24:
        return 900
    if hours <= 72:
        return 3600
    if hours <= 168:
        return 7200
    if hours <= 720:
        return 21600
    return 86400


def detail(conn, cfg, raw_ip, hours=DEFAULT_WIN):
    ip = normalize(raw_ip)
    try:
        hours = int(hours)
    except (TypeError, ValueError):
        hours = DEFAULT_WIN
    if hours not in WIN_CHOICES:
        hours = min(WIN_CHOICES, key=lambda x: abs(x - hours))
    win = hours * 3600
    t_now = now()
    start = t_now - win

    b_where, b_args = _blocked(cfg)
    nb_where, nb_args = _not_blocked(cfg)
    own = set(cfg.get("own_ips") or [])
    whitelist = list((cfg.get("policy") or {}).get("whitelist") or [])

    def scalar(sql, args=()):
        row = conn.execute(sql, args).fetchone()
        return int((row or [0])[0] or 0)

    # ---- 总量 ----
    total = scalar("SELECT SUM(n) FROM hits WHERE ip=?", (ip,))
    blocked = scalar("SELECT SUM(n) FROM hits WHERE ip=? AND " + b_where,
                     (ip,) + tuple(b_args))
    first = scalar("SELECT MIN(ts) FROM hits WHERE ip=?", (ip,))
    last = scalar("SELECT MAX(ts) FROM hits WHERE ip=?", (ip,))

    w_total = scalar("SELECT SUM(n) FROM hits WHERE ip=? AND ts>=?", (ip, start))
    w_blocked = scalar("SELECT SUM(n) FROM hits WHERE ip=? AND ts>=? AND " + b_where,
                       (ip,) + (start,) + tuple(b_args))
    w_paths = scalar("SELECT COUNT(DISTINCT path) FROM paths WHERE ip=? AND ts>=?",
                     (ip, start))

    # ---- 曲线 ----
    step = _step_for(hours)
    rows = conn.execute(
        "SELECT (ts/%d)*%d AS b, "
        "SUM(CASE WHEN %s THEN n ELSE 0 END), "
        "SUM(CASE WHEN %s THEN n ELSE 0 END) "
        "FROM hits WHERE ip=? AND ts>=? GROUP BY b ORDER BY b"
        % (step, step, b_where, nb_where),
        tuple(b_args) + tuple(nb_args) + (ip, start),
    ).fetchall()
    per = {int(r[0]): (int(r[1] or 0), int(r[2] or 0)) for r in rows}
    end = t_now - t_now % step
    points = []
    for i in range(int(win // step), 0, -1):
        t = end - i * step
        bl, ps = per.get(t, (0, 0))
        points.append({"t": t, "b": bl, "p": ps})

    # ---- 路径 ----
    paths = [
        {"path": p, "n": n or 0, "status": code, "sz": sz or 0, "last": ts or 0}
        for p, n, code, sz, ts in conn.execute(
            "SELECT path, SUM(n), status, MAX(sz), MAX(ts) FROM paths "
            "WHERE ip=? AND ts>=? AND path<>'' GROUP BY path, status "
            "ORDER BY SUM(n) DESC LIMIT 14", (ip, start))
    ]

    # ---- 状态码 ----
    status = [
        {"code": int(code), "n": int(n or 0)}
        for code, n in conn.execute(
            "SELECT status, SUM(n) FROM hits WHERE ip=? AND ts>=? "
            "GROUP BY status ORDER BY SUM(n) DESC LIMIT 8", (ip, start))
    ]

    # ---- 异常命中 ----
    anomaly = [
        {"kind": kind, "label": policy_mod.SOURCES.get(kind, kind),
         "n": n or 0, "vmax": vmax or 0, "last": ts or 0}
        for kind, n, vmax, ts in conn.execute(
            "SELECT kind, SUM(n), MAX(vmax), MAX(ts) FROM anomaly "
            "WHERE ip=? AND ts>=? GROUP BY kind ORDER BY SUM(n) DESC", (ip, start))
    ]

    # ---- UA ----
    agents = [
        {"ua": ua, "n": n or 0, "last": ts or 0}
        for ua, n, ts in conn.execute(
            "SELECT ua, SUM(n), MAX(ts) FROM agent WHERE ip=? AND ts>=? AND ua<>'' "
            "GROUP BY ua ORDER BY SUM(n) DESC LIMIT 6", (ip, start))
    ]

    # ---- SSH ----
    ssh_n = scalar("SELECT SUM(n) FROM sshfail WHERE ip=? AND ts>=?", (ip, start))
    ssh_all = scalar("SELECT SUM(n) FROM sshfail WHERE ip=?", (ip,))

    # ---- 敏感路径 ----
    fp = _spa_fingerprints(conn, min(start, t_now - 86400))
    hits_sensitive = []
    for ts, p, code, sz in conn.execute(
        "SELECT ts, path, status, sz FROM paths WHERE ip=? AND ts>=? AND sz>0 "
        "ORDER BY ts DESC LIMIT 200", (ip, start)):
        if not p or not SENSITIVE.search(p):
            continue
        real = (200 <= code < 300) and sz not in fp
        hits_sensitive.append({"path": p, "status": code, "sz": sz,
                               "ts": ts, "real": real})
        if len(hits_sensitive) >= 8:
            break

    # ---- 封禁状态：三层各查一次 ----
    st = state_mod.load(cfg)
    state_mod.purge_expired(st)
    nft_entry = state_mod.find_block(st, ip)
    nginx_ips = nginx_ops.read_ips(cfg)
    in_nginx = ip in nginx_ips
    cf_rules = st.get("cf_rules") or {}
    in_cf = ip in cf_rules

    bans = [
        {"ts": ts, "hours": h, "layer": layer, "mode": mode,
         "reason": reason, "rule": rule}
        for ts, h, layer, mode, reason, rule in conn.execute(
            "SELECT ts,hours,layer,mode,reason,rule FROM bans WHERE ip=? "
            "ORDER BY ts DESC LIMIT 10", (ip,))
    ]

    rec = (geo_mod.attach(conn, [ip]) or {}).get(ip) or {}

    return {
        "ip": ip,
        "geo": rec,
        "geo_label": geo_mod.label_of(rec) if rec else "",
        "private": _private(ip),
        "own": ip in own,
        "whitelisted": ip in whitelist,
        "window": {"hours": hours, "start": start, "step": step},
        "points": points,
        "sum": {
            "total": total, "blocked": blocked, "passed": total - blocked,
            "first": first, "last": last,
            "w_total": w_total, "w_blocked": w_blocked,
            "w_paths": w_paths, "ssh": ssh_n, "ssh_all": ssh_all,
        },
        "first_str": fmt_ts(first) if first else "",
        "last_str": fmt_ts(last) if last else "",
        "paths": paths,
        "status": status,
        "anomaly": anomaly,
        "agents": agents,
        "sensitive": hits_sensitive,
        "ban": {
            "nft": bool(nft_entry),
            "until": int((nft_entry or {}).get("until") or 0),
            "reason": (nft_entry or {}).get("reason") or "",
            "auto": bool((nft_entry or {}).get("auto")),
            "nginx": in_nginx,
            "cf": in_cf,
            "active": bool(nft_entry) or in_nginx or in_cf,
        },
        "bans": bans,
        "generated_at": t_now,
    }
