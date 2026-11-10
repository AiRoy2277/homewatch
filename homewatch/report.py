# -*- coding: utf-8 -*-
"""把 SQLite 里的聚合数据算成面板要的一份 JSON。

设计原则：单个函数一次性算完所有指标，面板只负责渲染。
这样以后加图表不用改前端取数逻辑，改这里加字段即可。
"""

from . import banmap as banmap_mod
from . import geo as geo_mod
from . import policy as policy_mod
from .patterns import SENSITIVE
from .utils import fmt_ts, now, today_start


def _blocked(cfg, col="status"):
    """返回 (SQL 片段, 参数列表)，用于动态状态码。"""
    codes = list(cfg.get("blocked_status") or [402, 403])
    ph = "(" + ",".join("?" * len(codes)) + ")"
    return "%s IN %s" % (col, ph), codes


def _not_blocked(cfg, col="status"):
    codes = list(cfg.get("blocked_status") or [402, 403])
    ph = "(" + ",".join("?" * len(codes)) + ")"
    return "%s NOT IN %s" % (col, ph), codes


def _spa_fingerprints(conn, since):
    """算出 SPA fallback 的响应体指纹。

    本站对任意路径都回 index.html，所以 ``/.env`` 也是 200。
    真正判断"是否泄漏"不能只看状态码，要看响应体大小是否等于首页。
    首页大小在一批 200 里出现次数最多，取前两个容错（gzip / br 两种编码）。
    """
    rows = conn.execute(
        "SELECT sz FROM paths WHERE ts>=? AND status=200 AND sz>0 "
        "GROUP BY sz HAVING COUNT(*)>=50 ORDER BY COUNT(*) DESC LIMIT 2",
        (since,),
    ).fetchall()
    return {r[0] for r in rows}


def _net_latest(conn):
    """读取最新一条 nft 快照，返回 {ssh: 97, origin: 58, ...}。"""
    cur = conn.execute("SELECT * FROM net LIMIT 0")
    cols = [d[0] for d in cur.description] if cur.description else []
    row = conn.execute("SELECT * FROM net ORDER BY ts DESC LIMIT 1").fetchone()
    if not row:
        return {}
    out = {}
    for name, val in zip(cols, row):
        if name == "ts":
            continue
        out[name[:-5] if name.endswith("_drop") else name] = val or 0

    # 兼容 0.1 版本写下的旧列名，升级后第一次采集完成前也能显示正确数字
    for old, new in (("ssl", "origin"), ("https", "panel")):
        if new not in out and old in out:
            out[new] = out[old]
    return out


def build(conn, cfg):
    t_now = now()
    minute_now = t_now - t_now % 60
    t_today = today_start()
    own = set(cfg.get("own_ips") or [])

    b_where, b_args = _blocked(cfg)
    nb_where, nb_args = _not_blocked(cfg)

    def scalar(sql, args=()):
        row = conn.execute(sql, args).fetchone()
        return row[0] if row and row[0] is not None else 0

    # ---- 今日总量 ----
    total_today = scalar("SELECT SUM(n) FROM hits WHERE ts>=?", (t_today,))
    blocked_today = scalar(
        "SELECT SUM(n) FROM hits WHERE ts>=? AND " + b_where, (t_today,) + tuple(b_args)
    )
    passed_today = total_today - blocked_today

    # ---- 近 10 分钟：判定状态的核心指标 ----
    win10 = minute_now - 600
    blocked_10m = scalar(
        "SELECT SUM(n) FROM hits WHERE ts>=? AND " + b_where, (win10,) + tuple(b_args)
    )
    passed_10m = scalar(
        "SELECT SUM(n) FROM hits WHERE ts>=? AND " + nb_where, (win10,) + tuple(nb_args)
    )

    # ---- 时间线：近 180 分钟，逐分钟 ----
    rows = conn.execute(
        "SELECT ts, "
        "SUM(CASE WHEN " + b_where + " THEN n ELSE 0 END), "
        "SUM(CASE WHEN " + nb_where + " THEN n ELSE 0 END) "
        "FROM hits WHERE ts>=? GROUP BY ts",
        tuple(b_args) + tuple(nb_args) + (minute_now - 179 * 60,),
    ).fetchall()
    per = {r[0]: (r[1] or 0, r[2] or 0) for r in rows}
    timeline = []
    for i in range(180, 0, -1):
        t = minute_now - i * 60
        bl, ps = per.get(t, (0, 0))
        timeline.append({"t": t, "b": bl, "p": ps})

    # ---- 来源 IP：近 24 小时 ----
    # 带一列近 10 分钟：只看 24 小时总量的话，下午已经停掉的攻击
    # 在面板上看起来像"还在猛扫"，容易误判。
    ips = []
    for ip, n, blk in conn.execute(
        "SELECT ip, SUM(n), SUM(CASE WHEN " + b_where + " THEN n ELSE 0 END) "
        "FROM hits WHERE ts>=? GROUP BY ip ORDER BY SUM(n) DESC LIMIT 12",
        tuple(b_args) + (minute_now - 86400,),
    ):
        if not ip:
            continue
        ips.append({"ip": ip, "n": n or 0, "blocked": blk or 0,
                    "own": ip in own, "n10": 0})

    if ips:
        # 一次查完近 10 分钟的量，避免每个 IP 一条 SQL
        recent = dict(conn.execute(
            "SELECT ip, SUM(n) FROM hits WHERE ts>=? GROUP BY ip",
            (minute_now - 600,)).fetchall())
        for x in ips:
            x["n10"] = int(recent.get(x["ip"]) or 0)

    # 归属地只读缓存，页面刷新不发网络请求
    geo_map = geo_mod.attach(conn, [x["ip"] for x in ips])
    for x in ips:
        x["geo"] = geo_map.get(x["ip"]) or {}

    # 每个 IP 最后一个 UA：只用来展示"这是什么客户端"，不参与判定
    ua_map = {}
    for ip, ua, _ts in conn.execute(
            "SELECT ip, ua, MAX(ts) FROM agent WHERE ts>=? GROUP BY ip",
            (minute_now - 86400,)):
        if ip and ua:
            ua_map[ip] = ua
    for x in ips:
        x["ua"] = ua_map.get(x["ip"], "")

    # ---- 来源地区：近 24 小时 ----
    win24 = minute_now - 86400
    geo_top = [
        {"cc": (cc or "").upper(),
         "country": geo_mod.REGION_NAME.get((cc or "").upper())
                    or country or cc or "未知",
         "n": n or 0}
        for cc, country, n in conn.execute(
            "SELECT g.cc, g.country, SUM(h.n) c FROM hits h "
            "JOIN geo g ON g.ip=h.ip WHERE h.ts>=? AND g.cc<>'' "
            "GROUP BY g.cc ORDER BY c DESC LIMIT 8", (win24,))
    ]
    geo_known = scalar(
        "SELECT SUM(h.n) FROM hits h JOIN geo g ON g.ip=h.ip "
        "WHERE h.ts>=? AND g.cc<>''", (win24,))
    total_24h = scalar("SELECT SUM(n) FROM hits WHERE ts>=?", (win24,))

    # ---- 被探路径：近 60 分钟 ----
    paths = [
        {"path": p, "n": n}
        for p, n in conn.execute(
            "SELECT path, SUM(n) FROM paths WHERE ts>=? AND " + b_where +
            " GROUP BY path ORDER BY SUM(n) DESC LIMIT 15",
            (minute_now - 3600,) + tuple(b_args),
        )
        if p
    ]

    # ---- 异常请求：近 60 分钟 ----
    anomaly = [
        {"kind": kind, "label": policy_mod.SOURCES.get(kind, kind),
         "n": n or 0, "ips": ips_n or 0}
        for kind, n, ips_n in conn.execute(
            "SELECT kind, SUM(n), COUNT(DISTINCT ip) FROM anomaly WHERE ts>=? "
            "GROUP BY kind ORDER BY SUM(n) DESC", (minute_now - 3600,))
    ]

    # ---- 敏感文件是否真的被读走 ----
    fp = _spa_fingerprints(conn, t_today)
    leak = []
    for ts, ip, p, sz in conn.execute(
        "SELECT ts, ip, path, sz FROM paths "
        "WHERE ts>=? AND status BETWEEN 200 AND 299 AND sz>0 "
        "GROUP BY path, ip ORDER BY ts DESC LIMIT 400",
        (t_today,),
    ):
        if ip in own or sz in fp or not p or not SENSITIVE.search(p):
            continue
        leak.append({"path": p, "ip": ip, "ts": ts, "sz": sz})
        if len(leak) >= 8:
            break

    # ---- SSH ----
    ssh_today = scalar("SELECT SUM(n) FROM sshfail WHERE ts>=?", (t_today,))
    ssh_10m = scalar("SELECT SUM(n) FROM sshfail WHERE ts>=?", (win10,))
    ssh_top = [
        {"ip": ip, "n": n}
        for ip, n in conn.execute(
            "SELECT ip, SUM(n) FROM sshfail WHERE ts>=? GROUP BY ip "
            "ORDER BY SUM(n) DESC LIMIT 8",
            (t_today,),
        )
    ]

    net = _net_latest(conn)

    # 把丢包计数摊平成列表，面板不用知道配置里有哪些键
    ports = cfg.get("watch_ports") or {}
    labels = cfg.get("port_labels") or {}
    net_items = [
        {
            "key": key,
            "label": "%s:%s" % (labels.get(key, key), port),
            "value": net.get(key, 0),
        }
        for key, port in ports.items()
    ]

    # ---- 自动策略 ----
    pol_cfg = cfg.get("policy") or {}
    pol_last = policy_mod.last_result(conn)
    auto_bans_today = scalar(
        "SELECT COUNT(*) FROM bans WHERE ts>=? AND mode='auto'", (t_today,))

    # ---- 状态判定：泄漏 > 高频拦截 > 零星 > 安静 ----
    red = int(cfg.get("red_threshold_10m", 50))
    yellow = int(cfg.get("yellow_threshold_10m", 1))
    if leak:
        level, msg = "red", "发现敏感路径被成功读取，需立即检查"
    elif blocked_10m >= red:
        level, msg = "red", "正在被扫描：近 10 分钟拦截 %d 次" % blocked_10m
    elif blocked_10m >= yellow:
        level, msg = "yellow", "有零星探测：近 10 分钟拦截 %d 次" % blocked_10m
    else:
        level, msg = "green", "安静：近 10 分钟无拦截，正常访问 %d 次" % passed_10m

    return {
        "generated_at": t_now,
        "generated_at_str": fmt_ts(t_now),
        "level": level,
        "msg": msg,
        "kpi": {
            "total_today": total_today,
            "blocked_today": blocked_today,
            "passed_today": passed_today,
            "blocked_10m": blocked_10m,
            "passed_10m": passed_10m,
            "ssh_today": ssh_today,
            "ssh_10m": ssh_10m,
            "auto_bans_today": auto_bans_today,
        },
        "net": net,
        "net_items": net_items,
        "timeline": timeline,
        "ips": ips,
        "paths": paths,
        "anomaly": anomaly,
        "leak": leak,
        "ssh_top": ssh_top,
        "geo_top": geo_top,
        "geo_known": geo_known,
        "total_24h": total_24h,
        "policy": {
            "enabled": bool(pol_cfg.get("enabled", True)),
            "auto_ban": bool(pol_cfg.get("auto_ban", True)),
            "dry_run": bool(pol_cfg.get("dry_run", False)),
            "last": pol_last,
        },
    }


# ---- 态势页的时间范围 ----
# (key, 标签, 窗口秒, 桶宽秒)。桶宽保证点数在 10~365 之间，
# 既能看出形状，又不至于把 30 天的分钟点全画出来。
RANGES = [
    ("10m", "10 分钟", 600, 60),
    ("30m", "30 分钟", 1800, 60),
    ("1h", "1 小时", 3600, 60),
    ("2h", "2 小时", 7200, 120),
    ("6h", "6 小时", 21600, 300),
    ("12h", "12 小时", 43200, 600),
    ("3d", "3 天", 259200, 1800),
    ("7d", "周", 604800, 3600),
    ("30d", "月", 2592000, 7200),
    ("90d", "季度", 7776000, 21600),
    ("365d", "年", 31536000, 86400),
]
RANGE_MAP = {k: (label, win, step) for k, label, win, step in RANGES}
DEFAULT_RANGE = "1h"


def range_list():
    return [{"key": k, "label": label, "window": win, "step": step}
            for k, label, win, step in RANGES]


def series(conn, cfg, key=None):
    """按时间范围聚合成一条曲线，附带区间汇总和 Top IP。

    数据只保留 retention_days 天，选月/季/年时窗口会被截断，
    用 covered 告诉前端"实际只覆盖到这里"，别假装有全年数据。
    """
    key = key if key in RANGE_MAP else DEFAULT_RANGE
    label, win, step = RANGE_MAP[key]
    t_now = now()
    end = t_now - t_now % step
    start = end - win
    b_where, b_args = _blocked(cfg)
    nb_where, nb_args = _not_blocked(cfg)

    rows = conn.execute(
        "SELECT (ts/%d)*%d AS b, "
        "SUM(CASE WHEN %s THEN n ELSE 0 END), "
        "SUM(CASE WHEN %s THEN n ELSE 0 END) "
        "FROM hits WHERE ts>=? GROUP BY b ORDER BY b" % (step, step, b_where, nb_where),
        tuple(b_args) + tuple(nb_args) + (start,),
    ).fetchall()
    per = {int(r[0]): (r[1] or 0, r[2] or 0) for r in rows}

    points = []
    covered = 0
    for i in range(int(win // step), 0, -1):
        t = end - i * step
        bl, ps = per.get(t, (0, 0))
        points.append({"t": t, "b": bl, "p": ps})
        if bl or ps:
            covered = i

    total = sum(p["b"] + p["p"] for p in points)
    blocked = sum(p["b"] for p in points)
    oldest = conn.execute("SELECT MIN(ts) FROM hits").fetchone()
    oldest = int(oldest[0] or 0) if oldest else 0
    span = min(win, max(0, t_now - oldest)) if oldest else win

    top = []
    for ip, n, blk in conn.execute(
        "SELECT ip, SUM(n), SUM(CASE WHEN " + b_where + " THEN n ELSE 0 END) "
        "FROM hits WHERE ts>=? AND ip<>'' GROUP BY ip "
        "ORDER BY SUM(n) DESC LIMIT 8",
        tuple(b_args) + (start,),
    ):
        top.append({"ip": ip, "n": n or 0, "blocked": blk or 0})

    return {
        "range": key, "label": label, "step": step, "window": win,
        "points": points,
        "sum": {"total": total, "blocked": blocked, "passed": total - blocked,
                "ips": len(top)},
        "top": top,
        "oldest": oldest,
        "covered": span,
        "truncated": bool(oldest and span < win - step),
    }


# ---- 来源 / 异常视图：同一套时间范围，一次算完 ----
def snapshot(conn, cfg, key=None, ip_limit=20, path_limit=18):
    """按范围返回来源与异常两块数据，供「来源」「异常」视图使用。

    和 series() 共用 RANGE_MAP，保证三个视图切范围时口径一致。
    """
    key = key if key in RANGE_MAP else DEFAULT_RANGE
    label, win, step = RANGE_MAP[key]
    t_now = now()
    start = t_now - win
    b_where, b_args = _blocked(cfg)
    nb_where, nb_args = _not_blocked(cfg)
    own = set(cfg.get("own_ips") or [])

    # ---- 来源 IP ----
    ips = []
    for ip, n, blk, last in conn.execute(
        "SELECT ip, SUM(n), SUM(CASE WHEN " + b_where + " THEN n ELSE 0 END), MAX(ts) "
        "FROM hits WHERE ts>=? AND ip<>'' GROUP BY ip "
        "ORDER BY SUM(n) DESC LIMIT ?",
        tuple(b_args) + (start, ip_limit),
    ):
        ips.append({"ip": ip, "n": n or 0, "blocked": blk or 0,
                    "last": last or 0, "own": ip in own})
    geo_map = geo_mod.attach(conn, [x["ip"] for x in ips])
    ua_map = {}
    for ip, ua, _ts in conn.execute(
            "SELECT ip, ua, MAX(ts) FROM agent WHERE ts>=? GROUP BY ip", (start,)):
        if ip and ua:
            ua_map[ip] = ua
    for x in ips:
        rec = geo_map.get(x["ip"]) or {}
        x["geo"] = rec
        x["ua"] = ua_map.get(x["ip"], "")
        x["label"] = geo_mod.label_of(rec) if rec else ""

    # ---- 地区分布 ----
    geo_top = [
        {"cc": (cc or "").upper(),
         "country": geo_mod.REGION_NAME.get((cc or "").upper()) or country or cc or "未知",
         "n": n or 0}
        for cc, country, n in conn.execute(
            "SELECT g.cc, g.country, SUM(h.n) c FROM hits h "
            "JOIN geo g ON g.ip=h.ip WHERE h.ts>=? AND g.cc<>'' "
            "GROUP BY g.cc ORDER BY c DESC LIMIT 10", (start,))
    ]
    geo_known = conn.execute(
        "SELECT SUM(h.n) FROM hits h JOIN geo g ON g.ip=h.ip "
        "WHERE h.ts>=? AND g.cc<>''", (start,)).fetchone()
    geo_known = int((geo_known or [0])[0] or 0)

    # ---- 被探路径 ----
    paths = [
        {"path": p, "n": n, "ips": ips_n}
        for p, n, ips_n in conn.execute(
            "SELECT path, SUM(n), COUNT(DISTINCT ip) FROM paths "
            "WHERE ts>=? AND path<>'' AND " + b_where +
            " GROUP BY path ORDER BY SUM(n) DESC LIMIT ?",
            (start,) + tuple(b_args) + (path_limit,))
    ]

    # ---- 状态码分布：判断"回的是 402 还是 200"很关键 ----
    status = [
        {"code": int(code), "n": n or 0}
        for code, n in conn.execute(
            "SELECT status, SUM(n) FROM hits WHERE ts>=? "
            "GROUP BY status ORDER BY SUM(n) DESC LIMIT 8", (start,))
    ]

    # ---- 异常 ----
    anomaly = [
        {"kind": kind, "label": policy_mod.SOURCES.get(kind, kind),
         "n": n or 0, "ips": ips_n or 0, "vmax": vmax or 0, "top": []}
        for kind, n, ips_n, vmax in conn.execute(
            "SELECT kind, SUM(n), COUNT(DISTINCT ip), MAX(vmax) FROM anomaly "
            "WHERE ts>=? GROUP BY kind ORDER BY SUM(n) DESC LIMIT 12", (start,))
    ]
    # 每种异常按 IP 拆开，界面上点一下就能看到"是谁干的"。
    # 一次 GROUP BY 取完再在内存里裁剪，避免每种类型一条 SQL。
    by_kind = {}
    for kind, ip, n, last in conn.execute(
            "SELECT kind, ip, SUM(n), MAX(ts) FROM anomaly WHERE ts>=? AND ip<>'' "
            "GROUP BY kind, ip ORDER BY SUM(n) DESC", (start,)):
        bucket = by_kind.setdefault(kind, [])
        if len(bucket) < 8:
            bucket.append({"ip": ip, "n": n or 0, "last": last or 0})
    for item in anomaly:
        item["top"] = by_kind.get(item["kind"], [])
        item["label"] = item["label"] or item["kind"]

    # ---- SSH ----
    ssh_total = conn.execute(
        "SELECT SUM(n) FROM sshfail WHERE ts>=?", (start,)).fetchone()
    ssh_total = int((ssh_total or [0])[0] or 0)
    ssh_top = [
        {"ip": ip, "n": n or 0, "last": last or 0}
        for ip, n, last in conn.execute(
            "SELECT ip, SUM(n), MAX(ts) FROM sshfail WHERE ts>=? "
            "GROUP BY ip ORDER BY SUM(n) DESC LIMIT 10", (start,))
    ]

    # ---- 敏感文件命中：SPA 回退站点要看响应体大小，不能只看状态码 ----
    fp = _spa_fingerprints(conn, start)
    leak = []
    seen = set()
    for ts, ip, p, sz in conn.execute(
        "SELECT ts, ip, path, sz FROM paths "
        "WHERE ts>=? AND status BETWEEN 200 AND 299 AND sz>0 "
        "ORDER BY ts DESC LIMIT 600", (start,)):
        if ip in own or sz in fp or not p or not SENSITIVE.search(p):
            continue
        k = (ip, p)
        if k in seen:
            continue
        seen.add(k)
        leak.append({"path": p, "ip": ip, "ts": ts, "sz": sz})
        if len(leak) >= 12:
            break

    oldest = conn.execute("SELECT MIN(ts) FROM hits").fetchone()
    oldest = int((oldest or [0])[0] or 0)
    span = min(win, max(0, t_now - oldest)) if oldest else win

    return {
        "range": key, "label": label, "window": win, "step": step,
        "start": start, "end": t_now,
        "ips": ips, "geo": geo_top, "geo_known": geo_known,
        "paths": paths, "status": status,
        "anomaly": anomaly,
        "ssh": {"total": ssh_total, "top": ssh_top},
        "leak": leak,
        # 封禁状态：前端拿这一份把"已封禁"标签铺到所有列表上
        "banned": banmap_mod.build(cfg),
        "oldest": oldest, "covered": span,
        "truncated": bool(oldest and span < win - step),
    }


def anomaly_ips(conn, cfg, kind, key=None, limit=30):
    """某类异常是哪些 IP 打出来的（点异常类型时弹窗用）。"""
    kind = str(kind or "").strip()[:40]
    if not kind:
        raise ValueError("缺少异常类型")
    key = key if key in RANGE_MAP else DEFAULT_RANGE
    label, win, step = RANGE_MAP[key]
    t_now = now()
    start = t_now - win

    rows = conn.execute(
        "SELECT ip, SUM(n), MAX(vmax), MAX(ts) FROM anomaly "
        "WHERE ts>=? AND kind=? AND ip<>'' GROUP BY ip "
        "ORDER BY SUM(n) DESC LIMIT ?", (start, kind, max(1, min(limit, 100)))
    ).fetchall()

    geo_map = geo_mod.attach(conn, [r[0] for r in rows])
    ips = []
    for ip, n, vmax, last in rows:
        rec = geo_map.get(ip) or {}
        ips.append({
            "ip": ip, "n": int(n or 0), "vmax": int(vmax or 0),
            "last": int(last or 0), "geo": rec,
            "label": geo_mod.label_of(rec) if rec else "",
        })

    paths = []
    if ips:
        ph = ",".join("?" * len(ips))
        paths = [
            {"path": p, "n": int(n or 0), "ips": int(c or 0)}
            for p, n, c in conn.execute(
                "SELECT path, SUM(n), COUNT(DISTINCT ip) FROM paths "
                "WHERE ts>=? AND ip IN (%s) AND path<>'' GROUP BY path "
                "ORDER BY SUM(n) DESC LIMIT 6" % ph,
                (start,) + tuple(x["ip"] for x in ips))
        ]

    total = conn.execute(
        "SELECT SUM(n), COUNT(DISTINCT ip) FROM anomaly WHERE ts>=? AND kind=?",
        (start, kind)).fetchone()
    return {
        "kind": kind,
        "label": policy_mod.SOURCES.get(kind, kind),
        "range": key, "range_label": label, "window": win,
        "start": start, "end": t_now,
        "n": int((total or [0])[0] or 0),
        "ip_count": int((total or [0, 0])[1] or 0),
        "ips": ips,
        "paths": paths,
        "banned": banmap_mod.build(cfg),
    }
