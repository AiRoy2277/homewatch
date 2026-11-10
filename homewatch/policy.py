# -*- coding: utf-8 -*-
"""安全策略引擎。

一次评估做四件事：
  1. 按规则从聚合数据里找出可疑 IP（SSH 爆破、拦截洪水、敏感路径、多路径爬取）；
  2. 过一遍保护名单（自己的 IP、白名单、内网、Cloudflare 回源段、已在封禁中）；
  3. 重复违规时长翻倍，单次最多封 ``max_bans_per_run`` 个；
  4. 一次性批量下发到 nftables + nginx，并写封禁流水与审计。

默认行为刻意保守：同一个 IP 连续触发才升级时长，单次评估封禁数量有上限，
``dry_run`` 打开后只记录"本来会封谁"。误封一个人比漏封一个扫描器代价更高。
"""

import ipaddress
import json
import re

from . import db
from .ops import nft as nft_ops
from .ops import nginx as nginx_ops
from .ops import state as state_mod
from .patterns import SENSITIVE
from .utils import now

# Cloudflare 对账间隔：不是每轮都拉一次规则列表，五分钟够用
CF_SYNC_INTERVAL = 300

SOURCES = {
    "ssh_fail": "SSH 失败登录",
    "http_blocked": "被拦截请求",
    "http_total": "全部请求",
    "http_error": "4xx/5xx 响应",
    "http_reject": "超大请求被拒",
    "distinct_paths": "不重复路径",
    "sensitive": "敏感路径",
    "long_uri": "超长 URL",
    "big_req": "超大请求报文",
    "bad_method": "异常请求方法",
    "bad_proto": "异常协议版本",
    "bad_ua": "恶意 User-Agent",
    "honeypot": "蜜罐路径",
}

# source -> anomaly.kind，采集时已经判定好，这里只做计数
ANOMALY_SOURCES = {
    "long_uri": "long_uri",
    "big_req": "big_req",
    "bad_method": "bad_method",
    "bad_proto": "bad_proto",
    "bad_ua": "bad_ua",
    "honeypot": "honeypot",
}

# 频率类规则。可信爬虫只豁免这些，蜜罐/敏感路径/超大报文照样封
RATE_SOURCES = {
    "ssh_fail", "http_blocked", "http_total", "http_error",
    "http_reject", "distinct_paths",
}

# 单 IP 命中多条规则时，先封"更像攻击"的那类。
# 蜜罐路径只有 1 次，但确定性远高于 60 次高频请求，不能被后者挤出单次上限。
CONFIDENCE = {
    "honeypot": 100,
    "http_reject": 90,
    "sensitive": 80,
    "ssh_fail": 75,
    "big_req": 70,
    "long_uri": 70,
    "bad_method": 65,
    "bad_ua": 65,
    "bad_proto": 60,
    "http_blocked": 50,
    "distinct_paths": 45,
    "http_error": 40,
    "http_total": 30,
}

# nginx 直接拒掉的请求：413 体太大、414 URI 太长、431 头太大
REJECT_STATUS = (413, 414, 431)

LAYERS = ("both", "nginx", "nft")
FIELD_LIMITS = {
    "window": (60, 86400),
    "threshold": (1, 100000),
    "hours": (0, 8760),
}


# ---------------- 小工具 ----------------


def _networks(cidrs):
    out = []
    for c in cidrs or []:
        try:
            out.append(ipaddress.ip_network(str(c).strip(), strict=False))
        except ValueError:
            continue
    return out


def _addr(ip):
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a


def _in_nets(addr, nets):
    if addr is None:
        return False
    for net in nets:
        if addr.version == net.version and addr in net:
            return True
    return False


def rules_of(cfg):
    return [r for r in (cfg.get("policy") or {}).get("rules") or []
            if isinstance(r, dict) and r.get("id")]


def _blocked_where(cfg):
    codes = list(cfg.get("blocked_status") or [402, 403])
    return "status IN (" + ",".join("?" * len(codes)) + ")", codes


def _not_blocked_where(cfg):
    codes = list(cfg.get("blocked_status") or [402, 403])
    return "status NOT IN (" + ",".join("?" * len(codes)) + ")", codes


def _merge_layer(a, b):
    if not a or a == b:
        return b or a or "both"
    return "both"


# ---------------- 规则匹配 ----------------


def _match(conn, cfg, rule):
    """返回 [(ip, 命中数)]，按命中数从多到少。"""
    src = rule.get("source")
    win = max(60, int(rule.get("window") or 600))
    thr = max(1, int(rule.get("threshold") or 10))
    # 数据是分钟级聚合的，窗口起点向下对齐到整分钟。
    # 否则 60 秒窗口只覆盖 1-2 个桶，还会把跨越整点的那一分钟整段切掉，
    # 表现就是"明明打了很多请求却不够阈值"。
    since = now() - win
    since -= since % 60

    if src == "ssh_fail":
        rows = conn.execute(
            "SELECT ip, SUM(n) c FROM sshfail WHERE ts>=? GROUP BY ip "
            "HAVING c>=? ORDER BY c DESC LIMIT 100", (since, thr))
    elif src == "http_blocked":
        where, args = _blocked_where(cfg)
        rows = conn.execute(
            "SELECT ip, SUM(n) c FROM hits WHERE ts>=? AND " + where +
            " GROUP BY ip HAVING c>=? ORDER BY c DESC LIMIT 100",
            (since,) + tuple(args) + (thr,))
    elif src == "http_total":
        rows = conn.execute(
            "SELECT ip, SUM(n) c FROM hits WHERE ts>=? GROUP BY ip "
            "HAVING c>=? ORDER BY c DESC LIMIT 100", (since, thr))
    elif src == "http_error":
        # 404 扫描这类"看起来正常但全是错"的流量。已拦截的 402 不算在内，
        # 否则同一个 IP 会被拦截洪水和错误洪水各记一次。
        where, args = _not_blocked_where(cfg)
        rows = conn.execute(
            "SELECT ip, SUM(n) c FROM hits WHERE ts>=? AND status>=400 AND " +
            where + " GROUP BY ip HAVING c>=? ORDER BY c DESC LIMIT 100",
            (since,) + tuple(args) + (thr,))
    elif src == "http_reject":
        ph = ",".join("?" * len(REJECT_STATUS))
        rows = conn.execute(
            "SELECT ip, SUM(n) c FROM hits WHERE ts>=? AND status IN (" + ph +
            ") GROUP BY ip HAVING c>=? ORDER BY c DESC LIMIT 100",
            (since,) + REJECT_STATUS + (thr,))
    elif src == "distinct_paths":
        rows = conn.execute(
            "SELECT ip, COUNT(DISTINCT path) c FROM paths WHERE ts>=? "
            "GROUP BY ip HAVING c>=? ORDER BY c DESC LIMIT 100", (since, thr))
    elif src == "sensitive":
        # 敏感路径不适合用 SQL 正则，命中量本来就小，取回来用 Python 判断
        per = {}
        for ip, path in conn.execute(
                "SELECT ip, path FROM paths WHERE ts>=? GROUP BY ip, path", (since,)):
            if ip and path and SENSITIVE.search(path):
                per[ip] = per.get(ip, 0) + 1
        rows = sorted(((ip, c) for ip, c in per.items() if c >= thr),
                      key=lambda kv: -kv[1])[:100]
    elif src in ANOMALY_SOURCES:
        rows = conn.execute(
            "SELECT ip, SUM(n) c FROM anomaly WHERE ts>=? AND kind=? "
            "GROUP BY ip HAVING c>=? ORDER BY c DESC LIMIT 100",
            (since, ANOMALY_SOURCES[src], thr))
    else:
        return []

    return [(ip, int(c or 0)) for ip, c in rows if ip]


def _candidates(conn, cfg):
    """把各条规则的命中合并成"每个 IP 一条"的候选列表。"""
    out = {}
    for rule in rules_of(cfg):
        if not rule.get("enabled", True):
            continue
        for ip, hits in _match(conn, cfg, rule):
            e = out.get(ip)
            if not e:
                e = out[ip] = {"ip": ip, "hits": 0, "hours": 0,
                               "layer": "", "rules": []}
            e["rules"].append({"id": rule.get("id"), "name": rule.get("name")
                               or rule.get("id"), "hits": hits,
                               "source": rule.get("source")})
            e["hits"] = max(e["hits"], hits)
            e["hours"] = max(e["hours"], int(rule.get("hours") or 24))
            e["layer"] = _merge_layer(e["layer"], rule.get("layer") or "both")
    return out


def _score(e):
    """排序用：先看规则置信度，再看命中次数。"""
    conf = max([CONFIDENCE.get(r.get("source"), 40) for r in e["rules"]] or [0])
    return conf, e["hits"]


def _bot_ips(conn, since, patterns):
    """最近一天里 UA 命中可信爬虫名单的 IP。"""
    pats = [re.compile(str(p), re.I) for p in (patterns or []) if str(p).strip()]
    if not pats:
        return set()
    out = set()
    try:
        rows = conn.execute(
            "SELECT ip, ua, MAX(ts) FROM agent WHERE ts>=? GROUP BY ip", (since,))
    except Exception:  # noqa: BLE001  老库没有 agent 表时不影响主流程
        return out
    for ip, ua, _ts in rows:
        if ua and any(p.search(ua) for p in pats):
            out.add(ip)
    return out


def availability(conn, cfg):
    """当前日志格式能不能支撑某些规则，以及对应的提醒。"""
    has_rlen = db.meta_get_int(conn, "log_has_rlen", 0) == 1
    has_ua = db.meta_get_int(conn, "log_has_ua", 0) == 1
    warnings = []
    for rule in rules_of(cfg):
        if not rule.get("enabled", True):
            continue
        src = rule.get("source")
        name = rule.get("name") or rule.get("id")
        if src == "big_req" and not has_rlen:
            warnings.append("「%s」需要日志里有 $request_length，当前格式没有，暂时不会命中"
                            % name)
        elif src == "bad_ua" and not has_ua:
            warnings.append("「%s」需要日志里有 $http_user_agent，当前格式没有，暂时不会命中"
                            % name)
    return {"request_length": has_rlen, "user_agent": has_ua,
            "warnings": warnings}


def wiring(cfg):
    """站点有没有按当前模式接好线（return 444 / access_log if=）。"""
    mode = nginx_ops.ban_mode(cfg)
    info = {"mode": mode, "mode_label": nginx_ops.mode_label(mode),
            "want_code": nginx_ops.code_of(mode), "wired": True,
            "log_wired": True, "files": [], "warnings": []}
    try:
        info.update(nginx_ops.scan(cfg))
    except Exception:  # noqa: BLE001  读不到站点目录不该影响评估
        return info
    codes = [f.get("return") for f in info.get("files") or [] if f.get("return")]
    if not info.get("files"):
        info["warnings"].append(
            "站点配置里没找到 $blocked_scanner 引用，封禁规则目前不会生效")
    elif codes and all(c != info["want_code"] for c in codes):
        info["warnings"].append(
            "站点还在返回 %s，点「应用静默模式」改成 %d 才会静默断开"
            % (codes[0], info["want_code"]))
    if not nginx_ops.logs_of(cfg) and not info.get("log_wired"):
        if info.get("log_supported") is False:
            info["warnings"].append(
                "本站点的 access_log 写在 http 级，没法按请求掐日志；"
                "「不记日志」退化为 silent（仍回 444，但照常记录）")
        else:
            info["warnings"].append(
                "「不记日志」需要站点 access_log 挂 if=$blocked_loggable，现在还在照常记录")
    return info


# ---------------- Cloudflare ----------------


def cf_sync(conn, cfg, ips=None, force=False):
    """把当前封禁名单推到 Cloudflare 边缘。

    ips 为空时自动取 nginx 名单 ∪ nft 名单 —— 两个名单都可能单独用过，
    取并集才不漏。返回结果同时写进 meta，面板不用发网络请求也能看到上次结果。
    """
    from . import cloudflare as cf

    pol = cfg.get("policy") or {}
    if not cf.configured(cfg):
        return {"ok": False, "skipped": True, "msg": "Cloudflare 未启用或没配 token"}
    if not force and not (cfg.get("cloudflare") or {}).get("auto_sync", True):
        return {"ok": False, "skipped": True, "msg": "自动同步已关闭"}

    if ips is None:
        try:
            st = state_mod.load(cfg)
            state_mod.purge_expired(st)
            ips = sorted(set(nginx_ops.read_ips(cfg))
                         | {x.get("ip") for x in st.get("blocked_ips", [])})
        except Exception:  # noqa: BLE001
            ips = []

    try:
        res = cf.sync(cfg, ips)
    except Exception as exc:  # noqa: BLE001  CF 挂了不能影响本地封禁
        res = {"ok": False, "msg": str(exc)[:200], "added": [],
               "exists": [], "failed": []}

    try:
        db.meta_set(conn, "cf_synced_at", now())
        db.meta_set(conn, "cf_last", json.dumps({
            "at": now(), "ok": res.get("ok"), "msg": res.get("msg", ""),
            "added": res.get("added") or [],
            "failed": (res.get("failed") or [])[:5],
        }, ensure_ascii=False))
        conn.commit()
    except Exception:  # noqa: BLE001
        pass
    return res


def cf_due(conn):
    try:
        last = int(db.meta_get(conn, "cf_synced_at", 0) or 0)
    except (TypeError, ValueError):
        last = 0
    return now() - last >= CF_SYNC_INTERVAL


def cf_last(conn):
    raw = db.meta_get(conn, "cf_last")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


# ---------------- 保护与升级 ----------------


def _repeat(conn, ip, hours):
    if hours <= 0:
        return 0
    row = conn.execute(
        "SELECT COUNT(*) FROM bans WHERE ip=? AND ts>=? AND mode!='dry'",
        (ip, now() - hours * 3600)).fetchone()
    return int(row[0] or 0) if row else 0


def _guard(cfg, ip, whitelist, cf_nets, lan_nets, blocked_ips, nginx_ips):
    """返回不允许封禁的原因；可以封则返回空串。"""
    addr = _addr(ip)
    if addr is None:
        return "地址不合法"
    if ip in (cfg.get("own_ips") or []):
        return "自己的 IP"
    if ip in whitelist:
        return "白名单"
    if _in_nets(addr, lan_nets):
        return "内网地址"
    if _in_nets(addr, cf_nets):
        return "Cloudflare 回源段"
    if not addr.is_global:
        return "非公网地址"
    if ip in blocked_ips or ip in nginx_ips:
        return "已在封禁名单"
    return ""


def _reason(e):
    names = []
    for r in e.get("rules", []):
        if r["name"] not in names:
            names.append(r["name"])
    return "自动封禁：" + "、".join(names)


def record(conn, ip, hours, layer, rule, reason, mode="auto", hits=0):
    """写一条封禁流水。重复调用同一条会被主键吃掉。"""
    try:
        conn.execute(
            "INSERT OR IGNORE INTO bans(ts,ip,hours,layer,rule,reason,mode,hits) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (now(), ip, int(hours or 0), layer or "", rule or "",
             reason or "", mode, int(hits or 0)))
        conn.commit()
    except Exception:  # noqa: BLE001  流水写失败不能影响封禁本身
        pass


def recent(conn, limit=20, mode=None):
    sql = ("SELECT ts,ip,hours,layer,rule,reason,mode,hits FROM bans")
    args = ()
    if mode:
        sql += " WHERE mode=?"
        args = (mode,)
    sql += " ORDER BY ts DESC LIMIT ?"
    args += (limit,)
    return [
        {"ts": r[0], "ip": r[1], "hours": r[2], "layer": r[3],
         "rule": r[4], "reason": r[5], "mode": r[6], "hits": r[7]}
        for r in conn.execute(sql, args)
    ]


# ---------------- 评估 ----------------


def evaluate(conn, cfg, apply=None, source="timer"):
    """跑一次策略评估。

    apply=None 跟随配置（auto_ban 且非 dry_run 才真封）；
    apply=False 强制只观察，用于面板上的"立即评估"。
    """
    pol = cfg.get("policy") or {}
    at = now()
    if not pol.get("enabled", True):
        return {"at": at, "enabled": False, "apply": False,
                "candidates": 0, "banned": [], "skipped": [],
                "msg": "自动策略已停用"}

    dry = bool(pol.get("dry_run", False))
    do_apply = (bool(pol.get("auto_ban", True)) if apply is None else bool(apply)) and not dry
    max_hours = int(pol.get("max_hours", 720))
    repeat_win = int(pol.get("repeat_window_hours", 72))
    max_bans = max(1, int(pol.get("max_bans_per_run", 3)))

    st = state_mod.load(cfg)
    state_mod.purge_expired(st)
    whitelist = set(pol.get("whitelist") or [])
    cf_nets = _networks(st.get("cf_ips4")) + _networks(st.get("cf_ips6"))
    lan_nets = _networks((cfg.get("firewall") or {}).get("lan_cidrs"))
    blocked_ips = {x.get("ip") for x in st.get("blocked_ips", [])}
    try:
        nginx_ips = set(nginx_ops.read_ips(cfg))
    except Exception:  # noqa: BLE001
        nginx_ips = set()

    cands = _candidates(conn, cfg)
    bots = _bot_ips(conn, at - 86400, pol.get("trusted_bots"))
    allowed, skipped = [], []
    for ip, e in sorted(cands.items(), key=lambda kv: _score(kv[1]), reverse=True):
        why = _guard(cfg, ip, whitelist, cf_nets, lan_nets,
                     blocked_ips, nginx_ips)
        if why:
            skipped.append({"ip": ip, "hits": e["hits"], "why": why})
            continue
        # 可信爬虫只豁免频率类规则；它要真去翻 .git 或者发超大报文，照样封
        if ip in bots and all(r.get("source") in RATE_SOURCES for r in e["rules"]):
            skipped.append({"ip": ip, "hits": e["hits"], "why": "可信爬虫"})
            continue
        level = _repeat(conn, ip, repeat_win)
        base = int(e["hours"] or 24)
        if base > 0 and level:
            # 每次复发翻倍，上限 max_hours
            base = min(max_hours, base * (2 ** min(level, 6)))
        e["hours"] = min(base, max_hours) if base > 0 else 0
        e["repeat"] = level
        e["reason"] = _reason(e)
        allowed.append(e)

    overflow = allowed[max_bans:]
    allowed = allowed[:max_bans]

    errors = []
    if do_apply and allowed:
        nft_items = [{"ip": e["ip"], "hours": e["hours"], "auto": True,
                      "reason": e["reason"], "rule": e["rules"][0]["id"]}
                     for e in allowed if e["layer"] in ("both", "nft")]
        nginx_list = [e["ip"] for e in allowed
                      if e["layer"] in ("both", "nginx")]
        try:
            if nft_items:
                nft_ops.block_many(cfg, nft_items)
        except Exception as exc:  # noqa: BLE001
            errors.append("nftables 失败：%s" % exc)
        try:
            if nginx_list:
                nginx_ops.add_many(cfg, nginx_list)
        except Exception as exc:  # noqa: BLE001
            errors.append("nginx 失败：%s" % exc)

    # Cloudflare 边缘同步：本轮有新封禁，或者到了例行对账时间就走一次。
    # 失败只记在 cf 字段里，不算"本地下发失败"，否则会误伤复发次数的统计。
    cf_res = None
    if do_apply and (allowed or cf_due(conn)):
        cf_res = cf_sync(conn, cfg)
        # 没配置 / 没开自动同步不算结果，别让它占着摘要和面板
        if cf_res and cf_res.get("skipped"):
            cf_res = None

    # 归属地只读缓存，不在评估里发网络请求
    from . import geo as geo_mod
    geo_map = geo_mod.attach(conn, [e["ip"] for e in allowed])
    # 两层都失败说明根本没下发成功，这时不写流水，否则会虚增"复发次数"
    write_flow = do_apply and len(errors) < 2
    mode = "auto" if do_apply else "dry"
    banned = []
    for e in allowed:
        rec = geo_map.get(e["ip"]) or {}
        banned.append({
            "ip": e["ip"], "hours": e["hours"], "layer": e["layer"],
            "hits": e["hits"], "repeat": e.get("repeat", 0),
            "reason": e["reason"], "rules": e["rules"],
            "geo": rec.get("label") or "", "cc": rec.get("cc") or "",
        })
        # 演练/只观察不落封禁流水，否则每分钟写一条会把记录刷满
        if write_flow:
            record(conn, e["ip"], e["hours"], e["layer"],
                   ",".join(r["id"] for r in e["rules"]), e["reason"],
                   mode=mode, hits=e["hits"])

    wire = wiring(cfg)
    summary = {
        "at": at,
        "enabled": True,
        "apply": do_apply,
        "dry_run": dry,
        "source": source,
        "candidates": len(cands),
        "banned": banned,
        "skipped": skipped[:20],
        "overflow": len(overflow),
        "errors": errors,
        "cf": cf_res,
        "wiring": {k: wire.get(k) for k in
                   ("mode", "mode_label", "want_code", "wired", "log_wired")},
        "limits": pol.get("limits") or {},
        "warnings": availability(conn, cfg)["warnings"] + wire.get("warnings", []),
        "msg": _with_cf(_summary_msg(do_apply, banned, dry, len(cands), errors), cf_res),
    }

    try:
        db.meta_set(conn, "policy_last", json.dumps(summary, ensure_ascii=False))
        conn.commit()
    except Exception:  # noqa: BLE001
        pass

    if banned:
        _audit(cfg, summary)
    return summary


def _with_cf(msg, cf_res):
    """把 Cloudflare 的结果缀在摘要后面。跳过的（没配/没开）不占字数。"""
    if not cf_res or cf_res.get("skipped"):
        return msg
    extra = cf_res.get("msg") or ""
    if not extra:
        return msg
    return (msg + "；" + extra)[:300]


def _summary_msg(do_apply, banned, dry, candidates, errors=None):
    if errors and banned:
        return "识别到 %d 个可疑 IP，但下发失败：%s" % (
            len(banned), "；".join(errors)[:200])
    if not banned:
        return "本轮没有需要处理的 IP（候选 %d 个）" % candidates
    if dry:
        return "演练模式：本应封禁 %d 个 IP，未下发规则" % len(banned)
    if not do_apply:
        return "自动封禁已关闭：识别到 %d 个可疑 IP，未下发" % len(banned)
    return "已自动封禁 %d 个 IP" % len(banned)


def _audit(cfg, summary):
    """整批写一条审计，避免一次封 3 个就往日志里塞 3 条。"""
    try:
        from .admin import audit
        ips = "、".join(x["ip"] for x in summary["banned"][:5])
        audit.write(cfg, "policy", "policy.auto",
                    {"ips": ips, "count": len(summary["banned"]),
                     "apply": summary["apply"]},
                    ok=not summary["errors"],
                    msg=summary["msg"])
    except Exception:  # noqa: BLE001
        pass


def last_result(conn):
    """读出上一次评估结果，面板用。"""
    raw = db.meta_get(conn, "policy_last")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None
