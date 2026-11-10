# -*- coding: utf-8 -*-
"""把"当前可管理的东西"汇总成一份给面板用的 JSON。

包含：受管端口状态、SSH 状态、两层封禁名单、Cloudflare 网段时间、最近审计。
systemctl / ss 这些调用有几百毫秒开销，做一个 3 秒的短缓存，
避免面板轮询把机器打满。
"""

import subprocess
import time

from .. import banmap as banmap_mod
from .. import cloudflare as cf_mod
from .. import db as db_mod
from .. import geo as geo_mod
from .. import policy as policy_mod
from ..ops import fw as fw_ops
from ..ops import geoblock as geo_ops
from ..ops import htpasswd as auth_ops
from ..ops import nginx as nginx_ops
from ..ops import nft as nft_ops
from ..ops import procs as procs_ops
from ..ops import sshd as ssh_ops
from ..ops import state as state_mod
from ..ops import units as units_ops
from . import audit

_CACHE = {"at": 0, "data": None}
CACHE_TTL = 3


def _listening_ports():
    """返回当前处于 LISTEN 的端口集合。"""
    try:
        r = subprocess.run(["ss", "-lntH"], capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.SubprocessError):
        return set()
    ports = set()
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        addr = parts[3]
        _, _, p = addr.rpartition(":")
        if p.isdigit():
            ports.add(int(p))
    return ports


def _units():
    """进程守护状态。systemctl 不可用时返回空表，而不是让整页 500。"""
    try:
        return units_ops.status()
    except Exception:  # noqa: BLE001
        return {"units": [], "guard": {"on": False},
                "warnings": ["读取 systemd 状态失败"], "last_collect": 0, "lag": 0}


def _fw(cfg):
    """防火墙规则 + 命中计数。读失败时给一份空表，别让整页 500。"""
    try:
        return fw_ops.list_rules(cfg, with_hits=True)
    except Exception:  # noqa: BLE001
        return {"rules": [], "policy": {"in": "accept", "out": "accept"},
                "container": True, "counters": False, "max": fw_ops.MAX_RULES,
                "error": "读取规则失败"}


def _listen():
    try:
        return procs_ops.listening()
    except Exception:  # noqa: BLE001
        return {}


def _geo_lock(cfg):
    """地域封锁状态。读失败给一份"关着"的空壳，别让整页 500。"""
    try:
        return geo_ops.status(cfg)
    except Exception as exc:  # noqa: BLE001
        return {"in": {"enabled": False, "scope": "web", "scope_label": "只挡 Web 端口",
                       "ports": []},
                "out": {"enabled": False}, "container": True, "allow": [],
                "cn": {"v4": 0, "v6": 0, "updated": 0, "source": "", "age_days": None},
                "exempt": {"lan": [], "own": [], "cf": 0, "dns": [], "allow": []},
                "hits": {"in": {"packets": 0, "bytes": 0},
                         "out": {"packets": 0, "bytes": 0}},
                "counters": False, "on": False, "error": str(exc)[:80]}


def _banned(cfg):
    try:
        return banmap_mod.build(cfg)
    except Exception:  # noqa: BLE001
        return {}


def build(cfg, force=False):
    now = int(time.time())
    if not force and _CACHE["data"] and now - _CACHE["at"] < CACHE_TTL:
        return _CACHE["data"]

    st = state_mod.load(cfg)
    state_mod.purge_expired(st)
    live = _listening_ports()
    listen = _listen()
    denied = {int(p) for p in st.get("denied_ports", [])}
    ctrl = nft_ops.ensure_ctrl(cfg, st)

    ports = []
    for item in cfg.get("managed_ports") or []:
        port = int(item.get("port", 0))
        if not port:
            continue
        mode = (ctrl.get(str(port)) or {})
        who = listen.get(port) or {}
        ports.append({
            "port": port,
            "label": item.get("label") or str(port),
            "desc": item.get("desc") or "",
            "readonly": bool(item.get("readonly")),
            "closed": port in denied or mode.get("in") == "deny",
            "listening": port in live,
            "ctrl": {
                "in": mode.get("in") or "allow",
                "out": mode.get("out") or "allow",
                "proto": mode.get("proto") or "tcp",
            },
            "procs": who.get("procs") or [],
            "container": who.get("container") or None,
            "addr": who.get("addr") or "",
        })

    ssh = ssh_ops.status()
    pend = st.get("ssh_port_pending")
    if pend:
        ssh["pending"] = {
            "old": pend.get("old"),
            "new": pend.get("new"),
            "deadline": pend.get("deadline"),
            "left": max(0, int(pend.get("deadline") or 0) - now),
        }

    pol = cfg.get("policy") or {}
    conn = None
    av = {"request_length": False, "user_agent": False, "warnings": []}
    cf_last = None
    cf_synced_at = 0
    try:
        conn = db_mod.connect(cfg["paths"]["db"])
        pol_last = policy_mod.last_result(conn)
        bans = policy_mod.recent(conn, 20)
        av = policy_mod.availability(conn, cfg)
        cf_last = policy_mod.cf_last(conn)
        try:
            cf_synced_at = int(db_mod.meta_get(conn, "cf_synced_at", 0) or 0)
        except (TypeError, ValueError):
            cf_synced_at = 0
        gb = geo_mod.attach(conn, [b.get("ip") for b in bans])
        for b in bans:
            rec = gb.get(b.get("ip")) or {}
            b["geo"] = rec.get("label") or ""
            b["cc"] = rec.get("cc") or ""
        blocked = st.get("blocked_ips", [])
        geo_map = geo_mod.attach(conn, [x.get("ip") for x in blocked])
        for item in blocked:
            rec = geo_map.get(item.get("ip")) or {}
            item["geo"] = rec.get("label") or ""
            item["cc"] = rec.get("cc") or ""
    except Exception:  # noqa: BLE001
        pol_last, bans, blocked = None, [], st.get("blocked_ips", [])
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass

    data = {
        "generated_at": now,
        "ports": ports,
        "fw": _fw(cfg),
        "geo_lock": _geo_lock(cfg),
        "banned": _banned(cfg),
        "fw_ctx": {
            "lan": (cfg.get("firewall") or {}).get("lan_cidrs") or [],
            "cf": (st.get("cf_ips4") or []) + (st.get("cf_ips6") or []),
            "own": cfg.get("own_ips") or [],
            "admin_port": int(cfg.get("admin_port") or 8088),
            "ssh_port": int(st.get("ssh_port") or 22),
        },
        "listen": [
            {"port": p, "procs": v.get("procs") or [], "addr": v.get("addr") or "",
             "container": v.get("container") or None}
            for p, v in sorted(listen.items())
        ],
        "units": _units(),
        "ssh": ssh,
        "auth": auth_ops.state(cfg),
        "blocked_nft": blocked,
        "blocked_nginx": nginx_ops.read_ips(cfg),
        "cf": {
            "updated": st.get("cf_updated", 0),
            "v4": len(st.get("cf_ips4", [])),
            "v6": len(st.get("cf_ips6", [])),
            "api": cf_mod.status(cfg),
            "last": cf_last,
            "synced_at": cf_synced_at,
        },
        "policy": {
            "enabled": bool(pol.get("enabled", True)),
            "auto_ban": bool(pol.get("auto_ban", True)),
            "dry_run": bool(pol.get("dry_run", False)),
            "ban_mode": nginx_ops.ban_mode(cfg),
            "ban_mode_label": nginx_ops.mode_label(nginx_ops.ban_mode(cfg)),
            "silent_log": bool(nginx_ops.logs_of(cfg)),
            "wiring": policy_mod.wiring(cfg),
            "max_bans_per_run": pol.get("max_bans_per_run", 3),
            "max_hours": pol.get("max_hours", 720),
            "repeat_window_hours": pol.get("repeat_window_hours", 72),
            "whitelist": pol.get("whitelist") or [],
            "limits": pol.get("limits") or {},
            "allowed_methods": pol.get("allowed_methods") or [],
            "trusted_bots": pol.get("trusted_bots") or [],
            "warnings": av.get("warnings") or [],
            "log_fields": {"request_length": bool(av.get("request_length")),
                           "user_agent": bool(av.get("user_agent"))},
            "rules": policy_mod.rules_of(cfg),
            "last": pol_last,
            "bans": bans,
        },
        "limits": {
            "red_threshold_10m": cfg.get("red_threshold_10m"),
            "yellow_threshold_10m": cfg.get("yellow_threshold_10m"),
            "retention_days": cfg.get("retention_days"),
        },
        "geo": {
            "enabled": bool((cfg.get("geo") or {}).get("enabled", True)),
            "provider": (cfg.get("geo") or {}).get("provider", "auto"),
        },
        "own_ips": cfg.get("own_ips") or [],
        "audit": audit.tail(cfg, 20),
    }
    _CACHE["at"], _CACHE["data"] = now, data
    return data


def invalidate():
    _CACHE["at"] = 0
    _CACHE["data"] = None
