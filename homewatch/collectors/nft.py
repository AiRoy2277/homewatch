# -*- coding: utf-8 -*-
"""nftables 丢包计数器采集。

只读 `nft list chain` 的输出文本，不依赖 python 的 nft 绑定库，
也不需要 root 以外的特殊权限（能读规则集即可）。

计数器是单调累计值，每次存一条快照，面板取最新一条。
同一端口可能有多条规则（IPv4 / IPv6 各一条），这里求和，
比只取第一条更准确。
"""

import re
import subprocess

from .. import db
from ..utils import now

CHAIN = ["nft", "list", "chain", "inet", "filter", "input"]


def read_ruleset(timeout=10):
    """读取 input chain 文本。失败返回空串，不抛出。"""
    try:
        r = subprocess.run(CHAIN, capture_output=True, text=True, timeout=timeout)
        return r.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def parse_counters(text, watch_ports):
    """从规则文本里抽出每个端口的丢包总数。

    watch_ports 形如 ``{"ssh": "22", "origin": "8443"}``，
    返回 ``{"ssh": 97, "origin": 58}``。
    """
    out = {}
    for key, port in watch_ports.items():
        total = 0
        pat = r"dport\s+%s\b[^\n]*?counter\s+packets\s+(\d+)" % re.escape(str(port))
        for m in re.finditer(pat, text):
            total += int(m.group(1))
        out[key] = total
    return out


def collect(conn, cfg):
    text = read_ruleset()
    if not text:
        return 0

    watch = cfg.get("watch_ports") or {}
    db.ensure_net_columns(conn, list(watch.keys()))
    vals = parse_counters(text, watch)

    cols = ["ts"] + ["%s_drop" % k for k in watch]
    sql = "INSERT OR REPLACE INTO net(%s) VALUES(%s)" % (
        ", ".join(cols), ", ".join("?" * len(cols))
    )
    conn.execute(sql, [now()] + [vals[k] for k in watch])
    conn.commit()
    return len(watch)
