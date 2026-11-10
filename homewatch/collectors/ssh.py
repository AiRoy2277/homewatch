# -*- coding: utf-8 -*-
"""SSH 暴力破解采集（读 journald）。

有两个坑踩过，写在这里避免以后重犯：

1. **不要用 ``-n N`` 搭配 ``--after-cursor``**。journalctl 会返回游标*之前*
   的一个滑动窗口，每次读到的都是不同的一批旧记录，导致计数一路虚涨。
   正确做法是用时间戳定位增量窗口，再用游标做幂等去重。

2. **游标去重表要持久化**。同一条日志在重叠窗口里会被读到多次，
   靠 ``sshseen`` 表的 PRIMARY KEY 保证只计一次。
"""

import json
import re
import subprocess

from .. import db
from ..utils import now, today_start

# 从消息里抠出源 IP，同时支持 IPv4 和 IPv6
IP_RE = re.compile(r"from ([0-9a-fA-F:.]+)")

# 首次采集（库里没有游标）时往前找多久
FIRST_RUN_WINDOW = 2 * 3600

# 时间戳重叠量：给 journal 落盘延迟留余量，重复部分由游标去重
OVERLAP = 120


def fetch_json(unit, since, timeout=40):
    cmd = ["journalctl", "-u", unit, "-o", "json", "--no-pager",
           "--since", "@%d" % since]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def collect(conn, cfg):
    unit = cfg.get("ssh_unit", "ssh")
    last = db.meta_get_int(conn, "ssh_last_ts", 0)
    if last:
        since = last - OVERLAP
    else:
        # 首次运行：从今天 0 点开始，但如果现在就是凌晨，
        # 至少回看 FIRST_RUN_WINDOW，避免刚开始监控时数字为空
        since = min(today_start(), now() - FIRST_RUN_WINDOW)

    out = fetch_json(unit, since)
    if not out:
        return 0

    agg = {}
    n = 0
    newest = since

    for line in out.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        msg = d.get("MESSAGE", "")
        if isinstance(msg, bytes):
            msg = msg.decode("utf-8", "replace")
        if "Failed password" not in msg:
            continue

        cur = d.get("__CURSOR", "")
        if not cur:
            continue

        # 幂等关键：游标已见过就跳过
        inserted = conn.execute(
            "INSERT OR IGNORE INTO sshseen(c) VALUES(?)", (cur,)
        ).rowcount
        if not inserted:
            continue

        m = IP_RE.search(msg)
        if not m:
            continue

        try:
            ts = int(d.get("__REALTIME_TIMESTAMP", "0")) // 1_000_000
        except (TypeError, ValueError):
            ts = now()

        newest = max(newest, ts)
        minute = ts - ts % 60
        key = (minute, m.group(1)[:64])
        agg[key] = agg.get(key, 0) + 1
        n += 1

    conn.executemany(
        "INSERT INTO sshfail(ts,ip,n) VALUES(?,?,?) "
        "ON CONFLICT(ts,ip) DO UPDATE SET n=n+excluded.n",
        [(a, b, v) for (a, b), v in agg.items()],
    )
    db.meta_set(conn, "ssh_last_ts", newest)
    conn.commit()
    return n
