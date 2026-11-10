# -*- coding: utf-8 -*-
"""共用小工具：时间解析、时间窗计算。"""

import re
from datetime import datetime, timedelta, timezone

# 面板和阈值统一按北京时间计算"今天"和"近 10 分钟"
CST = timezone(timedelta(hours=8))

MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}

_TS_RE = re.compile(r"(\d+)/(\w+)/(\d{4}):(\d+):(\d+):(\d+)")


def parse_ts(s):
    """nginx 时间戳 -> epoch 秒。

    形如 ``09/Nov/2026:11:49:22 +0000``。按行内自带的时区解析，
    不依赖系统 locale，也不依赖服务器时区设置。
    """
    try:
        date_part, _, off = s.partition(" ")
        m = _TS_RE.match(date_part)
        if not m:
            return None
        day, mon, year, hh, mm, ss = m.groups()
        sign = -1 if off[:1] == "-" else 1
        off_sec = 0
        if off:
            off_sec = sign * (int(off[1:3] or 0) * 3600 + int(off[3:5] or 0) * 60)
        tz = timezone(timedelta(seconds=off_sec))
        return int(
            datetime(int(year), MONTHS[mon], int(day),
                     int(hh), int(mm), int(ss), tzinfo=tz).timestamp()
        )
    except (ValueError, KeyError, AttributeError, IndexError):
        return None


def now():
    return int(datetime.now(CST).timestamp())


def minute_of(ts):
    return ts - ts % 60


def today_start():
    """北京时间今天 00:00 的 epoch。"""
    return int(
        datetime.now(CST).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    )


def fmt_ts(ts):
    return datetime.fromtimestamp(ts, CST).strftime("%Y-%m-%d %H:%M:%S")
