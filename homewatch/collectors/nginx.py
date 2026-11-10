# -*- coding: utf-8 -*-
"""nginx 访问日志增量采集。

增量靠两个 meta 值：文件 inode 和已消费的字节偏移。
inode 变了或文件变短（logrotate 的 copytruncate 或手工截断）就从头读，
这样轮转不会漏也不会重复。

除了"每分钟多少请求"，这里还顺手把**异常请求**挑出来按分钟聚合成
``anomaly`` 表：超长 URL、超大报文、异常方法、异常协议、恶意 UA、蜜罐路径。
判定线来自 ``policy.limits``，所以改配置后从下一条日志起生效（历史不回溯）。

``$request_length`` / ``$http_user_agent`` 属于可选字段：日志格式是默认
combined 时也能正常跑，只是"超大报文"这条规则不会命中，UA 相关的判定跳过。
"""

import os
import re

from .. import db
from ..patterns import BAD_UA, HONEYPOT
from ..utils import parse_ts

# 默认 combined 格式的前半段 + 可选的尾部（referer / UA / request_length / request_time）。
# 尾部整段可选，是为了兼容只配了 combined、没加 $request_length 的机器。
LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>[^"]*?) '
    r'(?P<proto>[^"]*)" (?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
    r'(?: (?P<rlen>\d+)(?: (?P<rtime>[\d.]+))?)?'
)

DEFAULT_METHODS = ("GET", "POST", "HEAD", "OPTIONS")
KNOWN_PROTOS = ("HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/2")
UA_KEEP = 160
ANOMALY_KINDS = ("long_uri", "big_req", "bad_method", "bad_proto", "bad_ua", "honeypot")


def _limits(cfg):
    pol = cfg.get("policy") or {}
    lim = pol.get("limits") or {}
    return (
        max(64, int(lim.get("uri_len") or 1024)),
        max(1024, int(lim.get("req_bytes") or 65536)),
        max(32, int(lim.get("ua_len") or 400)),
        {str(m).upper() for m in (pol.get("allowed_methods") or DEFAULT_METHODS)},
    )


def _probe_fields(log_path, tail_bytes=65536):
    """看文件末尾最后一条可解析的行，判断日志是否带 UA / request_length。

    只读末尾一小段，不入库，仅用于"这一轮没有新日志"时更新字段标记。
    """
    try:
        size = os.path.getsize(log_path)
        with open(log_path, "rb") as fh:
            fh.seek(max(0, size - tail_bytes))
            chunk = fh.read()
    except OSError:
        return False, False

    has_ua = has_rlen = False
    for raw in reversed(chunk.split(b"\n")):
        if not raw.strip():
            continue
        m = LINE_RE.match(raw.decode("utf-8", "replace"))
        if not m:
            continue
        has_ua = has_ua or m.group("ua") is not None
        has_rlen = has_rlen or m.group("rlen") is not None
        # 两个都确认了就没必要继续往前翻
        if has_ua and has_rlen:
            break
    return has_ua, has_rlen


def collect(conn, cfg):
    log_path = cfg["paths"]["nginx_log"]
    try:
        st = os.stat(log_path)
    except OSError:
        return 0

    uri_max, req_max, ua_max, methods = _limits(cfg)

    inode = db.meta_get(conn, "log_inode", "0")
    offset = db.meta_get_int(conn, "log_offset", 0)
    if str(st.st_ino) != inode or st.st_size < offset:
        offset = 0  # 轮转或截断

    hits = {}
    paths = {}
    anomaly = {}
    agents = {}
    n = 0
    bad = 0
    saw_rlen = False
    saw_ua = False

    def bump(minute, ip, kind, val=0):
        key = (minute, ip, kind)
        cur = anomaly.get(key)
        if cur:
            cur[0] += 1
            if val > cur[1]:
                cur[1] = val
        else:
            anomaly[key] = [1, val]

    with open(log_path, "rb") as fh:
        fh.seek(offset)
        while True:
            raw = fh.readline()
            # 没有换行结尾说明这行还没写完，留到下一轮再读，避免半行入库
            if not raw or not raw.endswith(b"\n"):
                break
            offset = fh.tell()
            line = raw.decode("utf-8", "replace").rstrip("\n")
            m = LINE_RE.match(line)
            if not m:
                bad += 1
                continue
            ts = parse_ts(m.group("ts"))
            if ts is None:
                bad += 1
                continue

            minute = ts - ts % 60
            ip = m.group("ip")[:64]
            status = int(m.group("status"))
            uri = m.group("path") or "/"
            method = (m.group("method") or "").upper()
            proto = m.group("proto") or ""
            ua = m.group("ua")
            rlen = m.group("rlen")

            # 存储用短路径；判定用原始请求行，否则长 URL 会被截断成"正常长度"
            path = uri[:200] or "/"
            size_s = m.group("size")
            sz = int(size_s) if size_s.isdigit() else 0

            key = (minute, ip, status)
            hits[key] = hits.get(key, 0) + 1

            pkey = (minute, ip, path, status)
            prev = paths.get(pkey)
            # 同一分钟内同一路径可能大小不同（fallback 首页 vs 真实文件），
            # 取最后一次的 sz 做指纹，够用且省事
            paths[pkey] = (prev[0] + 1, sz) if prev else (1, sz)

            # ---- 异常特征 ----
            ulen = len(uri)
            if ulen >= uri_max:
                bump(minute, ip, "long_uri", ulen)
            if rlen:
                saw_rlen = True
                rl = int(rlen)
                if rl >= req_max:
                    bump(minute, ip, "big_req", rl)
            if method not in methods:
                bump(minute, ip, "bad_method")
            if proto not in KNOWN_PROTOS:
                bump(minute, ip, "bad_proto")
            if HONEYPOT.search(uri):
                bump(minute, ip, "honeypot")
            if ua is not None:
                saw_ua = True
                if ua in ("", "-"):
                    bump(minute, ip, "bad_ua")
                elif len(ua) > ua_max or BAD_UA.search(ua):
                    bump(minute, ip, "bad_ua", len(ua))
                # 只留最后一条，每 IP 每分钟一行
                agents[(minute, ip)] = [ua[:UA_KEEP], 1]
            n += 1

    conn.executemany(
        "INSERT INTO hits(ts,ip,status,n) VALUES(?,?,?,?) "
        "ON CONFLICT(ts,ip,status) DO UPDATE SET n=n+excluded.n",
        [(a, b, c, v) for (a, b, c), v in hits.items()],
    )
    conn.executemany(
        "INSERT INTO paths(ts,ip,path,status,sz,n) VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(ts,ip,path,status) DO UPDATE SET n=n+excluded.n, sz=excluded.sz",
        [(a, b, c, d, v[1], v[0]) for (a, b, c, d), v in paths.items()],
    )
    if anomaly:
        conn.executemany(
            "INSERT INTO anomaly(ts,ip,kind,n,vmax) VALUES(?,?,?,?,?) "
            "ON CONFLICT(ts,ip,kind) DO UPDATE SET n=n+excluded.n, "
            "vmax=MAX(vmax,excluded.vmax)",
            [(a, b, c, v[0], v[1]) for (a, b, c), v in anomaly.items()],
        )
    if agents:
        conn.executemany(
            "INSERT INTO agent(ts,ip,ua,n) VALUES(?,?,?,?) "
            "ON CONFLICT(ts,ip) DO UPDATE SET n=n+excluded.n, ua=excluded.ua",
            [(a, b, v[0], v[1]) for (a, b), v in agents.items()],
        )

    # 站点静默时一小时可能一条新行都没有，标记就永远是"缺字段"，
    # 面板会一直显黄字告警。所以没读到新行时用文件末尾样本补一次判定。
    if not saw_ua or not saw_rlen:
        has_ua, has_rlen = _probe_fields(log_path)
        saw_ua = saw_ua or has_ua
        saw_rlen = saw_rlen or has_rlen

    db.meta_set(conn, "log_inode", st.st_ino)
    db.meta_set(conn, "log_offset", offset)
    if saw_rlen and not db.meta_get_int(conn, "log_has_rlen", 0):
        db.meta_set(conn, "log_has_rlen", 1)
    if saw_ua and not db.meta_get_int(conn, "log_has_ua", 0):
        db.meta_set(conn, "log_has_ua", 1)
    if bad:
        db.meta_set(conn, "log_bad_lines",
                    db.meta_get_int(conn, "log_bad_lines", 0) + bad)
    conn.commit()
    return n
