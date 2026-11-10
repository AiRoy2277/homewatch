# -*- coding: utf-8 -*-
"""SQLite 存取。

表结构刻意做成"分钟级聚合"而不是原始行：
一天的原始日志约 2.7 万行，聚合后只剩几百行，30 天也就几 MB，
而且面板查询不需要做全表扫描。
"""

import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS hits(
    ts INTEGER NOT NULL, ip TEXT NOT NULL, status INTEGER NOT NULL,
    n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(ts, ip, status));

CREATE TABLE IF NOT EXISTS paths(
    ts INTEGER NOT NULL, ip TEXT NOT NULL, path TEXT NOT NULL,
    status INTEGER NOT NULL, sz INTEGER NOT NULL DEFAULT 0,
    n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(ts, ip, path, status));

CREATE TABLE IF NOT EXISTS net(
    ts INTEGER PRIMARY KEY,
    ssh_drop INTEGER, ssl_drop INTEGER, https_drop INTEGER);

CREATE TABLE IF NOT EXISTS sshfail(
    ts INTEGER NOT NULL, ip TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(ts, ip));

-- journal 游标去重表：保证同一条失败记录只计一次
CREATE TABLE IF NOT EXISTS sshseen(c TEXT PRIMARY KEY);

CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);

-- IP 归属地缓存：只在这里落库，渲染时直接读，不在页面请求里发网络请求
CREATE TABLE IF NOT EXISTS geo(
    ip TEXT PRIMARY KEY, status TEXT DEFAULT 'ok',
    country TEXT DEFAULT '', cc TEXT DEFAULT '', region TEXT DEFAULT '',
    city TEXT DEFAULT '', isp TEXT DEFAULT '', asn TEXT DEFAULT '',
    ts INTEGER NOT NULL DEFAULT 0);

-- 封禁流水。state.json 只保留当前有效的封禁，过期就没了；
-- 这张表留着历史，用来算"重复违规"和面板上的封禁记录。
CREATE TABLE IF NOT EXISTS bans(
    ts INTEGER NOT NULL, ip TEXT NOT NULL, hours INTEGER DEFAULT 0,
    layer TEXT DEFAULT '', rule TEXT DEFAULT '', reason TEXT DEFAULT '',
    mode TEXT DEFAULT 'auto', hits INTEGER DEFAULT 0,
    PRIMARY KEY(ts, ip, rule));

-- 异常请求。只在采集时判定一次（超长 URL、超大报文、异常方法/协议/UA、蜜罐路径），
-- 按分钟聚合，不存原始行。vmax 保留该分钟内的最大值，方便以后改判定线时回溯。
CREATE TABLE IF NOT EXISTS anomaly(
    ts INTEGER NOT NULL, ip TEXT NOT NULL, kind TEXT NOT NULL,
    n INTEGER NOT NULL DEFAULT 0, vmax INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(ts, ip, kind));

-- 每个 IP 每分钟最后一条 UA。用途有两个：面板上显示"这是什么客户端"，
-- 以及让 Googlebot 这类可信爬虫不被频率规则误封。
-- 每 IP 每分钟只留一行，避免随机 UA 的扫描器把表撑爆。
CREATE TABLE IF NOT EXISTS agent(
    ts INTEGER NOT NULL, ip TEXT NOT NULL, ua TEXT NOT NULL DEFAULT '',
    n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(ts, ip));

CREATE INDEX IF NOT EXISTS idx_hits_ts ON hits(ts);
CREATE INDEX IF NOT EXISTS idx_paths_ts ON paths(ts);
CREATE INDEX IF NOT EXISTS idx_sshfail_ts ON sshfail(ts);
CREATE INDEX IF NOT EXISTS idx_geo_ts ON geo(ts);
CREATE INDEX IF NOT EXISTS idx_bans_ts ON bans(ts);
CREATE INDEX IF NOT EXISTS idx_bans_ip ON bans(ip);
CREATE INDEX IF NOT EXISTS idx_anomaly_ts ON anomaly(ts);
CREATE INDEX IF NOT EXISTS idx_anomaly_kind ON anomaly(ts, kind);
CREATE INDEX IF NOT EXISTS idx_agent_ts ON agent(ts);
"""


def connect(db_path):
    """打开连接并确保表结构就绪。"""
    d = os.path.dirname(db_path)
    if d:
        os.makedirs(d, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def ensure_net_columns(conn, keys):
    """net 表的丢包列按 watch_ports 的键动态补齐。

    老库已经有 ssh_drop / ssl_drop / https_drop，新增端口时自动 ALTER，
    不需要手工迁移，也不会丢历史。
    """
    have = {r[1] for r in conn.execute("PRAGMA table_info(net)")}
    for k in keys:
        col = "%s_drop" % k
        if col not in have:
            conn.execute("ALTER TABLE net ADD COLUMN %s INTEGER DEFAULT 0" % col)
    conn.commit()


def meta_get(conn, key, default=None):
    row = conn.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
    return row[0] if row else default


def meta_set(conn, key, value):
    conn.execute(
        "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
        (key, str(value)),
    )


def meta_get_int(conn, key, default=0):
    try:
        return int(meta_get(conn, key, default))
    except (TypeError, ValueError):
        return default
