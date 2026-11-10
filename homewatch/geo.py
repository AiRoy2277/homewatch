# -*- coding: utf-8 -*-
"""IP 归属地查询。

为什么要自己缓存一层
--------------------
面板每 15 秒刷一次，如果每次都去查在线接口，一分钟就是 4 次请求，
很快会被免费接口限流。所以归属地只在**采集循环**里补，补完写进
``geo`` 表缓存 ``ttl_days`` 天，渲染时纯读库、零网络请求。

查询顺序
--------
1. 私有 / 保留地址：本地直接判定为"内网"，不查。
2. ``geo.mmdb`` 有配置且装了 maxminddb：查本地库，最快也最稳。
3. ``provider=auto``：走 ipwho.is 单条接口，并发查（每个约 2-3 秒）。
4. ``provider=ipapi``：走 ip-api.com 批量接口，一次最多 100 个 IP。

没把 ip-api 放在 auto 的第一位，是因为它只支持 http，在国内网络里
经常连不上，白等超时。ipwho.is 是 https，实测稳定，还支持中文返回。
任何一步失败都只是"没有归属地"，不影响主流程。
"""

import ipaddress
import json
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .utils import now

IPAPI_BATCH = "http://ip-api.com/batch?lang=zh-CN"
IPWHO_SINGLE = "https://ipwho.is/%s?lang=zh-CN"
UA = "HomeWatch/1.0 (+lan monitor)"
FAIL_TTL = 6 * 3600
WORKERS = 8


def _addr(ip):
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a


def is_public(ip):
    a = _addr(ip)
    return bool(a) and not (
        a.is_private or a.is_loopback or a.is_link_local
        or a.is_reserved or a.is_multicast or a.is_unspecified
    )


# 在线接口返回的港澳台名称不统一（台湾 / Taiwan / 香港 / Hong Kong…），
# 统一按国家代码归一，避免同一个地区在面板上出现两种写法。
REGION_NAME = {"TW": "中国台湾", "HK": "中国香港", "MO": "中国澳门"}


def label_of(rec):
    """一行短描述：日本·东京 / 美国·弗吉尼亚 · Amazon。"""
    if not rec:
        return ""
    if rec.get("status") == "private":
        return "内网"
    cc = (rec.get("cc") or "").upper()
    country = REGION_NAME.get(cc) or rec.get("country")
    city = rec.get("city") or rec.get("region")
    # 归一化之后 "中国香港·Hong Kong" 就重复了，城市和国家同名的直接省掉
    if city and country != rec.get("country") and \
            city.strip().lower() == (rec.get("country") or "").strip().lower():
        city = ""
    parts = []
    region = "·".join(x for x in (country, city) if x)
    if region:
        parts.append(region)
    if rec.get("isp"):
        parts.append(rec["isp"])
    return " · ".join(parts)


# ---------------- 缓存表 ----------------


def _row_to_rec(row):
    return {
        "ip": row[0], "status": row[1] or "ok",
        "country": row[2] or "", "cc": (row[3] or "").upper(),
        "region": row[4] or "", "city": row[5] or "",
        "isp": row[6] or "", "asn": row[7] or "", "ts": row[8] or 0,
    }


def read_cache(conn, ips=None):
    """读缓存，不判断新鲜度。ips=None 表示全读。"""
    sql = ("SELECT ip,status,country,cc,region,city,isp,asn,ts FROM geo")
    args = ()
    if ips is not None:
        ips = [ip for ip in ips if ip]
        if not ips:
            return {}
        sql += " WHERE ip IN (%s)" % ",".join("?" * len(ips))
        args = tuple(ips)
    return {r[0]: _row_to_rec(r) for r in conn.execute(sql, args)}


def _save(conn, rec):
    conn.execute(
        "INSERT INTO geo(ip,status,country,cc,region,city,isp,asn,ts) "
        "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET "
        "status=excluded.status, country=excluded.country, cc=excluded.cc, "
        "region=excluded.region, city=excluded.city, isp=excluded.isp, "
        "asn=excluded.asn, ts=excluded.ts",
        (rec["ip"], rec.get("status", "ok"), rec.get("country", ""),
         (rec.get("cc") or "").upper(), rec.get("region", ""),
         rec.get("city", ""), rec.get("isp", ""), rec.get("asn", ""),
         int(rec.get("ts") or now())),
    )


def _fresh(rec, ttl, at):
    if not rec:
        return False
    age = at - int(rec.get("ts") or 0)
    if rec.get("status") == "fail":
        return age < FAIL_TTL
    return age < ttl


# ---------------- 查询实现 ----------------


def _mmdb_lookup(path, ips):
    try:
        import maxminddb  # type: ignore
    except ImportError:
        return {}
    try:
        reader = maxminddb.open_database(path)
    except (OSError, ValueError):
        return {}
    out = {}
    for ip in ips:
        try:
            d = reader.get(ip) or {}
        except (ValueError, KeyError):
            continue
        if not d:
            continue
        country = (d.get("country") or {}).get("names") or {}
        city = (d.get("city") or {}).get("names") or {}
        subs = d.get("subdivisions") or []
        region = ""
        if subs:
            region = (subs[0].get("names") or {}).get("zh-CN", "")
        out[ip] = {
            "ip": ip, "status": "ok",
            "country": country.get("zh-CN") or country.get("en") or "",
            "cc": (d.get("country") or {}).get("iso_code") or "",
            "region": region,
            "city": city.get("zh-CN") or city.get("en") or "",
            "isp": "", "asn": "", "ts": now(),
        }
    try:
        reader.close()
    except Exception:  # noqa: BLE001
        pass
    return out


def _ipapi_batch(ips, timeout=6):
    body = json.dumps([{"query": ip} for ip in ips]).encode("utf-8")
    req = urllib.request.Request(
        IPAPI_BATCH, data=body,
        headers={"Content-Type": "application/json", "User-Agent": UA},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        arr = json.loads(resp.read().decode("utf-8", "replace"))
    if not isinstance(arr, list):
        return {}

    out = {}
    for item in arr:
        if not isinstance(item, dict):
            continue
        ip = item.get("query") or ""
        if not ip:
            continue
        if item.get("status") != "success":
            out[ip] = {"ip": ip, "status": "fail", "ts": now()}
            continue
        out[ip] = {
            "ip": ip, "status": "ok",
            "country": item.get("country") or "",
            "cc": item.get("countryCode") or "",
            "region": item.get("regionName") or "",
            "city": item.get("city") or "",
            "isp": item.get("isp") or "",
            "asn": (item.get("as") or "").split()[0] if item.get("as") else "",
            "ts": now(),
        }
    return out


def _ipwho_single(ip, timeout=6):
    req = urllib.request.Request(IPWHO_SINGLE % ip, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        d = json.loads(resp.read().decode("utf-8", "replace"))
    if not d.get("success"):
        return {"ip": ip, "status": "fail", "ts": now()}
    conn_info = d.get("connection") or {}
    return {
        "ip": ip, "status": "ok",
        "country": d.get("country") or "",
        "cc": d.get("country_code") or "",
        "region": d.get("region") or "",
        "city": d.get("city") or "",
        "isp": conn_info.get("isp") or conn_info.get("org") or "",
        "asn": (conn_info.get("asn") or ""),
        "ts": now(),
    }


def _ipwho_many(ips):
    """并发查 ipwho.is。串行查 20 个要一分钟，并发 8 路约 10 秒。"""
    out = {}

    def one(ip):
        try:
            return _ipwho_single(ip)
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            return {"ip": ip, "status": "fail", "ts": now()}

    with ThreadPoolExecutor(max_workers=min(WORKERS, max(1, len(ips)))) as pool:
        for rec in pool.map(one, ips):
            out[rec["ip"]] = rec
    return out


def _query(cfg, ips):
    """按 provider 顺序查询，返回 {ip: rec}。"""
    geo_cfg = cfg.get("geo") or {}
    provider = (geo_cfg.get("provider") or "auto").lower()
    if provider == "offline" or not ips:
        return {}

    out = {}
    mmdb = geo_cfg.get("mmdb") or ""
    if provider in ("auto", "mmdb") and mmdb and os.path.exists(mmdb):
        out.update(_mmdb_lookup(mmdb, ips))
        if provider == "mmdb":
            return out
        ips = [ip for ip in ips if ip not in out]
        if not ips:
            return out

    if provider in ("ipapi", "ip-api"):
        try:
            return {**out, **_ipapi_batch(ips, timeout=8)}
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            return out

    out.update(_ipwho_many(ips))
    return out


# ---------------- 对外接口 ----------------


def top_ips(conn, since, limit=60):
    """近一段时间请求最多的 IP，用于决定这一轮补哪些归属地。"""
    rows = conn.execute(
        "SELECT ip FROM hits WHERE ts>=? GROUP BY ip ORDER BY SUM(n) DESC LIMIT ?",
        (since, limit),
    ).fetchall()
    return [r[0] for r in rows if r[0]]


def enrich(conn, cfg, ips=None, force=False, limit=None):
    """补齐一批 IP 的归属地，返回 {ip: rec}。

    ips 为空时取近 24 小时请求量前 60 的 IP。每次最多请求
    ``geo.max_per_run`` 个，避免采集这一轮被网络拖住。
    """
    geo_cfg = cfg.get("geo") or {}
    if not geo_cfg.get("enabled", True):
        return {}

    at = now()
    ttl = int(geo_cfg.get("ttl_days", 30)) * 86400
    limit = int(limit or geo_cfg.get("max_per_run", 20))

    if ips is None:
        ips = top_ips(conn, at - 86400)

    wanted = []
    seen = set()
    for ip in ips:
        if not ip or ip in seen:
            continue
        seen.add(ip)
        wanted.append(ip)

    cache = read_cache(conn, wanted)

    # 私有地址本地判定，不浪费请求
    todo = []
    for ip in wanted:
        if not is_public(ip):
            if ip not in cache:
                _save(conn, {"ip": ip, "status": "private", "ts": at})
                cache[ip] = {"ip": ip, "status": "private", "ts": at}
            continue
        if not force and _fresh(cache.get(ip), ttl, at):
            continue
        todo.append(ip)
    conn.commit()

    if todo:
        got = _query(cfg, todo[:limit])
        for ip, rec in got.items():
            _save(conn, rec)
            cache[ip] = rec
        conn.commit()
        # 没查到的也记一条，避免下一轮立刻重试
        for ip in todo[:limit]:
            if ip not in got:
                rec = {"ip": ip, "status": "fail", "ts": at}
                _save(conn, rec)
                cache[ip] = rec
        conn.commit()

    return {ip: cache[ip] for ip in wanted if ip in cache}


def attach(conn, ips):
    """给列表里的每条记录挂上缓存的归属地，不发网络请求。"""
    cache = read_cache(conn, ips)
    out = {}
    for ip in ips:
        rec = cache.get(ip)
        if rec:
            out[ip] = {
                "country": rec.get("country", ""),
                "cc": rec.get("cc", ""),
                "region": rec.get("region", ""),
                "city": rec.get("city", ""),
                "isp": rec.get("isp", ""),
                "label": label_of(rec),
                "private": rec.get("status") == "private",
            }
    return out
