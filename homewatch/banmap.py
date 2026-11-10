# -*- coding: utf-8 -*-
"""封禁状态汇总：给"每个展示 IP 的地方"一个统一的判定。

面板上 IP 出现在十几个位置（来源表、异常抽屉、SSH 爆破、泄漏命中、
封禁名单、IP 档案……）。以前只有 IP 档案自己去查三层，列表里只能看出
"这个 IP 被拦了很多次"，看不出"它现在到底还在不在封禁名单里"。

这里把三层（nft / nginx / Cloudflare）合成一张 ``{ip: {...}}``，
``/api/state``、``/api/range``、``/api/bans`` 都返回同一份，
前端拿到就整站一致：已封禁的显示标签，没封的给一键封禁。

读的是状态文件和 nginx 名单，不发网络请求，也不调 nft。
"""

from .ops import nginx as nginx_ops
from .ops import state as state_mod


def build(cfg, purge=True):
    st = state_mod.load(cfg)
    if purge:
        state_mod.purge_expired(st)

    out = {}

    def slot(ip):
        e = out.get(ip)
        if not e:
            e = {"ip": ip, "nft": False, "nginx": False, "cf": False,
                 "until": 0, "reason": "", "auto": False}
            out[ip] = e
        return e

    for item in st.get("blocked_ips") or []:
        ip = item.get("ip")
        if not ip:
            continue
        e = slot(ip)
        e["nft"] = True
        e["until"] = int(item.get("until") or 0)
        e["reason"] = item.get("reason") or ""
        e["auto"] = bool(item.get("auto"))

    try:
        for ip in nginx_ops.read_ips(cfg):
            if ip:
                slot(ip)["nginx"] = True
    except Exception:  # noqa: BLE001  名单文件读不到不该让整页挂掉
        pass

    for ip in (st.get("cf_rules") or {}):
        if ip:
            slot(ip)["cf"] = True

    for e in out.values():
        layers = [k for k in ("nft", "nginx", "cf") if e[k]]
        e["layers"] = layers
        e["label"] = "、".join({"nft": "nft", "nginx": "nginx",
                                "cf": "Cloudflare"}[k] for k in layers)
    return out


def summary(cfg):
    data = build(cfg)
    return {
        "total": len(data),
        "nft": sum(1 for e in data.values() if e["nft"]),
        "nginx": sum(1 for e in data.values() if e["nginx"]),
        "cf": sum(1 for e in data.values() if e["cf"]),
        "auto": sum(1 for e in data.values() if e["auto"]),
    }
