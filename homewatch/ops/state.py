# -*- coding: utf-8 -*-
"""运行时状态：端口开关、封禁名单、Cloudflare 网段。

为什么用 JSON 文件而不是直接读 nft：
nft 的集合里带 timeout 的元素，读出来只有"还剩几秒"，
回头重建配置时无法还原原始的封锁时长。用一个文件做单一来源，
重启、重建规则、UI 展示都从这里读，口径一致。

写操作一律"读-改-写"整个文件，并用临时文件 + os.replace 保证原子性。
"""

import json
import os
import time

EMPTY = {
    "denied_ports": [],      # 被显式关闭的端口 [8443]
    # 端口出入站类型 {"7000": {"in": "lan", "out": "allow", "proto": "tcp"}}
    # load() 只保留 EMPTY 里出现过的键，这里漏一个键就等于每次重启都丢配置
    "port_ctrl": {},
    "blocked_ips": [],       # [{"ip":..., "until":..., "reason":..., "added":...}]
    "cf_ips4": [],
    "cf_ips6": [],
    "cf_updated": 0,
    # SSH 端口：ssh_port 是当前值，pending 是"改了还没确认"的保险丝状态
    "ssh_port": 22,
    "ssh_port_pending": None,
    # Cloudflare 边缘规则：{ip: {"id": rule_id, "ts": 创建时间}}
    # 本地留一份是为了解封时能精确删掉自己建的那条，不去碰手工规则
    "cf_rules": {},
    # 防火墙规则表（有序、可增删改）：见 ops/fw.py
    # 同样必须出现在 EMPTY 里，否则 save 后重启就丢
    "fw": {"rules": [], "policy": {"in": "accept", "out": "accept"},
           "container": True, "seq": 0},
    # 地域封锁（境内/境外）：见 ops/geoblock.py。
    # 开关和豁免放这里，国内网段列表在 geo_cn.json（几千条，不塞进状态文件）
    "geo_lock": {"in": {"enabled": False, "scope": "web"},
                 "out": {"enabled": False},
                 "allow": [], "container": True,
                 "updated": 0, "attempted": 0, "source": "",
                 "v4": 0, "v6": 0},
    # 最近一次 CF 操作结果，面板上直接展示，失败原因不用翻日志
    "cf_last": {},
}


def path_for(cfg):
    db = cfg["paths"]["db"]
    return os.path.join(os.path.dirname(db) or ".", "state.json")


def load(cfg):
    p = path_for(cfg)
    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = {}
    out = json.loads(json.dumps(EMPTY))
    out.update({k: v for k, v in data.items() if k in out})
    return out


def save(cfg, state):
    p = path_for(cfg)
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, p)


def purge_expired(state, at=None):
    """清掉已过期的封禁，返回被清掉的那几条。"""
    at = at or int(time.time())
    alive, dead = [], []
    for item in state.get("blocked_ips", []):
        until = int(item.get("until") or 0)
        # until=0 表示永久
        if until and until <= at:
            dead.append(item)
        else:
            alive.append(item)
    state["blocked_ips"] = alive
    return dead


def find_block(state, ip):
    for item in state.get("blocked_ips", []):
        if item.get("ip") == ip:
            return item
    return None
