# -*- coding: utf-8 -*-
"""操作审计日志。

每一次写操作都留一条，包含：谁（来源 IP）、做了什么、参数、成功与否、耗时。
**密码类字段在入口处就被抹掉**，不写进日志、不写进响应。
"""

import json
import os
import time
from datetime import datetime

from ..utils import CST

# 这些参数值的真实内容永远不落盘。
# api_token 是 Cloudflare 的长期凭据，进了审计日志等于明文存了一份。
SECRET_KEYS = {"password", "new_password", "confirm", "old_password",
               "api_token", "token", "secret"}

DEFAULT_PATH = "/var/log/homewatch/audit.log"
MAX_READ = 100


def path_for(cfg):
    return (cfg.get("paths") or {}).get("audit_log") or DEFAULT_PATH


def scrub(args):
    out = {}
    for k, v in (args or {}).items():
        if k in SECRET_KEYS:
            out[k] = "***"
        elif isinstance(v, str) and len(v) > 200:
            out[k] = v[:200] + "…"
        else:
            out[k] = v
    return out


def write(cfg, ip, action, args=None, ok=True, msg="", ms=0):
    p = path_for(cfg)
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    entry = {
        "ts": int(time.time()),
        # 服务器时区通常是 UTC，这里统一按北京时间记录，避免看日志时差 8 小时
        "at": datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "action": action,
        "args": scrub(args),
        "ok": bool(ok),
        "msg": msg,
        "ms": int(ms),
    }
    try:
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass
    return entry


def tail(cfg, n=20):
    """读最近 n 条，用于面板展示。"""
    p = path_for(cfg)
    try:
        with open(p, "r", encoding="utf-8") as fh:
            lines = fh.readlines()[-n:]
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return list(reversed(out))
