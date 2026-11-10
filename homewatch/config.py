# -*- coding: utf-8 -*-
"""配置加载。

优先级：环境变量指定的路径 > 默认路径 > 内置默认值。
每次调用都重新读文件，改完配置不用重启服务（下一次 timer 触发即生效）。
"""

import copy
import json
import os

# 内置默认值。生产环境配置放在 /opt/homewatch/config.json，
# 开发时可以用 HOMEWATCH_CONFIG 指向本地文件，或用 HOMEWATCH_ROOT 把
# 所有路径重定向到一个沙箱目录。
DEFAULTS = {
    # 自己家的出口 IP / 内网地址，面板上会标"我的"，泄漏检测也会跳过它们
    "own_ips": [],
    # 近 10 分钟拦截数达到该值判定为"正在被扫描"
    "red_threshold_10m": 50,
    # 近 10 分钟拦截数达到该值判定为"零星探测"
    "yellow_threshold_10m": 1,
    # 明细数据保留天数（net 表只保留最近值，不受影响）
    "retention_days": 30,
    # 被判定为"已拦截"的状态码。444 是静默封禁的返回码（nginx 直接断开），
    # silent_log 打开时它仍会进日志，算进"被拦"才不会被当成 4xx 错误洪水。
    "blocked_status": [402, 403, 444],
    # 面板标题
    "title": "HomeWatch",
    # 面板自身监听端口（关闭它会导致无法访问面板，需要额外警告）
    "admin_port": 8088,
    # 改完 SSH 端口后，多少分钟内没确认就自动回滚（1–120）
    "ssh_confirm_minutes": 15,
    "paths": {
        "nginx_log": "/var/log/nginx/access.log",
        "db": "/var/lib/homewatch/hw.db",
        "out_dir": "/var/www/homewatch",
        "config": "/opt/homewatch/config.json",
        "audit_log": "/var/log/homewatch/audit.log",
        "nginx_blocklist": "/etc/nginx/conf.d/00-blocklist.conf",
        # 站点配置目录：静默封禁需要把站点里的 return 402 换成 444，
        # 并且给 access_log 挂上 if=$blocked_loggable 才能做到不写日志
        "nginx_sites": "/etc/nginx/sites-enabled",
        # 有些站点的写法是 if ($blocked_scanner) { include .../blocked-msg.conf; }，
        # 真正决定回什么码的是这个片段，静默模式改的就是它
        "nginx_reply": "/etc/nginx/snippets/blocked-msg.conf",
        # 面板登录密码（nginx basic auth）。和 root 系统密码是两回事
        "htpasswd": "/etc/nginx/.htpasswd.homewatch",
    },
    # 需要统计 nft 丢包计数的端口，键名会变成 net 表里的 <键>_drop 列
    "watch_ports": {"ssh": "22", "origin": "8443", "panel": "8088"},
    # 端口在面板上的显示名，缺省用键名
    "port_labels": {"ssh": "SSH", "origin": "源站", "panel": "面板"},
    # 面板上可以开关的端口。readonly 的只展示不给按
    "managed_ports": [
        {"port": 22, "label": "SSH", "desc": "远程管理"},
        {"port": 8088, "label": "监控面板", "desc": "本页自身"},
        {"port": 8443, "label": "源站 HTTPS", "desc": "Cloudflare 回源"},
    ],
    # 入站规则。allow：lan 只放行内网、cf 只放行 Cloudflare、any 不限来源
    "firewall": {
        "lan_cidrs": ["192.168.1.0/24"],
        "rules": [
            {"port": 22, "allow": "lan", "name": "SSH"},
            {"port": 8443, "allow": "cf", "name": "源站"},
            {"port": 8088, "allow": "lan", "name": "面板"},
        ],
    },
    # IP 归属地。只在采集循环里请求，结果进 geo 表缓存 ttl_days 天。
    # provider=auto 时优先本地 mmdb，没有就走在线接口；offline 表示只读缓存。
    "geo": {
        "enabled": True,
        "provider": "auto",
        "mmdb": "",
        "max_per_run": 20,
        "ttl_days": 30,
    },
    # 安全策略。规则命中后可以自动封禁，也可以只观察（dry_run）。
    # source 取值：
    #   ssh_fail       SSH 失败登录次数（journald）
    #   http_blocked   被拦截状态码的请求数（402/403）
    #   http_total     该 IP 的全部请求数（高频请求）
    #   http_error     4xx/5xx 响应数（不含已拦截），抓 404 扫描
    #   http_reject    nginx 直接拒掉的超大请求（413/414/431）
    #   distinct_paths 访问过的不重复路径数（爬虫指纹）
    #   sensitive      命中敏感文件特征的路径数
    #   long_uri       URI 长度超过 policy.limits.uri_len 的请求数
    #   big_req        请求行+头+体总字节超过 policy.limits.req_bytes 的次数
    #                  （需要日志里有 $request_length，没配就永远不会命中）
    #   bad_method     非常规请求方法数（TRACE/CONNECT/PROPFIND…）
    #   bad_proto      非 HTTP/1.0、1.1、2 的协议版本数
    #   bad_ua         空 UA、超长 UA 或命中扫描器指纹的请求数
    #   honeypot       命中蜜罐路径的次数（一次就够）
    "policy": {
        "enabled": True,
        # 关闭它只告警不封禁，适合刚上线时观察误报
        "auto_ban": True,
        # 只记录"本来会封谁"，不真的下发规则
        "dry_run": False,
        # 封禁响应方式：
        #   visible     返回 402 + 文案，扫描器能看到"我被封了"
        #   silent      返回 444，连接直接断开，不回任何字节
        #   silent_nolog 同 silent，但被拦请求不写 access.log（最省磁盘）
        "ban_mode": "silent",
        # silent / silent_nolog 之外仍想保留被拦记录时用；false = 该 IP 不再写日志
        "silent_log": True,
        # 单次评估最多封几个，防止误判时一次封掉一大片
        "max_bans_per_run": 3,
        # 自动封禁时长上限（小时）
        "max_hours": 720,
        # 同一 IP 在多少小时内再次触发时，时长翻倍
        "repeat_window_hours": 72,
        # 永不封禁的地址，支持单个 IP 或网段
        "whitelist": [],
        # 采集时的异常判定线。改小更敏感、误报更多；只影响之后的日志。
        "limits": {
            # URI（含查询串）多少字节算"超长"。nginx 默认请求行上限约 8K
            "uri_len": 1024,
            # 请求总字节（请求行 + 头 + 体）超过多少算"超大报文"
            "req_bytes": 65536,
            # UA 超过多少字符算异常。正常浏览器 UA 在 100-160 之间
            "ua_len": 400,
        },
        # 允许的请求方法，其余计入 bad_method。纯静态站不需要 PUT/DELETE
        "allowed_methods": ["GET", "POST", "HEAD", "OPTIONS"],
        # 命中这些 UA 的 IP 不会被**频率类**规则封禁（蜜罐、敏感路径等仍然生效）。
        # 目的是别把 Googlebot 这类爬虫当成 CC 攻击。
        "trusted_bots": [
            "googlebot", "bingbot", "baiduspider", "yandex", "applebot",
            "duckduckbot", "uptimerobot", "pingdom", "statuscake",
        ],
        "rules": [
            # 高置信度：单次命中就足够
            {"id": "honeypot", "name": "蜜罐路径", "enabled": True,
             "source": "honeypot", "window": 3600, "threshold": 1,
             "hours": 72, "layer": "both"},
            {"id": "oversize", "name": "超大请求被拒", "enabled": True,
             "source": "http_reject", "window": 600, "threshold": 1,
             "hours": 24, "layer": "both"},
            {"id": "sensitive_probe", "name": "敏感文件探测", "enabled": True,
             "source": "sensitive", "window": 3600, "threshold": 3,
             "hours": 48, "layer": "both"},
            {"id": "ssh_brute", "name": "SSH 爆破", "enabled": True,
             "source": "ssh_fail", "window": 600, "threshold": 10,
             "hours": 24, "layer": "nft"},
            # 频率类：短时间内打太多
            # 窗口按整分钟对齐（数据是分钟级聚合），120 秒 ≈ 每秒钟 1 个请求
            {"id": "ip_rate", "name": "单 IP 高频请求", "enabled": True,
             "source": "http_total", "window": 120, "threshold": 120,
             "hours": 12, "layer": "both"},
            {"id": "http_flood", "name": "拦截洪水", "enabled": True,
             "source": "http_blocked", "window": 300, "threshold": 120,
             "hours": 6, "layer": "both"},
            {"id": "error_flood", "name": "错误响应洪水", "enabled": True,
             "source": "http_error", "window": 300, "threshold": 200,
             "hours": 6, "layer": "both"},
            {"id": "path_crawl", "name": "路径爬取", "enabled": True,
             "source": "distinct_paths", "window": 300, "threshold": 120,
             "hours": 6, "layer": "both"},
            # 报文特征类
            {"id": "long_uri", "name": "超长 URL", "enabled": True,
             "source": "long_uri", "window": 300, "threshold": 3,
             "hours": 24, "layer": "both"},
            {"id": "big_req", "name": "超大请求报文", "enabled": True,
             "source": "big_req", "window": 300, "threshold": 2,
             "hours": 24, "layer": "both"},
            {"id": "bad_method", "name": "异常请求方法", "enabled": True,
             "source": "bad_method", "window": 300, "threshold": 3,
             "hours": 24, "layer": "both"},
            {"id": "bad_ua", "name": "恶意 User-Agent", "enabled": True,
             "source": "bad_ua", "window": 600, "threshold": 5,
             "hours": 12, "layer": "both"},
            {"id": "bad_proto", "name": "异常协议版本", "enabled": False,
             "source": "bad_proto", "window": 300, "threshold": 5,
             "hours": 12, "layer": "both"},
        ],
    },
    # Cloudflare：把封禁同步到边缘，让请求根本不回源。
    # token 需要 Zone.Firewall 的编辑权限；只填 zone_id 或 zone_name 之一即可。
    "cloudflare": {
        "enabled": False,
        "api_token": "",
        # 账户级 token 的 /user/tokens/verify 会 401，填上账户 ID 才能自检
        "account_id": "",
        "zone_id": "",
        "zone_name": "",
        # 策略自动封禁后同时推到 CF（封禁 IP 在边缘就被挡掉）
        "auto_sync": True,
        # 规则备注前缀，删除时只删带这个前缀的，避免误删手工规则
        "note": "HomeWatch",
        # 单次 API 超时（秒）。CF 不通不能拖住每分钟的采集循环
        "timeout": 8,
    },
}


def _deep_merge(base, override):
    """递归合并，让局部配置只覆盖它关心的键。"""
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def config_path():
    env = os.environ.get("HOMEWATCH_CONFIG")
    if env:
        return env
    return DEFAULTS["paths"]["config"]


def _ensure_rules(cfg):
    """把内置新增的规则补进已有配置。

    配置里已经存在的规则一律不动（哪怕被停用），只有整条被删掉的才补回来。
    这样升级后新检测项默认生效，不用手工去改 config.json；
    不想要某条就在面板上停用，而不是删掉。
    """
    pol = cfg.get("policy")
    if not isinstance(pol, dict):
        return
    rules = pol.get("rules")
    if not isinstance(rules, list):
        pol["rules"] = copy.deepcopy(DEFAULTS["policy"]["rules"])
        return
    have = {r.get("id") for r in rules if isinstance(r, dict)}
    for d in DEFAULTS["policy"]["rules"]:
        if d["id"] not in have:
            rules.append(copy.deepcopy(d))


def load(path=None):
    """读取配置。文件不存在或解析失败时返回内置默认值，不抛异常。"""
    # 用 deepcopy 而不是逐键复制：以后往 DEFAULTS 加新键时不会漏
    cfg = copy.deepcopy(DEFAULTS)
    target = path or config_path()
    try:
        with open(target, "r", encoding="utf-8") as fh:
            cfg = _deep_merge(cfg, json.load(fh))
    except (OSError, ValueError):
        pass

    # HOMEWATCH_ROOT 必须最后应用：它的语义是"把一切重定向到沙箱目录"，
    # 如果放在合并之前，配置文件里的绝对路径会把它覆盖掉。
    root = os.environ.get("HOMEWATCH_ROOT")
    if root:
        cfg["paths"]["db"] = os.path.join(root, "hw.db")
        cfg["paths"]["out_dir"] = os.path.join(root, "www")
    _ensure_rules(cfg)
    _ensure_blocked_status(cfg)
    return cfg


def _ensure_blocked_status(cfg):
    """把 444 补进"已拦截"名单。

    静默封禁回的是 444，如果它不算"被拦"，面板会把这批流量算成
    "4xx 错误洪水"——KPI 和被拦曲线全都错位。这个状态码只有我们自己在用，
    自动补上比让人去改配置可靠。
    """
    codes = cfg.get("blocked_status")
    if not isinstance(codes, list):
        cfg["blocked_status"] = list(DEFAULTS["blocked_status"])
        return
    if 444 not in codes:
        codes.append(444)


def blocked_in_clause(cfg):
    """生成 SQL 的 IN 占位符，避免各处手写 (402,403)。"""
    codes = cfg.get("blocked_status") or [402, 403]
    return "(" + ",".join("?" * len(codes)) + ")", list(codes)


def save(path, cfg):
    """把配置写回磁盘（部署脚本和以后的 Web 配置页会用）。"""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
