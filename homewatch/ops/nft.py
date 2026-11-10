# -*- coding: utf-8 -*-
"""nftables 规则生成与动态集合维护。

设计要点
--------
**用命名集合，而不是每次重写整条链。**
端口开关和 IP 封禁都是往集合里增删元素（``add element`` / ``flush set``），
不重建 table。这样有两个好处：丢包计数器不会每次归零；规则链不会被短暂清空。

**所有 nft 调用都走 ``nft -f -`` 从 stdin 读脚本。**
避免把 ``{ 1.2.3.4 timeout 24h }`` 这种带花括号的语法塞进 argv，
也避免任何 shell 拼接。

**只在集合缺失时才整体重建**（首次部署或表被外部清掉）。
"""

import ipaddress
import re
import subprocess
import time

from . import fw as fw_mod
from . import geoblock as geo_ops
from . import state as state_mod

CONF_PATH = "/etc/nftables.conf"
TABLE = "inet filter"

# 允许引用的来源类型 -> 集合名
ALLOW_SETS = {
    "lan": "lan4",
    "cf": "cf_ips4",
}

# 出入站类型。入站按来源地址限制，出站按目标地址限制。
IN_MODES = ("allow", "lan", "cf", "deny")
OUT_MODES = ("allow", "lan", "deny")
MODE_LABEL = {
    "allow": "全部放行",
    "lan": "仅内网",
    "cf": "仅 Cloudflare",
    "deny": "禁止",
}
PROTO_LABEL = {"tcp": "TCP", "udp": "UDP", "both": "TCP+UDP"}


class NftError(RuntimeError):
    pass


def _default_ctrl(cfg):
    """从旧的 firewall.rules 推出每个端口的出入站类型。

    v0.6 之前只有"开/关"和"允许来源"，没有出站的概念。
    迁移时把 allow 映射成 in=lan/cf/allow，出站一律放行，
    保证升级那一刻的行为和升级前一模一样。
    """
    ctrl = {}
    for item in cfg.get("managed_ports") or []:
        try:
            port = str(int(item.get("port", 0)))
        except (TypeError, ValueError):
            continue
        ctrl[port] = {"in": "allow", "out": "allow", "proto": "tcp"}
    for rule in (cfg.get("firewall") or {}).get("rules") or []:
        try:
            port = str(int(rule["port"]))
        except (KeyError, TypeError, ValueError):
            continue
        allow = rule.get("allow", "lan")
        ctrl.setdefault(port, {"in": "allow", "out": "allow", "proto": "tcp"})
        ctrl[port]["in"] = "allow" if allow == "any" else (
            allow if allow in IN_MODES else "lan")
    return ctrl


def ensure_ctrl(cfg, state):
    """补齐 port_ctrl：老库、新端口、被 denied_ports 关掉的端口都要对上。"""
    cur = state.get("port_ctrl")
    if not isinstance(cur, dict):
        cur = {}
    for port, item in _default_ctrl(cfg).items():
        cur.setdefault(port, item)
    for port in state.get("denied_ports") or []:
        try:
            key = str(int(port))
        except (TypeError, ValueError):
            continue
        entry = cur.setdefault(key, {"in": "allow", "out": "allow", "proto": "tcp"})
        if entry.get("in") != "deny":
            entry["in"] = "deny"
    state["port_ctrl"] = cur
    return cur


def _run(args, text=None, timeout=15):
    try:
        return subprocess.run(
            args, input=text, capture_output=True, text=True, timeout=timeout
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise NftError(str(exc))


def nft_script(script, check=False):
    """执行一段 nft 脚本，失败抛 NftError。"""
    args = ["nft"]
    if check:
        args.append("-c")
    args += ["-f", "-"]
    r = _run(args, text=script)
    if r.returncode != 0:
        raise NftError((r.stderr or r.stdout).strip() or "nft 执行失败")
    return r.stdout


def set_exists(name):
    r = _run(["nft", "list", "set", TABLE, name])
    return r.returncode == 0


def _split_cidrs(cidrs):
    v4, v6 = [], []
    for c in cidrs or []:
        (v6 if ":" in c else v4).append(c)
    return v4, v6


def _elems_line(items, indent="            "):
    if not items:
        return ""
    return ",\n".join(indent + x for x in items)


def render(state, cfg):
    """生成完整的 /etc/nftables.conf 内容。"""
    fw = cfg.get("firewall") or {}
    lan4, lan6 = _split_cidrs(fw.get("lan_cidrs"))
    if not lan4:
        # 没有内网段还生成 "!= @lan4" 的规则，会把所有人（包括自己）全都挡掉
        raise NftError("配置缺少 firewall.lan_cidrs，拒绝生成可能锁死机器的规则")

    cf4 = state.get("cf_ips4") or []
    cf6 = state.get("cf_ips6") or []
    now = int(time.time())
    ctrl = ensure_ctrl(cfg, state)

    # 防呆：有 cf 类型的规则却拿不到 Cloudflare 网段，
    # 生成的 "saddr != @cf_ips4" 会恒真，等于把 8443 整个封死、站点立刻挂掉。
    needs_cf = any((v.get("in") == "cf" or v.get("out") == "cf")
                   for v in ctrl.values())
    if needs_cf and not cf4:
        raise NftError(
            "Cloudflare 网段为空，拒绝生成规则（会导致源站端口被全部丢弃）。"
            "请先运行 firewall refresh-cf")

    # 面板自己的端口一旦禁止入站，就再也进不来了，配置文件里也不允许
    admin_port = str(int(cfg.get("admin_port") or 8088))
    if (ctrl.get(admin_port) or {}).get("in") == "deny":
        raise NftError("面板端口 %s 不允许设为禁止入站（会把自己锁在外面）" % admin_port)

    blocked4 = [e for e in state.get("blocked_ips", []) if ":" not in e["ip"]]
    blocked6 = [e for e in state.get("blocked_ips", []) if ":" in e["ip"]]

    def block_elems(items):
        out = []
        for it in items:
            until = int(it.get("until") or 0)
            if until:
                # nft 的 timeout 是 32 位秒数，8 亿秒（约 25 年）以上会溢出报错
                left = max(1, min(until - now, 365 * 86400))
                out.append("%s timeout %ds" % (it["ip"], left))
            else:
                out.append(it["ip"])
        return out

    lines = [
        "#!/usr/sbin/nft -f",
        "# 由 HomeWatch 生成，请勿手工编辑（下次操作会覆盖）",
        "# 生成时间：%s" % time.strftime("%Y-%m-%d %H:%M:%S"),
        "",
        "add table inet filter",
        "delete table inet filter",
        "",
        "table inet filter {",
        "    set lan4 {",
        "        type ipv4_addr",
        "        flags interval",
        "        elements = {",
        _elems_line(lan4),
        "        }",
        "    }",
        "    set lan6 {",
        "        type ipv6_addr",
        "        flags interval",
    ]
    if lan6:
        lines += ["        elements = {", _elems_line(lan6), "        }"]
    lines += [
        "    }",
        "    set cf_ips4 {",
        "        type ipv4_addr",
        "        flags interval",
    ]
    if cf4:
        lines += ["        elements = {", _elems_line(cf4), "        }"]
    lines += [
        "    }",
        "    set cf_ips6 {",
        "        type ipv6_addr",
        "        flags interval",
    ]
    if cf6:
        lines += ["        elements = {", _elems_line(cf6), "        }"]
    lines += [
        "    }",
        "    set blocked_ips {",
        "        type ipv4_addr",
        "        flags timeout",
    ]
    b4 = block_elems(blocked4)
    if b4:
        lines += ["        elements = {", _elems_line(b4), "        }"]
    lines += [
        "    }",
        "    set blocked_ips6 {",
        "        type ipv6_addr",
        "        flags timeout",
    ]
    b6 = block_elems(blocked6)
    if b6:
        lines += ["        elements = {", _elems_line(b6), "        }"]
    lines += [
        "    }",
        "    set denied_ports {",
        "        type inet_service",
        "        flags interval",
    ]
    dp = [str(p) for p in state.get("denied_ports", [])]
    if dp:
        lines += ["        elements = {", _elems_line(dp), "        }"]
    # 自定义防火墙规则：主链先 jump 进子链求值，命中就是终态判决。
    # 顺序很关键——放在 port_ctrl 的 drop 之前，"白名单放行"才能穿透
    # 已关闭的端口（这正是云厂商安全组的用法）。
    fw_state = fw_mod.normalize_state(state)
    fw_mod.check_generation(state, cfg)
    default_in = fw_state["policy"].get("in", "accept")
    default_out = fw_state["policy"].get("out", "accept")

    # 地域封锁：没有国内网段清单时绝不能生成"非国内即丢弃"的规则
    try:
        geo_ops.check_generation(state, cfg)
    except geo_ops.GeoError as exc:
        raise NftError(str(exc))

    lines += ["    }"]
    # 地域封锁用的四个集合（cn4/cn6/geo_allow4/geo_allow6），未开启时为空。
    # 必须落在 denied_ports 的花括号之外，否则 nft 解析到 set 会报语法错。
    lines += geo_ops.set_lines(state, cfg)
    lines += [
        "",
        "    chain input {",
        "        type filter hook input priority filter; policy accept;",
        '        iif "lo" accept',
        "        ip saddr @blocked_ips counter drop",
        "        ip6 saddr @blocked_ips6 counter drop",
        "        jump fw_in",
    ]
    # 地域拦截放在 jump fw_in 之后：规则表里的「放行」仍能当白名单穿透它
    lines += geo_ops.input_lines(state, cfg)

    # 入站：按来源类型逐端口生成。deny 直接丢，lan/cf 只放行对应网段。
    def _protos(entry):
        p = entry.get("proto") or "tcp"
        return ["tcp", "udp"] if p == "both" else [p]

    for port in sorted(ctrl, key=lambda x: int(x)):
        entry = ctrl[port] or {}
        mode = entry.get("in") or "allow"
        if mode == "allow":
            continue
        for proto in _protos(entry):
            if mode == "deny":
                lines.append("        %s dport %s counter drop" % (proto, port))
            elif mode == "cf":
                lines.append("        %s dport %s ip saddr != @cf_ips4 counter drop"
                             % (proto, port))
                lines.append("        %s dport %s ip6 saddr != @cf_ips6 counter drop"
                             % (proto, port))
            else:
                lines.append("        %s dport %s ip saddr != @lan4 counter drop"
                             % (proto, port))
                lines.append("        %s dport %s ip6 saddr != @lan6 counter drop"
                             % (proto, port))

    # 默认拒绝：已经建立的连接要放行，否则回程包会被自己丢掉
    if default_in == "drop":
        lines += [
            "        ct state established,related counter accept",
            '        counter drop comment "hw:default-deny-in"',
        ]

    lines += [
        "    }",
        "    chain forward {",
        "        type filter hook forward priority filter; policy accept;",
        "        jump fw_fwd",
        "    }",
        "    chain output {",
        "        type filter hook output priority filter; policy accept;",
        "        jump fw_out",
    ]

    # 地域拦截：只挡新连接，已建立的回程包先放行
    lines += geo_ops.output_lines(state, cfg)

    # 出站：按目标地址限制。lo 永远放行，否则本机进程自己就串不起来了。
    for port in sorted(ctrl, key=lambda x: int(x)):
        entry = ctrl[port] or {}
        mode = entry.get("out") or "allow"
        if mode == "allow":
            continue
        for proto in _protos(entry):
            if mode == "deny":
                lines.append('        oif != "lo" %s dport %s counter drop'
                             % (proto, port))
            else:
                lines.append('        oif != "lo" %s dport %s ip daddr != @lan4 '
                             'counter drop' % (proto, port))
                lines.append('        oif != "lo" %s dport %s ip6 daddr != @lan6 '
                             'counter drop' % (proto, port))

    if default_out == "drop":
        lines += [
            "        ct state established,related counter accept",
            '        counter drop comment "hw:default-deny-out"',
        ]

    lines += [
        "    }",
    ]
    lines += fw_mod.chains(state, cfg)
    lines += [
        "}",
        "",
    ]
    return "\n".join(lines)


def write_config(state, cfg):
    """只写文件，不应用。用于让重启后能恢复当前集合内容。"""
    text = render(state, cfg)
    nft_script(text, check=True)  # 语法自检，坏配置绝不落到磁盘
    tmp = CONF_PATH + ".new"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    subprocess.run(["cp", "-a", CONF_PATH, CONF_PATH + ".bak"], check=False)
    subprocess.run(["cp", tmp, CONF_PATH], check=True)
    subprocess.run(["rm", "-f", tmp], check=False)


def rebuild(state, cfg):
    """整体重建 table。首次部署或集合被外部删掉时用。

    注意：重建会把 counter 清零。
    """
    text = render(state, cfg)
    nft_script(text, check=True)
    nft_script(text)
    # 国内网段数以千计，一次 nft 批处理塞不下（内核回 Message too long），
    # 所以重建完再把它们分批灌进 cn4/cn6，最后开闸把地域规则通电。
    if geo_ops.has_lock(state):
        geo_ops.fill(cfg, state)


def sync(state, cfg):
    """把状态同步到运行时集合，并落盘配置。

    正常路径是"清空集合 + 重新填入"，两条命令一次脚本下发，
    避免逐条增删时出现中间态。
    """
    state_mod.purge_expired(state)
    now = int(time.time())

    if not set_exists("denied_ports"):
        rebuild(state, cfg)
        write_config(state, cfg)
        return "rebuilt"

    b4, b6 = [], []
    for it in state.get("blocked_ips", []):
        until = int(it.get("until") or 0)
        spec = it["ip"] if not until else "%s timeout %ds" % (
            it["ip"], max(1, min(until - now, 365 * 86400)))
        (b6 if ":" in it["ip"] else b4).append(spec)

    def body(setname, elems):
        out = ["flush set %s %s" % (TABLE, setname)]
        if elems:
            out.append("add element %s %s { %s }" % (
                TABLE, setname, ", ".join(elems)))
        return out

    script = "\n".join(
        body("denied_ports", [str(p) for p in state.get("denied_ports", [])])
        + body("blocked_ips", b4)
        + body("blocked_ips6", b6)
    ) + "\n"
    nft_script(script)
    # 重启后 /etc/nftables.conf 里 cn4、cn6 是空的（体积太大，开机那一次
    # nft -f 装不下），闸门也就没通电，这里发现没通电就补一次。
    geo_ops.ensure(cfg, state)
    write_config(state, cfg)
    return "synced"


# ---------------- 对外的动作 ----------------


def set_port_ctrl(cfg, port, direction, mode, proto=None):
    """设置端口的入站/出站类型。

    规则结构变了（多一条还是少一条 drop），只刷集合不够，必须重建整表。
    ``nft -f`` 是一次 netlink 事务，"删表 + 建表 + 填规则"要么全成要么全不成，
    不存在中间的空窗期，所以重建是安全的。
    """
    port = int(port)
    if not 1 <= port <= 65535:
        raise NftError("端口超出范围")
    if direction not in ("in", "out"):
        raise NftError("direction 只能是 in / out")
    allowed = IN_MODES if direction == "in" else OUT_MODES
    if mode not in allowed:
        raise NftError("类型只能是 %s" % " / ".join(allowed))
    if proto is not None and proto not in PROTO_LABEL:
        raise NftError("协议只能是 tcp / udp / both")

    if direction == "in" and mode == "deny":
        if port == int(cfg.get("admin_port") or 8088):
            raise NftError("面板端口 %d 不允许设为禁止入站（会把自己锁在外面）" % port)

    st = state_mod.load(cfg)
    ctrl = ensure_ctrl(cfg, st)
    entry = ctrl.setdefault(str(port), {"in": "allow", "out": "allow", "proto": "tcp"})
    if proto:
        entry["proto"] = proto
    entry[direction] = mode

    # denied_ports 只做兼容保留，和 in=deny 保持同步
    denied = set(int(p) for p in st.get("denied_ports") or [])
    if direction == "in":
        if mode == "deny":
            denied.add(port)
        else:
            denied.discard(port)
        st["denied_ports"] = sorted(denied)

    state_mod.save(cfg, st)
    rebuild(st, cfg)
    write_config(st, cfg)
    return st


def set_port(cfg, port, enabled, ports_meta=None):
    """打开或关闭一个端口（兼容旧接口）。enabled=False 表示禁止入站。"""
    return set_port_ctrl(cfg, port, "in", "allow" if enabled else "deny")


def block_many(cfg, items):
    """批量封禁，只同步一次规则集。

    items: [{"ip":..., "hours":..., "reason":..., "rule":...}, ...]
    hours<=0 表示永久。自动策略一次封多个时必须走这里，
    否则每个 IP 都会做一次 full sync，nft 会被刷很多遍。
    """
    st = state_mod.load(cfg)
    at = int(time.time())
    index = {x.get("ip"): x for x in st["blocked_ips"]}

    for it in items or []:
        addr = ipaddress.ip_address(str(it.get("ip", "")).strip())
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        key = str(addr)
        hours = int(it.get("hours") or 0)
        until = at + hours * 3600 if hours > 0 else 0
        reason = str(it.get("reason") or "")[:160]
        rule = str(it.get("rule") or "")[:40]
        auto = bool(it.get("auto"))

        cur = index.get(key)
        if cur:
            cur["until"] = until
            cur["added"] = at
            if reason:
                cur["reason"] = reason
            if rule:
                cur["rule"] = rule
            if auto:
                cur["auto"] = True
        else:
            entry = {"ip": key, "until": until, "reason": reason,
                     "added": at, "auto": auto}
            if rule:
                entry["rule"] = rule
            st["blocked_ips"].append(entry)
            index[key] = entry

    state_mod.save(cfg, st)
    sync(st, cfg)
    return st


def block_ip(cfg, ip, hours=24, reason="", rule=""):
    """封禁一个 IP。hours<=0 表示永久。"""
    return block_many(cfg, [{"ip": ip, "hours": hours,
                             "reason": reason, "rule": rule}])


def unblock_ip(cfg, ip):
    addr = ipaddress.ip_address(ip)
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    key = str(addr)
    st = state_mod.load(cfg)
    before = len(st["blocked_ips"])
    st["blocked_ips"] = [x for x in st["blocked_ips"] if x["ip"] != key]
    if len(st["blocked_ips"]) == before:
        return st, False
    state_mod.save(cfg, st)
    sync(st, cfg)
    return st, True


def refresh_cf(cfg, timeout=12):
    """从 Cloudflare 官方地址刷新回源网段。"""
    import urllib.request

    def fetch(url):
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return [ln.strip() for ln in r.read().decode().splitlines() if ln.strip()]

    try:
        v4 = fetch("https://www.cloudflare.com/ips-v4")
        v6 = fetch("https://www.cloudflare.com/ips-v6")
    except Exception as exc:  # noqa: BLE001
        raise NftError("拉取 Cloudflare 网段失败：%s" % exc)

    if not v4:
        raise NftError("Cloudflare 返回了空的 IPv4 网段列表，已放弃更新")

    st = state_mod.load(cfg)
    st["cf_ips4"] = v4
    st["cf_ips6"] = v6
    st["cf_updated"] = int(time.time())
    state_mod.save(cfg, st)
    sync(st, cfg)
    return st


def read_set_elements(name):
    """读出运行时某个集合的成员。用于从旧配置迁移。"""
    r = _run(["nft", "list", "set", TABLE, name])
    if r.returncode != 0:
        return []
    m = re.search(r"elements\s*=\s*\{(.*?)\}", r.stdout, re.S)
    if not m:
        return []
    out = []
    for part in m.group(1).split(","):
        token = part.strip().split()[0] if part.strip() else ""
        if not token:
            continue
        try:
            ipaddress.ip_network(token, strict=False)
            out.append(token)
        except ValueError:
            continue
    return out


def init_firewall(cfg):
    """首次启用带集合的规则集。

    尽量沿用运行时已有的 Cloudflare 网段，避免重建瞬间把回源放行规则打空。
    拿不到才去网上拉。
    """
    st = state_mod.load(cfg)
    if not st.get("cf_ips4"):
        st["cf_ips4"] = read_set_elements("cf_ips4")
        st["cf_ips6"] = read_set_elements("cf_ips6")
        st["cf_updated"] = int(time.time()) if st["cf_ips4"] else 0
    if not st.get("cf_ips4"):
        return refresh_cf(cfg)

    state_mod.save(cfg, st)
    rebuild(st, cfg)
    write_config(st, cfg)
    return st
