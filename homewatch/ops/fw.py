# -*- coding: utf-8 -*-
"""防火墙规则表：云厂商控制台那种"有序规则 + 增删改查 + 命中计数"。

和 ``port_ctrl``（端口页）的分工
--------------------------------
``port_ctrl`` 是**按端口**的粗粒度开关，落在主链 input/output 上；
``fw`` 是**按规则**的细粒度表，落在 ``fw_in`` / ``fw_out`` / ``fw_fwd``
三条子链里，主链先 ``jump`` 进去求值，所以：

- 放行规则可以当白名单用：即使某个端口在端口页设成"禁止"，
  命中白名单的源地址仍然能进来（nft 的 accept 是终态判决）；
- 拒绝规则可以做得比端口页更细：指定来源、端口范围、协议；
- 默认策略 = "拒绝"时，只有规则表里放行的新连接能进来，这就是
  云厂商安全组的行为。默认仍是"放行"，升级那一刻行为不变。

数据结构（state["fw"]）::

    {
      "rules": [
        {"id": "fw1a2b", "name": "SSH 仅内网", "dir": "in",
         "proto": "tcp", "port": "22", "src": ["192.168.1.0/24"],
         "action": "accept", "enabled": true, "priority": 10,
         "note": "", "created": 1700000000}
      ],
      "policy": {"in": "accept", "out": "accept"},
      "container": true,       # 入站规则是否同时作用于 forward（容器端口）
      "seq": 0
    }

``src`` 为空表示"任意地址"；出站方向它表示目标地址。
"""

import ipaddress
import json
import re
import secrets
import subprocess
import time

from . import geoblock as geo_ops
from . import state as state_mod

TABLE = "inet filter"
CHAINS = ("fw_in", "fw_out", "fw_fwd")

DIRS = ("in", "out")
PROTOS = ("tcp", "udp", "icmp", "all")
ACTIONS = ("accept", "drop")

DIR_LABEL = {"in": "入站", "out": "出站"}
PROTO_LABEL = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "all": "全部"}
ACTION_LABEL = {"accept": "放行", "drop": "拒绝"}
POLICY_LABEL = {"accept": "放行", "drop": "拒绝"}

MAX_RULES = 200
MAX_SRC = 16

_PORT_RE = re.compile(r"^\s*(\d{1,5})\s*(?:[-~:]\s*(\d{1,5}))?\s*$")


class FwError(ValueError):
    pass


def empty():
    return {"rules": [], "policy": {"in": "accept", "out": "accept"},
            "container": True, "seq": 0}


def normalize_state(state):
    """把 state["fw"] 修成完整结构（老库、手改过的文件都兜住）。"""
    cur = state.get("fw")
    if not isinstance(cur, dict):
        cur = {}
    out = empty()
    rules = cur.get("rules")
    if isinstance(rules, list):
        clean = []
        for i, r in enumerate(rules):
            if not isinstance(r, dict):
                continue
            try:
                item = _normalize_rule(r)
            except FwError:
                continue
            item["id"] = str(r.get("id") or "")[:24] or _new_id()
            item["created"] = int(r.get("created") or 0) or int(time.time())
            item["priority"] = int(r.get("priority") or (i + 1) * 10)
            item["enabled"] = bool(r.get("enabled", True))
            clean.append(item)
        clean.sort(key=lambda x: (x["priority"], x["created"]))
        out["rules"] = clean[:MAX_RULES]
    pol = cur.get("policy") if isinstance(cur.get("policy"), dict) else {}
    for d in DIRS:
        v = str(pol.get(d) or "accept")
        out["policy"][d] = v if v in ("accept", "drop") else "accept"
    if isinstance(cur.get("container"), bool):
        out["container"] = cur["container"]
    try:
        out["seq"] = int(cur.get("seq") or 0)
    except (TypeError, ValueError):
        out["seq"] = 0
    state["fw"] = out
    return out


def _new_id():
    return "fw%04x%s" % (int(time.time()) % 0x10000, secrets.token_hex(2))


def _norm_port(raw):
    """端口：''(全部) / '22' / '8000-8100'。"""
    text = str(raw if raw is not None else "").strip()
    if not text or text in ("*", "any", "all", "全部"):
        return ""
    m = _PORT_RE.match(text)
    if not m:
        raise FwError("端口格式不对，只能是 22、8000-8100 或留空表示全部")
    lo = int(m.group(1))
    hi = int(m.group(2) or lo)
    if not 1 <= lo <= 65535 or not 1 <= hi <= 65535:
        raise FwError("端口超出 1-65535")
    if lo > hi:
        lo, hi = hi, lo
    return str(lo) if lo == hi else "%d-%d" % (lo, hi)


def _norm_src(raw):
    """来源/目标地址列表。支持 IP、CIDR、逗号/空格分隔，空表示任意。"""
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = [x for x in re.split(r"[\s,，;；]+", raw) if x]
    elif isinstance(raw, (list, tuple)):
        parts = []
        for x in raw:
            parts.extend([y for y in re.split(r"[\s,，;；]+", str(x)) if y])
    else:
        raise FwError("地址格式不对")

    out, seen = [], set()
    for p in parts:
        if p in ("any", "*", "0.0.0.0/0", "::/0", "全部", "任意"):
            return []
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            raise FwError("地址 %s 不是合法的 IP 或网段" % p[:40])
        key = str(net)
        if key not in seen:
            seen.add(key)
            out.append(key)
        if len(out) > MAX_SRC:
            raise FwError("一条规则最多 %d 个地址" % MAX_SRC)
    return out


def _normalize_rule(data):
    if not isinstance(data, dict):
        raise FwError("规则格式不对")
    d = str(data.get("dir") or "in").lower()
    if d not in DIRS:
        raise FwError("方向只能是 in / out")

    proto = str(data.get("proto") or "tcp").lower()
    if proto not in PROTOS:
        raise FwError("协议只能是 tcp / udp / icmp / all")

    action = str(data.get("action") or "accept").lower()
    if action not in ACTIONS:
        raise FwError("动作只能是 accept / drop")

    name = str(data.get("name") or "").strip()[:40] or "未命名规则"
    note = str(data.get("note") or "").strip()[:80]
    port = _norm_port(data.get("port"))
    if proto == "icmp":
        port = ""
    src = _norm_src(data.get("src"))
    return {"name": name, "dir": d, "proto": proto, "port": port,
            "src": src, "action": action, "note": note}


# ---------------- 规则合法性 / 锁死保护 ----------------


def _port_span(port):
    if not port:
        return (1, 65535)
    lo, _, hi = str(port).partition("-")
    return int(lo), int(hi or lo)


def covers(port, target):
    lo, hi = _port_span(port)
    return lo <= int(target) <= hi


def _covers_lan(cfg, src):
    """这条规则的来源是否把整个内网（也就是面板的访问来源）都包住了。"""
    if not src:
        return True
    lan = [ipaddress.ip_network(x, strict=False)
           for x in ((cfg.get("firewall") or {}).get("lan_cidrs") or [])
           if x]
    for item in src:
        net = ipaddress.ip_network(item, strict=False)
        for one in lan:
            if net.version != one.version:
                continue
            if net == one or (net.prefixlen < one.prefixlen and net.supernet_of(one)):
                return True
    return False


def check_rule(cfg, st, rule, rid=None):
    """拒绝会把自己锁在外面的规则。

    入站 + 拒绝 + 覆盖面板端口 + 来源包含整个内网（或任意），这一条
    一定会让面板再也打不开；只封某个外部 IP 是合理需求，放行。
    """
    warnings = []
    admin = int(cfg.get("admin_port") or 8088)
    if rule["dir"] == "in" and rule["action"] == "drop":
        if covers(rule["port"], admin) and _covers_lan(cfg, rule["src"]):
            raise FwError(
                "这条规则会连面板端口 %d 一起拒绝，你会再也打不开这个页面。"
                "只封某个具体 IP 可以，或者改用「入站默认拒绝 + 白名单放行」。" % admin)
        if covers(rule["port"], 22):
            warnings.append("规则覆盖了 SSH 端口 22，确认白名单里有你当前的出口地址")
    if rule["dir"] == "out" and rule["action"] == "drop":
        warnings.append("出站拒绝会影响本机访问外部服务（DNS/HTTPS/接口调用）")
    return warnings


def effective_rules(st):
    return [r for r in st.get("fw", {}).get("rules", []) if r.get("enabled")]


def unprotected_listening(cfg, st, ports):
    """默认拒绝时，哪些端口没有任何放行规则。"""
    accepts = [r for r in effective_rules(st)
               if r["dir"] == "in" and r["action"] == "accept"]
    return [p for p in ports
            if not any(covers(r["port"], p) for r in accepts)]


def check_policy(cfg, st, direction):
    """切到"默认拒绝"前的防呆：面板端口必须有白名单放行规则。"""
    if st["fw"]["policy"].get(direction) != "drop":
        return []
    admin = int(cfg.get("admin_port") or 8088)
    accepts = [r for r in effective_rules(st)
               if r["dir"] == "in" and r["action"] == "accept"]
    guarded = [r for r in accepts if covers(r["port"], admin) and r["src"]]
    if not guarded:
        raise FwError(
            "入站默认拒绝之前，先加一条放行面板端口 %d 的白名单规则"
            "（来源填内网网段或你的出口 IP），否则页面立刻打不开。" % admin)
    msgs = []
    try:
        ports = sorted({int(x) for x in (cfg.get("watch_ports") or {}).values()})
    except (TypeError, ValueError):
        ports = []
    if ports:
        missing = unprotected_listening(cfg, st, ports)
        if missing:
            msgs.append("以下监听端口没有放行规则，会被挡住：%s"
                        % "、".join(str(x) for x in missing))
    if direction == "out":
        msgs.append("出站默认拒绝后，本机的 DNS / HTTPS 出站也要单独放行")
    return msgs


# ---------------- 渲染 ----------------

_ADDR = {"in": {"4": "ip saddr", "6": "ip6 saddr"},
         "out": {"4": "ip daddr", "6": "ip6 daddr"}}


def _families(src):
    """按地址族拆开：无地址限制时返回 [(4, None)]，只匹配一次。"""
    if not src:
        return [(4, None)]
    v4 = [x for x in src if ":" not in x]
    v6 = [x for x in src if ":" in x]
    out = []
    if v4:
        out.append((4, v4))
    if v6:
        out.append((6, v6))
    return out


def _proto_heads(rule):
    """返回 [(proto 关键字, 是否需要端口)]。"""
    p = rule["proto"]
    if p == "icmp":
        return [("icmp", False)]
    if p == "all":
        return [("tcp", True), ("udp", True)]
    return [(p, True)]


def rule_lines(rule, indent="        "):
    """把一条规则摊成若干行 nft 规则（按地址族/协议展开）。"""
    lines = []
    for fam, addrs in _families(rule["src"]):
        addr = ""
        if addrs:
            addr = " %s { %s }" % (_ADDR[rule["dir"]][str(fam)], ", ".join(addrs))
        for proto, with_port in _proto_heads(rule):
            if proto == "icmp":
                head = "meta l4proto ipv6-icmp" if fam == 6 else "meta l4proto icmp"
            elif with_port and rule["port"]:
                head = "%s dport %s" % (proto, rule["port"])
            else:
                head = "meta l4proto %s" % proto
            parts = [head + addr]
            if rule["dir"] == "out":
                parts.append('oif != "lo"')
            parts.append("counter")
            parts.append(rule["action"])
            # comment 必须挂在判决之后：nft 里它是规则属性，
            # 写成 counter comment "x" drop 会报 unexpected drop
            parts.append('comment "hw:%s"' % rule["id"])
            lines.append(indent + " ".join(p for p in parts if p))
    return lines


def chains(st, cfg=None):
    """生成三条子链的文本（缩进 4 空格，供 table 块内使用）。"""
    fw = normalize_state(st)
    rules = [r for r in fw["rules"] if r["enabled"]]
    order = lambda x: (x["priority"], x["created"])  # noqa: E731

    def block(name, items):
        out = ["    chain %s {" % name]
        out.extend(items)
        out.append("    }")
        return out

    in_lines = []
    for r in sorted([x for x in rules if x["dir"] == "in"], key=order):
        in_lines.extend(rule_lines(r))
    out_lines = []
    for r in sorted([x for x in rules if x["dir"] == "out"], key=order):
        out_lines.extend(rule_lines(r))

    fwd_lines = []
    if fw.get("container", True):
        for r in sorted([x for x in rules if x["dir"] == "in"], key=order):
            if r["action"] != "drop":
                continue  # 转发链保持 accept，只把显式拒绝落下去
            fwd_lines.extend(rule_lines(r))
    # 地域封锁的入站拒绝也镜像到转发链，容器端口一样进不来
    if cfg:
        fwd_lines.extend(geo_ops.fwd_lines(st, cfg, indent="        "))

    lines = []
    lines += block("fw_in", in_lines)
    lines += block("fw_out", out_lines)
    lines += block("fw_fwd", fwd_lines)
    return lines


def check_generation(st, cfg):
    """生成前最后一道保险：默认拒绝时面板端口必须能被放行。"""
    fw = normalize_state(st)
    if fw["policy"].get("in") != "drop":
        return
    admin = int(cfg.get("admin_port") or 8088)
    accepts = [r for r in effective_rules(st)
               if r["dir"] == "in" and r["action"] == "accept"]
    if not any(covers(r["port"], admin) and r["src"] for r in accepts):
        raise FwError("入站默认拒绝，但没有任何放行面板端口 %d 的白名单规则" % admin)


# ---------------- 读写 / 增删改 ----------------


def _load(cfg):
    st = state_mod.load(cfg)
    normalize_state(st)
    return st


def _apply(cfg, st):
    """写状态 + 重建规则；重建失败就回滚状态，避免下次启动继续炸。"""
    from . import nft as nft_ops

    check_generation(st, cfg)
    before = state_mod.load(cfg)
    state_mod.save(cfg, st)
    try:
        nft_ops.rebuild(st, cfg)
        nft_ops.write_config(st, cfg)
    except Exception:
        try:
            state_mod.save(cfg, before)
        except Exception:  # noqa: BLE001
            pass
        raise


def list_rules(cfg, with_hits=True):
    st = _load(cfg)
    fw = st["fw"]
    hits = counters() if with_hits else {}
    readable = counters_ok() if with_hits else False
    items = []
    for r in sorted(fw["rules"], key=lambda x: (x["priority"], x["created"])):
        item = dict(r)
        item["dir_label"] = DIR_LABEL.get(r["dir"], r["dir"])
        item["proto_label"] = PROTO_LABEL.get(r["proto"], r["proto"])
        item["action_label"] = ACTION_LABEL.get(r["action"], r["action"])
        item["port_label"] = r["port"] or "全部"
        item["src_label"] = "任意" if not r["src"] else (
            r["src"][0] if len(r["src"]) == 1 else "%s 等 %d 个" % (r["src"][0], len(r["src"])))
        hit = hits.get(r["id"]) or {}
        item["hits"] = int(hit.get("packets") or 0)
        item["bytes"] = int(hit.get("bytes") or 0)
        items.append(item)
    return {
        "rules": items,
        "policy": dict(fw["policy"]),
        "container": bool(fw.get("container", True)),
        "counters": readable,
        "max": MAX_RULES,
    }


def add(cfg, data):
    st = _load(cfg)
    rule = _normalize_rule(data)
    if len(st["fw"]["rules"]) >= MAX_RULES:
        raise FwError("规则最多 %d 条" % MAX_RULES)
    rid = _new_id()
    rule["id"] = rid
    rule["created"] = int(time.time())
    rule["enabled"] = bool(data.get("enabled", True))
    prios = [int(r.get("priority") or 0) for r in st["fw"]["rules"]]
    rule["priority"] = (max(prios) + 10) if prios else 10
    warnings = check_rule(cfg, st, rule, rid)
    st["fw"]["rules"].append(rule)
    _apply(cfg, st)
    return {"msg": "已新增规则「%s」" % rule["name"], "id": rid, "warnings": warnings}


def update(cfg, rid, data):
    st = _load(cfg)
    cur = next((r for r in st["fw"]["rules"] if r["id"] == rid), None)
    if not cur:
        raise FwError("规则不存在或已删除")
    rule = _normalize_rule({**cur, **data})
    rule.update({"id": rid, "created": cur["created"],
                 "priority": cur.get("priority", 10),
                 "enabled": bool(data.get("enabled", cur.get("enabled", True)))})
    warnings = check_rule(cfg, st, rule, rid)
    st["fw"]["rules"] = [rule if r["id"] == rid else r for r in st["fw"]["rules"]]
    _apply(cfg, st)
    return {"msg": "已保存规则「%s」" % rule["name"], "id": rid, "warnings": warnings}


def remove(cfg, rid):
    st = _load(cfg)
    cur = next((r for r in st["fw"]["rules"] if r["id"] == rid), None)
    if not cur:
        raise FwError("规则不存在或已删除")
    st["fw"]["rules"] = [r for r in st["fw"]["rules"] if r["id"] != rid]
    _apply(cfg, st)
    return {"msg": "已删除规则「%s」" % cur["name"], "id": rid}


def toggle(cfg, rid, enabled):
    st = _load(cfg)
    cur = next((r for r in st["fw"]["rules"] if r["id"] == rid), None)
    if not cur:
        raise FwError("规则不存在或已删除")
    cur["enabled"] = bool(enabled)
    _apply(cfg, st)
    return {"msg": "%s「%s」" % ("已启用" if enabled else "已停用", cur["name"])}


def move(cfg, rid, delta):
    """上移 / 下移一条规则（和相邻规则换位置后重排优先级）。"""
    st = _load(cfg)
    rules = sorted(st["fw"]["rules"], key=lambda x: (x["priority"], x["created"]))
    idx = next((i for i, r in enumerate(rules) if r["id"] == rid), -1)
    if idx < 0:
        raise FwError("规则不存在或已删除")
    j = idx + (1 if int(delta) > 0 else -1)
    if not 0 <= j < len(rules):
        return {"msg": "已经到%s了" % ("最后" if delta > 0 else "最前")}
    rules.insert(j, rules.pop(idx))
    for i, r in enumerate(rules):
        r["priority"] = (i + 1) * 10
    st["fw"]["rules"] = rules
    _apply(cfg, st)
    return {"msg": "已调整顺序"}


def set_policy(cfg, direction, policy):
    if direction not in DIRS:
        raise FwError("方向只能是 in / out")
    if policy not in ("accept", "drop"):
        raise FwError("默认策略只能是 accept / drop")
    st = _load(cfg)
    st["fw"]["policy"][direction] = policy
    msgs = check_policy(cfg, st, direction) if policy == "drop" else []
    _apply(cfg, st)
    return {"msg": "%s默认策略：%s" % (DIR_LABEL[direction], POLICY_LABEL[policy]),
            "warnings": msgs}


def set_container(cfg, enabled):
    st = _load(cfg)
    st["fw"]["container"] = bool(enabled)
    _apply(cfg, st)
    return {"msg": "入站规则%s作用于容器转发" % ("已" if enabled else "不再")}


def seed_from_ports(cfg):
    """按端口页的出入站类型生成等价的放行规则。

    默认拒绝之前先用它铺一遍，切过去才不会把现有服务全挡掉。
    """
    from . import nft as nft_ops

    st = _load(cfg)
    ctrl = nft_ops.ensure_ctrl(cfg, st)
    lan = [x for x in ((cfg.get("firewall") or {}).get("lan_cidrs") or [])]
    labels = {int(m["port"]): m.get("label") or str(m["port"])
              for m in (cfg.get("managed_ports") or []) if m.get("port")}
    exists = {(r["dir"], r["port"], tuple(r["src"]), r["action"])
              for r in st["fw"]["rules"]}
    added = 0
    prio = max([int(r.get("priority") or 0) for r in st["fw"]["rules"]] or [0])
    for port, item in sorted(ctrl.items(), key=lambda kv: int(kv[0])):
        mode = item.get("in") or "allow"
        if mode == "deny":
            continue
        src = []
        if mode == "cf":
            src = ["cf"]  # 占位，下面换成 CF 网段
        elif mode == "lan":
            src = lan
        if src == ["cf"]:
            cf4 = st.get("cf_ips4") or []
            cf6 = st.get("cf_ips6") or []
            src = list(cf4) + list(cf6)
            if not src:
                continue
        key = ("in", port, tuple(src), "accept")
        if key in exists:
            continue
        prio += 10
        rid = _new_id()
        rule = {"id": rid, "name": "%s（%s）" % (labels.get(int(port), port), port),
                "dir": "in", "proto": item.get("proto") or "tcp",
                "port": port, "src": src, "action": "accept",
                "enabled": True, "priority": prio, "note": "从端口页生成",
                "created": int(time.time())}
        st["fw"]["rules"].append(rule)
        added += 1
    if not added:
        raise FwError("端口页里的端口都已经有对应规则了")
    _apply(cfg, st)
    return {"msg": "已按端口页生成 %d 条放行规则" % added, "added": added}


def _run(args, timeout=8):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def counters_ok():
    """计数器是否读得到（和"有没有命中"是两件事，别混用）。"""
    r = _run(["nft", "-j", "list", "chain", TABLE, CHAINS[0]], timeout=6)
    return bool(r is not None and r.returncode == 0)


def counters():
    """从运行时链里读每条规则的命中包数/字节数。读不到就返回空表。"""
    out = {}
    for chain in CHAINS:
        r = _run(["nft", "-j", "list", "chain", TABLE, chain])
        if r is None or r.returncode != 0:
            continue
        try:
            data = json.loads(r.stdout or "{}")
        except ValueError:
            continue
        for item in data.get("nftables") or []:
            rule = item.get("rule") if isinstance(item, dict) else None
            if not rule:
                continue
            comment = str(rule.get("comment") or "")
            if not comment.startswith("hw:"):
                continue
            rid = comment[3:]
            pk = by = 0
            for expr in rule.get("expr") or []:
                c = expr.get("counter") if isinstance(expr, dict) else None
                if c:
                    pk += int(c.get("packets") or 0)
                    by += int(c.get("bytes") or 0)
            agg = out.setdefault(rid, {"packets": 0, "bytes": 0})
            agg["packets"] += pk
            agg["bytes"] += by
    return out


def preview(cfg):
    """给面板/CLI 看的规则文本（不含主链，便于核对）。"""
    st = _load(cfg)
    return "\n".join(chains(st, cfg))
