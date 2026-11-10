# -*- coding: utf-8 -*-
"""地域封锁：按「国内 / 境外」区分，一把开关挡掉境外流量。

为什么用网段清单而不是逐个查归属地
----------------------------------
nft 一次集合查找就能判定，不需要为每个新连接查库；而且出站方向
（目标地址）根本没有现成的归属地查询，只能靠网段。

两个方向分开管
--------------
- ``in``（外来）：境外来源访问本机。可以选作用范围——只挡 Web 端口，
  或者所有端口（含 SSH，等于"任何形式都进不来"）。
- ``out``（对外）：本机主动连境外。默认放行已建立的连接，只挡**新**连接，
  否则回给境外访客的响应包也会被自己丢掉。

数据从哪来
----------
``_SOURCES`` 按顺序试，成功一个就停：官方 APNIC 委派文件在国内网络下
实测 8 秒只下到 3%（4MB 的 HTTP 拉取），所以主源用按国家整理好的纯 CIDR
列表，官方文件留作兜底。拉到之后合并相邻网段（collapse）再落盘，
渲染规则时纯读文件、不联网。

数据落在哪
----------
``<db 目录>/geo_cn.json``：网段列表单独放，不塞进 state.json——
几千条 CIDR 会让"每 15 秒读一次状态"变成反复解析 100KB JSON。
state 里只留计数和更新时间，面板不读文件就能显示。

为什么要分两次下发（踩过的坑）
------------------------------
``nft -f`` 是**一次 netlink 批处理**，整份脚本超过约 64KB，内核直接回
``netlink: Error: Could not process rule: Message too long``。实测：单条
4339 段的脚本 72KB 能过，再加一个 1688 段的 IPv6 集合（合计 104KB）就挂。
所以 6000 多个网段**不可能**写进 /etc/nftables.conf，只能：

1. 建表时只声明空的 cn4 / cn6（文件从 181KB 缩到 5KB）；
2. ``fill()`` 分批 ``add element``（每批 900 段，单条 ~17KB）；
3. 灌完再往闸门集合 geo_on4 / geo_on6 里塞 ``0.0.0.0/0``，规则一次性通电。

闸门空着的时候 ``ip saddr @geo_on4`` 谁都不匹配，规则等于不存在——所以
中途失败最坏只是"封锁没生效"，不会把自己人全挡在外面。开机时 nftables
读到的也是闸门空着的配置，第一次采集（``geoblock.ensure``）会把网段补回去。
"""

import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.request

from . import state as state_mod

UA = "HomeWatch/0.8 (+lan monitor)"
MAX_ALLOW = 64
SCOPES = ("web", "all")
SCOPE_LABEL = {"web": "只挡 Web 端口", "all": "所有端口（含 SSH）"}

# (名字, IPv4 地址列表, IPv6 地址列表)。按顺序尝试，第一个成功的就用。
_SOURCES = [
    ("clang.cn",
     ["https://ispip.clang.cn/all_cn.txt"],
     ["https://ispip.clang.cn/all_cn_ipv6.txt"]),
    ("ipdeny",
     ["https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone"],
     ["https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone"]),
]
APNIC_URL = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"


class GeoError(ValueError):
    pass


# ---------------- 状态 ----------------


def empty():
    return {
        "in": {"enabled": False, "scope": "web"},
        "out": {"enabled": False},
        # 额外豁免的地址（内网 / 我的 IP / Cloudflare / DNS 由渲染时自动并入）
        "allow": [],
        # 入站规则是否同时作用于容器转发（forward 链）
        "container": True,
        # 国内网段清单的元信息（列表本身在 geo_cn.json）
        "updated": 0, "attempted": 0, "source": "",
        "v4": 0, "v6": 0,
    }


def normalize_state(state):
    """把 state["geo_lock"] 修成完整结构，老库/手改文件都兜住。"""
    cur = state.get("geo_lock")
    if not isinstance(cur, dict):
        cur = {}
    out = empty()

    for d in ("in", "out"):
        src = cur.get(d) if isinstance(cur.get(d), dict) else {}
        out[d]["enabled"] = bool(src.get("enabled", out[d]["enabled"]))
        if d == "in":
            scope = str(src.get("scope") or "web").lower()
            out["in"]["scope"] = scope if scope in SCOPES else "web"

    allow = cur.get("allow")
    if isinstance(allow, list):
        clean = []
        for item in allow:
            try:
                net = ipaddress.ip_network(str(item).strip(), strict=False)
            except ValueError:
                continue
            key = str(net)
            if key not in clean:
                clean.append(key)
        out["allow"] = clean[:MAX_ALLOW]

    if isinstance(cur.get("container"), bool):
        out["container"] = cur["container"]

    for key in ("updated", "attempted", "v4", "v6"):
        try:
            out[key] = int(cur.get(key) or 0)
        except (TypeError, ValueError):
            out[key] = 0
    out["source"] = str(cur.get("source") or "")[:24]
    state["geo_lock"] = out
    return out


# ---------------- 国内网段清单 ----------------


def cn_path(cfg):
    db = ((cfg.get("paths") or {}).get("db") or "/var/lib/homewatch/hw.db")
    return os.path.join(os.path.dirname(db) or ".", "geo_cn.json")


def load_cn(cfg):
    """读国内网段清单。文件坏了当作没有，不让整页 500。"""
    try:
        with open(cn_path(cfg), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {"v4": [], "v6": [], "updated": 0, "source": ""}
    out = {"v4": [], "v6": [], "updated": 0, "source": ""}
    if isinstance(data, dict):
        for key in ("v4", "v6"):
            vals = data.get(key)
            if isinstance(vals, list):
                out[key] = [x for x in vals if isinstance(x, str) and x][:20000]
        try:
            out["updated"] = int(data.get("updated") or 0)
        except (TypeError, ValueError):
            out["updated"] = 0
        out["source"] = str(data.get("source") or "")[:24]
    return out


def save_cn(cfg, v4, v6, source):
    p = cn_path(cfg)
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"source": source, "updated": int(time.time()),
                   "v4": v4, "v6": v6}, fh, separators=(",", ":"))
        fh.write("\n")
    os.replace(tmp, p)
    return p


_CIDR_RE = re.compile(r"^[0-9a-fA-F:.]+/\d{1,3}$")


def parse_cidrs(text):
    """从纯 CIDR 列表里取出 (v4, v6)，合并相邻网段。

    允许行尾注释、空行、以及文件里混进说明文字——不是 CIDR 的行直接跳过。
    """
    nets = []
    for line in str(text or "").splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        token = line.split()[0].strip(",")
        if not _CIDR_RE.match(token):
            continue
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    return _collapse(nets)


def parse_apnic(text):
    """解析 APNIC 委派文件里 ``apnic|CN|ipv4|1.0.1.0|256|...`` 这种行。"""
    nets = []
    for line in str(text or "").splitlines():
        parts = line.split("|")
        if len(parts) < 5 or parts[1] != "CN":
            continue
        kind, addr, count = parts[2], parts[3], parts[4]
        try:
            if kind == "ipv4":
                size = int(count)
                if size <= 0:
                    continue
                base = int(ipaddress.IPv4Address(addr))
                nets.extend(ipaddress.summarize_address_range(
                    ipaddress.IPv4Address(base),
                    ipaddress.IPv4Address(base + size - 1)))
            elif kind == "ipv6":
                nets.append(ipaddress.ip_network("%s/%s" % (addr, count), strict=False))
        except (ValueError, TypeError):
            continue
    return _collapse(nets)


def _collapse(nets):
    v4 = sorted({n for n in nets if n.version == 4})
    v6 = sorted({n for n in nets if n.version == 6})
    try:
        v4 = list(ipaddress.collapse_addresses(v4))
    except (TypeError, ValueError):
        pass
    try:
        v6 = list(ipaddress.collapse_addresses(v6))
    except (TypeError, ValueError):
        pass
    return [str(n) for n in v4], [str(n) for n in v6]


def _fetch(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def refresh_cn(cfg, timeout=12):
    """联网拉一次国内网段。所有源都失败时抛 GeoError，已存的清单不动。"""
    st = _load(cfg)
    g = st["geo_lock"]
    g["attempted"] = int(time.time())
    errors = []

    for name, v4_urls, v6_urls in _SOURCES:
        v4, v6 = [], []
        try:
            for u in v4_urls:
                v4 = parse_cidrs(_fetch(u, timeout))[0]
                if v4:
                    break
        except (urllib.error.URLError, OSError, ValueError) as exc:
            errors.append("%s v4: %s" % (name, str(exc)[:60]))
        try:
            for u in v6_urls:
                v6 = parse_cidrs(_fetch(u, timeout))[1]
                if v6:
                    break
        except (urllib.error.URLError, OSError, ValueError) as exc:
            errors.append("%s v6: %s" % (name, str(exc)[:60]))

        if not v4:
            continue
        save_cn(cfg, v4, v6, name)
        g["updated"] = int(time.time())
        g["source"] = name
        g["v4"] = len(v4)
        g["v6"] = len(v6)
        state_mod.save(cfg, st)
        return {"msg": "已更新国内网段：IPv4 %d 段 / IPv6 %d 段（来源 %s）"
                       % (len(v4), len(v6), name),
                "source": name, "v4": len(v4), "v6": len(v6)}

    state_mod.save(cfg, st)
    raise GeoError("拉取国内网段失败：%s" % ("；".join(errors[:3]) or "所有源都没返回数据"))


def maybe_refresh(cfg, days=14, retry_hours=6):
    """采集循环里顺手续期。只在开启/临近过期时联网，失败不抛。"""
    st = _load(cfg)
    g = st["geo_lock"]
    if not (g["in"]["enabled"] or g["out"]["enabled"]):
        return None
    at = int(time.time())
    if g["updated"] and at - g["updated"] < days * 86400:
        return None
    if g["attempted"] and at - g["attempted"] < retry_hours * 3600:
        return None
    try:
        return refresh_cn(cfg)
    except (GeoError, OSError):
        return None


# ---------------- 豁免清单 ----------------


def _norm(net):
    try:
        return str(ipaddress.ip_network(str(net).strip(), strict=False))
    except ValueError:
        return ""


def dns_servers(path="/etc/resolv.conf"):
    """本机 DNS。出站封锁最容易踩的坑就是把解析器一起挡了。"""
    out = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    key = _norm(parts[1])
                    if key and key not in out:
                        out.append(key)
    except OSError:
        pass
    return out


def exemptions(cfg, st=None):
    """渲染和界面共用的一份"谁不受地域封锁影响"。"""
    st = st or _load(cfg)
    g = st["geo_lock"]
    lan = [_norm(x) for x in ((cfg.get("firewall") or {}).get("lan_cidrs") or [])]
    own = [_norm(x) for x in (cfg.get("own_ips") or [])]
    cf = [_norm(x) for x in (st.get("cf_ips4") or []) + (st.get("cf_ips6") or [])]
    allow = list(g.get("allow") or [])
    dns = dns_servers()
    return {"lan": [x for x in lan if x],
            "own": [x for x in own if x],
            "cf": [x for x in cf if x],
            "dns": dns,
            "allow": allow}


def _allow_sets(cfg, st):
    """豁免集合的最终形态：合并成不重叠的最小网段。

    两个坑必须在这里一次性解决：
    1. nft 的 ``flags interval`` 集合不接受互相重叠的元素
       ——"自己的 IP 192.168.1.50/32"本来就落在内网段 192.168.1.0/24 里，
       直接列出来会报 ``conflicting intervals specified``，整份规则都加载失败；
    2. 相邻的段（……/24 与下一个 /24）合并后集合更小，nft 启动更快。
    所以这里统一 collapse 一遍，展示用的分组信息仍然留在 exemptions() 里。
    """
    ex = exemptions(cfg, st)
    v4, v6 = [], []
    for key in ("lan", "own", "cf", "dns", "allow"):
        for item in ex[key]:
            (v6 if ":" in item else v4).append(item)

    def nets(items):
        out = []
        for x in items:
            try:
                out.append(ipaddress.ip_network(x, strict=False))
            except (TypeError, ValueError):
                continue
        return out

    a4, _ = _collapse(nets(v4))
    _, a6 = _collapse(nets(v6))
    return a4, a6, ex


# ---------------- 渲染 ----------------


def web_ports(cfg, st):
    """「只挡 Web 端口」到底挡哪些：80/443 + 面板端口 + 对公网开放过的端口。

    SSH 端口永远不算 Web，否则"只挡 Web"会把远程管理一起断掉。
    """
    from . import nft as nft_ops

    ssh = {22}
    try:
        ssh.add(int(st.get("ssh_port") or 22))
    except (TypeError, ValueError):
        pass
    ports = {80, 443, int(cfg.get("admin_port") or 8088)}
    try:
        ctrl = nft_ops.ensure_ctrl(cfg, st)
    except Exception:  # noqa: BLE001  端口表异常不该让规则生成失败
        ctrl = {}
    for port, item in (ctrl or {}).items():
        if (item or {}).get("in") in ("allow", "cf"):
            try:
                num = int(port)
            except (TypeError, ValueError):
                continue
            if num in ssh:
                continue
            ports.add(num)
    return sorted(p for p in ports if 1 <= p <= 65535)


def _elements(items, indent="            "):
    return ",\n".join(indent + x for x in items)


def set_lines(st, cfg):
    """地域封锁要用的集合声明。cn4 / cn6 只建壳，元素由 fill() 分批灌。

    为什么不能把国内网段直接写进 nft 文件：``nft -f`` 是**一次 netlink 批处理**，
    整份脚本超过约 64KB 内核就回 ``Message too long``，而 4000 多个网段光元素
    就有 100KB 出头，必然超。所以：
      * cn4 / cn6        —— 空集合，之后用 ``add element`` 分批填；
      * geo_on4/geo_on6  —— 闸门。空着的时候规则完全不匹配（等于没开），
                            网段灌完再塞 0.0.0.0/0 / ::/0 进去，一次性通电。
    这样即使中途失败，最坏结果只是"地域封锁没生效"，而不是把自己人全挡在外面。
    """
    g = normalize_state(st)
    if not (g["in"]["enabled"] or g["out"]["enabled"]):
        return []
    cn = load_cn(cfg)
    allow4, allow6, _ex = _allow_sets(cfg, st)

    lines = []
    for fam, kind, items, allow in ((4, "ipv4_addr", cn["v4"], allow4),
                                    (6, "ipv6_addr", cn["v6"], allow6)):
        if not items:
            continue
        lines += ["    set cn%d {" % fam,
                  "        type %s" % kind,
                  "        flags interval",
                  "    }"]
        lines += ["    set geo_on%d {" % fam,
                  "        type %s" % kind,
                  "        flags interval",
                  "    }"]
        if allow:
            lines += ["    set geo_allow%d {" % fam,
                      "        type %s" % kind,
                      "        flags interval",
                      "        elements = {",
                      _elements(allow),
                      "        }",
                      "    }"]
    return lines


CHUNK = 900  # 单条 nft 脚本里塞多少网段；900 * ~30 字节，离 64KB 很安全


def _chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def fill_lines(st, cfg, chunk=CHUNK):
    """把国内网段分批灌进 cn4 / cn6，最后开闸。返回一串 nft 脚本。"""
    g = normalize_state(st)
    if not (g["in"]["enabled"] or g["out"]["enabled"]):
        return []
    from .nft import TABLE

    cn = load_cn(cfg)
    out = []
    # 先关闸：重新灌的时候不能让"集合半空"的瞬间把正常流量丢掉
    for fam in (4, 6):
        out.append("flush set %s geo_on%d\n" % (TABLE, fam))
    for fam, items in ((4, cn["v4"]), (6, cn["v6"])):
        if not items:
            continue
        out.append("flush set %s cn%d\n" % (TABLE, fam))
        for part in _chunks(items, chunk):
            out.append("add element %s cn%d { %s }\n"
                       % (TABLE, fam, ", ".join(part)))
    # 最后开闸：一条命令，原子生效
    for fam, gate in ((4, "0.0.0.0/0"), (6, "::/0")):
        if cn["v4"] if fam == 4 else cn["v6"]:
            out.append("add element %s geo_on%d { %s }\n" % (TABLE, fam, gate))
    return out


def has_lock(st):
    """地域封锁是否处于开启状态（任一方向）。"""
    g = normalize_state(st)
    return bool(g["in"]["enabled"] or g["out"]["enabled"])


def gate_open(cfg):
    """闸门是否已经通电（闸门集合里有 0.0.0.0/0）。表不在 / nft 不可用都算没开。"""
    from . import nft as nft_ops

    for fam, gate in ((4, "0.0.0.0/0"), (6, "::/0")):
        try:
            r = nft_ops._run(["nft", "list", "set", nft_ops.TABLE,
                              "geo_on%d" % fam])
        except nft_ops.NftError:
            return False
        if r.returncode == 0 and gate in (r.stdout or ""):
            return True
    return False


def fill(cfg, st=None):
    """真正下发生效：空表 / 刚重建 / 重启之后都靠它把网段补回去。"""
    from . import nft as nft_ops

    scripts = fill_lines(st or _load(cfg), cfg)
    if not scripts:
        return False
    for s in scripts:
        nft_ops.nft_script(s)
    return True


def ensure(cfg, st=None):
    """地域封锁开着，但闸门没通电（重启、集合被清、上次灌一半失败）就补一次。"""
    g = normalize_state(st or _load(cfg))
    if not (g["in"]["enabled"] or g["out"]["enabled"]):
        return False
    from . import nft as nft_ops

    if not nft_ops.set_exists("cn4") and not nft_ops.set_exists("cn6"):
        return False  # 表还没建，等 rebuild
    if gate_open(cfg):
        return False
    return fill(cfg)


def _match(fam, cn_items, allow_items, direction):
    """拼出「闸门开着 + 既不在国内网段、也不在豁免里」的条件。

    某一侧没有成员时就不再写那个集合——引用一个空集合会让规则恒真，
    反过来又会让 nft 找不到集合名，不如干脆不写。
    """
    prop = "saddr" if direction == "in" else "daddr"
    head = "ip " if fam == 4 else "ip6 "
    parts = ["%ssaddr @geo_on%d" % (head, fam)]  # 闸门：没通电时整条规则不匹配
    if cn_items:
        parts.append("%s%s != @cn%d" % (head, prop, fam))
    if allow_items:
        parts.append("%s%s != @geo_allow%d" % (head, prop, fam))
    return " ".join(parts)


def _hook_lines(g, cn, cfg, st, direction, indent):
    """入站/出站的核心判定。IPv6 没有清单时不生成规则（不能全丢 v6）。"""
    allow4, allow6, _ex = _allow_sets(cfg, st)
    scope = g["in"]["scope"] if direction == "in" else "all"

    heads = [""]
    if direction == "in" and scope == "web":
        pset = ", ".join(str(p) for p in web_ports(cfg, st))
        heads = ["tcp dport { %s } " % pset, "udp dport { %s } " % pset]
    extra = 'oif != "lo" ' if direction == "out" else ""
    label = "in" if direction == "in" else "out"

    out = []
    for head in heads:
        for fam, cn_items, allow_items in ((4, cn["v4"], allow4),
                                           (6, cn["v6"], allow6)):
            if not cn_items:
                continue
            cond = _match(fam, cn_items, allow_items, direction)
            out.append('%s%s%s%s counter drop comment "hw:geo-%s"'
                       % (indent, head, extra, cond, label))
    return out


def input_lines(st, cfg, indent="        "):
    """入站拒绝。放在 jump fw_in 之后，规则表里的「放行」仍能穿透当白名单。"""
    g = normalize_state(st)
    if not g["in"]["enabled"]:
        return []
    cn = load_cn(cfg)
    if not cn["v4"] and not cn["v6"]:
        raise GeoError("国内网段清单是空的，先刷新国内网段再开地域封锁")
    return _hook_lines(g, cn, cfg, st, "in", indent)


def output_lines(st, cfg, indent="        "):
    """出站拒绝。已建立的连接先放行，否则回给境外访客的响应包会被丢掉。"""
    g = normalize_state(st)
    if not g["out"]["enabled"]:
        return []
    cn = load_cn(cfg)
    if not cn["v4"] and not cn["v6"]:
        raise GeoError("国内网段清单是空的，先刷新国内网段再开地域封锁")
    lines = ['%sct state established,related counter accept comment "hw:geo-out-est"'
             % indent]
    return lines + _hook_lines(g, cn, cfg, st, "out", indent)


def fwd_lines(st, cfg, indent="        "):
    """转发链（容器）：入站封锁顺手镜像过去，容器端口一样进不来。"""
    g = normalize_state(st)
    if not (g["in"]["enabled"] and g["container"]):
        return []
    return input_lines(st, cfg, indent=indent)


def check_generation(st, cfg):
    """生成前最后一道保险。"""
    g = normalize_state(st)
    if not (g["in"]["enabled"] or g["out"]["enabled"]):
        return
    cn = load_cn(cfg)
    if not cn["v4"] and not cn["v6"]:
        raise GeoError("地域封锁已开启但国内网段清单为空，拒绝生成规则"
                       "（否则会把所有地址都挡掉）")


# ---------------- 读写 ----------------


def _load(cfg):
    st = state_mod.load(cfg)
    normalize_state(st)
    return st


def _apply(cfg, st):
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


def _in_cn(cn, ip):
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    for item in (cn["v6"] if addr.version == 6 else cn["v4"]):
        try:
            if addr in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False


def _exempt(cfg, st, ip):
    ex = exemptions(cfg, st)
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    for item in ex["lan"] + ex["own"] + ex["allow"]:
        try:
            if addr in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False


def _guard_client(cfg, st, client):
    """别把当前访问面板的自己挡在外面。

    ctx.ip 是 nginx 传过来的真实来源；本地 CLI/套接字情况下是 "local"，
    这时不做判断。
    """
    ip = str(client or "").strip()
    if not ip or ip in ("local", "-", "unix"):
        return
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return
    if not addr.is_global:
        return
    if _exempt(cfg, st, ip):
        return
    if _in_cn(load_cn(cfg), ip):
        return
    raise GeoError(
        "你当前用的是境外地址 %s，开「外来」封锁会把面板本身一起挡掉。"
        "先把你的出口 IP 加进「自定义放行」，或者到服务器上用 "
        "hw.py geo lock in --on 执行。" % ip)


def _out_warnings(cfg):
    out = ["出站封锁会影响本机主动连境外的服务：apt / pip 更新、"
           "Let's Encrypt 证书续期、时钟同步、以及 app 里调用的境外 API。"]
    if (cfg.get("cloudflare") or {}).get("enabled"):
        out.append("Cloudflare API 在境外，开启后边缘规则同步会失败——"
                   "要么把它加进放行，要么先关自动同步。")
    if ((cfg.get("geo") or {}).get("provider") or "auto") != "offline":
        out.append("IP 归属地查询接口在境外，开启后新 IP 的归属地会补不上（缓存里的仍可显示）。")
    return out


def set_lock(cfg, direction, enabled, scope=None, client=None, force=False):
    if direction not in ("in", "out"):
        raise GeoError("方向只能是 in / out")
    st = _load(cfg)
    g = st["geo_lock"]
    warnings = []

    if enabled:
        cn = load_cn(cfg)
        if not cn["v4"] and not cn["v6"]:
            raise GeoError("还没有国内网段清单，先点「刷新国内网段」再开")
        if direction == "in":
            if scope:
                if scope not in SCOPES:
                    raise GeoError("范围只能是 web / all")
                g["in"]["scope"] = scope
            if not force:
                _guard_client(cfg, st, client)
            if g["in"]["scope"] == "all":
                warnings.append("范围是「所有端口」，SSH 也一并挡；"
                                "确认内网和自定义放行里有你当前的地址。")
        else:
            warnings.extend(_out_warnings(cfg))

    g[direction]["enabled"] = bool(enabled)
    _apply(cfg, st)
    if direction == "in":
        msg = "境外访问拦截：%s（%s）" % (
            "已开启" if enabled else "已关闭", SCOPE_LABEL.get(g["in"]["scope"], ""))
    else:
        msg = "境外出站拦截：%s" % ("已开启" if enabled else "已关闭")
    return {"msg": msg, "warnings": warnings, "geo_lock": status(cfg)}


def set_scope(cfg, scope):
    if scope not in SCOPES:
        raise GeoError("范围只能是 web / all")
    st = _load(cfg)
    st["geo_lock"]["in"]["scope"] = scope
    _apply(cfg, st)
    return {"msg": "拦截范围：%s" % SCOPE_LABEL[scope], "geo_lock": status(cfg)}


def set_container(cfg, enabled):
    st = _load(cfg)
    st["geo_lock"]["container"] = bool(enabled)
    _apply(cfg, st)
    return {"msg": "容器转发%s受境外拦截影响" % ("也" if enabled else "不再"),
            "geo_lock": status(cfg)}


def set_allow(cfg, op, raw):
    if op not in ("add", "remove"):
        raise GeoError("op 只能是 add / remove")
    key = _norm(raw)
    if not key:
        raise GeoError("不是合法的 IP 或网段")
    st = _load(cfg)
    allow = list(st["geo_lock"]["allow"])
    if op == "add":
        if key in allow:
            return {"msg": "%s 已经在放行清单里" % key, "geo_lock": status(cfg)}
        if len(allow) >= MAX_ALLOW:
            raise GeoError("自定义放行最多 %d 条" % MAX_ALLOW)
        allow.append(key)
    else:
        if key not in allow:
            return {"msg": "%s 不在放行清单里" % key, "geo_lock": status(cfg)}
        allow = [x for x in allow if x != key]
    st["geo_lock"]["allow"] = allow
    _apply(cfg, st)
    return {"msg": "自定义放行已%s %s（%d 条）" % (
        "加入" if op == "add" else "移除", key, len(allow)),
        "geo_lock": status(cfg)}


# ---------------- 读数 ----------------


def _run(args, timeout=8):
    import subprocess
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


_COUNTER_CACHE = {"at": 0, "ok": False, "data": None}
_COUNTER_TTL = 2


def counters():
    """读地域规则的命中包数/字节数。读不到返回 (False, {})。

    面板每 15 秒轮询一次、状态接口还有自己的 3 秒缓存，
    这里再加 2 秒短缓存，避免同一轮刷新里重复 fork nft。
    """
    at = int(time.time())
    if _COUNTER_CACHE["data"] is not None and at - _COUNTER_CACHE["at"] < _COUNTER_TTL:
        return _COUNTER_CACHE["ok"], _COUNTER_CACHE["data"]

    out = {"in": {"packets": 0, "bytes": 0}, "out": {"packets": 0, "bytes": 0}}
    ok = False
    for chain in ("input", "forward", "output"):
        r = _run(["nft", "-j", "list", "chain", "inet filter", chain])
        if r is None or r.returncode != 0:
            continue
        ok = True
        try:
            data = json.loads(r.stdout or "{}")
        except ValueError:
            continue
        for item in data.get("nftables") or []:
            rule = item.get("rule") if isinstance(item, dict) else None
            if not rule:
                continue
            comment = str(rule.get("comment") or "")
            if not comment.startswith("hw:geo-") or comment.endswith("-est"):
                continue
            key = "out" if comment.endswith("out") else "in"
            for expr in rule.get("expr") or []:
                c = expr.get("counter") if isinstance(expr, dict) else None
                if c:
                    out[key]["packets"] += int(c.get("packets") or 0)
                    out[key]["bytes"] += int(c.get("bytes") or 0)
    _COUNTER_CACHE.update({"at": at, "ok": ok, "data": out})
    return ok, out


def status(cfg, with_hits=True):
    st = _load(cfg)
    g = st["geo_lock"]
    cn = load_cn(cfg)
    _allow4, _allow6, ex = _allow_sets(cfg, st)
    readable, hits = counters() if with_hits else (False, {})
    age = int(time.time()) - g["updated"] if g["updated"] else None
    return {
        "in": {"enabled": g["in"]["enabled"], "scope": g["in"]["scope"],
               "scope_label": SCOPE_LABEL[g["in"]["scope"]],
               "ports": web_ports(cfg, st) if g["in"]["scope"] == "web" else []},
        "out": {"enabled": g["out"]["enabled"]},
        "container": bool(g["container"]),
        "allow": list(g["allow"]),
        "cn": {"v4": len(cn["v4"]), "v6": len(cn["v6"]),
               "updated": g["updated"], "source": g["source"] or cn["source"],
               "age_days": (age // 86400) if age is not None else None},
        "exempt": {"lan": ex["lan"], "own": ex["own"],
                   "cf": len(ex["cf"]), "dns": ex["dns"], "allow": ex["allow"]},
        "hits": hits, "counters": readable,
        "on": g["in"]["enabled"] or g["out"]["enabled"],
        # 闸门没通电 = 规则还没真正生效（重启后等采集进程补网段的那一刻）
        "loaded": gate_open(cfg) if (g["in"]["enabled"] or g["out"]["enabled"]) else False,
    }


def preview(cfg):
    """给面板/CLI 看的规则文本（集合太多时只截取前后几行）。"""
    st = _load(cfg)
    lines = input_lines(st, cfg) + output_lines(st, cfg)
    if not lines:
        return "（未开启，没有生成任何地域规则）"
    cn = load_cn(cfg)
    head = ["set cn4 / cn6：IPv4 %d 段 / IPv6 %d 段（来源 %s）"
            % (len(cn["v4"]), len(cn["v6"]), cn["source"] or "未刷新"),
            "网段分批灌进集合（一次 nft 批处理塞不下这么多），这里只列判定规则；",
            "规则开头 %s @geo_on4 是闸门，集合灌满后才通电。"
            % ("ip saddr" if cn["v4"] else "ip6 saddr"),
            ""]
    return "\n".join(head + [x.strip() for x in lines])
