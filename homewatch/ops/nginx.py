# -*- coding: utf-8 -*-
"""nginx 封禁名单维护。

为什么封禁要同时写 nginx 和 nft：

- 走 Cloudflare 进来的流量，nft 看到的源地址是 **CF 的 IP**，不是攻击者的，
  所以在 nft 层封攻击者 IP 对这条路完全无效；
- nginx 里有 ``realip``，``$remote_addr`` 已经被还原成真实客户端 IP，
  在这里封才对 CF 流量生效。

所以两边都写：nginx 管应用层（CF 回源），nft 管网络层（直连、SSH）。

封禁的三种响应方式（``policy.ban_mode``）：

- ``visible``  402 + 文案。扫描器知道"我被封了"，日志里留得下痕迹；
- ``silent``   444。nginx 不回任何字节直接断开连接，扫描器只能看到超时；
- ``silent_nolog`` 同 444，并且这些请求不再写 access.log。

444 和"不写日志"都**不能**在 00-blocklist.conf 里单独做到：
``map`` 只能产出变量，真正回包的地方是站点配置里的 ``return``。
所以本模块带一个受控的站点 patch（备份 → 改 → nginx -t → 失败全量还原），
只动引用了 ``$blocked_scanner`` 的那一个 server 块，别的地方一个字不碰。
"""

import ipaddress
import os
import re
import shutil
import subprocess
import time

DEFAULT_PATH = "/etc/nginx/conf.d/00-blocklist.conf"
DEFAULT_SITES = "/etc/nginx/sites-enabled"
# 回包片段：站点里 `if ($blocked_scanner) { include .../blocked-msg.conf; }`
# 这种写法下，真正决定回什么的是这个片段，不是站点文件本身
DEFAULT_REPLY = "/etc/nginx/snippets/blocked-msg.conf"

# mode -> (状态码, 是否写日志)
MODES = {
    "visible": (402, True),
    "silent": (444, True),
    "silent_nolog": (444, False),
}
DEFAULT_MODE = "silent"

HEADER = """# 扫描源封禁（由 HomeWatch 维护，最后更新 %s）
# 手工改动会在下次封禁/解封/切换模式时被整份覆盖
# 模式：%s（%s）
"""

# 站点里的引用形态：if ($blocked_scanner) { return 402; }
RETURN_RE = re.compile(
    r"(if\s*\(\s*\$blocked_scanner\s*\)\s*\{\s*return\s+)(\d{3})(\s*;)")
ACCESS_LOG_RE = re.compile(r"^([ \t]*access_log\s+)(\S+)([^;]*);", re.M)
# 回包片段里的 return：return 402 "文案"; / return 444;
REPLY_RE = re.compile(r"return\s+(\d{3})(\s+\"((?:[^\"\\]|\\.)*)\")?\s*;", re.S)
INCLUDE_RE = re.compile(r"include\s+([^;\s]*blocked-msg\.conf)\s*;")
GUARD_RE = re.compile(r"if\s*\(\s*\$blocked_scanner\s*\)")
# 切到 444 之后原文案就没地方放了，用注释存一份，切回 visible 时原样还回去
MSG_HINT_RE = re.compile(r"^#\s*原文案：(.*)$", re.M)


class NginxError(RuntimeError):
    pass


# ---------------- 模式 ----------------


def path_for(cfg):
    return (cfg.get("paths") or {}).get("nginx_blocklist") or DEFAULT_PATH


def sites_for(cfg):
    return (cfg.get("paths") or {}).get("nginx_sites") or DEFAULT_SITES


def reply_for(cfg):
    return (cfg.get("paths") or {}).get("nginx_reply") or DEFAULT_REPLY


def ban_mode(cfg):
    pol = cfg.get("policy") or {}
    mode = str(pol.get("ban_mode") or DEFAULT_MODE)
    return mode if mode in MODES else DEFAULT_MODE


def code_of(mode):
    return MODES.get(mode, MODES[DEFAULT_MODE])[0]


def logs_of(cfg, mode=None):
    """该模式是否仍写 access.log。silent 下还受 policy.silent_log 控制。"""
    mode = mode or ban_mode(cfg)
    default = MODES.get(mode, MODES[DEFAULT_MODE])[1]
    if mode == "silent_nolog":
        return False
    pol = cfg.get("policy") or {}
    if mode == "silent" and pol.get("silent_log") is False:
        return False
    return default


def mode_label(mode):
    return {
        "visible": "402 可见拦截",
        "silent": "444 静默断开",
        "silent_nolog": "444 静默 + 不记日志",
    }.get(mode, mode)


# ---------------- 名单读写 ----------------


def read_ips(cfg):
    """读出当前封禁名单。文件不存在或格式异常时返回空列表。"""
    p = path_for(cfg)
    try:
        with open(p, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return []
    ips = []
    m = re.search(r"map\s+\$remote_addr\s+\$blocked_scanner\s*\{(.*?)\}", text, re.S)
    body = m.group(1) if m else text
    for line in body.splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("default"):
            continue
        token = line.split()[0].rstrip(";")
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        ips.append(token)
    return ips


def render(ips, mode=DEFAULT_MODE, log=True):
    """生成 00-blocklist.conf。

    ``$blocked_loggable`` 始终输出，站点只要接过一次 ``access_log ... if=$blocked_loggable``，
    以后切换"记不记日志"就只是改配置，不用再动站点。
    """
    code = code_of(mode)
    lines = [HEADER % (time.strftime("%Y-%m-%d %H:%M:%S"), mode, mode_label(mode)),
             "map $remote_addr $blocked_scanner {",
             "    default 0;"]
    for ip in ips:
        lines.append("    %-16s 1;" % ip if ":" not in ip else "    %s 1;" % ip)
    lines.append("}")
    lines.append("")
    lines.append("# 0 = 该请求不写 access_log（站点里要写 access_log ... if=$blocked_loggable;）")
    lines.append("map $blocked_scanner $blocked_loggable {")
    lines.append("    default 1;")
    if not log:
        lines.append("    1       0;")
    lines.append("}")
    # 仅供人看：真正决定响应码的是站点里的 return，这里只是把期望值记下来
    lines.append("")
    lines.append("# 期望响应：%d（站点需写 if ($blocked_scanner) { return %d; }）" % (code, code))
    return "\n".join(lines) + "\n"


def _run(cmd, timeout=25):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _test():
    try:
        r = _run(["nginx", "-t"], timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        raise NginxError("执行 nginx -t 失败：%s" % exc)
    if r.returncode != 0:
        raise NginxError((r.stderr or "").strip() or "nginx -t 失败")


def _reload():
    _test()
    try:
        r = _run(["systemctl", "reload", "nginx"])
    except (OSError, subprocess.SubprocessError) as exc:
        raise NginxError("reload nginx 失败：%s" % exc)
    if r.returncode != 0:
        raise NginxError((r.stderr or "").strip() or "reload nginx 失败")


def _reload_quiet():
    try:
        _run(["systemctl", "reload", "nginx"])
    except (OSError, subprocess.SubprocessError):
        pass


def write_ips(cfg, ips, mode=None, log=None):
    """写入并用 reload 生效；校验失败自动回滚。"""
    mode = mode or ban_mode(cfg)
    log = logs_of(cfg, mode) if log is None else bool(log)
    p = path_for(cfg)
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    backup = None
    try:
        with open(p, "r", encoding="utf-8") as fh:
            backup = fh.read()
    except OSError:
        backup = None

    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(render(ips, mode, log))
    os.replace(tmp, p)

    try:
        _reload()
    except Exception:
        # 回滚到改之前的内容，避免把站点改坏。这里捕获所有异常：
        # nginx 不存在、reload 超时、校验失败都必须回滚，不能留下半套名单。
        if backup is not None:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(backup)
        else:
            try:
                os.remove(p)
            except OSError:
                pass
        _reload_quiet()
        raise
    return ips


def add_many(cfg, ips):
    """批量加名单，只 reload 一次。返回 (全部名单, 本次新增)。"""
    cur = read_ips(cfg)
    have = set(cur)
    added = []
    for raw in ips or []:
        try:
            addr = ipaddress.ip_address(str(raw).strip())
        except ValueError:
            continue
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        key = str(addr)
        if key in have:
            continue
        cur.append(key)
        have.add(key)
        added.append(key)
    if added:
        write_ips(cfg, cur)
    return cur, added


def add(cfg, ip):
    ips, added = add_many(cfg, [ip])
    return ips, bool(added)


def remove(cfg, ip):
    addr = ipaddress.ip_address(ip)
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    key = str(addr)
    ips = read_ips(cfg)
    if key not in ips:
        return ips, False
    ips = [x for x in ips if x != key]
    return write_ips(cfg, ips), True


# ---------------- 站点接线 ----------------


def _blocks(text):
    """找出所有 server { ... } 的范围，按大括号配对，忽略注释与字符串里的括号。"""
    out = []
    for m in re.finditer(r"\bserver\s*\{", text):
        start = text.rfind("\n", 0, m.start()) + 1
        i = text.find("{", m.start())
        depth = 0
        j = i
        while j < len(text):
            ch = text[j]
            if ch == "#":
                nl = text.find("\n", j)
                j = len(text) if nl < 0 else nl
                continue
            if ch == '"':
                k = j + 1
                while k < len(text) and text[k] != '"':
                    k += 2 if text[k] == "\\" else 1
                j = k + 1
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    out.append((start, j + 1))
                    break
            j += 1
    return out


def _site_dirs(cfg):
    """要扫描的站点目录。支持逗号分隔；顺手带上同级的 conf.d。

    有些人不用 sites-enabled，直接往 conf.d 里扔 server 块，
    只扫一个目录会漏掉"封禁规则没人引用"这种最容易犯的错。
    """
    raw = str(sites_for(cfg) or DEFAULT_SITES)
    dirs = [x.strip() for x in raw.split(",") if x.strip()]
    for d in list(dirs):
        sib = os.path.join(os.path.dirname(d.rstrip("/")), "conf.d")
        if os.path.isdir(sib) and sib not in dirs:
            dirs.append(sib)
    return dirs


def _site_files(cfg):
    skip = os.path.abspath(path_for(cfg))
    files = []
    for d in _site_dirs(cfg):
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for name in names:
            p = os.path.join(d, name)
            if not os.path.isfile(p):
                continue
            # .bak.2026… 这类备份也带 server 块，扫进来会让"接线状态"变得忽明忽暗
            if ".bak" in name or name.endswith((".tmp", ".disabled", ".hw.tmp")):
                continue
            if os.path.abspath(p) == skip:
                continue
            files.append(p)
    return files


def scan(cfg):
    """站点接线状态：有没有引用 $blocked_scanner、return 是几、日志有没有条件化。"""
    mode = ban_mode(cfg)
    want_code = code_of(mode)
    want_log = logs_of(cfg, mode)

    # 优先看回包片段：站点只在 if 里 include 它，改 return 就是改这一个文件
    st = reply_state(cfg)
    if st["exists"] and reply_used(cfg):
        wired = st["code"] == want_code
        return {
            "mode": mode,
            "mode_label": mode_label(mode),
            "want_code": want_code,
            "want_log": want_log,
            "via": "include",
            "reply": st["path"],
            "reply_code": st["code"],
            "files": [{"path": st["path"], "return": st["code"],
                       "conditional_log": False, "has_access_log": False}],
            "wired": wired,
            # http 级 access_log 不挂条件，站点这一层没法单独掐日志
            "log_wired": False,
            "log_supported": False,
            "ready": wired,
            "sites_dir": sites_for(cfg),
        }

    found = []
    for p in _site_files(cfg):
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for start, end in _blocks(text):
            body = text[start:end]
            if "$blocked_scanner" not in body:
                continue
            m = RETURN_RE.search(body)
            al = ACCESS_LOG_RE.search(body)
            found.append({
                "path": p,
                "return": int(m.group(2)) if m else None,
                "conditional_log": bool(al and "if=$blocked_loggable" in al.group(0)),
                "has_access_log": bool(al),
            })
    wired = bool(found) and all(f["return"] == want_code for f in found)
    log_wired = bool(found) and all(f["conditional_log"] for f in found)
    return {
        "mode": mode,
        "mode_label": mode_label(mode),
        "want_code": want_code,
        "want_log": want_log,
        "via": "inline",
        "files": found,
        "wired": wired,
        "log_wired": log_wired,
        "log_supported": True,
        # 完全接好：状态码对得上，而且"不写日志"这件事站点也支持
        "ready": wired and (want_log or log_wired),
        "sites_dir": sites_for(cfg),
    }


# ---------------- 回包片段（include 写法） ----------------


def reply_state(cfg):
    """读回包片段的现状：在不在、有没有 $blocked_scanner 判断、返回几、文案是什么。"""
    p = reply_for(cfg)
    try:
        with open(p, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return {"path": p, "exists": False, "code": None, "text": "", "msg": "",
                "guarded": False}
    m = REPLY_RE.search(text)
    hint = MSG_HINT_RE.search(text)
    msg = (hint.group(1) if hint else (m.group(3) if m else "")) or ""
    return {"path": p, "exists": True,
            "code": int(m.group(1)) if m else None,
            "text": text,
            "msg": msg.replace("\\n", "\n"),
            # 片段被 include 在 server 级，没有这层判断就等于"所有请求都挡"
            "guarded": bool(GUARD_RE.search(text))}


def reply_used(cfg):
    """站点里有没有 include 这个片段（有就说明走的是片段接线）。"""
    name = os.path.basename(reply_for(cfg))
    for p in _site_files(cfg):
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if name in text and INCLUDE_RE.search(text):
            return True
    return False


DEFAULT_MSG = "哥们没钱，别搞了。"


def _smoke(cfg):
    """改完片段后从本机打一次站点，确认没被"全员 444"。

    444 在 nginx -t 里是完全合法的，语法检查发现不了这种事故；
    所以拿站点自己的 listen 端口 + server_name 真发一个请求看有没有响应体。
    """
    port = name = scheme = None
    host = "127.0.0.1"
    for p in _site_files(cfg):
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        m = re.search(r"listen\s+(?:([0-9a-fA-F\.\*]+):)?(\d+)([^;]*);", text)
        n = re.search(r"server_name\s+([^\s;]+)", text)
        if m and n:
            if m.group(1) and m.group(1) not in ("*", "0.0.0.0"):
                host = m.group(1)
            port, name = m.group(2), n.group(1)
            scheme = "https" if "ssl" in m.group(3) else "http"
            break
    if not (port and name):
        return None
    try:
        r = _run(["curl", "-sk", "-m", "6", "-o", "/dev/null", "-w", "%{http_code}",
                  "-H", "Host: %s" % name, "%s://%s:%s/" % (scheme, host, port)],
                 timeout=12)
    except (OSError, subprocess.SubprocessError):
        return None
    code = (r.stdout or "").strip()
    # 只有"明确被 444 挡掉"才算事故；000 多半是本机没这条路（监听在别的地址），
    # 判定不了就别乱回滚
    if code == "444":
        raise NginxError("自检失败：本机 %s://%s:%s 返回 444（多半是片段少了判断），已回滚"
                         % (scheme, host, port))
    return code


def apply_reply(cfg, mode=None):
    """把回包片段整份重写成目标模式。失败自动还原。

    这个片段是被 `include` 在 **server 级**的，所以必须保留
    ``if ($blocked_scanner) { ... }`` 这层判断 —— 少了它，所有请求都会被挡掉
    （线上踩过一次，站点直接 520）。检测不到判断就拒绝改写，宁可不动。
    """
    mode = mode or ban_mode(cfg)
    code = code_of(mode)
    st = reply_state(cfg)
    if not st["exists"]:
        raise NginxError("没找到回包片段 %s" % st["path"])
    if st["code"] == code and st["guarded"]:
        return {"changed": [], "notes": ["回包片段已经是 %d" % code], "mode": mode,
                "reply": st["path"]}
    if not st["guarded"]:
        raise NginxError(
            "回包片段里没有 `if ($blocked_scanner)` 判断，拒绝改写："
            "这个片段 include 在 server 级，写裸 return 会把整站打死。"
            "请先手工把它改回 if 包裹的形态（备份在 %s.hw.bak）" % st["path"])

    msg = st["msg"] or DEFAULT_MSG
    body = ["# 封禁回包（由 HomeWatch 维护，最后更新 %s）"
            % time.strftime("%Y-%m-%d %H:%M:%S"),
            "# 模式：%s（%s）；切换模式会整份重写本文件" % (mode, mode_label(mode)),
            "# 原文案：%s" % msg.replace("\n", "\\n"),
            "if ($blocked_scanner) {"]
    if code == 444:
        body.append("    return 444;")
    else:
        body.append('    return %d "%s";' % (
            code, msg.replace('"', '\\"').replace("\n", "\\n")))
    body.append("}")
    new = "\n".join(body) + "\n"

    bak = st["path"] + ".hw.bak"
    if not os.path.exists(bak):
        try:
            shutil.copy2(st["path"], bak)
        except OSError:
            pass
    tmp = st["path"] + ".hw.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(new)
    os.replace(tmp, st["path"])
    try:
        _reload()
        # 写完再读回来确认：包裹还在、码是对的
        chk = reply_state(cfg)
        if chk["code"] != code or not chk["guarded"]:
            raise NginxError("改写后自检不通过（code=%s guarded=%s）"
                             % (chk["code"], chk["guarded"]))
        _smoke(cfg)
    except Exception:
        with open(st["path"], "w", encoding="utf-8") as fh:
            fh.write(st["text"])
        _reload_quiet()
        raise
    return {"changed": [st["path"]],
            "notes": ["回包 %s → %d" % (st["code"], code)],
            "mode": mode, "reply": st["path"]}


def _patch_text(text, code, conditional_log=True):
    """把 server 块里的 return 改成目标码，并给 access_log 挂上 if=。

    返回 (新文本, 改动说明列表)。没接线的块原样保留。
    """
    notes = []
    for start, end in reversed(_blocks(text)):
        body = text[start:end]
        if "$blocked_scanner" not in body:
            continue

        def _ret(m):
            old = m.group(2)
            if old == str(code):
                return m.group(0)
            notes.append("return %s → %d" % (old, code))
            return "%s%d%s" % (m.group(1), code, m.group(3))

        new_body = RETURN_RE.sub(_ret, body)

        if conditional_log:
            def _log(m):
                if m.group(2) == "off":
                    return m.group(0)
                if "if=$blocked_loggable" in m.group(0):
                    return m.group(0)
                if "if=" in m.group(3):
                    # 已经挂了别的条件，再叠一个会语义打架，留给人确认
                    notes.append("access_log 已有别的条件，跳过")
                    return m.group(0)
                notes.append("access_log 挂条件")
                return "%s%s%s if=$blocked_loggable;" % (
                    m.group(1), m.group(2), m.group(3).rstrip())

            new_body = ACCESS_LOG_RE.sub(_log, new_body)

        text = text[:start] + new_body + text[end:]
    return text, notes


def apply_sites(cfg, mode=None, log=None):
    """把站点配置改成当前模式要求的形态。

    只处理"引用了 $blocked_scanner 的 server 块"，改完统一 nginx -t，
    失败则把所有文件还原成改之前的内容 —— 不允许出现"一半站点改了"的状态。

    access_log 的条件**总是**挂上：map 里默认值是 1，挂着不影响正常记日志，
    但等哪天切到"不记日志"就立刻生效，不用再改一次站点。
    """
    mode = mode or ban_mode(cfg)
    code = code_of(mode)
    want_log = logs_of(cfg, mode) if log is None else bool(log)

    # 站点用 include 片段回包时，改的只是那一个片段，别去动 30 个 server 块
    st = reply_state(cfg)
    if st["exists"] and reply_used(cfg):
        res = apply_reply(cfg, mode)
        try:
            write_ips(cfg, read_ips(cfg), mode=mode, log=want_log)
        except Exception:
            # 片段已经生效，名单写失败只影响"记不记日志"，不该把片段回滚
            pass
        return res

    changed, notes = [], []
    backups = {}
    for p in _site_files(cfg):
        try:
            with open(p, "r", encoding="utf-8") as fh:
                old = fh.read()
        except OSError:
            continue
        if "$blocked_scanner" not in old:
            continue
        new, n = _patch_text(old, code, conditional_log=True)
        if new == old:
            continue
        backups[p] = old
        # 首次改动前留一份原始版本，方便人工回滚（只留最早的那份）
        bak = p + ".hw.bak"
        if not os.path.exists(bak):
            try:
                shutil.copy2(p, bak)
            except OSError:
                pass
        tmp = p + ".hw.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(new)
        os.replace(tmp, p)
        changed.append(p)
        notes.extend("%s: %s" % (os.path.basename(p), x) for x in n)

    if changed:
        try:
            _reload()
        except Exception:
            for p, old in backups.items():
                try:
                    with open(p, "w", encoding="utf-8") as fh:
                        fh.write(old)
                except OSError:
                    pass
            _reload_quiet()
            raise

    # 站点没变也要重写名单：$blocked_loggable 的取值在名单文件里，
    # 切换"记不记日志"靠的就是这一处
    try:
        write_ips(cfg, read_ips(cfg), mode=mode, log=want_log)
    except Exception:
        # 站点都改好了才发现名单写不进去，不该把站点回滚掉；下次封禁会补
        if not changed:
            raise
    return {"changed": changed, "notes": notes, "mode": mode}
