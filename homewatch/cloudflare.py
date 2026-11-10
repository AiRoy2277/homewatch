# -*- coding: utf-8 -*-
"""Cloudflare 边缘控制。

本地封禁解决的是"请求到了源站我怎么回"；这里解决的是"请求根本别到我这儿"。

两条通路的分工：

- 直连源站（攻击者已经知道你的 IP） → 只能靠 nftables / nginx；
- 走 Cloudflare 的流量 → 在边缘就该拦掉，回源流量既不占你的带宽，
  也不出现在 access.log 里。

用法上只用 Zone 级的 IP Access Rules：一条 IP 一条规则，语义简单、可单独删除，
清理时只认自己写进去的备注前缀，不会碰手工建的规则。

设计约束：
- 纯标准库（urllib），不引入 requests；
- 每个请求都有超时，批量同步还有总预算 —— 这是每分钟跑在采集循环里的代码，
  CF 挂了不能把整轮采集拖死；
- 失败一律翻译成人话，面板上直接给人看。
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.cloudflare.com/client/v4"
UA = "HomeWatch/0.4.4"
MAX_SYNC_PER_RUN = 20
SYNC_BUDGET = 20.0       # 一次批量同步最多占用多少秒
rule_url = "/zones/%s/firewall/access_rules/rules"


class CfError(RuntimeError):
    def __init__(self, msg, code=None, status=None):
        super().__init__(msg)
        self.code = code
        self.status = status


# ---------------- 基础 ----------------


def conf(cfg):
    return cfg.get("cloudflare") or {}


def configured(cfg):
    c = conf(cfg)
    return bool(c.get("enabled") and c.get("api_token")
                and (c.get("zone_id") or c.get("zone_name")))


def _redact(token):
    token = str(token or "")
    if len(token) <= 10:
        return "***"
    return token[:4] + "…" + token[-4:]


def _call(cfg, method, path, body=None, timeout=None, deadline=None):
    """发一个 API 请求，返回 result 字段。失败抛 CfError。"""
    c = conf(cfg)
    token = str(c.get("api_token") or "").strip()
    if not token:
        raise CfError("还没有配置 API Token")
    if not token.isascii() or any(ch in token for ch in "\r\n\t \"'"):
        raise CfError("API Token 含非法字符")

    base = float(c.get("timeout") or 8)
    if deadline:
        left = deadline - time.time()
        if left <= 0.5:
            raise CfError("本次同步时间预算用完，剩下的下一轮再同步")
        base = min(base, left)
    if timeout:
        base = min(base, float(timeout))

    url = API + path
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("User-Agent", UA)
    req.add_header("Content-Type", "application/json")
    if method != "GET":
        req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=base) as r:
            raw = r.read()
    except urllib.error.HTTPError as exc:
        raw = b""
        try:
            raw = exc.read()
        except Exception:  # noqa: BLE001
            pass
        raise CfError(_explain(exc.code, raw), status=exc.code)
    except urllib.error.URLError as exc:
        raise CfError("连不上 Cloudflare：%s" % getattr(exc, "reason", exc))
    except OSError as exc:
        raise CfError("请求 Cloudflare 失败：%s" % exc)

    try:
        payload = json.loads(raw.decode("utf-8", "replace") or "{}")
    except ValueError:
        raise CfError("Cloudflare 返回的不是 JSON（可能被网关拦截）")

    if not payload.get("success", False):
        errs = payload.get("errors") or []
        msg = "；".join(str(e.get("message") or e) for e in errs[:2]) or "未知错误"
        code = errs[0].get("code") if errs else None
        raise CfError(_friendly(msg, code), code=code)
    return payload.get("result")


def _friendly(msg, code):
    low = str(msg).lower()
    if code in (10000, 9109) or "authentication" in low or "invalid token" in low:
        return "Token 无效或已过期（%s）" % msg[:120]
    if "permission" in low or "not authorized" in low:
        return "Token 权限不足，需要 Zone.Firewall 的编辑权限（%s）" % msg[:120]
    if "deprecated" in low:
        return "该接口已被 Cloudflare 下线：%s" % msg[:160]
    return msg[:200]


def _explain(status, raw):
    detail = ""
    try:
        payload = json.loads(raw.decode("utf-8", "replace") or "{}")
        errs = payload.get("errors") or []
        if errs:
            detail = "：" + "；".join(str(e.get("message") or e)[:120] for e in errs[:2])
    except Exception:  # noqa: BLE001
        pass
    if status == 401:
        return "Token 无效（HTTP 401）" + detail
    if status == 403:
        return "Token 没有操作权限（HTTP 403）" + detail
    if status == 404:
        return "Zone 或规则不存在（HTTP 404）" + detail
    if status == 429:
        return "Cloudflare 限流，稍后再试（HTTP 429）"
    if status >= 500:
        return "Cloudflare 服务端错误（HTTP %d）" % status
    return "Cloudflare 返回 HTTP %d%s" % (status, detail)


# ---------------- Zone ----------------


def zone(cfg, deadline=None):
    """返回 {"id","name"}。优先用配置里的 zone_id，其次按域名查。"""
    c = conf(cfg)
    zid = str(c.get("zone_id") or "").strip()
    if zid:
        return {"id": zid, "name": str(c.get("zone_name") or "").strip()}
    name = str(c.get("zone_name") or "").strip()
    if not name:
        raise CfError("没有配置 zone_id 或 zone_name")
    q = urllib.parse.quote(name, safe="")
    res = _call(cfg, "GET", "/zones?name=%s&per_page=5" % q, deadline=deadline) or []
    if not res:
        raise CfError("Token 下找不到域名 %s（检查 zone_name 或 token 权限）" % name)
    return {"id": res[0].get("id"), "name": res[0].get("name") or name}


def verify(cfg, deadline=None):
    """token 是否可用 + 能不能拿到 zone。面板上的"检测连接"就是它。

    `/user/tokens/verify` 只认"用户级" token；账户级（account-owned）token 调它会
    401 Invalid API Token，但 Zone 接口是好用的 —— 所以这里两条路都试，任何一条
    能证明 token 活着就行，真正算"能不能用"的还是下面 zone() 那一步。
    """
    if not configured(cfg):
        return {"ok": False, "msg": "未启用或缺少 token / zone"}

    c = conf(cfg)
    acct = str(c.get("account_id") or "").strip()
    paths = []
    if acct:
        paths.append("/accounts/%s/tokens/verify" % acct)
    paths.append("/user/tokens/verify")

    state = ""
    last = ""
    for p in paths:
        try:
            tok = _call(cfg, "GET", p, deadline=deadline) or {}
            state = str(tok.get("status") or "active")
            break
        except CfError as exc:
            last = str(exc)
            continue

    try:
        z = zone(cfg, deadline=deadline)
    except CfError as exc:
        return {"ok": False, "msg": "%s%s" % (exc, ("（token 自检：%s）" % last) if last else "")}

    return {"ok": True, "token": state or "active",
            "zone": z.get("name") or z.get("id"), "zone_id": z.get("id"),
            "msg": "已连接 %s" % (z.get("name") or z.get("id"))}


# ---------------- IP Access Rules ----------------


def rules(cfg, deadline=None):
    """列出 zone 下的 IP 规则（最多 200 条）。"""
    z = zone(cfg, deadline=deadline)
    path = (rule_url % z["id"]) + "?per_page=100&page=1"
    out = []
    for page in (1, 2):
        p = path.replace("page=1", "page=%d" % page)
        res = _call(cfg, "GET", p, deadline=deadline) or []
        for r in res:
            cfgv = r.get("configuration") or {}
            out.append({
                "id": r.get("id"),
                "ip": cfgv.get("value") or "",
                "mode": r.get("mode") or "",
                "notes": r.get("notes") or "",
                "created": r.get("created_on") or "",
            })
        if len(res) < 100:
            break
    return out


def _note(cfg, extra=""):
    base = str(conf(cfg).get("note") or "HomeWatch")
    return (base + (" " + extra if extra else ""))[:200]


def _is_ours(cfg, rule):
    prefix = str(conf(cfg).get("note") or "HomeWatch")
    return str(rule.get("notes") or "").startswith(prefix)


def block(cfg, ip, note="", deadline=None):
    """给单个 IP 建一条 block 规则。已存在则不重复创建。"""
    z = zone(cfg, deadline=deadline)
    body = {
        "mode": "block",
        "configuration": {"target": "ip", "value": ip},
        "notes": _note(cfg, note),
    }
    res = _call(cfg, "POST", rule_url % z["id"], body=body, deadline=deadline) or {}
    return {"id": res.get("id"), "ip": ip, "notes": res.get("notes") or body["notes"]}


def unblock(cfg, ip, deadline=None):
    """删除该 IP 下由本程序创建的规则。返回删掉的条数。"""
    z = zone(cfg, deadline=deadline)
    removed = 0
    for r in rules(cfg, deadline=deadline):
        if r.get("ip") != ip or not _is_ours(cfg, r):
            continue
        _call(cfg, "DELETE", (rule_url % z["id"]) + "/" + str(r["id"]),
              deadline=deadline)
        removed += 1
    return removed


def sync(cfg, ips, deadline=None):
    """把一批 IP 推到边缘。返回统计。单次最多 MAX_SYNC_PER_RUN 个。"""
    c = conf(cfg)
    if not configured(cfg):
        return {"ok": False, "msg": "未启用 Cloudflare 同步",
                "added": [], "exists": [], "failed": []}

    deadline = deadline or (time.time() + SYNC_BUDGET)
    want = []
    for ip in ips or []:
        ip = str(ip or "").strip()
        if ip and ip not in want:
            want.append(ip)
    want = want[:MAX_SYNC_PER_RUN]

    try:
        have = {}
        for r in rules(cfg, deadline=deadline):
            if _is_ours(cfg, r):
                have[r["ip"]] = r
    except CfError as exc:
        return {"ok": False, "msg": str(exc), "added": [], "exists": [], "failed": []}

    added, exists, failed = [], [], []
    for ip in want:
        if ip in have:
            exists.append(ip)
            continue
        if time.time() >= deadline:
            failed.append({"ip": ip, "error": "时间预算用完，下一轮继续"})
            continue
        try:
            block(cfg, ip, "auto", deadline=deadline)
            added.append(ip)
        except CfError as exc:
            failed.append({"ip": ip, "error": str(exc)})

    return {
        "ok": not failed,
        "added": added,
        "exists": exists,
        "failed": failed,
        "total": len(want),
        "msg": _sync_msg(added, exists, failed),
    }


def _sync_msg(added, exists, failed):
    if not (added or exists or failed):
        return "没有需要同步的 IP"
    parts = []
    if added:
        parts.append("新增 %d" % len(added))
    if exists:
        parts.append("已存在 %d" % len(exists))
    if failed:
        parts.append("失败 %d（%s）" % (len(failed), failed[0].get("error", "")[:80]))
    return "Cloudflare 边缘规则：" + "，".join(parts)


def prune(cfg, keep_ips, deadline=None):
    """删掉本地已经解封、但 CF 上还在的规则。"""
    keep = {str(x) for x in (keep_ips or [])}
    z = zone(cfg, deadline=deadline)
    removed = []
    for r in rules(cfg, deadline=deadline):
        if not _is_ours(cfg, r) or r.get("ip") in keep:
            continue
        if time.time() >= (deadline or 1e18):
            break
        try:
            _call(cfg, "DELETE", (rule_url % z["id"]) + "/" + str(r["id"]),
                  deadline=deadline)
            removed.append(r.get("ip"))
        except CfError:
            continue
    return removed


def purge_cache(cfg, deadline=None):
    z = zone(cfg, deadline=deadline)
    _call(cfg, "POST", "/zones/%s/purge_cache" % z["id"],
          body={"purge_everything": True}, deadline=deadline)
    return True


def status(cfg):
    """面板用：不联网，只报告配置形态。联网检测走 verify()。"""
    c = conf(cfg)
    return {
        "enabled": bool(c.get("enabled")),
        "configured": configured(cfg),
        "auto_sync": bool(c.get("auto_sync", True)),
        "zone": str(c.get("zone_name") or "") or (
            ("ID " + str(c.get("zone_id"))[:8] + "…") if c.get("zone_id") else ""),
        "zone_id": str(c.get("zone_id") or ""),
        "token": _redact(c.get("api_token")),
        "has_token": bool(c.get("api_token")),
        "note": str(c.get("note") or "HomeWatch"),
        "timeout": c.get("timeout") or 8,
    }
