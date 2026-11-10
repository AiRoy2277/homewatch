# -*- coding: utf-8 -*-
"""受控动作白名单。

面板能做的事**只有**这里登记的这些。没有"执行任意命令"的入口，
每个参数都在进入执行层之前做类型和范围校验。
"""

import ipaddress
import re
import time

from .. import cloudflare as cf_mod
from .. import db as db_mod
from .. import geo as geo_mod
from .. import policy as policy_mod
from .. import sshport
from ..ops import fw as fw_ops
from ..ops import geoblock as geo_ops
from ..ops import htpasswd as auth_ops
from ..ops import nft as nft_ops
from ..ops import nginx as nginx_ops
from ..ops import sshd as ssh_ops
from ..ops import units as units_ops


class ActionError(ValueError):
    """参数不合法。返回给前端时只暴露这句话，不含内部细节。"""


def _need(params, key, kind, default=None):
    if key not in params:
        if default is not None:
            return default
        raise ActionError("缺少参数：%s" % key)
    val = params[key]
    if kind is int:
        try:
            return int(val)
        except (TypeError, ValueError):
            raise ActionError("%s 必须是整数" % key)
    if kind is bool:
        if isinstance(val, bool):
            return val
        raise ActionError("%s 必须是布尔值" % key)
    if kind is str:
        if not isinstance(val, str):
            raise ActionError("%s 必须是字符串" % key)
        return val
    return val


def _port_meta(cfg, port):
    for item in cfg.get("managed_ports") or []:
        if int(item.get("port", 0)) == int(port):
            return item
    return None


def act_port_set(cfg, params, ctx):
    port = _need(params, "port", int)
    enabled = _need(params, "enabled", bool)

    if not 1 <= port <= 65535:
        raise ActionError("端口超出范围")
    meta = _port_meta(cfg, port)
    if not meta:
        raise ActionError("端口 %d 不在受管列表里" % port)
    if meta.get("readonly"):
        raise ActionError("%s 不允许从面板开关" % meta.get("label", port))

    nft_ops.set_port(cfg, port, enabled)
    label = meta.get("label") or str(port)
    if enabled:
        return {"msg": "%s（%d）已开放" % (label, port)}

    warn = "已关闭 %s（%d）" % (label, port)
    if int(port) == int(cfg.get("admin_port", 8088)):
        warn += "。⚠ 面板自身端口已关闭，你将无法再访问本页，需从 PVE 控制台恢复"
    elif int(port) == 22:
        warn += "。⚠ SSH 端口已关闭，需要通过「SSH 开关」或 PVE 控制台恢复"
    return {"msg": warn, "warning": True}


def act_ssh_set(cfg, params, ctx):
    enabled = _need(params, "enabled", bool)
    ssh_ops.set_enabled(enabled)
    if enabled:
        return {"msg": "SSH 已开启（仍只允许内网访问）"}
    return {
        "msg": "SSH 已关闭，22 端口不再监听",
        "warning": True,
        "note": "只能通过本面板或 PVE Console 重新开启",
    }


def act_ssh_password(cfg, params, ctx):
    pw = params.get("password")
    if not isinstance(pw, str):
        raise ActionError("密码格式不正确")
    confirm = params.get("confirm")
    if confirm is not None and confirm != pw:
        raise ActionError("两次输入的密码不一致")

    ok, why = ssh_ops.check_password(pw)
    if not ok:
        raise ActionError(why)

    ssh_ops.set_password(pw)
    return {"msg": "root 密码已更新", "note": "正在使用的 SSH 会话不会断开"}


def act_auth_password(cfg, params, ctx):
    """改面板登录密码（nginx basic auth）。和 root 密码是两个东西。"""
    pw = params.get("password")
    if not isinstance(pw, str):
        raise ActionError("密码格式不正确")
    confirm = params.get("confirm")
    if confirm is not None and confirm != pw:
        raise ActionError("两次输入的密码不一致")

    try:
        res = auth_ops.set_password(cfg, pw)
    except auth_ops.HtpasswdError as exc:
        raise ActionError(str(exc))

    return {
        "msg": "面板登录密码已更新（用户名 %s）" % res["user"],
        "user": res["user"],
        "path": res["path"],
        # 浏览器会继续拿旧凭据请求，接下来的调用会 401，前端据此提示重新登录
        "relogin": True,
        "note": "当前页面会在几秒后要求重新登录，用新密码即可",
    }


def act_ssh_port(cfg, params, ctx):
    """切换 SSH 端口。改完写保险丝，超时未确认自动回滚。"""
    port = _need(params, "port", int)
    minutes = params.get("minutes")
    if minutes is not None:
        try:
            minutes = int(minutes)
        except (TypeError, ValueError):
            raise ActionError("minutes 必须是整数")

    old = ssh_ops.current_port()
    try:
        res = sshport.change(cfg, port, minutes)
    except (sshport.PortError, ssh_ops.SshError) as exc:
        raise ActionError(str(exc))

    return {
        "msg": "SSH 端口已从 %d 改为 %d，请在 %d 分钟内用新端口登录确认"
               % (res["old"], res["new"], res["minutes"]),
        "warning": True,
        "port": res["new"],
        "old_port": res["old"],
        "minutes": res["minutes"],
        "deadline": res["deadline"],
        "note": "超时未确认会自动回滚；确认按钮在 SSH 卡片里",
    }


def act_ssh_port_confirm(cfg, params, ctx):
    try:
        return sshport.confirm(cfg)
    except (sshport.PortError, ssh_ops.SshError) as exc:
        raise ActionError(str(exc))


def act_ssh_port_rollback(cfg, params, ctx):
    try:
        return sshport.rollback(cfg)
    except (sshport.PortError, ssh_ops.SshError) as exc:
        raise ActionError(str(exc))


def _norm_ip(raw):
    if not isinstance(raw, str):
        raise ActionError("IP 格式不正确")
    raw = raw.strip()
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        raise ActionError("不是合法的 IP 地址：%s" % raw[:40])
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def act_ip_block(cfg, params, ctx):
    ip = _norm_ip(params.get("ip"))
    hours = _need(params, "hours", int, default=24)
    if hours < 0 or hours > 24 * 365:
        raise ActionError("时长需在 0（永久）到 8760 小时之间")
    layer = params.get("layer", "both")
    if layer not in ("both", "nginx", "nft"):
        raise ActionError("layer 只能是 both / nginx / nft")

    own = set(cfg.get("own_ips") or [])
    if ip in own:
        raise ActionError("这是你自己的 IP，封掉会导致失联。确实要封请先把它从 own_ips 移除")

    reason = str(params.get("reason") or "")[:120]
    done = []

    if layer in ("both", "nginx"):
        nginx_ops.add(cfg, ip)
        done.append("nginx（对 Cloudflare 回源流量生效）")
    if layer in ("both", "nft"):
        nft_ops.block_ip(cfg, ip, hours=hours, reason=reason)
        done.append("nftables（对直连、SSH 生效）")

    try:
        conn = _conn(cfg)
        try:
            policy_mod.record(conn, ip, hours, layer, "manual",
                              reason or "手动封禁", mode="manual")
        finally:
            conn.close()
    except Exception:  # noqa: BLE001  流水写失败不影响封禁
        pass

    # 配了 Cloudflare 就顺手推一条边缘规则：直连还能靠本地，走 CF 的流量
    # 在边缘就被挡掉，连回源都不会发生
    note = ""
    if cf_mod.configured(cfg):
        try:
            res = cf_mod.sync(cfg, [ip], deadline=time.time() + 12)
            if res.get("added"):
                done.append("Cloudflare")
            elif not res.get("ok"):
                note = "（Cloudflare 未同步：%s）" % str(res.get("msg") or "")[:60]
        except Exception as exc:  # noqa: BLE001
            note = "（Cloudflare 未同步：%s）" % str(exc)[:60]

    return {"msg": "已封禁 %s：%s%s" % (ip, "；".join(done), note),
            "ip": ip, "hours": hours}


def act_ip_unblock(cfg, params, ctx):
    ip = _norm_ip(params.get("ip"))
    done = []

    try:
        r = nft_ops.unblock_ip(cfg, ip)
        if r[1]:
            done.append("nftables")
    except Exception:  # noqa: BLE001  解封时 nft 失败不该阻塞 nginx 侧
        pass

    removed, did = nginx_ops.remove(cfg, ip)
    if did:
        done.append("nginx")

    if cf_mod.configured(cfg):
        try:
            if cf_mod.unblock(cfg, ip):
                done.append("Cloudflare")
        except Exception:  # noqa: BLE001  CF 挂了不该挡住本地解封
            pass

    if not done:
        return {"msg": "%s 本来就不在封禁名单里" % ip}
    return {"msg": "已解封 %s（%s）" % (ip, "、".join(done))}


def act_cf_refresh(cfg, params, ctx):
    st = nft_ops.refresh_cf(cfg)
    return {"msg": "已更新 Cloudflare 回源网段：IPv4 %d 段 / IPv6 %d 段"
                   % (len(st.get("cf_ips4", [])), len(st.get("cf_ips6", [])))}


# ---------------- Cloudflare 边缘 ----------------


def _cf_conf(cfg):
    return cfg.setdefault("cloudflare", {})


def act_cf_set(cfg, params, ctx):
    """配置 CF 连接。token 只进配置文件，永远不回显。"""
    c = _cf_conf(cfg)
    touched = []

    if "enabled" in params:
        c["enabled"] = _need(params, "enabled", bool)
        touched.append("启用" if c["enabled"] else "停用")
    if "auto_sync" in params:
        c["auto_sync"] = _need(params, "auto_sync", bool)
        touched.append("自动同步" + ("开" if c["auto_sync"] else "关"))
    if "zone_name" in params:
        z = _need(params, "zone_name", str).strip()[:120]
        if z and not re.match(r"^[A-Za-z0-9.\-]+$", z):
            raise ActionError("域名格式不正确")
        c["zone_name"] = z
        if z:
            touched.append("域名 " + z)
    if "zone_id" in params:
        z = _need(params, "zone_id", str).strip()[:64]
        if z and not re.match(r"^[A-Za-z0-9]+$", z):
            raise ActionError("Zone ID 格式不正确")
        c["zone_id"] = z
    if "api_token" in params:
        tok = _need(params, "api_token", str).strip()
        if tok:
            if len(tok) < 20 or len(tok) > 200 or not re.match(r"^[A-Za-z0-9_\-]+$", tok):
                raise ActionError("API Token 格式不正确（应为 40 位左右的字母数字）")
            c["api_token"] = tok
            touched.append("Token 已更新")
        else:
            c["api_token"] = ""
            c["enabled"] = False
            touched.append("Token 已清除")

    if not touched:
        raise ActionError("没有要修改的项")

    _save_cfg(cfg)
    _harden_config(cfg)
    return {"msg": "Cloudflare 配置已更新：" + "、".join(touched),
            "cloudflare": cf_mod.status(cfg)}


def _harden_config(cfg):
    """配置文件里有 token，权限收窄到 600。"""
    import os
    from .. import config as config_mod
    path = (cfg.get("paths") or {}).get("config") or config_mod.config_path()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def act_cf_test(cfg, params, ctx):
    res = cf_mod.verify(cfg, deadline=time.time() + 12)
    if not res.get("ok"):
        return {"msg": res.get("msg") or "连接失败", "warning": True,
                "cloudflare": cf_mod.status(cfg), "verify": res}
    return {"msg": res.get("msg"), "cloudflare": cf_mod.status(cfg), "verify": res}


def act_cf_rules(cfg, params, ctx):
    try:
        items = cf_mod.rules(cfg, deadline=time.time() + 12)
    except cf_mod.CfError as exc:
        raise ActionError(str(exc))
    return {"msg": "Cloudflare 边缘规则 %d 条" % len(items), "rules": items}


def act_cf_sync(cfg, params, ctx):
    if not cf_mod.configured(cfg):
        raise ActionError("先填 API Token 和域名，再点「检测连接」确认通了")
    conn = _conn(cfg)
    try:
        res = policy_mod.cf_sync(conn, cfg, force=True)
    finally:
        conn.close()
    if res.get("skipped"):
        raise ActionError(res.get("msg") or "未启用")
    return {"msg": res.get("msg") or "已同步", "result": res}


def act_cf_unblock(cfg, params, ctx):
    ip = _norm_ip(params.get("ip"))
    try:
        n = cf_mod.unblock(cfg, ip)
    except cf_mod.CfError as exc:
        raise ActionError(str(exc))
    if not n:
        return {"msg": "Cloudflare 上没有 %s 的自动规则" % ip}
    return {"msg": "已从 Cloudflare 删除 %s 的 %d 条规则" % (ip, n)}


def act_cf_purge(cfg, params, ctx):
    try:
        cf_mod.purge_cache(cfg, deadline=time.time() + 12)
    except cf_mod.CfError as exc:
        raise ActionError(str(exc))
    return {"msg": "Cloudflare 缓存已全部清除"}


def act_nginx_mode(cfg, params, ctx):
    """切换封禁响应方式，并把站点配置改到位。"""
    mode = _need(params, "mode", str)
    if mode not in nginx_ops.MODES:
        raise ActionError("未知模式：%s" % mode)
    apply_sites = bool(params.get("apply_sites", True))

    pol = cfg.setdefault("policy", {})
    old = pol.get("ban_mode") or nginx_ops.DEFAULT_MODE
    pol["ban_mode"] = mode
    if "silent_log" in params:
        pol["silent_log"] = _need(params, "silent_log", bool)

    notes, changed = [], []
    if apply_sites:
        try:
            res = nginx_ops.apply_sites(cfg)
            changed, notes = res.get("changed") or [], res.get("notes") or []
        except nginx_ops.NginxError as exc:
            # 站点没改成，配置也别落盘，保持两边一致
            pol["ban_mode"] = old
            raise ActionError("站点配置没改成功，已回滚：%s" % exc)

    _save_cfg(cfg)
    msg = "封禁模式：%s → %s" % (nginx_ops.mode_label(old),
                                 nginx_ops.mode_label(mode))
    if apply_sites:
        msg += ("；改了 %d 个站点文件" % len(changed)) if changed else "；站点本来就对，没动"
    return {"msg": msg, "mode": mode, "changed": changed,
            "notes": notes[:10], "wiring": policy_mod.wiring(cfg)}


def act_nginx_apply(cfg, params, ctx):
    """按当前配置把站点重新接线一次（换过 vhost、重装 nginx 之后用）。"""
    try:
        res = nginx_ops.apply_sites(cfg)
    except nginx_ops.NginxError as exc:
        raise ActionError(str(exc))
    changed = res.get("changed") or []
    return {"msg": ("已更新 %d 个站点文件" % len(changed)) if changed
                   else "站点已经是当前模式的写法，没有改动",
            "changed": changed, "notes": (res.get("notes") or [])[:10]}


def act_config_set(cfg, params, ctx):
    """只开放三个安全参数，其余配置项不通过面板改。"""
    from .. import config as config_mod

    key = _need(params, "key", str)
    allowed = {
        "red_threshold_10m": (int, 1, 100000),
        "yellow_threshold_10m": (int, 0, 100000),
        "retention_days": (int, 1, 3650),
    }
    if key not in allowed:
        raise ActionError("该配置项不允许在线修改")
    kind, lo, hi = allowed[key]
    val = _need(params, "value", kind)
    if not lo <= val <= hi:
        raise ActionError("取值需在 %d 到 %d 之间" % (lo, hi))

    # 用当前生效的配置路径，而不是默认路径，避免 CLI 指定 -c 时改错文件
    path = (cfg.get("paths") or {}).get("config") or config_mod.config_path()
    cfg[key] = val
    clean = {k: v for k, v in cfg.items() if not k.startswith("_")}
    config_mod.save(path, clean)
    return {"msg": "%s 已改为 %s" % (key, val)}


# ---------------- 安全策略 ----------------


def _conn(cfg):
    return db_mod.connect(cfg["paths"]["db"])


def _save_cfg(cfg):
    from .. import config as config_mod
    path = (cfg.get("paths") or {}).get("config") or config_mod.config_path()
    clean = {k: v for k, v in cfg.items() if not k.startswith("_")}
    config_mod.save(path, clean)


def act_policy_set(cfg, params, ctx):
    """改策略总开关类的参数。"""
    key = _need(params, "key", str)
    pol = cfg.setdefault("policy", {})
    bools = {"enabled": "策略总开关", "auto_ban": "自动封禁", "dry_run": "演练模式",
             "silent_log": "静默模式记日志"}
    ints = {
        "max_bans_per_run": ("单次封禁上限", 1, 20),
        "max_hours": ("最长封禁时长", 1, 8760),
        "repeat_window_hours": ("复发统计窗口", 1, 8760),
    }
    if key == "ban_mode":
        val = _need(params, "value", str)
        if val not in nginx_ops.MODES:
            raise ActionError("ban_mode 只能是 visible / silent / silent_nolog")
        old = pol.get("ban_mode") or nginx_ops.DEFAULT_MODE
        pol["ban_mode"] = val
        _save_cfg(cfg)
        try:
            res = nginx_ops.apply_sites(cfg)
            changed = len(res.get("changed") or [])
        except nginx_ops.NginxError as exc:
            pol["ban_mode"] = old
            _save_cfg(cfg)
            raise ActionError("站点配置没改成功，已回滚：%s" % exc)
        return {"msg": "封禁模式已改为「%s」%s" % (
                    nginx_ops.mode_label(val),
                    "，同步了 %d 个站点文件" % changed if changed else ""),
                "policy": pol, "wiring": policy_mod.wiring(cfg)}
    if key in bools:
        val = _need(params, "value", bool)
        pol[key] = val
        _save_cfg(cfg)
        return {"msg": "%s已%s" % (bools[key], "开启" if val else "关闭"),
                "policy": pol}
    if key in ints:
        label, lo, hi = ints[key]
        val = _need(params, "value", int)
        if not lo <= val <= hi:
            raise ActionError("%s需在 %d 到 %d 之间" % (label, lo, hi))
        pol[key] = val
        _save_cfg(cfg)
        return {"msg": "%s已改为 %d" % (label, val), "policy": pol}
    # 异常判定线单独放在 policy.limits 里
    limits = {
        "uri_len": ("URI 超长判定线", 64, 8192),
        "req_bytes": ("报文大小判定线", 1024, 10485760),
        "ua_len": ("UA 长度判定线", 32, 4096),
    }
    if key in limits:
        label, lo, hi = limits[key]
        val = _need(params, "value", int)
        if not lo <= val <= hi:
            raise ActionError("%s需在 %d 到 %d 之间" % (label, lo, hi))
        pol.setdefault("limits", {})[key] = val
        _save_cfg(cfg)
        unit = "字符" if key == "ua_len" else "字节"
        return {"msg": "%s已改为 %d %s（对之后的日志生效）" % (label, val, unit),
                "policy": pol}
    raise ActionError("该策略参数不允许在线修改")


def act_policy_rule(cfg, params, ctx):
    """改一条规则的开关、窗口、阈值、时长、生效层。"""
    rid = _need(params, "id", str)[:40]
    patch = params.get("patch")
    if not isinstance(patch, dict):
        raise ActionError("patch 必须是对象")

    pol = cfg.setdefault("policy", {})
    rules = pol.setdefault("rules", [])
    rule = next((r for r in rules if r.get("id") == rid), None)
    if not rule:
        raise ActionError("没有这条规则：%s" % rid)

    allowed = {"enabled", "window", "threshold", "hours", "layer", "name"}
    for key, val in patch.items():
        if key not in allowed:
            raise ActionError("规则字段 %s 不允许修改" % key)
        if key == "enabled":
            if not isinstance(val, bool):
                raise ActionError("enabled 必须是布尔值")
        elif key == "layer":
            if val not in policy_mod.LAYERS:
                raise ActionError("layer 只能是 both / nginx / nft")
        elif key == "name":
            if not isinstance(val, str) or not val.strip() or len(val) > 24:
                raise ActionError("名称需为 1-24 个字符")
            val = val.strip()
        else:
            try:
                val = int(val)
            except (TypeError, ValueError):
                raise ActionError("%s 必须是整数" % key)
            lo, hi = policy_mod.FIELD_LIMITS[key]
            if not lo <= val <= hi:
                raise ActionError("%s 需在 %d 到 %d 之间" % (key, lo, hi))
        rule[key] = val

    _save_cfg(cfg)
    return {"msg": "规则「%s」已更新" % (rule.get("name") or rid), "rule": rule}


def act_policy_whitelist(cfg, params, ctx):
    op = _need(params, "op", str)
    if op not in ("add", "remove"):
        raise ActionError("op 只能是 add / remove")
    raw = _need(params, "ip", str).strip()[:64]
    try:
        addr = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        raise ActionError("不是合法的 IP 或网段：%s" % raw)

    pol = cfg.setdefault("policy", {})
    wl = [str(x) for x in (pol.get("whitelist") or [])]
    # 单个地址存成 1.2.3.4，网段存成 1.2.3.0/24
    key = str(addr) if addr.num_addresses > 1 else str(addr.network_address)

    if op == "add":
        if key in wl:
            return {"msg": "%s 已在白名单里" % key, "whitelist": wl}
        if len(wl) >= 200:
            raise ActionError("白名单最多 200 条")
        wl.append(key)
    else:
        if key not in wl:
            return {"msg": "%s 不在白名单里" % key, "whitelist": wl}
        wl = [x for x in wl if x != key]

    pol["whitelist"] = wl
    _save_cfg(cfg)
    return {"msg": "白名单已更新（%d 条）" % len(wl), "whitelist": wl}


def act_policy_bot(cfg, params, ctx):
    """可信爬虫名单。只做字面匹配，所以限制字符集，避免被当成正则写进来。"""
    op = _need(params, "op", str)
    if op not in ("add", "remove"):
        raise ActionError("op 只能是 add / remove")
    ua = _need(params, "ua", str).strip()[:40]
    if len(ua) < 2 or not re.match(r"^[A-Za-z0-9 ._\-]+$", ua):
        raise ActionError("关键字只支持字母、数字、空格和 . _ -")

    pol = cfg.setdefault("policy", {})
    bots = [str(x) for x in (pol.get("trusted_bots") or [])]
    exist = next((b for b in bots if b.lower() == ua.lower()), None)

    if op == "add":
        if exist:
            return {"msg": "%s 已在名单里" % ua, "trusted_bots": bots}
        if len(bots) >= 50:
            raise ActionError("最多 50 条")
        bots.append(ua)
    else:
        if not exist:
            return {"msg": "%s 不在名单里" % ua, "trusted_bots": bots}
        bots = [b for b in bots if b.lower() != ua.lower()]

    pol["trusted_bots"] = bots
    _save_cfg(cfg)
    return {"msg": "可信爬虫名单已更新（%d 条）" % len(bots),
            "trusted_bots": bots}


def act_policy_run(cfg, params, ctx):
    """手动跑一次评估。默认只观察，apply=true 才真的下发。"""
    apply = bool(params.get("apply", False))
    conn = _conn(cfg)
    try:
        res = policy_mod.evaluate(conn, cfg, apply=apply, source="manual")
    finally:
        conn.close()
    return {"msg": res.get("msg", ""), "result": res}


def act_geo_lookup(cfg, params, ctx):
    ip = _norm_ip(params.get("ip"))
    conn = _conn(cfg)
    try:
        recs = geo_mod.enrich(conn, cfg, [ip], force=True)
    finally:
        conn.close()
    rec = recs.get(ip)
    if not rec:
        raise ActionError("查不到 %s 的归属地（接口不可用或已关闭查询）" % ip)
    return {"msg": "%s：%s" % (ip, geo_mod.label_of(rec) or "未知"),
            "ip": ip, "geo": rec}


# ---------------- 端口出入站 ----------------


def act_port_ctrl(cfg, params, ctx):
    """设置某个端口的入站/出站类型和协议。"""
    port = _need(params, "port", int)
    direction = _need(params, "direction", str)
    mode = _need(params, "mode", str)
    proto = params.get("proto")

    meta = _port_meta(cfg, port)
    if not meta:
        raise ActionError("端口 %d 不在受管列表里" % port)
    if direction == "in" and meta.get("readonly"):
        raise ActionError("%s 不允许从面板改入站" % meta.get("label", port))

    label = meta.get("label") or str(port)
    warn = ""
    if direction == "in" and mode == "deny":
        if int(port) == 22:
            warn = "。⚠ SSH 端口已禁止入站，只能从 PVE Console 恢复"
        elif int(port) == int(cfg.get("admin_port") or 8088):
            raise ActionError("面板端口不允许禁止入站")
        else:
            warn = "。该端口的连接会被全部丢弃"

    try:
        nft_ops.set_port_ctrl(cfg, port, direction, mode, proto=proto)
    except nft_ops.NftError as exc:
        raise ActionError(str(exc))

    way = "入站" if direction == "in" else "出站"
    tail = ""
    if proto:
        tail = " · %s" % nft_ops.PROTO_LABEL.get(proto, proto)
    return {
        "msg": "%s（%d）%s：%s%s%s" % (label, port, way,
                                      nft_ops.MODE_LABEL.get(mode, mode), tail, warn),
        "warning": bool(warn),
        "port": port, "direction": direction, "mode": mode,
    }


# ---------------- 进程守护 ----------------


def _unit_err(exc):
    raise ActionError(str(exc))


def act_svc_set(cfg, params, ctx):
    unit = _need(params, "unit", str)
    action = _need(params, "action", str)
    if action not in ("start", "stop", "restart", "enable", "disable"):
        raise ActionError("不支持的操作")
    try:
        return units_ops.set_state(cfg, unit, action)
    except units_ops.UnitError as exc:
        _unit_err(exc)


def act_svc_guard(cfg, params, ctx):
    enabled = _need(params, "enabled", bool)
    try:
        res = units_ops.set_guard(cfg, enabled)
    except units_ops.UnitError as exc:
        _unit_err(exc)
    try:
        cfg.setdefault("daemon", {})["guard"] = bool(enabled)
        _save_cfg(cfg)
    except Exception:  # noqa: BLE001  配置写失败不影响已生效的 drop-in
        pass
    return res


def act_svc_heal(cfg, params, ctx):
    try:
        return units_ops.heal(cfg)
    except units_ops.UnitError as exc:
        _unit_err(exc)


# ---------------- 防火墙规则（云厂商式） ----------------


def _fw_guard(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except (fw_ops.FwError, nft_ops.NftError) as exc:
        raise ActionError(str(exc))


def act_fw_save(cfg, params, ctx):
    rid = (params.get("id") or "").strip()
    payload = {k: params.get(k) for k in
               ("name", "dir", "proto", "port", "src", "action", "note", "enabled")
               if k in params}
    if rid:
        return _fw_guard(fw_ops.update, cfg, rid, payload)
    return _fw_guard(fw_ops.add, cfg, payload)


def act_fw_del(cfg, params, ctx):
    rid = _need(params, "id", str)
    return _fw_guard(fw_ops.remove, cfg, rid)


def act_fw_toggle(cfg, params, ctx):
    rid = _need(params, "id", str)
    enabled = _need(params, "enabled", bool)
    return _fw_guard(fw_ops.toggle, cfg, rid, enabled)


def act_fw_move(cfg, params, ctx):
    rid = _need(params, "id", str)
    delta = _need(params, "delta", int)
    return _fw_guard(fw_ops.move, cfg, rid, delta)


def act_fw_policy(cfg, params, ctx):
    direction = _need(params, "direction", str)
    policy = _need(params, "policy", str)
    return _fw_guard(fw_ops.set_policy, cfg, direction, policy)


def act_fw_container(cfg, params, ctx):
    enabled = _need(params, "enabled", bool)
    return _fw_guard(fw_ops.set_container, cfg, enabled)


def act_fw_seed(cfg, params, ctx):
    return _fw_guard(fw_ops.seed_from_ports, cfg)


# ---------------- 地域封锁（境内 / 境外） ----------------


def _geo_guard(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except (geo_ops.GeoError, nft_ops.NftError) as exc:
        raise ActionError(str(exc))


def act_geo_lock(cfg, params, ctx):
    direction = _need(params, "direction", str)
    enabled = _need(params, "enabled", bool)
    scope = params.get("scope")
    if scope is not None:
        scope = str(scope)
    force = bool(params.get("force", False))
    return _geo_guard(geo_ops.set_lock, cfg, direction, enabled,
                      scope=scope, client=(ctx or {}).get("ip"), force=force)


def act_geo_scope(cfg, params, ctx):
    return _geo_guard(geo_ops.set_scope, cfg, _need(params, "scope", str))


def act_geo_allow(cfg, params, ctx):
    return _geo_guard(geo_ops.set_allow, cfg, _need(params, "op", str),
                      _need(params, "ip", str))


def act_geo_container(cfg, params, ctx):
    return _geo_guard(geo_ops.set_container, cfg,
                      _need(params, "enabled", bool))


def act_geo_cn(cfg, params, ctx):
    return _geo_guard(geo_ops.refresh_cn, cfg)


ACTIONS = {
    "port.set": act_port_set,
    "port.ctrl": act_port_ctrl,
    "fw.save": act_fw_save,
    "fw.del": act_fw_del,
    "fw.toggle": act_fw_toggle,
    "fw.move": act_fw_move,
    "fw.policy": act_fw_policy,
    "fw.container": act_fw_container,
    "fw.seed": act_fw_seed,
    "geo.lock": act_geo_lock,
    "geo.scope": act_geo_scope,
    "geo.allow": act_geo_allow,
    "geo.container": act_geo_container,
    "geo.cn": act_geo_cn,
    "svc.set": act_svc_set,
    "svc.guard": act_svc_guard,
    "svc.heal": act_svc_heal,
    "ssh.set": act_ssh_set,
    "ssh.password": act_ssh_password,
    "auth.password": act_auth_password,
    "ssh.port": act_ssh_port,
    "ssh.port.confirm": act_ssh_port_confirm,
    "ssh.port.rollback": act_ssh_port_rollback,
    "ip.block": act_ip_block,
    "ip.unblock": act_ip_unblock,
    "cf.refresh": act_cf_refresh,
    "cf.set": act_cf_set,
    "cf.test": act_cf_test,
    "cf.rules": act_cf_rules,
    "cf.sync": act_cf_sync,
    "cf.unblock": act_cf_unblock,
    "cf.purge": act_cf_purge,
    "nginx.mode": act_nginx_mode,
    "nginx.apply": act_nginx_apply,
    "config.set": act_config_set,
    "policy.set": act_policy_set,
    "policy.rule": act_policy_rule,
    "policy.whitelist": act_policy_whitelist,
    "policy.bot": act_policy_bot,
    "policy.run": act_policy_run,
    "geo.lookup": act_geo_lookup,
}


def run(cfg, name, params, ctx):
    fn = ACTIONS.get(name)
    if not fn:
        raise ActionError("未知动作：%s" % name)
    return fn(cfg, params or {}, ctx)
