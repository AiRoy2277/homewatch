# -*- coding: utf-8 -*-
"""SSH 端口切换：系统配置、防火墙规则、配置文件和保险丝一起改。

为什么单独一个模块
------------------
换端口不是"改一个数字"：要同时动 ssh.socket 的 drop-in、sshd_config、
nftables 里放行内网到该端口的规则、以及配置里的 watch_ports / managed_ports。
任一步漏掉，结果都是"服务在跑但连不上"。

**保险丝**：改完写一个待确认状态，超过 confirm_minutes 没人确认就自动改回去。
理由很直白——端口改错、或者新端口被上游防火墙挡了，用户就再也进不来，
这台机器又不在手边。默认 15 分钟，够登录验证一次。

回滚顺序与修改相反：先恢复配置，再恢复系统端口，最后重建防火墙。
这样即使中途失败，也不会出现"防火墙放行了新端口、sshd 却还在旧端口"的组合。
"""

import copy
import time

from . import config as config_mod
from .ops import nft as nft_ops
from .ops import sshd as sshd_ops
from .ops import state as state_mod

DEFAULT_CONFIRM_MINUTES = 15
MIN_CONFIRM_MINUTES = 1
MAX_CONFIRM_MINUTES = 120


class PortError(RuntimeError):
    pass


def _save_cfg(cfg):
    path = (cfg.get("paths") or {}).get("config") or config_mod.config_path()
    clean = {k: v for k, v in cfg.items() if not k.startswith("_")}
    config_mod.save(path, clean)


def _retag(cfg, old, new):
    """把配置里所有引用 old 端口的地方改成 new。"""
    old, new = int(old), int(new)

    for rule in (cfg.get("firewall") or {}).get("rules") or []:
        try:
            if int(rule.get("port", 0)) == old:
                rule["port"] = new
        except (TypeError, ValueError):
            continue

    watch = cfg.get("watch_ports")
    if isinstance(watch, dict) and str(watch.get("ssh")) == str(old):
        watch["ssh"] = str(new)

    for item in cfg.get("managed_ports") or []:
        label = (item.get("label") or "").upper()
        if "SSH" not in label:
            continue
        try:
            if int(item.get("port", 0)) == old:
                item["port"] = new
        except (TypeError, ValueError):
            continue


def _conflicts(cfg, port, old):
    """端口冲突检查。返回错误说明或空字符串。"""
    port = int(port)
    if port == int(cfg.get("admin_port") or 8088):
        return "不能占用面板端口 %d，否则面板自己也访问不了" % port

    for item in cfg.get("managed_ports") or []:
        try:
            p = int(item.get("port", 0))
        except (TypeError, ValueError):
            continue
        if p == port and p != int(old):
            return "端口 %d 已被「%s」占用" % (port, item.get("label") or p)

    if (cfg.get("firewall") or {}).get("rules"):
        for rule in cfg["firewall"]["rules"]:
            try:
                p = int(rule.get("port", 0))
            except (TypeError, ValueError):
                continue
            if p == port and p != int(old):
                return "防火墙里端口 %d 已分配给「%s」" % (
                    port, rule.get("name") or p)
    return ""


def change(cfg, port, minutes=None):
    """切换 SSH 端口，返回 {"old","new","active","deadline","minutes"}。

    失败会尽最大努力回滚，然后把异常抛给调用方（面板/CLI 直接显示原因）。
    """
    ok, why = sshd_ops.check_port(port)
    if not ok:
        raise PortError(why)
    new = int(port)

    old = sshd_ops.current_port()
    if new == old:
        raise PortError("新端口与当前端口相同（%d）" % old)

    conflict = _conflicts(cfg, new, old)
    if conflict:
        raise PortError(conflict)

    minutes = int(minutes or cfg.get("ssh_confirm_minutes") or DEFAULT_CONFIRM_MINUTES)
    minutes = max(MIN_CONFIRM_MINUTES, min(MAX_CONFIRM_MINUTES, minutes))

    # 系统层先改（内部失败会自动退回旧端口并抛出原因）
    res = sshd_ops.set_port(new)

    snapshot = copy.deepcopy(cfg)
    try:
        _retag(cfg, old, new)
        _save_cfg(cfg)
        st = state_mod.load(cfg)
        st["ssh_port"] = new
        st["ssh_port_pending"] = {
            "old": old, "new": new,
            "at": int(time.time()),
            "deadline": int(time.time()) + minutes * 60,
        }
        state_mod.save(cfg, st)
        nft_ops.rebuild(st, cfg)
    except Exception as exc:  # noqa: BLE001
        # 配置或防火墙没改成 → 把系统端口也退回去，保持三者一致
        cfg.clear()
        cfg.update(snapshot)
        try:
            _save_cfg(cfg)
        except OSError:
            pass
        try:
            sshd_ops.rollback_port(old)
        except sshd_ops.SshError:
            pass
        try:
            nft_ops.rebuild(state_mod.load(cfg), cfg)
        except nft_ops.NftError:
            pass
        raise PortError("端口已改但配置/防火墙同步失败：%s（已回滚到 %d）"
                        % (exc, old))

    return {
        "old": old, "new": new, "active": res.get("active", True),
        "minutes": minutes,
        "deadline": int(time.time()) + minutes * 60,
    }


def pending(cfg):
    """返回待确认状态，附带剩余秒数。没有则返回 None。"""
    st = state_mod.load(cfg)
    p = st.get("ssh_port_pending")
    if not p:
        return None
    left = int(p.get("deadline") or 0) - int(time.time())
    if left <= 0:
        return p
    out = dict(p)
    out["left"] = left
    return out


def confirm(cfg):
    """确认新端口可用，撤掉保险丝。"""
    st = state_mod.load(cfg)
    p = st.get("ssh_port_pending")
    if not p:
        return {"msg": "没有待确认的端口变更"}
    st["ssh_port"] = int(p.get("new") or st.get("ssh_port") or 22)
    st["ssh_port_pending"] = None
    state_mod.save(cfg, st)
    return {"msg": "已保留新端口 %d" % st["ssh_port"], "port": st["ssh_port"]}


def rollback(cfg, reason="用户撤销"):
    """立刻改回旧端口。"""
    st = state_mod.load(cfg)
    p = st.get("ssh_port_pending")
    if not p:
        return {"msg": "没有待回滚的端口变更"}

    old = int(p.get("old") or 22)
    cur = int(p.get("new") or 0)
    sshd_ops.rollback_port(old)

    try:
        _retag(cfg, cur, old)
        _save_cfg(cfg)
        nft_ops.rebuild(st, cfg)
    finally:
        st["ssh_port"] = old
        st["ssh_port_pending"] = None
        state_mod.save(cfg, st)

    return {"msg": "已回滚到 %d（%s）" % (old, reason), "port": old}


def check_timeout(cfg):
    """保险丝超时检查，由每分钟的采集循环调用。

    返回处理结果（没触发返回 None）。失败不抛异常——采集不能因为回滚失败就整轮挂掉。
    """
    st = state_mod.load(cfg)
    p = st.get("ssh_port_pending")
    if not p:
        return None
    if int(time.time()) < int(p.get("deadline") or 0):
        return None

    old = int(p.get("old") or 22)
    cur = int(p.get("new") or 0)
    waited = max(1, (int(time.time()) - int(p.get("at") or 0)) // 60)
    try:
        sshd_ops.rollback_port(old)
        _retag(cfg, cur, old)
        _save_cfg(cfg)
        nft_ops.rebuild(st, cfg)
        msg = "新端口 %d 在 %d 分钟内未确认，已自动回滚到 %d" % (cur, waited, old)
    except Exception as exc:  # noqa: BLE001
        msg = "端口 %d 未确认，自动回滚失败：%s" % (cur, exc)
    finally:
        st["ssh_port"] = old
        st["ssh_port_pending"] = None
        state_mod.save(cfg, st)
    return {"msg": msg, "port": old}
