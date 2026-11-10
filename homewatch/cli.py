# -*- coding: utf-8 -*-
"""命令行入口。

采集类：collect / render / run / status / doctor
管理类：port / ssh / block / unblock / firewall / admin

管理类命令和面板走的是同一套 ops 代码，所以命令行能做的事，
面板也能做，反之亦然。面板挂掉时命令行就是自救通道。
"""

import argparse
import getpass
import os
import sys

from . import __version__, config, db, geo, policy, report
from .collectors import nft, nginx, ssh
from .utils import fmt_ts, now
from .web import render as render_mod

COMMANDS = (
    "collect", "render", "run", "status", "doctor",
    "port", "fw", "ssh", "block", "unblock", "firewall", "admin",
    "policy", "geo", "cf", "auth", "svc",
)


# ---------------- 采集类 ----------------


def _open(cfg):
    return db.connect(cfg["paths"]["db"])


def _save_cfg(cfg):
    """把当前生效的配置写回它自己的路径。"""
    path = (cfg.get("paths") or {}).get("config") or config.config_path()
    clean = {k: v for k, v in cfg.items() if not k.startswith("_")}
    config.save(path, clean)


def do_collect(cfg, conn):
    n_nginx = nginx.collect(conn, cfg)
    nft.collect(conn, cfg)
    n_ssh = ssh.collect(conn, cfg)

    # 归属地：只补缓存里缺失或过期的，每次最多 geo.max_per_run 个
    n_geo = 0
    try:
        n_geo = len(geo.enrich(conn, cfg))
    except Exception:  # noqa: BLE001  归属地失败不影响采集
        pass

    # 地域封锁的国内网段：只有开着封锁且清单过期（默认 14 天）时才联网
    try:
        from .ops import geoblock as geo_ops
        geo_ops.maybe_refresh(cfg)
        # 重启后 /etc/nftables.conf 里的 cn4/cn6 是空的（几千个网段塞不进
        # 一次 nft 批处理），闸门也就没通电，这里发现没生效就补一次。
        geo_ops.ensure(cfg)
    except Exception:  # noqa: BLE001  拉不到就继续用旧清单
        pass

    # 安全策略：命中规则按配置自动封禁（或只记录）
    pol = None
    try:
        pol = policy.evaluate(conn, cfg)
    except Exception as exc:  # noqa: BLE001
        pol = {"enabled": True, "apply": False, "banned": [],
               "msg": "策略执行失败：%s" % exc}

    # SSH 端口保险丝：改完 N 分钟没确认就自动改回去。
    # 放在采集循环里而不是单独定时器，是因为采集本来每分钟就跑一次。
    guard = None
    try:
        from . import sshport
        guard = sshport.check_timeout(cfg)
    except Exception as exc:  # noqa: BLE001
        guard = {"msg": "端口保险丝检查失败：%s" % exc}

    cutoff = now() - int(cfg.get("retention_days", 30)) * 86400
    for table in ("hits", "paths", "sshfail", "bans", "anomaly", "agent"):
        conn.execute("DELETE FROM %s WHERE ts < ?" % table, (cutoff,))
    # 采集心跳：站点安静时 hits 可能很久没有新行，但采集其实一直在跑。
    # 守护面板用这个时间判断"定时器还在不在工作"，别拿 MAX(hits.ts) 当心跳。
    db.meta_set(conn, "collect_at", str(now()))
    conn.commit()
    return {"nginx": n_nginx, "ssh": n_ssh, "geo": n_geo,
            "policy": pol, "sshport": guard}


def cmd_collect(args):
    cfg = config.load(args.config)
    conn = _open(cfg)
    try:
        r = do_collect(cfg, conn)
    finally:
        conn.close()
    print("collected nginx=%d ssh=%d geo=%d" % (r["nginx"], r["ssh"], r["geo"]))
    if r["policy"] and r["policy"].get("banned"):
        print("policy: %s" % r["policy"].get("msg"))
    if r.get("sshport"):
        print("ssh port: %s" % r["sshport"].get("msg"))
    return 0


def cmd_render(args):
    cfg = config.load(args.config)
    conn = _open(cfg)
    try:
        data = render_mod.render(conn, cfg)
    finally:
        conn.close()
    print("rendered -> %s" % cfg["paths"]["out_dir"])
    print(render_mod.summary(data))
    return 0


def cmd_run(args):
    cfg = config.load(args.config)
    conn = _open(cfg)
    try:
        r = do_collect(cfg, conn)
        data = render_mod.render(conn, cfg)
    finally:
        conn.close()
    print("nginx=%d ssh=%d | %s" % (r["nginx"], r["ssh"], render_mod.summary(data)))
    if r["policy"]:
        print("policy: %s" % r["policy"].get("msg"))
    if r.get("sshport"):
        print("ssh port: %s" % r["sshport"].get("msg"))
    return 0


def cmd_status(args):
    cfg = config.load(args.config)
    conn = _open(cfg)
    try:
        data = report.build(conn, cfg)
        last = policy.last_result(conn)
    finally:
        conn.close()

    print(render_mod.summary(data))
    print("配置：%s" % config.config_path())
    print("数据库：%s" % cfg["paths"]["db"])
    if data["ips"]:
        top = ", ".join("%s(%d)" % (i["ip"], i["n"]) for i in data["ips"][:4])
        print("Top IP：%s" % top)
    pol = cfg.get("policy") or {}
    print("策略：%s，自动封禁 %s，演练 %s，今日自动封禁 %d" % (
        "已启用" if pol.get("enabled", True) else "已停用",
        "开" if pol.get("auto_ban", True) else "关",
        "开" if pol.get("dry_run") else "关",
        data["kpi"]["auto_bans_today"]))
    if last:
        print("上次评估：%s" % last.get("msg", ""))
    if data["leak"]:
        print("⚠ 敏感路径命中 %d 条：" % len(data["leak"]))
        for x in data["leak"]:
            print("    %s  %s" % (x["path"], x["ip"]))
    return 0


def cmd_doctor(args):
    cfg = config.load(args.config)
    print("HomeWatch %s" % __version__)
    print("配置路径      %s" % config.config_path())
    print("配置文件存在  %s" % (
        "是" if os.path.exists(config.config_path()) else "否（用内置默认值）"))

    ok = True
    log = cfg["paths"]["nginx_log"]
    if os.path.exists(log):
        size = os.path.getsize(log)
        print("nginx 日志    可读，%.1f MB" % (size / 1048576.0))
        try:
            with open(log, "rb") as fh:
                fh.seek(max(0, size - 200000))
                tail = [x for x in fh.read().decode("utf-8", "replace").splitlines() if x]
            ua = rl = 0
            for line in tail[-100:]:
                m = nginx.LINE_RE.match(line)
                if not m:
                    continue
                ua += 1 if m.group("ua") is not None else 0
                rl += 1 if m.group("rlen") is not None else 0
            print("日志字段      $http_user_agent %s · $request_length %s%s" % (
                "有" if ua else "无", "有" if rl else "无",
                "" if rl else "（big_req 规则不会命中，配法见 docs/ops.md）"))
        except OSError:
            pass
    else:
        print("nginx 日志    不存在：%s" % log)
        ok = False

    rules = nft.read_ruleset()
    if rules:
        vals = nft.parse_counters(rules, cfg.get("watch_ports") or {})
        print("nft 规则集    可读 %s" % vals)
    else:
        print("nft 规则集    读取失败（非 root 或未安装 nftables）")
        ok = False

    probe = ssh.fetch_json(cfg.get("ssh_unit", "ssh"), now() - 600, timeout=15)
    if probe:
        print("journald      可读，近 10 分钟 %d 条 ssh 日志" % len(probe.splitlines()))
    else:
        print("journald      读取失败（非 root 或无 ssh 单元）")

    db_path = cfg["paths"]["db"]
    try:
        conn = db.connect(db_path)
        rows = conn.execute("SELECT COUNT(*) FROM hits").fetchone()[0]
        last = db.meta_get(conn, "log_offset", "0")
        conn.close()
        print("数据库        可写，hits %d 行，日志偏移 %s" % (rows, last))
    except Exception as exc:  # noqa: BLE001
        print("数据库        不可用：%s" % exc)
        ok = False

    out_dir = cfg["paths"]["out_dir"]
    print("输出目录      %s（存在：%s）" % (
        out_dir, "是" if os.path.isdir(out_dir) else "否"))
    print("时间          %s" % fmt_ts(now()))
    return 0 if ok else 1


# ---------------- 管理类 ----------------


def cmd_port(args):
    from .admin import overview
    from .ops import nft as nft_ops

    cfg = config.load(args.config)
    if args.op == "list":
        data = overview.build(cfg, force=True)
        print("%-6s %-14s %-8s %-8s %s" % ("端口", "名称", "监听", "防火墙", "说明"))
        for p in data["ports"]:
            print("%-6d %-14s %-8s %-8s %s" % (
                p["port"], p["label"],
                "是" if p["listening"] else "否",
                "关闭" if p["closed"] else "放行",
                p["desc"]))
        return 0

    port = args.port
    if not port:
        print("需要指定端口，例如：hw.py port close 8443")
        return 2

    if args.op == "ctrl":
        nft_ops.set_port_ctrl(cfg, port, args.direction, args.mode, proto=args.proto)
        print("已设置 %d %s = %s（%s）" % (
            port, "入站" if args.direction == "in" else "出站",
            args.mode, args.proto))
        return 0

    enabled = args.op == "open"
    nft_ops.set_port(cfg, port, enabled)
    meta = next((m for m in cfg.get("managed_ports") or []
                 if int(m.get("port", 0)) == port), None)
    label = (meta or {}).get("label") or str(port)
    print("%s %s（%d）" % ("已开放" if enabled else "已关闭", label, port))
    if not enabled and port == int(cfg.get("admin_port", 8088)):
        print("⚠ 这是面板自身端口，关闭后本页面将无法访问")
    return 0


def cmd_ssh(args):
    from . import sshport
    from .ops import sshd as ssh_ops

    if args.op == "status":
        st = ssh_ops.status()
        print("socket 运行：%s   开机自启：%s" % (
            "是" if st["socket_active"] else "否",
            "是" if st["socket_enabled"] else "否"))
        print("服务运行：%s   %d 监听：%s" % (
            "是" if st["service_active"] else "否",
            st["port"], "是" if st["listening"] else "否"))
        if st["password_age"] is not None:
            print("root 密码已使用 %d 天" % st["password_age"])

        cfg = config.load(args.config)
        p = sshport.pending(cfg)
        if p:
            left = int(p.get("left") or 0)
            print("⚠ 端口 %s → %s 待确认，剩余 %d 分 %d 秒；超时自动回滚到 %s" % (
                p.get("old"), p.get("new"), left // 60, left % 60, p.get("old")))
        return 0

    if args.op in ("on", "off"):
        enabled = args.op == "on"
        ssh_ops.set_enabled(enabled)
        print("SSH 已%s" % ("开启" if enabled else "关闭"))
        if not enabled:
            print("提示：之后可通过本面板或 PVE Console 重新开启")
        return 0

    if args.op == "passwd":
        pw = getpass.getpass("新密码：")
        if pw != getpass.getpass("再输一次："):
            print("两次输入不一致")
            return 2
        ok, why = ssh_ops.check_password(pw)
        if not ok:
            print("强度不足：%s" % why)
            return 2
        ssh_ops.set_password(pw)
        print("root 密码已更新")
        return 0

    cfg = config.load(args.config)

    if args.op == "port":
        if not args.value:
            st = ssh_ops.status()
            print("当前端口：%d" % st["port"])
            return 0
        try:
            port = int(args.value)
        except ValueError:
            print("端口必须是数字")
            return 2
        try:
            res = sshport.change(cfg, port)
        except (sshport.PortError, ssh_ops.SshError) as exc:
            print("失败：%s" % exc)
            return 1
        print("端口已从 %d 改为 %d" % (res["old"], res["new"]))
        print("请在 %d 分钟内用新端口登录，然后执行：" % res["minutes"])
        print("    hw.py ssh port-confirm     # 保留新端口")
        print("    hw.py ssh port-rollback    # 立刻改回去")
        print("超时未确认会自动回滚到 %d。" % res["old"])
        return 0

    if args.op == "port-confirm":
        print(sshport.confirm(cfg)["msg"])
        return 0

    if args.op == "port-rollback":
        print(sshport.rollback(cfg)["msg"])
        return 0

    return 2


def cmd_auth(args):
    """面板登录密码（nginx basic auth），跟 ssh passwd 改的 root 密码不是一回事。"""
    from .ops import htpasswd as auth_ops

    cfg = config.load(args.config)

    if args.op == "status":
        st = auth_ops.state(cfg)
        print("用户名：%s" % st["user"])
        print("密码文件：%s（%s）" % (st["path"], "存在" if st["exists"] else "不存在"))
        if st["exists"]:
            print("上次修改：%s（%d 天前）" % (
                fmt_ts(st["mtime"]), st["age_days"]))
            print("文件权限：%s   用户：%s" % (st["mode"], "、".join(st["users"])))
        for w in st["warnings"]:
            print("  ! %s" % w)
        print("改密码：hw.py auth passwd（交互），或 printf '新密码\\n' | hw.py auth passwd --stdin")
        return 0

    if args.op == "passwd":
        if args.stdin:
            pw = (sys.stdin.readline() or "").rstrip("\r\n")
            if not pw:
                print("没有从标准输入读到密码")
                return 2
        else:
            pw = getpass.getpass("新密码：")
            if pw != getpass.getpass("再输一次："):
                print("两次输入不一致")
                return 2
        try:
            res = auth_ops.set_password(cfg, pw)
        except auth_ops.HtpasswdError as exc:
            print("改密码失败：%s" % exc)
            return 2
        print("面板登录密码已更新（用户名 %s）" % res["user"])
        print("nginx reload：%s" % ("已重载" if res["reloaded"] else "未重载（不影响新密码生效）"))
        return 0

    print("用法：hw.py auth status | hw.py auth passwd [--stdin]")
    return 2


def cmd_block(args):
    from .ops import nft as nft_ops
    from .ops import nginx as nginx_ops

    cfg = config.load(args.config)
    if args.ip in set(cfg.get("own_ips") or []):
        print("这是你自己的 IP，封掉会失联。若确实要封，先从 own_ips 移除")
        return 2

    done = []
    if args.layer in ("both", "nginx"):
        _, added = nginx_ops.add(cfg, args.ip)
        done.append("nginx" + ("" if added else "(已存在)"))
    if args.layer in ("both", "nft"):
        nft_ops.block_ip(cfg, args.ip, hours=args.hours, reason=args.reason or "manual")
        done.append("nftables")
    print("已封禁 %s：%s（%s）" % (
        args.ip, "、".join(done),
        "永久" if args.hours <= 0 else "%d 小时" % args.hours))
    try:
        conn = _open(cfg)
        try:
            policy.record(conn, args.ip, args.hours, args.layer, "manual",
                          args.reason or "手动封禁", mode="manual")
        finally:
            conn.close()
    except Exception:  # noqa: BLE001  流水写失败不影响封禁
        pass
    return 0


def cmd_unblock(args):
    from .ops import nft as nft_ops
    from .ops import nginx as nginx_ops

    cfg = config.load(args.config)
    hit = []
    try:
        if nft_ops.unblock_ip(cfg, args.ip)[1]:
            hit.append("nftables")
    except Exception:  # noqa: BLE001
        pass
    if nginx_ops.remove(cfg, args.ip)[1]:
        hit.append("nginx")
    print("已解封 %s（%s）" % (args.ip, "、".join(hit)) if hit else "%s 不在名单里" % args.ip)
    return 0


def cmd_firewall(args):
    from .ops import nft as nft_ops

    cfg = config.load(args.config)
    if args.op == "refresh-cf":
        st = nft_ops.refresh_cf(cfg)
        print("Cloudflare 网段已更新：v4 %d 段 / v6 %d 段" % (
            len(st["cf_ips4"]), len(st["cf_ips6"])))
        return 0

    if args.op == "init":
        st = nft_ops.init_firewall(cfg)
        print("规则集已初始化为集合结构：Cloudflare v4 %d 段 / v6 %d 段，"
              "关闭端口 %s" % (
                  len(st.get("cf_ips4") or []), len(st.get("cf_ips6") or []),
                  st.get("denied_ports") or "无"))
        return 0

    print(nft.read_ruleset() or "（读不到规则集，需要 root）")
    return 0


def cmd_policy(args):
    cfg = config.load(args.config)
    pol = cfg.setdefault("policy", {})
    op = args.op
    rest = list(args.arg or [])

    if op == "status":
        print("总开关：%s   自动封禁：%s   演练模式：%s" % (
            "启用" if pol.get("enabled", True) else "停用",
            "开" if pol.get("auto_ban", True) else "关",
            "开" if pol.get("dry_run") else "关"))
        print("单次上限 %s 个，最长 %s 小时，复发窗口 %s 小时，白名单 %d 条" % (
            pol.get("max_bans_per_run", 3), pol.get("max_hours", 720),
            pol.get("repeat_window_hours", 72), len(pol.get("whitelist") or [])))
        from .ops import nginx as nginx_ops
        print("封禁响应：%s（%s）" % (
            nginx_ops.mode_label(nginx_ops.ban_mode(cfg)),
            "写日志" if nginx_ops.logs_of(cfg) else "不写日志"))
        from . import cloudflare as cf_mod
        cs = cf_mod.status(cfg)
        print("Cloudflare：%s%s" % (
            ("已连接 " + cs["zone"]) if cs["configured"] else "未配置",
            "，自动同步开" if (cs["configured"] and cs["auto_sync"]) else ""))
        print("%-16s %-12s %-8s %-8s %-8s %-8s %s" % (
            "规则", "来源", "窗口", "阈值", "封禁", "层", "状态"))
        for r in policy.rules_of(cfg):
            print("%-16s %-12s %-8s %-8s %-8s %-8s %s" % (
                r.get("id"), r.get("source"),
                "%ds" % int(r.get("window", 600)), r.get("threshold"),
                "%sh" % r.get("hours"), r.get("layer"),
                "启用" if r.get("enabled", True) else "停用"))
        conn = _open(cfg)
        try:
            last = policy.last_result(conn)
            bans = policy.recent(conn, 10)
            av = policy.availability(conn, cfg)
        finally:
            conn.close()
        lim = pol.get("limits") or {}
        print("异常判定线：URI≥%s 字节 · 报文≥%s 字节 · UA>%s 字符 · 允许方法 %s" % (
            lim.get("uri_len", 1024), lim.get("req_bytes", 65536),
            lim.get("ua_len", 400), "/".join(pol.get("allowed_methods") or [])))
        for w in av["warnings"]:
            print("⚠ %s" % w)
        if last:
            print("上次评估 %s：%s" % (fmt_ts(last.get("at", 0)), last.get("msg")))
            for x in last.get("banned", [])[:10]:
                print("    %-16s %s  %s" % (x.get("ip"), x.get("hours"),
                                            x.get("geo") or ""))
        if bans:
            print("最近封禁记录：")
            for b in bans:
                print("    %s  %-16s %s" % (
                    fmt_ts(b["ts"]), b["ip"],
                    "%sh" % b["hours"] if b["hours"] else "永久"))
        return 0

    if op == "run":
        conn = _open(cfg)
        try:
            res = policy.evaluate(conn, cfg, apply=bool(args.apply))
        finally:
            conn.close()
        print(res.get("msg"))
        for x in res.get("banned", []):
            print("  %-16s %-6s %-14s %s" % (
                x["ip"], "%sh" % x["hours"] if x["hours"] else "永久",
                x["layer"], x.get("reason") or ""))
        for x in res.get("skipped", [])[:10]:
            print("  跳过 %-16s %s" % (x["ip"], x["why"]))
        if not args.apply and res.get("banned"):
            print("（演练结果，未下发规则。确实要封请加 --apply）")
        return 0

    if op in ("enable", "disable"):
        pol["enabled"] = op == "enable"
        _save_cfg(cfg)
        print("策略总开关已%s" % ("启用" if pol["enabled"] else "停用"))
        return 0

    if op in ("auto", "dry"):
        val = (rest[0] if rest else "").lower()
        if val not in ("on", "off"):
            print("用法：hw.py policy %s on|off" % op)
            return 2
        key = "auto_ban" if op == "auto" else "dry_run"
        pol[key] = val == "on"
        _save_cfg(cfg)
        print("%s已%s" % ("自动封禁" if op == "auto" else "演练模式",
                           "开启" if pol[key] else "关闭"))
        return 0

    if op == "mode":
        from .ops import nginx as nginx_ops
        if not rest:
            cur = nginx_ops.ban_mode(cfg)
            info = policy.wiring(cfg)
            print("当前模式：%s（%s）" % (cur, nginx_ops.mode_label(cur)))
            print("站点接线：%s" % ("已完成" if info.get("wired") else "未接线"))
            for w in info.get("warnings") or []:
                print("⚠ %s" % w)
            return 0
        want = rest[0]
        if want not in nginx_ops.MODES:
            print("用法：hw.py policy mode visible|silent|silent_nolog")
            return 2
        old = nginx_ops.ban_mode(cfg)
        pol["ban_mode"] = want
        try:
            res = nginx_ops.apply_sites(cfg)
        except Exception as exc:  # noqa: BLE001
            pol["ban_mode"] = old
            _save_cfg(cfg)
            print("站点配置没改成功，已回滚：%s" % exc)
            return 1
        _save_cfg(cfg)
        print("封禁模式：%s → %s" % (nginx_ops.mode_label(old),
                                     nginx_ops.mode_label(want)))
        for p in res.get("changed") or []:
            print("  改了 %s" % p)
        for n in res.get("notes") or []:
            print("  %s" % n)
        if not res.get("changed"):
            print("  站点本来就是目标写法，没有改动")
        return 0

    if op == "limit":
        bounds = {"uri_len": (64, 8192), "req_bytes": (1024, 10485760),
                  "ua_len": (32, 4096)}
        lim = pol.setdefault("limits", {})
        if not rest:
            for k in bounds:
                print("%-10s = %s" % (k, lim.get(k)))
            return 0
        if len(rest) < 2 or rest[0] not in bounds:
            print("用法：hw.py policy limit uri_len|req_bytes|ua_len <数值>")
            return 2
        key = rest[0]
        try:
            val = int(rest[1])
        except ValueError:
            print("数值不合法：%s" % rest[1])
            return 2
        lo, hi = bounds[key]
        if not lo <= val <= hi:
            print("%s 需要在 %d 到 %d 之间" % (key, lo, hi))
            return 2
        lim[key] = val
        _save_cfg(cfg)
        print("%s 已改为 %d（对之后的日志生效）" % (key, val))
        return 0

    if op == "bot":
        sub = rest[0] if rest else "list"
        bots = list(pol.get("trusted_bots") or [])
        if sub == "list":
            print("\n".join(bots) if bots else "（未配置可信爬虫）")
            return 0
        if sub not in ("add", "remove") or len(rest) < 2:
            print("用法：hw.py policy bot add|remove <UA 关键字>")
            return 2
        key = rest[1]
        if sub == "add":
            if key.lower() in [b.lower() for b in bots]:
                print("%s 已在名单里" % key)
                return 0
            bots.append(key)
        else:
            bots = [b for b in bots if b.lower() != key.lower()]
        pol["trusted_bots"] = bots
        _save_cfg(cfg)
        print("可信爬虫名单已更新：%d 条" % len(bots))
        return 0

    if op == "whitelist":
        sub = rest[0] if rest else "list"
        wl = list(pol.get("whitelist") or [])
        if sub == "list":
            print("\n".join(wl) if wl else "（白名单为空）")
            return 0
        if sub not in ("add", "remove") or len(rest) < 2:
            print("用法：hw.py policy whitelist add|remove <IP/网段>")
            return 2
        ip = rest[1]
        import ipaddress
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            print("不是合法的 IP 或网段：%s" % ip)
            return 2
        if sub == "add":
            if ip in wl:
                print("%s 已在白名单里" % ip)
                return 0
            if len(wl) >= 200:
                print("白名单最多 200 条")
                return 2
            wl.append(ip)
        else:
            if ip not in wl:
                print("%s 不在白名单里" % ip)
                return 0
            wl = [x for x in wl if x != ip]
        pol["whitelist"] = wl
        _save_cfg(cfg)
        print("白名单已更新：%d 条" % len(wl))
        return 0

    return 2


def cmd_cf(args):
    from . import cloudflare as cf

    cfg = config.load(args.config)
    op = args.op or "status"

    if op == "status":
        s = cf.status(cfg)
        print("启用：%s   已配置：%s   自动同步：%s" % (
            "是" if s["enabled"] else "否",
            "是" if s["configured"] else "否",
            "开" if s["auto_sync"] else "关"))
        print("域名：%s   Token：%s   备注前缀：%s" % (
            s["zone"] or "—", s["token"] if s["has_token"] else "未配置", s["note"]))
        conn = _open(cfg)
        try:
            last = policy.cf_last(conn)
        finally:
            conn.close()
        if last:
            print("上次同步 %s：%s" % (fmt_ts(last.get("at", 0)), last.get("msg") or ""))
        return 0

    if op == "test":
        res = cf.verify(cfg)
        print(("✓ " if res.get("ok") else "✗ ") + (res.get("msg") or ""))
        return 0 if res.get("ok") else 1

    if op == "rules":
        try:
            items = cf.rules(cfg)
        except cf.CfError as exc:
            print("读取失败：%s" % exc)
            return 1
        if not items:
            print("（边缘没有 IP 规则）")
            return 0
        for r in items:
            print("%-18s %-8s %-10s %s" % (
                r.get("ip"), r.get("mode"), (r.get("created") or "")[:10],
                r.get("notes") or ""))
        return 0

    if op == "sync":
        conn = _open(cfg)
        try:
            res = policy.cf_sync(conn, cfg, force=True)
        finally:
            conn.close()
        print(res.get("msg") or "已同步")
        for ip in res.get("added") or []:
            print("  新增 %s" % ip)
        for x in res.get("failed") or []:
            print("  失败 %s：%s" % (x.get("ip"), x.get("error")))
        return 0 if res.get("ok") else 1

    if op in ("block", "unblock"):
        if not args.ip:
            print("用法：hw.py cf %s 1.2.3.4" % op)
            return 2
        try:
            if op == "block":
                r = cf.block(cfg, args.ip, "cli")
                print("已写入边缘规则 %s（%s）" % (args.ip, r.get("id")))
            else:
                n = cf.unblock(cfg, args.ip)
                print("已从边缘删除 %d 条规则" % n if n else "边缘没有 %s 的自动规则" % args.ip)
        except cf.CfError as exc:
            print("失败：%s" % exc)
            return 1
        return 0

    if op == "purge":
        try:
            cf.purge_cache(cfg)
        except cf.CfError as exc:
            print("清缓存失败：%s" % exc)
            return 1
        print("Cloudflare 缓存已清空")
        return 0

    print("用法：hw.py cf status|test|rules|sync|block|unblock|purge")
    return 2


def cmd_svc(args):
    from .ops import units as units_ops

    cfg = config.load(args.config)
    op = args.op or "status"
    try:
        if op == "guard":
            on = (args.value or "on").lower() not in ("off", "0", "false", "no")
            print(units_ops.set_guard(cfg, on)["msg"])
            return 0
        if op == "heal":
            print(units_ops.heal(cfg)["msg"])
            return 0
        if op != "status":
            unit = args.unit
            if not unit:
                print("需要指定单元，例如：hw.py svc restart homewatch-admin.service")
                return 2
            print(units_ops.set_state(cfg, unit, op)["msg"])
            return 0
    except units_ops.UnitError as exc:
        print("失败：%s" % exc)
        return 1

    st = units_ops.status(cfg)
    print("%-28s %-10s %-8s %-6s %s" % ("单元", "状态", "开机自启", "重启", "说明"))
    for u in st["units"]:
        print("%-28s %-10s %-8s %-6d %s" % (
            u["name"], u["active"], "是" if u["enabled"] else "否",
            u["restarts"], u["description"]))
    print("守护（崩溃自动拉起）：%s" % ("开" if st["guard"]["on"] else "关"))
    for w in st["warnings"]:
        print("⚠ %s" % w)
    return 0


def _geo_admin(cfg, args):
    """地域封锁的 CLI。和面板「地域」页走同一套 ops，面板挂了也能改。"""
    from .ops import geoblock as geo_ops

    op = args.op
    try:
        if op == "cn-refresh":
            print(geo_ops.refresh_cn(cfg)["msg"])
            return 0

        if op == "cn-list":
            cn = geo_ops.load_cn(cfg)
            print("# 来源 %s，更新时间 %s" % (
                cn["source"] or "-",
                fmt_ts(cn["updated"]) if cn["updated"] else "从未"))
            for label, items in (("IPv4", cn["v4"]), ("IPv6", cn["v6"])):
                print("\n[%s] %d 段" % (label, len(items)))
                for x in items:
                    print(x)
            return 0

        if op == "nft":
            print(geo_ops.preview(cfg))
            return 0

        if op in ("lock", "unlock", "out"):
            direction = "out" if op == "out" else "in"
            if op == "unlock":
                enabled = False
            else:
                if op == "lock" and args.ip in ("in", "out"):
                    direction = args.ip
                if not (args.on or args.off):
                    print("用法：hw.py geo lock in|out --on [--scope web|all]")
                    return 2
                enabled = bool(args.on)
            res = geo_ops.set_lock(cfg, direction, enabled, scope=args.scope,
                                   force=args.force)
            print(res["msg"])
            for w in res.get("warnings") or []:
                print("⚠ %s" % w)
            return 0

        if op in ("allow", "deny"):
            if not args.ip:
                print("用法：hw.py geo allow 1.2.3.4 / hw.py geo deny 1.2.3.4")
                return 2
            res = geo_ops.set_allow(cfg, "add" if op == "allow" else "remove", args.ip)
            print(res["msg"])
            return 0

        st = geo_ops.status(cfg)
        cn = st["cn"]
        print("外来封锁：%s" % ("开 · " + st["in"]["scope_label"] if st["in"]["enabled"] else "关"))
        if st["in"]["enabled"] and st["in"]["scope"] == "web":
            print("  作用端口：%s" % "、".join(str(p) for p in st["in"]["ports"]))
        print("对外封锁：%s" % ("开" if st["out"]["enabled"] else "关"))
        print("容器转发：%s" % ("也拦" if st["container"] else "不拦"))
        if st["on"]:
            print("规则生效：%s" % ("已通电" if st.get("loaded")
                                   else "未通电（闸门空着，内核里没有网段，等采集进程补）"))
        print("国内网段：IPv4 %d 段 / IPv6 %d 段 · 来源 %s · %s" % (
            cn["v4"], cn["v6"], cn["source"] or "-",
            ("%d 天前更新" % cn["age_days"]) if cn["age_days"] is not None else "从未更新"))
        ex = st["exempt"]
        print("豁免：内网 %d / 我的 IP %d / Cloudflare %d / DNS %d / 自定义 %d" % (
            len(ex["lan"]), len(ex["own"]), ex["cf"], len(ex["dns"]), len(ex["allow"])))
        for x in ex["allow"]:
            print("  + %s" % x)
        if st["counters"]:
            print("命中：外来 %d 包 / %.1f MB · 对外 %d 包 / %.1f MB" % (
                st["hits"]["in"]["packets"], st["hits"]["in"]["bytes"] / 1048576.0,
                st["hits"]["out"]["packets"], st["hits"]["out"]["bytes"] / 1048576.0))
        else:
            print("命中：读不到 nft 计数器")
        return 0
    except geo_ops.GeoError as exc:
        print("失败：%s" % exc)
        return 1


def cmd_geo(args):
    cfg = config.load(args.config)
    conn = _open(cfg)
    try:
        if args.op == "lookup":
            if not args.ip:
                print("用法：hw.py geo lookup 1.2.3.4")
                return 2
            recs = geo.enrich(conn, cfg, [args.ip], force=True)
            rec = recs.get(args.ip)
            if not rec:
                print("查不到（未启用或接口不可用）")
                return 1
            print("%-16s %s" % (rec.get("country") or "-",
                                geo.label_of(rec) or "-"))
            print("  cc=%s region=%s city=%s isp=%s asn=%s" % (
                rec.get("cc"), rec.get("region"), rec.get("city"),
                rec.get("isp"), rec.get("asn")))
            return 0

        if args.op == "refresh":
            recs = geo.enrich(conn, cfg, force=True, limit=50)
            print("已刷新 %d 个 IP 的归属地" % len(recs))
            return 0

        if args.op in ("status", "lock", "unlock", "out", "allow", "deny",
                       "cn-refresh", "cn-list", "nft"):
            return _geo_admin(cfg, args)

        ips = [x["ip"] for x in report.build(conn, cfg)["ips"]]
        cache = geo.attach(conn, ips)
        if not cache:
            print("还没有归属地数据，先跑 hw.py collect")
            return 0
        for ip in ips:
            rec = cache.get(ip) or {}
            print("%-18s %-6s %s" % (ip, rec.get("cc") or "-",
                                     rec.get("label") or "未知"))
        return 0
    finally:
        conn.close()


def cmd_admin(args):
    from .admin import server

    server.serve(args.sock)
    return 0


# ---------------- 入口 ----------------


def cmd_fw(args):
    """防火墙规则：和面板上的"防火墙"页走同一套 ops。"""
    from .ops import fw as fw_ops

    cfg = config.load(args.config)
    op = args.op or "list"
    extra = list(args.args or [])

    def _payload():
        return {
            "name": args.name, "dir": args.dir, "proto": args.proto,
            "port": args.port, "src": args.src, "action": args.action,
            "note": args.note,
        }

    try:
        if op == "list":
            data = fw_ops.list_rules(cfg)
            print("%-4s %-6s %-8s %-6s %-6s %-12s %-6s %-8s %s" % (
                "#", "方向", "动作", "协议", "端口", "来源/目标", "命中", "状态", "名称"))
            for i, r in enumerate(data["rules"], 1):
                print("%-4d %-6s %-8s %-6s %-6s %-12s %-6d %-8s %s" % (
                    i, r["dir_label"], r["action_label"], r["proto_label"],
                    r["port_label"], r["src_label"], r["hits"],
                    "启用" if r["enabled"] else "停用", r["name"]))
            p = data["policy"]
            print("默认策略：入站 %s · 出站 %s · 容器转发 %s · 计数 %s" % (
                fw_ops.POLICY_LABEL[p["in"]], fw_ops.POLICY_LABEL[p["out"]],
                "应用" if data["container"] else "不应用",
                "可读" if data["counters"] else "不可读"))
            return 0

        if op == "nft":
            print(fw_ops.preview(cfg))
            return 0

        if op == "add":
            res = fw_ops.add(cfg, _payload())
        elif op == "edit":
            rid = extra[0] if extra else args.id
            if not rid:
                print("用法：hw.py fw edit <规则ID> --port 22 ...")
                return 2
            res = fw_ops.update(cfg, rid, _payload())
        elif op == "del":
            res = fw_ops.remove(cfg, _need_arg(extra, args.id, "规则ID"))
        elif op in ("on", "off"):
            res = fw_ops.toggle(cfg, _need_arg(extra, args.id, "规则ID"), op == "on")
        elif op in ("up", "down"):
            res = fw_ops.move(cfg, _need_arg(extra, args.id, "规则ID"),
                              1 if op == "down" else -1)
        elif op == "policy":
            if len(extra) < 2:
                print("用法：hw.py fw policy in|out accept|drop")
                return 2
            res = fw_ops.set_policy(cfg, extra[0], extra[1])
        elif op == "container":
            res = fw_ops.set_container(cfg, (extra[0] if extra else "on") != "off")
        elif op == "seed":
            res = fw_ops.seed_from_ports(cfg)
        else:
            print("不支持的子命令：%s" % op)
            return 2
    except fw_ops.FwError as exc:
        print("失败：%s" % exc)
        return 1

    print(res.get("msg", "完成"))
    for w in res.get("warnings") or []:
        print("⚠ %s" % w)
    return 0


def _need_arg(extra, fallback, label):
    val = (extra[0] if extra else "") or fallback
    if not val:
        raise SystemExit("缺少%s" % label)
    return val


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ["run"]
    elif argv[0] not in COMMANDS and not argv[0].startswith("-"):
        argv = ["run"] + argv

    p = argparse.ArgumentParser(
        prog="homewatch", description="家庭公网入口态势监控")
    p.add_argument("-c", "--config", help="配置文件路径，默认 /opt/homewatch/config.json")
    p.add_argument("--version", action="version", version="HomeWatch %s" % __version__)
    sub = p.add_subparsers(dest="cmd")

    for name, help_text in (
        ("collect", "只采集入库"),
        ("render", "只重新生成面板"),
        ("run", "采集 + 渲染（timer 调用）"),
        ("status", "命令行查看当前状态"),
        ("doctor", "环境自检"),
    ):
        sub.add_parser(name, help=help_text)

    sp = sub.add_parser("port", help="列端口 / 开关端口 / 设置出入站类型")
    sp.add_argument("op", choices=["list", "open", "close", "ctrl"])
    sp.add_argument("port", nargs="?", type=int)
    sp.add_argument("--dir", dest="direction", choices=["in", "out"], default="in",
                    help="ctrl 用：入站还是出站")
    sp.add_argument("--mode", choices=["allow", "lan", "cf", "deny"], default="allow",
                    help="ctrl 用：放行 / 仅内网 / 仅 Cloudflare / 禁止")
    sp.add_argument("--proto", choices=["tcp", "udp", "both"], default="tcp")

    sp = sub.add_parser("ssh", help="SSH 状态、开关、改密码、换端口")
    sp.add_argument("op", choices=["status", "on", "off", "passwd",
                                   "port", "port-confirm", "port-rollback"])
    sp.add_argument("value", nargs="?", help="port 后面跟新端口号")

    sp = sub.add_parser("auth", help="面板登录密码：查看、修改")
    sp.add_argument("op", nargs="?", default="status", choices=["status", "passwd"])
    sp.add_argument("--stdin", action="store_true", help="从标准输入读一行密码（脚本用）")

    sp = sub.add_parser("block", help="封禁一个 IP")
    sp.add_argument("ip")
    sp.add_argument("--hours", type=int, default=24, help="封禁时长，0 表示永久")
    sp.add_argument("--layer", choices=["both", "nginx", "nft"], default="both")
    sp.add_argument("--reason", default="")

    sp = sub.add_parser("unblock", help="解封一个 IP")
    sp.add_argument("ip")

    sp = sub.add_parser("firewall", help="查看规则 / 刷新 Cloudflare 网段 / 初始化")
    sp.add_argument("op", nargs="?", choices=["show", "refresh-cf", "init"], default="show")

    sp = sub.add_parser("fw", help="防火墙规则：列出、增删改、排序、默认策略")
    sp.add_argument("op", nargs="?", default="list",
                    choices=["list", "add", "edit", "del", "on", "off", "up", "down",
                             "policy", "container", "seed", "nft"])
    sp.add_argument("args", nargs="*", help="规则 ID / policy 的 in|out accept|drop")
    sp.add_argument("--id", help="规则 ID（也可以直接跟位置参数）")
    sp.add_argument("--name")
    sp.add_argument("--dir", default="in", choices=["in", "out"])
    sp.add_argument("--proto", default="tcp", choices=["tcp", "udp", "icmp", "all"])
    sp.add_argument("--port", default="", help="22 / 8000-8100 / 留空表示全部")
    sp.add_argument("--src", default="", help="来源(入站)/目标(出站)：1.2.3.4,10.0.0.0/8")
    sp.add_argument("--action", default="accept", choices=["accept", "drop"])
    sp.add_argument("--note", default="")

    sp = sub.add_parser("policy", help="安全策略：状态、规则、自动封禁")
    sp.add_argument("op", nargs="?", default="status",
                    choices=["status", "run", "enable", "disable", "auto", "dry",
                             "mode", "whitelist", "limit", "bot"])
    sp.add_argument("arg", nargs="*")
    sp.add_argument("--apply", action="store_true", help="演练之外真的下发规则")

    sp = sub.add_parser("cf", help="Cloudflare 边缘：连通性、规则、同步")
    sp.add_argument("op", nargs="?", default="status",
                    choices=["status", "test", "rules", "sync",
                             "block", "unblock", "purge"])
    sp.add_argument("ip", nargs="?")

    sp = sub.add_parser("geo", help="IP 归属地 / 地域封锁（境内·境外）")
    sp.add_argument("op", nargs="?", default="top",
                    choices=["top", "lookup", "refresh", "status",
                             "lock", "unlock", "out", "allow", "deny",
                             "cn-refresh", "cn-list", "nft"])
    sp.add_argument("ip", nargs="?", help="lookup 用；lock 用 in|out；allow 用 IP")
    sp.add_argument("--on", action="store_true", help="lock 时表示开启")
    sp.add_argument("--off", action="store_true", help="lock 时表示关闭")
    sp.add_argument("--scope", choices=["web", "all"], default=None,
                    help="外来封锁的作用范围：web / all")
    sp.add_argument("--force", action="store_true",
                    help="跳过\"别把你自己挡在外面\"的检查")

    sp = sub.add_parser("svc", help="进程守护：状态、开关服务、修复")
    sp.add_argument("op", nargs="?", default="status",
                    choices=["status", "start", "stop", "restart",
                             "enable", "disable", "guard", "heal"])
    sp.add_argument("unit", nargs="?")
    sp.add_argument("value", nargs="?", help="guard 后面跟 on / off")

    sp = sub.add_parser("admin", help="前台启动管理接口（调试用）")
    sp.add_argument("--sock", default=None)

    args = p.parse_args(argv)
    handler = {
        "collect": cmd_collect,
        "render": cmd_render,
        "run": cmd_run,
        "status": cmd_status,
        "doctor": cmd_doctor,
        "port": cmd_port,
        "ssh": cmd_ssh,
        "auth": cmd_auth,
        "block": cmd_block,
        "unblock": cmd_unblock,
        "firewall": cmd_firewall,
        "fw": cmd_fw,
        "policy": cmd_policy,
        "cf": cmd_cf,
        "geo": cmd_geo,
        "svc": cmd_svc,
        "admin": cmd_admin,
    }.get(args.cmd, cmd_run)
    return handler(args)
