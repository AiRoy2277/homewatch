# -*- coding: utf-8 -*-
"""进程守护：把 HomeWatch 相关的 systemd 单元摊平成面板能显示的表格。

面板能做的只有"开 / 停 / 重启 / 开机自启"这四种，单元名走白名单，
不提供任意 systemctl 参数入口。

一个必须小心的地方：**重启管理接口自己**。
如果在请求线程里直接 ``systemctl restart homewatch-admin.service``，
systemd 会先杀掉当前进程，浏览器拿不到响应，面板上就是"点了没反应"。
所以对自己动手时用 ``systemd-run --on-active=2`` 延后两秒执行，
先把 JSON 回给前端，再由 systemd 去重启。
"""

import os
import re
import subprocess
import time

from .. import config as config_mod

GUARD_DIR = "/etc/systemd/system/homewatch-admin.service.d"
GUARD_FILE = os.path.join(GUARD_DIR, "10-homewatch-guard.conf")
ADMIN_SVC = "homewatch-admin.service"
GUARD_TMPL = """# 由 HomeWatch 面板生成：进程守护（崩溃自动拉起）
[Service]
Restart=%s
RestartSec=3
"""

# 白名单。readonly 的单元只展示状态，不给开关（nginx 挂了整站挂，
# 面板也跟着挂，不适合在面板里点着玩）。
UNITS = [
    {"name": "homewatch.timer", "label": "采集定时器",
     "desc": "每分钟唤一次采集，停了就没有新数据", "kind": "timer"},
    {"name": "homewatch.service", "label": "采集任务",
     "desc": "读 nginx 日志写入本地库，一次跑完就退出", "kind": "oneshot",
     "trigger": "homewatch.timer"},
    {"name": "homewatch-admin.service", "label": "管理接口",
     "desc": "面板背后的 Unix socket 服务", "kind": "daemon"},
    {"name": "nginx.service", "label": "Nginx",
     "desc": "站点与面板入口，只读", "kind": "daemon", "readonly": True},
]
UNIT_NAMES = [u["name"] for u in UNITS]
SELF = "homewatch-admin.service"


class UnitError(RuntimeError):
    pass


def _run(args, timeout=20):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise UnitError(str(exc))


def _systemctl(*args):
    return _run(["systemctl"] + list(args))


def _show(unit):
    """一次 systemctl show 取回所有要展示的属性。"""
    props = ("ActiveState,SubState,UnitFileState,ExecMainPID,NRestarts,"
             "ActiveEnterTimestamp,MemoryCurrent,Result,Description,"
             "NextElapseUSecRealtime,LastTriggerUSec")
    r = _systemctl("show", unit, "-p", props)
    out = {}
    for line in (r.stdout or "").splitlines():
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k] = v
    return out


def _secs_from_usec(raw):
    """systemd 的 usec 时间戳转 epoch 秒；n/a 或空返回 0。"""
    if not raw or not raw.isdigit():
        return 0
    usec = int(raw)
    if usec <= 0:
        return 0
    # 实时时钟的单位是 1970 起的微秒
    return usec // 1000000


def _human_bytes(n):
    try:
        n = int(n)
    except (TypeError, ValueError):
        return ""
    if n <= 0 or n >= 2 ** 60:  # 2^60 是 systemd 表示"未知"的哨兵值
        return ""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%.0f %s" if unit == "B" else "%.1f %s") % (n, unit)
        n /= 1024.0
    return ""


def guard_state():
    """读取守护实际是否生效（不只看配置里的开关）。

    两处都可能配 Restart：面板写的 drop-in，以及 unit 文件本身。
    只看 drop-in 会把"unit 里已经写了 Restart=always"误报成没开。
    """
    try:
        with open(GUARD_FILE, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        text = ""
    if text:
        m = re.search(r"^\s*Restart\s*=\s*(\S+)", text, re.M)
        restart = (m.group(1) if m else "").strip()
        return {"on": restart not in ("", "no"), "file": GUARD_FILE,
                "restart": restart, "source": "dropin"}

    # 没有 drop-in：读生效值（systemd 已经把 unit 和所有 drop-in 合并好了）
    r = _systemctl("show", ADMIN_SVC, "-p", "Restart", "-p", "FragmentPath")
    props = {}
    for line in (r.stdout or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()
    restart = props.get("Restart", "")
    return {
        "on": restart not in ("", "no"),
        "file": props.get("FragmentPath") or ADMIN_SVC,
        "restart": restart,
        "source": "unit" if restart else "",
    }


def _last_collect_ts(cfg):
    """最近一次采集跑完的时间，用来判断"守护真的在跑吗"。

    优先用 meta.collect_at 心跳：站点安静时 hits 里可能半小时没有新行，
    拿 MAX(hits.ts) 当心跳会把"没流量"误报成"采集挂了"。
    """
    from .. import db as db_mod
    try:
        conn = db_mod.connect(cfg["paths"]["db"])
    except Exception:  # noqa: BLE001
        return 0
    try:
        beat = db_mod.meta_get_int(conn, "collect_at", 0)
        if beat:
            return beat
        row = conn.execute("SELECT MAX(ts) FROM hits").fetchone()
        return int((row or [0])[0] or 0)
    except Exception:  # noqa: BLE001
        return 0
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


def status(cfg=None):
    cfg = cfg or config_mod.load()
    units = []
    failed = []
    for meta in UNITS:
        try:
            s = _show(meta["name"])
        except (UnitError, OSError):
            s = {}
        active = (s.get("ActiveState") or "").lower()
        enabled = (s.get("UnitFileState") or "").lower()
        item = {
            "name": meta["name"],
            "label": meta["label"],
            "desc": meta["desc"],
            "kind": meta["kind"],
            "readonly": bool(meta.get("readonly")),
            "active": active,
            "sub": (s.get("SubState") or "").lower(),
            "enabled": enabled in ("enabled", "enabled-runtime", "static"),
            "unit_state": enabled,
            "pid": int(s.get("ExecMainPID") or 0) or 0,
            "restarts": int(s.get("NRestarts") or 0) or 0,
            "result": (s.get("Result") or "").lower(),
            "memory": _human_bytes(s.get("MemoryCurrent")),
            "since": _secs_from_usec(s.get("ActiveEnterTimestamp")),
            "description": s.get("Description") or meta["desc"],
            "next": 0,
        }
        if meta["kind"] == "timer":
            item["next"] = _secs_from_usec(s.get("NextElapseUSecRealtime"))
            item["last_trigger"] = _secs_from_usec(s.get("LastTriggerUSec"))
        if active not in ("active", "activating", "reloading"):
            failed.append(meta["label"])
        units.append(item)

    g = guard_state()
    last = _last_collect_ts(cfg)
    lag = int(time.time()) - last if last else 0
    warnings = []
    if not g["on"]:
        warnings.append("进程守护已关闭：管理接口崩溃后不会自动拉起")
    timer = next((u for u in units if u["kind"] == "timer"), None)
    if timer and timer["active"] != "active":
        warnings.append("采集定时器未运行，页面数据会停止更新")
    if last and lag > 180:
        warnings.append("已经 %d 分钟没有新采集，检查采集任务" % (lag // 60))
    if not last:
        warnings.append("库里还没有采集数据")

    return {
        "units": units,
        "guard": g,
        "last_collect": last,
        "lag": lag,
        "warnings": warnings,
        "checked_at": int(time.time()),
    }


def _need_root():
    if os.geteuid() != 0:
        raise UnitError("需要 root 权限才能操作系统服务")


def _schedule_restart(unit):
    """延后两秒重启指定单元，先把响应回给浏览器。"""
    stamp = "%d" % (int(time.time()) % 100000)
    args = ["systemd-run", "--on-active=2", "--collect", "--quiet",
            "--unit=hw-svc-%s" % stamp, "systemctl", "restart", unit]
    r = _run(args)
    if r.returncode == 0:
        return True
    # 没有 systemd-run 就退回 --no-block：响应可能被吃掉，前端会重连
    r2 = _systemctl("restart", "--no-block", unit)
    if r2.returncode != 0:
        raise UnitError((r2.stderr or "").strip() or "重启失败")
    return False


def set_state(cfg, unit, action):
    _need_root()
    if unit not in UNIT_NAMES:
        raise UnitError("不认识的单元：%s" % unit)
    meta = next(u for u in UNITS if u["name"] == unit)
    if meta.get("readonly"):
        raise UnitError("%s 不允许从面板操作" % meta["label"])

    if action == "restart" and unit == SELF:
        delayed = _schedule_restart(unit)
        return {"msg": "管理接口将在 2 秒后重启，页面稍后自动重连",
                "delayed": delayed}

    if action == "start":
        if meta["kind"] == "oneshot":
            # 采集任务是 oneshot，start 会阻塞到跑完
            r = _systemctl("start", unit)
            if r.returncode != 0:
                raise UnitError((r.stderr or "").strip() or "启动失败")
            return {"msg": "%s 已执行一次" % meta["label"]}
        r = _systemctl("start", unit)
        msg = "%s 已启动" % meta["label"]
    elif action == "stop":
        r = _systemctl("stop", unit)
        msg = "%s 已停止" % meta["label"]
    elif action == "restart":
        r = _systemctl("restart", unit)
        msg = "%s 已重启" % meta["label"]
    elif action == "enable":
        args = ["enable"]
        if meta["kind"] == "daemon":
            args.append("--now")
        r = _systemctl(*(args + [unit]))
        msg = "%s 已设为开机自启" % meta["label"]
    elif action == "disable":
        r = _systemctl("disable", unit)
        msg = "%s 已取消开机自启（当前进程不受影响）" % meta["label"]
    else:
        raise UnitError("不支持的操作：%s" % action)

    if r.returncode != 0:
        raise UnitError((r.stderr or r.stdout or "").strip()[:200] or "systemctl 执行失败")
    return {"msg": msg}


def set_guard(cfg, enabled):
    """守护开关：改 Restart= 策略并 reload。

    只作用于管理接口这个常驻进程；采集是 timer 触发的一次性任务，
    每轮结束本来就会退出，给它配 Restart 没有意义。
    """
    _need_root()
    os.makedirs(GUARD_DIR, exist_ok=True)
    text = GUARD_TMPL % ("always" if enabled else "no")
    tmp = GUARD_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, GUARD_FILE)
    r = _systemctl("daemon-reload")
    if r.returncode != 0:
        raise UnitError((r.stderr or "").strip() or "daemon-reload 失败")

    # 开关本身不影响正在跑的进程，只有下次异常退出时的行为不同
    return {
        "msg": "进程守护已%s：管理接口%s" % (
            "开启" if enabled else "关闭",
            "崩溃后 3 秒自动拉起" if enabled else "崩溃后不再自动拉起"),
        "guard": guard_state(),
    }


def heal(cfg):
    """一键修复：补齐开机自启、拉起没在跑的关键单元。"""
    _need_root()
    done = []
    r = _systemctl("daemon-reload")
    if r.returncode != 0:
        raise UnitError((r.stderr or "").strip() or "daemon-reload 失败")
    done.append("重载 systemd")

    for unit in ("homewatch.timer", "homewatch-admin.service"):
        r = _systemctl("enable", "--now", unit)
        if r.returncode == 0:
            done.append("确认 %s 运行" % unit)
        else:
            done.append("%s 失败：%s" % (unit, (r.stderr or "").strip()[:80]))

    st = status(cfg)
    timer = next((u for u in st["units"] if u["name"] == "homewatch.timer"), None)
    if timer and timer["active"] != "active":
        _systemctl("start", "homewatch.timer")
        done.append("重新启动采集定时器")

    return {"msg": "；".join(done)}
