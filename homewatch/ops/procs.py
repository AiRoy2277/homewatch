# -*- coding: utf-8 -*-
"""谁在监听哪个端口：进程名、PID、以及（如果跑在 Docker 里）容器名。

防火墙规则要能"看得见服务"才有意义——否则用户只知道 8080 开着，
不知道那是 nginx 还是某个容器的端口。这里只读 ``ss`` 和 ``docker ps``，
不做任何变更；拿不到权限就返回空字段，不影响面板。
"""

import re
import subprocess

_SS_USER = re.compile(r'users:\(\("([^"]*)",pid=(\d+)')


def _run(args, timeout=8):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return ""
    return r.stdout or ""


def _containers():
    """{宿主端口: 容器名}。docker 不在或没权限时返回空字典。"""
    out = {}
    text = _run(["docker", "ps", "--no-trunc", "--format",
                 "{{.Names}}\t{{.Image}}\t{{.Ports}}"], timeout=6)
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        name, image, ports = parts[0], parts[1], parts[2]
        for item in ports.split(","):
            m = re.search(r"(?:[\d.]+|\[::\]):(\d+)->", item)
            if m:
                out[int(m.group(1))] = {"name": name, "image": image}
    return out


def listening():
    """{端口: {"procs": [...], "pids": [...], "addr": "...", "container": {...}}}"""
    text = _run(["ss", "-lntupH"])
    used_process = bool(text)
    if not text:
        text = _run(["ss", "-lntH"])
    containers = _containers()
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[4] if used_process else parts[3]
        addr, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        port = int(port)
        item = out.setdefault(port, {"procs": [], "pids": [], "addr": addr,
                                     "container": None})
        if not item["addr"] or item["addr"].startswith("*"):
            item["addr"] = addr
        if used_process:
            for name, pid in _SS_USER.findall(line):
                if name not in item["procs"]:
                    item["procs"].append(name)
                if pid not in item["pids"]:
                    item["pids"].append(int(pid))
        if port in containers:
            item["container"] = containers[port]
    return out


def attach(ports):
    """给端口列表补上"谁在监听"。ports 是 int 列表，返回同结构的字典。"""
    live = listening()
    return {p: live.get(p) for p in ports}
