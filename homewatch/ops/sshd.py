# -*- coding: utf-8 -*-
"""SSH 开关与 root 密码修改。

Debian 12 用 **socket activation**：``systemd`` 自己持有 22 端口，
收到连接才拉起 sshd。所以只 ``stop ssh.service`` 是没用的，
几秒后端口又会被拉起（实测 pid 从 12765 变成 12948）。

正确顺序是：先 ``disable``（阻止被唤醒），再 ``stop``。

密码通过 stdin 传给 chpasswd，**绝不放进 argv**——
命令行参数会出现在 ``ps`` 里，任何本地用户都能看到。
"""

import os
import re
import subprocess
import time

SSH_UNIT = "ssh"

# Debian 12 的监听端口在 ssh.socket 里，不在 sshd_config。
# 改端口必须写 drop-in：先清空继承来的 ListenStream，再追加新的。
SOCKET_DROPIN_DIR = "/etc/systemd/system/ssh.socket.d"
SOCKET_DROPIN = os.path.join(SOCKET_DROPIN_DIR, "10-homewatch-port.conf")
SSHD_CONFIG = "/etc/ssh/sshd_config"
DROPIN_TMPL = """# 由 HomeWatch 生成，改端口请用面板或 hw.py ssh port
[Socket]
ListenStream=
ListenStream=%d
"""

PORT_MIN, PORT_MAX = 1, 65535
# 动这台机器管理通道的端口，留出回滚时间
DEFAULT_CONFIRM_MINUTES = 15

# 1024 以下是特权端口，sshd 以 root 运行可以绑，但更容易和已有服务撞上，
# 所以不拦，只在冲突检查里靠 ss 判断。


class SshError(RuntimeError):
    pass


def _run(args, text=None, timeout=20):
    try:
        return subprocess.run(args, input=text, capture_output=True,
                              text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SshError(str(exc))


def _systemctl(*args):
    return _run(["systemctl"] + list(args))


def _listening_ports():
    """ss -lntH 里所有处于 LISTEN 的本地端口。"""
    try:
        r = _run(["ss", "-lntH"])
    except SshError:
        return None
    if r.returncode != 0:
        return None
    ports = set()
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        _, _, p = parts[3].rpartition(":")
        if p.isdigit():
            ports.add(int(p))
    return ports


def listening(port=22):
    """指定端口是否有监听。拿不到 ss 输出时返回 None。"""
    ports = _listening_ports()
    if ports is None:
        return None
    return int(port) in ports


def current_port():
    """当前 SSH 监听端口。

    以 ssh.socket 的实际配置为准（socket activation 下 sshd_config 的 Port 不生效），
    拿不到再退到 sshd_config 里未注释的 Port，最后默认 22。
    """
    try:
        r = _systemctl("show", "ssh.socket", "-p", "Listen")
        if r.returncode == 0:
            found = [int(x) for x in re.findall(r":(\d+)\s*\(Stream\)", r.stdout)]
            if found:
                return found[0]
    except SshError:
        pass

    try:
        with open(SSHD_CONFIG, "r", encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"^\s*Port\s+(\d+)\s*$", line, re.I)
                if m:
                    return int(m.group(1))
    except OSError:
        pass
    return 22


def port_in_use(port):
    ports = _listening_ports()
    return bool(ports) and int(port) in ports


def _unit_state(unit, verb):
    """systemctl 查询，失败时返回空字符串而不是把异常抛给面板。"""
    try:
        r = _systemctl(verb, unit)
    except SshError:
        return ""
    return r.stdout.strip()


def status():
    port = current_port()
    return {
        "socket_active": _unit_state("ssh.socket", "is-active") == "active",
        "socket_enabled": _unit_state("ssh.socket", "is-enabled") == "enabled",
        "service_active": _unit_state("ssh.service", "is-active") == "active",
        "listening": listening(port),
        "password_age": password_age(),
        "port": port,
    }


def set_enabled(enabled):
    """开 / 关 SSH。返回 (是否成功, 说明)。"""
    if enabled:
        r = _systemctl("enable", "--now", "ssh.socket")
        if r.returncode != 0:
            raise SshError((r.stderr or "").strip() or "启动 ssh.socket 失败")
        # 保险：socket 起来后立刻确认端口在监听
        time.sleep(1)
        port = current_port()
        if listening(port) is False:
            raise SshError("ssh.socket 已启动但 %d 端口未监听" % port)
        return True

    # 顺序很重要：先断掉唤醒源，再停实例
    for args in (("disable", "ssh.socket"), ("stop", "ssh.socket"), ("stop", "ssh.service")):
        r = _systemctl(*args)
        # disable 对已禁用的单元返回 0；其他失败才算问题
        if r.returncode != 0 and args[0] != "disable":
            raise SshError((r.stderr or "").strip() or "停止 %s 失败" % " ".join(args))
    return False


def check_port(port):
    """校验 SSH 端口，返回 (是否可用, 原因)。"""
    try:
        p = int(port)
    except (TypeError, ValueError):
        return False, "端口必须是整数"
    if p < PORT_MIN or p > PORT_MAX:
        return False, "端口需在 %d–%d 之间" % (PORT_MIN, PORT_MAX)
    return True, ""


def _read_file(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _write_file(path, text):
    """原子写。unit 文件和 sshd_config 都不能出现写一半的状态。"""
    tmp = path + ".hw-tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def _patch_sshd_port(text, port):
    """把 sshd_config 里的 Port 改掉，多余的 Port 行删掉。

    保留未注释的那一行位置，避免把用户的注释块顺序打乱；
    一行都没有就在末尾补一条，兼容"完全用默认值"的配置。
    """
    out, done = [], False
    for line in text.splitlines():
        if re.match(r"^\s*Port\s+\d+\s*$", line, re.I):
            if not done:
                out.append("Port %d" % port)
                done = True
            continue
        out.append(line)
    if not done:
        out.append("")
        out.append("# 由 HomeWatch 维护，与 ssh.socket 的 ListenStream 保持一致")
        out.append("Port %d" % port)
    return "\n".join(out) + "\n"


def _apply(port, restore_config=None):
    """写 drop-in + 改 sshd_config + 重启，返回 SSH 是否处于启用状态。"""
    os.makedirs(SOCKET_DROPIN_DIR, exist_ok=True)
    _write_file(SOCKET_DROPIN, DROPIN_TMPL % int(port))

    if restore_config is not None:
        _write_file(SSHD_CONFIG, restore_config)
    else:
        _write_file(SSHD_CONFIG, _patch_sshd_port(_read_file(SSHD_CONFIG), port))

    r = _systemctl("daemon-reload")
    if r.returncode != 0:
        raise SshError((r.stderr or "").strip() or "systemctl daemon-reload 失败")

    # SSH 本来就是关着的，只改配置，不把它拉起来 —— 否则用户会发现
    # "我只是改了个端口，怎么 SSH 自己开了"。
    # 用 enabled 而不是 active 判断：刚 daemon-reload 时 systemd 会因为
    # 配置变化把 socket 关掉，此时 active=no 但单元仍是启用状态。
    if _systemctl("is-enabled", "ssh.socket").stdout.strip() != "enabled":
        return False

    # 顺序不能反：Accept=no 的 socket 模式下 ssh.service 会一直持有监听 fd，
    # 这时 restart ssh.socket 会被 systemd 拒绝（"Socket service ssh.service
    # already active, refusing"），新端口根本没监听上。
    # 正确做法是先停服务释放 fd，再重启 socket，最后让 socket 把服务拉起来。
    _systemctl("stop", "ssh.service")

    r = _systemctl("restart", "ssh.socket")
    if r.returncode != 0:
        raise SshError((r.stderr or "").strip() or "重启 ssh.socket 失败")

    time.sleep(1)
    if listening(port) is False:
        raise SshError("%d 端口未监听，可能被占用或配置没生效" % int(port))

    # 服务起来与否不影响可用性：连进来时 socket 会自动激活它。
    # 但原本在跑的话就拉起来，保持状态一致。
    _systemctl("start", "ssh.service")
    return True


def set_port(port):
    """切换 SSH 监听端口。失败会自动退回原端口。

    返回 {"old":..., "new":..., "active":...}；active 表示改完后 SSH 是否在监听。
    """
    ok, why = check_port(port)
    if not ok:
        raise SshError(why)

    new = int(port)
    old = current_port()
    if new == old:
        raise SshError("新端口与当前端口相同（%d）" % old)
    if port_in_use(new):
        raise SshError("%d 端口已被其他服务占用，换一个" % new)

    original = _read_file(SSHD_CONFIG)
    _write_file(SSHD_CONFIG + ".hw-bak", original)
    try:
        active = _apply(new)
    except SshError as exc:
        try:
            _apply(old, restore_config=original)
        except SshError:
            raise SshError("%s；回滚到 %d 也失败了，请立刻从 PVE Console 检查 sshd" % (exc, old))
        raise SshError("%s（已回滚到 %d）" % (exc, old))
    return {"old": old, "new": new, "active": active}


def rollback_port(port):
    """把端口改回指定值，用于保险丝超时或用户主动撤销。"""
    ok, why = check_port(port)
    if not ok:
        raise SshError(why)
    backup = None
    try:
        backup = _read_file(SSHD_CONFIG + ".hw-bak")
    except OSError:
        pass
    return _apply(int(port), restore_config=backup)


def password_age():
    """root 密码最后一次修改距今多少天。拿不到返回 None。"""
    try:
        r = _run(["chage", "-l", "root"])
    except SshError:
        return None
    if r.returncode != 0:
        return None
    m = re.search(r"Last password change\s*:\s*(.+)$", r.stdout, re.M)
    if not m:
        return None
    raw = m.group(1).strip()
    if not raw or raw.lower().startswith(("never", "must", "password")):
        return None
    try:
        d = time.mktime(time.strptime(raw, "%b %d, %Y"))
        return int((time.time() - d) // 86400)
    except ValueError:
        return None


WEAK_PATTERNS = [
    (r"^[a-z]+$", "只有小写字母"),
    (r"^[0-9]+$", "只有数字"),
    (r"(.)\1{3,}", "存在连续 4 个及以上相同字符"),
    (r"^(?:123|abc|qwe|password|admin|root)", "以常见弱口令开头"),
]


def check_password(pw):
    """返回 (是否合格, 原因)。"""
    if not isinstance(pw, str):
        return False, "密码必须是字符串"
    if len(pw) < 12:
        return False, "至少 12 位（当前 %d 位）" % len(pw)
    if len(pw) > 128:
        return False, "不能超过 128 位"
    if re.search(r"[\s\x00\n\r]", pw):
        return False, "不能包含空格、换行或控制字符"

    classes = sum([
        bool(re.search(r"[a-z]", pw)),
        bool(re.search(r"[A-Z]", pw)),
        bool(re.search(r"[0-9]", pw)),
        bool(re.search(r"[^a-zA-Z0-9]", pw)),
    ])
    if classes < 3:
        return False, "需要至少包含大小写字母、数字、符号中的三类（当前 %d 类）" % classes

    for pat, why in WEAK_PATTERNS:
        if re.search(pat, pw, re.I):
            return False, "强度不足：%s" % why
    return True, ""


def set_password(pw):
    """修改 root 密码。密码经 stdin 传输，不落 argv、不落日志。"""
    ok, why = check_password(pw)
    if not ok:
        raise SshError(why)

    r = _run(["chpasswd"], text="root:%s\n" % pw)
    if r.returncode != 0:
        raise SshError((r.stderr or "").strip() or "chpasswd 执行失败")

    # 复核：passwd -S 的第二个字段是 P 表示已设置密码
    v = _run(["passwd", "-S", "root"])
    fields = v.stdout.split()
    if len(fields) < 2 or fields[1] != "P":
        raise SshError("密码写入后复核失败：%s" % v.stdout.strip())
    return True
