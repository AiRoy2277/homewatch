# -*- coding: utf-8 -*-
"""面板登录密码（nginx basic auth 的 htpasswd 文件）。

这两个"密码"是两件事，面板上要分开写清楚：

- root 密码 —— 系统账号，SSH 登录用，改的是 /etc/shadow；
- 面板登录密码 —— 访问 /api/ 管理接口时的 HTTP Basic 凭据，用户名固定 admin，
  存在 nginx 的 htpasswd 文件里。

本模块只改 htpasswd 里同一个用户的密码字段，保留其他行、文件属主和权限
（线上是 root:www-data 640），改之前留一份 .hw.bak。
"""
import os
import shutil
import subprocess
import time

from .sshd import check_password

DEFAULT_PATH = "/etc/nginx/.htpasswd.homewatch"
DEFAULT_OWNER = ("root", "www-data")
USER = "admin"


class HtpasswdError(Exception):
    pass


def path_of(cfg):
    return (cfg.get("paths") or {}).get("htpasswd") or DEFAULT_PATH


def users_of(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return [ln.split(":", 1)[0].strip() for ln in fh
                    if ":" in ln and ln.strip()]
    except OSError:
        return []


def state(cfg):
    """面板登录凭据的现状：文件在不在、有几个用户、密码多久没换。"""
    p = path_of(cfg)
    info = {"path": p, "exists": False, "user": USER, "users": [],
            "age_days": None, "mtime": None, "backup": False,
            "mode": None, "owner": None, "warnings": []}
    try:
        st = os.stat(p)
    except OSError:
        info["warnings"].append("找不到 %s，管理接口现在应该进不去" % p)
        return info

    info.update({
        "exists": True,
        "users": users_of(p),
        "age_days": int((time.time() - st.st_mtime) // 86400),
        "mtime": int(st.st_mtime),
        "backup": os.path.exists(p + ".hw.bak"),
        "mode": "%04o" % (st.st_mode & 0o777),
    })
    # 文件权限放宽到 others 可读时提醒一句：哈希本身不是密码，但不该外泄
    if st.st_mode & 0o007:
        info["warnings"].append("文件权限 %04o 对其他人可读，建议 0640"
                                % (st.st_mode & 0o777))
    if USER not in info["users"]:
        info["warnings"].append("文件里没有 %s 这个用户，改密码会新增一行" % USER)
    return info


def _hash_password(pw):
    """用 openssl 生成 SHA-512 crypt 哈希（和 install 时的生成方式一致）。"""
    try:
        r = subprocess.run(["openssl", "passwd", "-6", "-stdin"],
                           input=pw + "\n", capture_output=True,
                           text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        raise HtpasswdError("生成密码哈希失败：%s" % exc)
    out = (r.stdout or "").strip()
    if r.returncode != 0 or not out.startswith("$6$"):
        raise HtpasswdError("openssl 没能生成哈希：%s"
                            % ((r.stderr or out).strip()[:120] or "未知错误"))
    return out


def set_password(cfg, pw, user=USER, reload_nginx=True):
    """改密码。只动目标用户那一行，其余内容原样保留。"""
    ok, why = check_password(pw)
    if not ok:
        raise HtpasswdError(why)

    p = path_of(cfg)
    d = os.path.dirname(p) or "."
    if not os.path.isdir(d):
        raise HtpasswdError("目录不存在：%s" % d)

    try:
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except FileNotFoundError:
        lines = []
    except OSError as exc:
        raise HtpasswdError("读不到 %s：%s" % (p, exc))

    hashed = _hash_password(pw)
    entry = "%s:%s" % (user, hashed)
    kept, hit = [], False
    for line in lines:
        if not line.strip():
            continue
        if line.split(":", 1)[0].strip() == user:
            kept.append(entry)
            hit = True
        else:
            kept.append(line)
    if not hit:
        kept.append(entry)
    body = "\n".join(kept) + "\n"

    old_mode, old_owner = 0o640, None
    if os.path.exists(p):
        bak = p + ".hw.bak"
        try:
            st = os.stat(p)
            old_mode = st.st_mode & 0o777
            old_owner = (st.st_uid, st.st_gid)
        except OSError:
            pass
        if not os.path.exists(bak):
            try:
                shutil.copy2(p, bak)
            except OSError:
                pass

    tmp = p + ".hw.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.chmod(tmp, old_mode)
        if old_owner and hasattr(os, "chown"):
            try:
                os.chown(tmp, old_owner[0], old_owner[1])
            except OSError:
                pass          # 非 root 跑不动，交给文件默认属主
        elif not old_owner and hasattr(os, "chown"):
            try:
                import grp
                import pwd
                uid = pwd.getpwnam(DEFAULT_OWNER[0]).pw_uid
                gid = grp.getgrnam(DEFAULT_OWNER[1]).gr_gid
                os.chown(tmp, uid, gid)
            except (KeyError, OSError):
                pass
        os.replace(tmp, p)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise HtpasswdError("写 %s 失败：%s" % (p, exc))

    # 改完读回来确认：行数没丢、哈希形状对
    got = users_of(p)
    if user not in got:
        raise HtpasswdError("写入后没读回 %s，请检查 %s" % (user, p))

    reloaded = None
    if reload_nginx:
        try:
            r = subprocess.run(["systemctl", "reload", "nginx"],
                               capture_output=True, text=True, timeout=20)
            reloaded = r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            reloaded = False
    return {"path": p, "user": user, "users": got, "reloaded": reloaded}
