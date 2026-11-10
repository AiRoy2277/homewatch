#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HomeWatch 部署脚本。

    python deploy/deploy.py push      只上传代码并试跑（最常用）
    python deploy/deploy.py install   首次安装 / 大版本升级
    python deploy/deploy.py check     远程自检 + 读出当前状态
    python deploy/deploy.py cf        只写 Cloudflare token 并重启管理接口

上面的参数都可以写在项目根目录的 .env 里（已被 .gitignore 忽略），
例如 CF_TOKEN=... / CF_ZONE=example.com / SSH_PW=...，省得每次带一长串环境变量。

install 做五件事：
  1. 上传代码
  2. 装 homewatch.timer（采集）和 homewatch-admin.service（管理接口）
  3. 首次生成 basic auth 凭据
  4. 更新 nginx 站点（新增 /api/ 反代）
  5. 把 nftables 升级成集合结构（带 4 分钟自动回滚保护）

连接信息用环境变量覆盖：

    SSH_PW=xxx                    # 必填，root 密码
    HOMEWATCH_HOST=192.168.1.10
    HOMEWATCH_ADMIN_PASSWORD=xxx  # 面板管理员密码，不填则随机生成并打印
"""

import json
import os
import secrets
import string
import sys
import time

try:
    import paramiko
except ImportError:
    sys.exit("需要 paramiko：pip install paramiko")


def load_dotenv(path):
    """把 .env 读进环境变量（已存在的环境变量优先，不覆盖）。"""
    if not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(ROOT, ".env"))

HOST = os.environ.get("HOMEWATCH_HOST", "")
USER = os.environ.get("HOMEWATCH_USER", "root")
PW = os.environ.get("SSH_PW", "")
PORT = int(os.environ.get("HOMEWATCH_PORT", "22"))
PANEL_PORT = int(os.environ.get("HOMEWATCH_PANEL_PORT", "8088"))

REMOTE = "/opt/homewatch"
HTPASSWD = "/etc/nginx/.htpasswd.homewatch"
SKIP_DIRS = {"__pycache__", ".git", ".idea", ".vscode"}


def upload_tree(sftp, local, remote):
    n = 0
    try:
        sftp.mkdir(remote)
    except OSError:
        pass
    for name in sorted(os.listdir(local)):
        if name in SKIP_DIRS:
            continue
        lp = os.path.join(local, name)
        rp = remote + "/" + name
        if os.path.isdir(lp):
            n += upload_tree(sftp, lp, rp)
        elif name.endswith(".pyc"):
            continue
        else:
            sftp.put(lp, rp)
            n += 1
    return n


def gen_password(n=20):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


# 在远端跑的小脚本：把 stdin 里的 JSON 合并进 /opt/homewatch/config.json 的 cloudflare 段。
# 单独放一个文件而不是 python -c，是因为 token 里有特殊字符，塞进 shell 命令行容易被吃掉。
CF_PATCH = '''# -*- coding: utf-8 -*-
import json
import shutil
import sys
import time

p = "/opt/homewatch/config.json"
try:
    with open(p, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
except (OSError, ValueError):
    sys.exit("读不到 %s" % p)

cf = cfg.setdefault("cloudflare", {})
cf.update(json.loads(sys.stdin.read()))
shutil.copy2(p, p + ".bak-" + time.strftime("%Y%m%d-%H%M%S"))
with open(p, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, ensure_ascii=False, indent=2)
    fh.write(chr(10))
print("CF_CONFIG_OK zone=%s token=%s… enabled=%s" % (
    cf.get("zone_name") or cf.get("zone_id"), (cf.get("api_token") or "")[:6],
    cf.get("enabled")))
'''


def cf_config(run, sftp, token, zone, account=""):
    """把 Cloudflare token 写进远端配置（改前自动备份 config.json）。"""
    rp = "/tmp/hw_cf_patch.py"
    fh = sftp.open(rp, "w")
    fh.write(CF_PATCH)
    fh.close()
    patch = {"enabled": True, "api_token": token, "zone_name": zone,
             "auto_sync": True}
    if account:
        patch["account_id"] = account
    out = run("/usr/bin/python3 %s" % rp, stdin_data=json.dumps(patch))
    run("rm -f %s" % rp)
    return out


def main():
    stage = sys.argv[1] if len(sys.argv) > 1 else "push"
    if not HOST:
        sys.exit("缺少 HOMEWATCH_HOST（服务器的内网地址），例如：\n"
                 "  HOMEWATCH_HOST=192.168.1.10 SSH_PW=... python deploy/deploy.py push")
    if not PW and not os.path.exists(os.environ.get("SSH_KEY")
                                     or os.path.expanduser("~/.ssh/id_ed25519")):
        sys.exit("缺少 SSH_PW 环境变量，也没找到私钥（SSH_KEY=...）")

    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if PW:
            cli.connect(HOST, port=PORT, username=USER, password=PW, timeout=12)
        else:
            # 没有密码就走私钥（SSH_KEY 可指定，默认 ~/.ssh/id_ed25519）
            key = os.environ.get("SSH_KEY") or os.path.expanduser("~/.ssh/id_ed25519")
            cli.connect(HOST, port=PORT, username=USER, key_filename=key,
                        look_for_keys=True, allow_agent=True, timeout=12)
    except paramiko.AuthenticationException:
        sys.exit("认证失败：既没有可用的 SSH_PW，也没有服务端接受的私钥"
                 "（可以在 .env 里写 SSH_PW=... 或 SSH_KEY=...）")
    except Exception as exc:  # noqa: BLE001  连不上要有一句人话
        sys.exit("连不上 %s:%s —— %s" % (HOST, PORT, exc))

    sftp = cli.open_sftp()

    def run(cmd, t=120, stdin_data=None):
        si, so, se = cli.exec_command(cmd, timeout=t)
        if stdin_data is not None:
            si.write(stdin_data)
            si.flush()
            si.channel.shutdown_write()
        return (so.read() + se.read()).decode("utf-8", "replace").strip()

    print("== 目标 %s:%s ==" % (HOST, REMOTE))
    print(run("mkdir -p %s /var/lib/homewatch /var/www/homewatch /run/homewatch "
              "/var/log/homewatch" % REMOTE))

    print("== 上传代码 ==")
    sftp.put(os.path.join(ROOT, "hw.py"), REMOTE + "/hw.py")
    n = 1 + upload_tree(sftp, os.path.join(ROOT, "homewatch"), REMOTE + "/homewatch")
    print("已上传 %d 个文件" % n)

    if run("test -f %s/config.json && echo YES" % REMOTE) != "YES":
        sftp.put(os.path.join(ROOT, "config.example.json"), REMOTE + "/config.json")
        print("config.json 已按示例创建")
    print(run("chmod 755 %s/hw.py" % REMOTE))

    print("== 语法检查 ==")
    print(run("cd %s && /usr/bin/python3 -m compileall -q hw.py homewatch "
              "&& echo COMPILE_OK" % REMOTE))

    print("== 试跑采集 ==")
    print(run("/usr/bin/python3 %s/hw.py collect 2>&1 | tail -3" % REMOTE))

    # Cloudflare 配置：CF_TOKEN 有值就一起写进去，不用手工去服务器上改 json
    cf_token = os.environ.get("CF_TOKEN") or os.environ.get("CLOUDFLARE_API_TOKEN", "")
    cf_zone = os.environ.get("CF_ZONE") or os.environ.get("CLOUDFLARE_ZONE", "")
    cf_acct = os.environ.get("CF_ACCOUNT") or ""
    if stage == "cf" or (cf_token and stage in ("push", "install")):
        if not cf_token:
            sys.exit("缺少 CF_TOKEN 环境变量")
        print("== Cloudflare 配置 ==")
        print(cf_config(run, sftp, cf_token, cf_zone, cf_acct))
        print(run("systemctl restart homewatch-admin.service 2>/dev/null; sleep 1; "
                  "systemctl is-active homewatch-admin.service"))
        print(run("/usr/bin/python3 %s/hw.py cf status 2>&1 | head -14" % REMOTE))
        if stage == "cf":
            sftp.close()
            cli.close()
            print("== 完成 ==")
            return

    if stage in ("install", "check"):
        print("== status ==")
        print(run("/usr/bin/python3 %s/hw.py status 2>&1 | head -8" % REMOTE))

    if stage == "install":
        # ---------- 1. systemd ----------
        print("== systemd ==")
        for unit in ("homewatch.service", "homewatch.timer", "homewatch-admin.service"):
            sftp.put(os.path.join(ROOT, "deploy", unit), "/etc/systemd/system/" + unit)
        print(run("systemctl daemon-reload && systemctl enable --now homewatch.timer "
                  "&& echo TIMER_OK"))
        print(run("systemctl enable --now homewatch-admin.service && sleep 2 "
                  "&& systemctl is-active homewatch-admin.service"))
        print(run("ls -l /run/homewatch/admin.sock 2>&1"))

        # ---------- 2. basic auth ----------
        print("== 管理凭据 ==")
        if run("test -f %s && echo YES" % HTPASSWD) == "YES":
            print("已存在，保留原密码（要重置请先删除 %s）" % HTPASSWD)
        else:
            admin_pw = os.environ.get("HOMEWATCH_ADMIN_PASSWORD") or gen_password()
            hashed = run("openssl passwd -6 -stdin", stdin_data=admin_pw + "\n").strip()
            if not hashed.startswith("$6$"):
                print("生成哈希失败：%s" % hashed[:120])
                sys.exit(1)
            sftp.open("/tmp/.htpasswd.homewatch", "w").write(
                "admin:%s\n" % hashed)
            print(run("cp /tmp/.htpasswd.homewatch %s && chmod 640 %s "
                      "&& chown root:www-data %s && rm -f /tmp/.htpasswd.homewatch "
                      "&& echo HTPASSWD_OK" % (HTPASSWD, HTPASSWD, HTPASSWD)))
            print("\n  用户名：admin")
            print("  密码：  %s" % admin_pw)
            print("  （只显示这一次，请立即保存）\n")

        # ---------- 3. nginx ----------
        print("== nginx 站点 ==")
        run("cp -a /etc/nginx/conf.d/homewatch.conf /tmp/homewatch.conf.bak 2>/dev/null")
        sftp.put(os.path.join(ROOT, "deploy", "nginx-homewatch.conf"),
                 "/etc/nginx/conf.d/homewatch.conf")
        test = run("nginx -t 2>&1 | tail -3")
        print(test)
        if "successful" in test:
            print(run("systemctl reload nginx && sleep 2 && echo RELOADED"))
        else:
            print("nginx 校验失败，已回滚")
            run("cp /tmp/homewatch.conf.bak /etc/nginx/conf.d/homewatch.conf")
            sys.exit(1)

        # ---------- 4. nftables 升级 ----------
        print("== nftables 升级为集合结构 ==")
        if "denied_ports" in run("nft list sets inet filter 2>&1"):
            print("已经是集合结构，跳过")
        else:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            bak = "/etc/nftables.conf.bak.%s" % stamp
            print(run("cp -a /etc/nftables.conf %s && echo BACKUP_OK" % bak))
            # 4 分钟内如果 SSH 失联，自动回滚（保险丝）
            print(run(
                "nohup setsid sh -c 'sleep 240; cp %s /etc/nftables.conf; "
                "/usr/sbin/nft -f /etc/nftables.conf' >/dev/null 2>&1 & echo GUARD_STARTED"
                % bak))
            print(run("/usr/bin/python3 %s/hw.py firewall init 2>&1 | tail -4" % REMOTE))
            time.sleep(2)
            if "ALIVE" in run("echo ALIVE"):
                run("pkill -f '%s' " % bak)
                print("SSH 正常，保险丝已取消")
            else:
                print("SSH 失联！4 分钟后会自动回滚，请等待")
                sys.exit(2)
            print(run("nft list chain inet filter input 2>&1 | head -16"))

    # 管理接口是常驻进程：代码换了不重启，面板还是旧逻辑（踩过一次，
    # 部署完以为没生效，其实是进程还跑着老代码）
    if run("systemctl is-active homewatch-admin.service 2>/dev/null").strip() == "active":
        print("== 重启管理接口 ==")
        print(run("systemctl restart homewatch-admin.service && sleep 1 "
                  "&& systemctl is-active homewatch-admin.service"))

    print("== 自检 ==")
    # 页面模板变了不重新渲染，浏览器刷新看到的还是旧 HTML（踩过两次）
    print(run("/usr/bin/python3 %s/hw.py render 2>&1 | tail -3" % REMOTE))
    print(run("/usr/bin/python3 %s/hw.py doctor 2>&1 | head -12" % REMOTE))

    print("== 封禁模式 ==")
    print(run("/usr/bin/python3 %s/hw.py policy mode 2>&1" % REMOTE))

    if stage in ("install", "check"):
        print("== 面板 ==")
        panel = "http://%s:%s" % (HOST, PANEL_PORT)
        print(run("curl -s -o /dev/null -w 'index=%{http_code} ' "
                  "%s/; " % panel +
                  "curl -s -o /dev/null -w 'api_unauth=%{http_code}\\n' " +
                  "%s/api/state" % panel))

    sftp.close()
    cli.close()
    print("== 完成 ==")


if __name__ == "__main__":
    main()
