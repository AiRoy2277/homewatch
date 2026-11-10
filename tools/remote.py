# -*- coding: utf-8 -*-
"""在线上一跑一条命令（读 .env 的连接信息，密码或私钥都行）。

    python tools/remote.py 'nft list chain inet filter fw_in'
    echo '...' | python tools/remote.py --stdin 'nft -c -f -'
"""
import os
import sys

import paramiko

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_dotenv(path):
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_dotenv(os.path.join(ROOT, ".env"))
HOST = os.environ.get("HOMEWATCH_HOST", "192.168.1.50")
USER = os.environ.get("HOMEWATCH_USER", "root")
PORT = int(os.environ.get("HOMEWATCH_PORT", "22"))
PW = os.environ.get("SSH_PW", "")

args = sys.argv[1:]
stdin_data = None
if args and args[0] == "--stdin":
    stdin_data = sys.stdin.read()
    args = args[1:]
cmd = " ".join(args) or "true"

cli = paramiko.SSHClient()
cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
if PW:
    cli.connect(HOST, port=PORT, username=USER, password=PW, timeout=12)
else:
    key = os.environ.get("SSH_KEY") or os.path.expanduser("~/.ssh/id_ed25519")
    cli.connect(HOST, port=PORT, username=USER, key_filename=key,
                look_for_keys=True, allow_agent=True, timeout=12)

stdin, stdout, stderr = cli.exec_command(cmd, timeout=30)
if stdin_data:
    stdin.write(stdin_data)
    stdin.channel.shutdown_write()
out = stdout.read().decode("utf-8", "replace")
err = stderr.read().decode("utf-8", "replace")
code = stdout.channel.recv_exit_status()
cli.close()
if out:
    sys.stdout.write(out)
if err:
    sys.stderr.write(err)
sys.exit(code)
