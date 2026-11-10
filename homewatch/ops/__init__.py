# -*- coding: utf-8 -*-
"""HomeWatch 的写操作层。

这一层是**唯一**会修改系统的代码，其余模块都只读。
所有对外部命令的调用都走 subprocess 的列表参数形式，不拼 shell 字符串，
避免参数里的特殊字符变成命令。

模块划分：
  state  运行时状态的单一来源（JSON 文件）
  nft    nftables 规则生成与应用（端口开关、IP 封禁）
  nginx  nginx 封禁名单读写与 reload
  sshd   SSH 开关、改密码
"""

__all__ = ["state", "nft", "nginx", "sshd"]
