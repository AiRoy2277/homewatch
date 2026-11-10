# -*- coding: utf-8 -*-
"""把 report 的结果写成面板可读的静态文件。

两个产物：
  data.json   面板每 15 秒拉一次的数据
  index.html  页面骨架（内容全靠 JS 填，所以只有配置变了才需要重写）

写入用 "临时文件 + os.replace" 的方式，保证 nginx 永远读不到半截文件。
"""

import json
import os

from .. import __version__, report
from ..utils import fmt_ts

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "page.html")


def _atomic_write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def load_template():
    with open(TEMPLATE, "r", encoding="utf-8") as fh:
        return fh.read()


def render(conn, cfg):
    """生成 data.json 和 index.html，返回写出的数据。"""
    data = report.build(conn, cfg)
    out_dir = cfg["paths"]["out_dir"]
    os.makedirs(out_dir, exist_ok=True)

    _atomic_write(
        os.path.join(out_dir, "data.json"),
        json.dumps(data, ensure_ascii=False),
    )

    title = cfg.get("title") or "HomeWatch"
    html = (load_template()
            .replace("__TITLE__", title)
            .replace("__VERSION__", "v" + __version__))
    _atomic_write(os.path.join(out_dir, "index.html"), html)
    return data


def summary(data):
    """给 CLI 用的一行摘要。"""
    k = data["kpi"]
    return "[%s] %s | 今日 %d 条，拦截 %d，正常 %d，SSH 尝试 %d（%s）" % (
        data["level"].upper(), data["msg"], k["total_today"], k["blocked_today"],
        k["passed_today"], k["ssh_today"], fmt_ts(data["generated_at"]),
    )
