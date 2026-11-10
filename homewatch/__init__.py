# -*- coding: utf-8 -*-
"""HomeWatch - 家庭公网入口态势监控。

采集 nginx 访问日志、nftables 拦截计数器、SSH 爆破记录，
聚合进 SQLite，生成一个只读的局域网态势面板。
"""

__version__ = "0.8.0"
__all__ = ["__version__"]
