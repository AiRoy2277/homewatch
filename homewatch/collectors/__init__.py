# -*- coding: utf-8 -*-
"""采集器集合。

每个采集器签名统一为 ``collect(conn, cfg) -> int``，返回本次新增的记录数。
任何一个采集器失败都不应该影响其他两个，所以内部各自吞异常并在
collect_all 里单独核算。
"""

from . import nginx, nft, ssh  # noqa: F401

__all__ = ["nginx", "nft", "ssh"]
