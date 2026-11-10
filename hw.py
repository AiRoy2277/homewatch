#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HomeWatch 启动器。

服务器上这个文件位于 /opt/homewatch/hw.py，包目录在 /opt/homewatch/homewatch/。
保留这层壳有两个好处：

1. systemd 的 ExecStart 不用改（还是 ``python3 /opt/homewatch/hw.py run``）；
2. 手动敲 ``hw.py collect`` 的老习惯继续有效。

本地开发直接 ``python hw.py status`` 即可，不需要安装成包。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from homewatch.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
