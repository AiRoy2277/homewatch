# -*- coding: utf-8 -*-
"""面板静态文件生成。

注意：这里**不要** re-export ``render`` 函数。
``from .web import render`` 依赖 ``render`` 解析到子模块 ``render.py``，
一旦在包初始化里绑定同名函数，就会变成函数，调用方拿不到 ``summary`` 等成员。
"""

__all__ = []
