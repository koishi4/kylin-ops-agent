"""内存相关 MCP 工具。对应评分①「OS 感知」。"""
from __future__ import annotations

import psutil


def memory_info() -> dict:
    """查询系统内存与交换分区使用情况。READONLY。

    Returns:
        含物理内存 total/used/available/percent 及 swap 使用情况的字典
    """
    vm = psutil.virtual_memory()
    sw = psutil.swap_memory()
    return {
        "ok": True,
        "level": "READONLY",
        "total_gb": round(vm.total / 1e9, 2),
        "used_gb": round(vm.used / 1e9, 2),
        "available_gb": round(vm.available / 1e9, 2),
        "percent": vm.percent,
        "swap_total_gb": round(sw.total / 1e9, 2),
        "swap_used_gb": round(sw.used / 1e9, 2),
        "swap_percent": sw.percent,
    }
