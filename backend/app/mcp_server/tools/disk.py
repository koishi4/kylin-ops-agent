"""磁盘相关 MCP 工具。对应评分①「OS 感知」。"""
from __future__ import annotations

import psutil


def disk_usage(path: str = "/") -> dict:
    """查询指定挂载点的磁盘使用情况。READONLY。

    Args:
        path: 要查询的挂载点路径，默认根目录 "/"
    Returns:
        含 total_gb/used_gb/free_gb/percent 的字典；路径不存在时返回结构化错误
    """
    try:
        u = psutil.disk_usage(path)
    except (FileNotFoundError, OSError) as e:
        return {"ok": False, "level": "READONLY", "error": f"path not found: {path} ({e})"}
    return {
        "ok": True,
        "level": "READONLY",
        "path": path,
        "total_gb": round(u.total / 1e9, 2),
        "used_gb": round(u.used / 1e9, 2),
        "free_gb": round(u.free / 1e9, 2),
        "percent": u.percent,
    }
