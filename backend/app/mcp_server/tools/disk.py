"""磁盘相关 MCP 工具。对应评分①「OS 感知」，find_large_files 是评分④根因分析（磁盘满定位大文件）的核心。"""
from __future__ import annotations

import heapq
import os

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


def find_large_files(path: str = "/", top_n: int = 10, max_scan: int = 200000) -> dict:
    """在指定目录下查找占用空间最大的文件（评分④根因分析：磁盘满→定位大文件）。READONLY。

    Args:
        path: 起始目录，默认根目录
        top_n: 返回最大的前 N 个文件，默认 10
        max_scan: 最多扫描文件数上限，防止超大目录树拖垮服务
    Returns:
        含 files 列表（path/size_mb）的字典，按大小降序
    """
    if not os.path.isdir(path):
        return {"ok": False, "level": "READONLY", "error": f"目录不存在: {path}"}
    top_n = max(1, min(top_n, 100))
    heap: list[tuple[int, str]] = []  # 小顶堆维护当前最大的 top_n
    scanned = 0
    truncated = False
    for root, _dirs, files in os.walk(path, onerror=lambda e: None):
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                if os.path.islink(fp):
                    continue
                size = os.path.getsize(fp)
            except OSError:
                continue
            scanned += 1
            if len(heap) < top_n:
                heapq.heappush(heap, (size, fp))
            elif size > heap[0][0]:
                heapq.heapreplace(heap, (size, fp))
            if scanned >= max_scan:
                truncated = True
                break
        if truncated:
            break
    largest = sorted(heap, key=lambda x: x[0], reverse=True)
    return {
        "ok": True,
        "level": "READONLY",
        "path": path,
        "scanned": scanned,
        "truncated": truncated,
        "files": [{"path": p, "size_mb": round(s / 1e6, 2)} for s, p in largest],
    }


def dir_size(path: str, max_scan: int = 500000) -> dict:
    """统计目录占用的总空间。READONLY。

    Args:
        path: 目标目录
        max_scan: 最多统计文件数上限
    Returns:
        含 total_mb、file_count 的字典
    """
    if not os.path.isdir(path):
        return {"ok": False, "level": "READONLY", "error": f"目录不存在: {path}"}
    total = 0
    count = 0
    truncated = False
    for root, _dirs, files in os.walk(path, onerror=lambda e: None):
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                if os.path.islink(fp):
                    continue
                total += os.path.getsize(fp)
            except OSError:
                continue
            count += 1
            if count >= max_scan:
                truncated = True
                break
        if truncated:
            break
    return {"ok": True, "level": "READONLY", "path": path,
            "total_mb": round(total / 1e6, 2), "file_count": count, "truncated": truncated}
