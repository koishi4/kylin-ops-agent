"""磁盘相关 MCP 工具。对应评分①「OS 感知」，find_large_files 是评分④根因分析（磁盘满定位大文件）的核心。"""
from __future__ import annotations

import heapq
import os

import psutil

from ._validate import (
    MAX_SCAN_DIR,
    MAX_SCAN_FILES,
    clamp_scan,
    is_refused_scan_root,
    prune_walk_dirs,
    scan_prune_roots,
)


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
    if is_refused_scan_root(path):
        return {"ok": False, "level": "READONLY",
                "error": f"拒绝扫描伪文件系统/运行时目录: {path}（/proc、/sys、/dev、/run 不可遍历）"}
    if not os.path.isdir(path):
        return {"ok": False, "level": "READONLY", "error": f"目录不存在: {path}"}
    top_n = max(1, min(top_n, 100))
    max_scan = clamp_scan(max_scan, MAX_SCAN_FILES)  # P0-3：硬上限夹断，防超大目录树拖垮服务
    heap: list[tuple[int, str]] = []  # 小顶堆维护当前最大的 top_n
    scanned = 0
    truncated = False
    # 遍历剪枝：伪文件系统 + WSL 的 /mnt Windows 挂载默认不深入（显式以其为扫描根除外）
    pruned = scan_prune_roots(path)
    for root, dirs, files in os.walk(path, onerror=lambda e: None):
        prune_walk_dirs(root, dirs, pruned)
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
    out = {
        "ok": True,
        "level": "READONLY",
        "path": path,
        "scanned": scanned,
        "truncated": truncated,
        "files": [{"path": p, "size_mb": round(s / 1e6, 2)} for s, p in largest],
    }
    if truncated:
        out["reason"] = f"max_scan limit reached ({max_scan})"
    return out


def dir_size(path: str, max_scan: int = 500000) -> dict:
    """统计目录占用的总空间。READONLY。

    Args:
        path: 目标目录
        max_scan: 最多统计文件数上限
    Returns:
        含 total_mb、file_count 的字典
    """
    if is_refused_scan_root(path):
        return {"ok": False, "level": "READONLY",
                "error": f"拒绝扫描伪文件系统/运行时目录: {path}（/proc、/sys、/dev、/run 不可遍历）"}
    if not os.path.isdir(path):
        return {"ok": False, "level": "READONLY", "error": f"目录不存在: {path}"}
    max_scan = clamp_scan(max_scan, MAX_SCAN_DIR)  # P0-3：硬上限夹断
    total = 0
    count = 0
    truncated = False
    # 遍历剪枝：与 find_large_files 同口径（伪文件系统 + /mnt Windows 挂载默认不深入）
    pruned = scan_prune_roots(path)
    for root, dirs, files in os.walk(path, onerror=lambda e: None):
        prune_walk_dirs(root, dirs, pruned)
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
    out = {"ok": True, "level": "READONLY", "path": path,
           "total_mb": round(total / 1e6, 2), "file_count": count, "truncated": truncated}
    if truncated:
        out["reason"] = f"max_scan limit reached ({max_scan})"
    return out


def inode_usage(path: str = "/") -> dict:
    """查询挂载点的 inode（索引节点）使用情况。READONLY。

    评分④根因分析差异化：磁盘「字节没满却写不进文件」的经典故障——inode 耗尽（海量小文件/
    邮件队列/会话缓存把 inode 用光）。`disk_usage` 只看字节占用，看不出这种；本工具补上 inode 维度，
    与 disk_usage 配成一对，让「No space left on device 但 df 显示还有空间」能被一眼定位。

    Args:
        path: 要查询的挂载点路径，默认根目录 "/"
    Returns:
        含 inodes_total/used/free/percent 的字典；路径不存在/不可达时返回结构化错误
    """
    try:
        # statvfs 是只读 syscall，不触发任何遍历或外部命令，零副作用、零开销。
        st = os.statvfs(path)
    except (FileNotFoundError, OSError) as e:
        return {"ok": False, "level": "READONLY", "error": f"path not found: {path} ({e})"}
    total = st.f_files                      # 文件系统 inode 总数
    free = st.f_ffree                       # 空闲 inode 数
    used = total - free
    # 某些文件系统（如 tmpfs 动态分配、overlay）f_files 可能为 0，避免除零。
    percent = round(used / total * 100, 1) if total else 0.0
    return {
        "ok": True,
        "level": "READONLY",
        "path": path,
        "inodes_total": total,
        "inodes_used": used,
        "inodes_free": free,
        "percent": percent,
        # 给根因分析一个直接可用的判据：inode 近满但字节未满 = 典型「小文件耗尽 inode」。
        "exhausted": percent >= 95.0,
    }
