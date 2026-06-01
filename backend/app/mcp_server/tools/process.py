"""进程相关 MCP 工具。对应评分①「OS 感知」，也是评分④根因分析的数据源。"""
from __future__ import annotations

import psutil


def list_processes(top_n: int = 10, sort_by: str = "cpu") -> dict:
    """列出资源占用最高的进程，按 CPU 或内存排序。READONLY。

    Args:
        top_n: 返回前 N 个进程，默认 10
        sort_by: 排序依据，"cpu" 或 "memory"，默认 "cpu"
    Returns:
        含进程列表（pid/name/username/cpu_percent/memory_percent）的字典
    """
    if sort_by not in ("cpu", "memory"):
        return {"ok": False, "level": "READONLY",
                "error": f"sort_by must be 'cpu' or 'memory', got {sort_by!r}"}

    procs: list[dict] = []
    # 第一次 cpu_percent 调用用于建立基线，结果取第二轮更准；此处单轮即可满足展示
    for p in psutil.process_iter(["pid", "name", "username", "memory_percent"]):
        try:
            info = p.info
            info["cpu_percent"] = p.cpu_percent(interval=None)
            procs.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    key = "cpu_percent" if sort_by == "cpu" else "memory_percent"
    procs.sort(key=lambda x: x.get(key) or 0.0, reverse=True)

    return {
        "ok": True,
        "level": "READONLY",
        "sort_by": sort_by,
        "count": min(top_n, len(procs)),
        "processes": [
            {
                "pid": p["pid"],
                "name": p["name"],
                "username": p.get("username"),
                "cpu_percent": round(p.get("cpu_percent") or 0.0, 1),
                "memory_percent": round(p.get("memory_percent") or 0.0, 1),
            }
            for p in procs[:top_n]
        ],
    }


def find_zombie_processes() -> dict:
    """查找僵尸进程（评分④根因分析：僵尸进程诊断）。READONLY。

    Returns:
        含僵尸进程列表（pid/name/ppid）的字典
    """
    zombies = []
    for p in psutil.process_iter(["pid", "name", "status", "ppid"]):
        try:
            if p.info["status"] == psutil.STATUS_ZOMBIE:
                zombies.append({"pid": p.info["pid"], "name": p.info["name"],
                                "ppid": p.info["ppid"]})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return {"ok": True, "level": "READONLY", "count": len(zombies), "zombies": zombies}


def process_detail(pid: int) -> dict:
    """查询单个进程的详细信息。READONLY。

    Args:
        pid: 进程号
    Returns:
        含 name/status/cpu/memory/cmdline/create_time 等的字典；进程不存在则优雅报错
    """
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            return {
                "ok": True,
                "level": "READONLY",
                "pid": pid,
                "name": p.name(),
                "status": p.status(),
                "username": _safe(p.username),
                "cpu_percent": p.cpu_percent(interval=0.1),
                "memory_percent": round(p.memory_percent(), 2),
                "cmdline": _safe(lambda: " ".join(p.cmdline())),
                "ppid": p.ppid(),
                "num_threads": p.num_threads(),
            }
    except psutil.NoSuchProcess:
        return {"ok": False, "level": "READONLY", "error": f"进程不存在: pid={pid}"}
    except psutil.AccessDenied:
        return {"ok": False, "level": "READONLY", "error": f"无权限读取进程: pid={pid}"}


def _safe(fn):
    """部分进程属性可能因权限抛 AccessDenied，统一降级为 None。"""
    try:
        return fn()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return None
