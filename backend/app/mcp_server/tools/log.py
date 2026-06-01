"""日志相关 MCP 工具。对应评分①「OS 感知」，也是评分④根因分析的关键数据源。
journalctl 是 systemd 日志查询；tail_log 读普通日志文件尾部。
"""
from __future__ import annotations

import os

from ._shell import run_cmd


def tail_log(path: str, lines: int = 50) -> dict:
    """读取日志文件的尾部若干行。READONLY。

    Args:
        path: 日志文件路径
        lines: 读取末尾行数，默认 50，上限 1000
    Returns:
        含 lines 列表的字典；文件不存在/超大时优雅返回错误
    """
    lines = max(1, min(lines, 1000))
    if not os.path.isfile(path):
        return {"ok": False, "level": "READONLY", "error": f"文件不存在或非普通文件: {path}"}
    try:
        # 高效读尾部：从文件末尾按块回读，避免整文件载入内存
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 8192
            data = b""
            pos = size
            while pos > 0 and data.count(b"\n") <= lines:
                step = min(block, pos)
                pos -= step
                f.seek(pos)
                data = f.read(step) + data
        text = data.decode("utf-8", errors="replace").splitlines()
        return {"ok": True, "level": "READONLY", "path": path,
                "lines": text[-lines:], "count": min(lines, len(text))}
    except OSError as e:
        return {"ok": False, "level": "READONLY", "error": str(e)}


def query_journal(unit: str | None = None, since: str | None = None,
                  priority: str | None = None, lines: int = 100) -> dict:
    """查询 systemd journal 日志（封装 journalctl）。READONLY。

    Args:
        unit: 服务单元名，如 "sshd"、"nginx.service"
        since: 起始时间，如 "1 hour ago"、"2026-06-01"
        priority: 优先级过滤，如 "err"、"warning"
        lines: 返回最多行数，默认 100，上限 1000
    Returns:
        含日志文本的字典
    """
    lines = max(1, min(lines, 1000))
    args = ["journalctl", "--no-pager", "-n", str(lines)]
    if unit:
        args += ["-u", unit]
    if since:
        args += ["--since", since]
    if priority:
        args += ["-p", priority]
    r = run_cmd(args, timeout=15)
    if not r["ok"]:
        return {"ok": False, "level": "READONLY",
                "error": r.get("error") or r.get("stderr", "journalctl 查询失败")}
    return {"ok": True, "level": "READONLY", "unit": unit,
            "lines": r["stdout"].splitlines()}
