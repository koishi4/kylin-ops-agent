"""文件句柄相关 MCP 工具（封装 lsof）。对应评分①「OS 感知」。

典型场景：定位「谁占用了这个文件/挂载点导致无法卸载/删除」，是根因分析常用手段。
"""
from __future__ import annotations

from ._shell import run_cmd


def list_open_files(path: str) -> dict:
    """列出打开指定文件/目录的进程（封装 lsof）。READONLY。

    Args:
        path: 要排查占用的文件或目录路径
    Returns:
        含占用进程列表（command/pid/user/fd/name）的字典
    """
    # lsof +D 递归目录、直接给文件则查该文件；统一用 lsof <path>
    r = run_cmd(["lsof", "--", path], timeout=15)
    # lsof 在「无进程占用」时返回码非 0 且无输出，这属于正常情况而非错误
    if not r["ok"] and not r.get("stdout"):
        if r.get("error"):
            return {"ok": False, "level": "READONLY", "error": r["error"]}
        return {"ok": True, "level": "READONLY", "path": path, "count": 0, "holders": []}

    holders = []
    rows = r["stdout"].splitlines()
    for line in rows[1:]:  # 跳过表头
        cols = line.split(None, 8)
        if len(cols) >= 9:
            holders.append({
                "command": cols[0], "pid": cols[1], "user": cols[2],
                "fd": cols[3], "type": cols[4], "name": cols[8],
            })
    return {"ok": True, "level": "READONLY", "path": path,
            "count": len(holders), "holders": holders}
