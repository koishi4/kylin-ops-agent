"""网络相关 MCP 工具。对应评分①「OS 感知」。
优先用 psutil，无权限时回退 ss 命令，始终返回结构化结果，绝不抛异常给 Agent。
"""
from __future__ import annotations

import psutil

from ._shell import run_cmd


def list_listening_ports() -> dict:
    """列出本机正在监听的端口及其进程。READONLY。

    Returns:
        含监听项列表（port/address/pid/process）的字典
    """
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        # 无权限读取全量连接时，回退到 ss 命令
        r = run_cmd(["ss", "-tlnH"])
        return {"ok": r["ok"], "level": "READONLY", "source": "ss",
                "raw": r.get("stdout", ""), "error": r.get("error")}

    listening = []
    for c in conns:
        if c.status == psutil.CONN_LISTEN and c.laddr:
            pname = None
            if c.pid:
                try:
                    pname = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pname = None
            listening.append({
                "address": c.laddr.ip,
                "port": c.laddr.port,
                "pid": c.pid,
                "process": pname,
            })
    listening.sort(key=lambda x: x["port"])
    return {"ok": True, "level": "READONLY", "source": "psutil",
            "count": len(listening), "listening": listening}


def check_port(port: int) -> dict:
    """检查指定端口是否被监听，并尽可能给出占用进程。READONLY。

    Args:
        port: 要检查的端口号
    Returns:
        含 in_use(bool) 及占用进程信息的字典
    """
    if not (0 < port < 65536):
        return {"ok": False, "level": "READONLY", "error": f"端口超出范围: {port}"}
    info = list_listening_ports()
    if not info.get("ok"):
        return info
    for item in info.get("listening", []):
        if item["port"] == port:
            return {"ok": True, "level": "READONLY", "port": port,
                    "in_use": True, "pid": item["pid"], "process": item["process"],
                    "address": item["address"]}
    return {"ok": True, "level": "READONLY", "port": port, "in_use": False}
