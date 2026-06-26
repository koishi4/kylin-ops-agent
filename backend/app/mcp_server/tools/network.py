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


def firewall_status() -> dict:
    """查询本机防火墙规则态势（只读 list/show，绝不改规则）。READONLY。

    安全态势可视化：与 list_listening_ports 配成一对——「开了哪些端口」×「防火墙放行/拦了什么」，
    构成主机暴露面的完整画面，也是受控动作 block_ip 的前置侦察（先看防火墙现状，再决定封禁）。

    探测顺序（用第一个可用后端，全程只读子命令）：
      firewalld（firewall-cmd --list-all） → nftables（nft list ruleset） → iptables（iptables -S）。
    这些 list/show 子命令本身不改状态；但读取规则通常需 root，无权限时优雅返回结构化错误。

    Returns:
        含 backend(命中的后端)/rules(原始规则文本行)/active 的字典；均不可用时结构化报错
    """
    # 注意：此处一律是 --list-all / list ruleset / -S 这类**只读**子命令，
    # 与受控动作 block_ip 的 -I ... -j DROP（改规则）有本质区别，故走 run_cmd 只读探针、不经 executor。
    state = run_cmd(["firewall-cmd", "--state"])
    if state.get("ok") and "running" in (state.get("stdout") or ""):
        listing = run_cmd(["firewall-cmd", "--list-all"])
        if listing.get("ok"):
            return {"ok": True, "level": "READONLY", "backend": "firewalld", "active": True,
                    "rules": (listing.get("stdout") or "").splitlines()}

    nft = run_cmd(["nft", "list", "ruleset"])
    if nft.get("ok") and (nft.get("stdout") or "").strip():
        return {"ok": True, "level": "READONLY", "backend": "nftables", "active": True,
                "rules": (nft.get("stdout") or "").splitlines()}

    ipt = run_cmd(["iptables", "-S"])
    if ipt.get("ok"):
        lines = (ipt.get("stdout") or "").splitlines()
        # 仅有默认 policy（-P ... ACCEPT）而无具体规则 → 视为未启用有效拦截。
        has_rules = any(ln.startswith("-A") for ln in lines)
        return {"ok": True, "level": "READONLY", "backend": "iptables", "active": has_rules,
                "rules": lines}

    return {"ok": False, "level": "READONLY",
            "error": "无法读取防火墙规则：firewalld/nftables/iptables 均不可用或需要 root 权限。"}
