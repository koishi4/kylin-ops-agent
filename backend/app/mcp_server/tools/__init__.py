"""MCP 工具注册表。

每个工具是一个纯函数（便于直接 pytest），在此集中登记读写级别，
由 server.py 统一注册到 FastMCP，由护栏据 level 决定是否需二次确认。

level 取值见 mcp-tool-builder skill：READONLY / MUTATING / PRIVILEGED。
第 2 周补全到进程/网络/磁盘/日志/句柄/系统六大类，全部 READONLY（只做感知，不改系统）。
真正的 MUTATING 动作（kill/clean）走 core/executor.py 并强制过护栏。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .auth import login_history
from .disk import disk_usage, dir_size, find_large_files, inode_usage
from .handle import list_open_files
from .log import query_journal, tail_log
from .memory import memory_info
from .network import check_port, firewall_status, list_listening_ports
from .posture_tool import kernel_posture
from .process import find_zombie_processes, list_processes, process_detail
from .schedule import list_cron_jobs
from .system import list_failed_units, service_status, system_load, uptime_info
from .vuln_intel import query_vuln_intel


@dataclass(frozen=True)
class ToolSpec:
    fn: Callable[..., dict]
    level: str  # READONLY / MUTATING / PRIVILEGED


# 工具名 → 规格。server.py 遍历此表注册；client/编排器据此判断是否自动放行。
REGISTRY: dict[str, ToolSpec] = {
    # 磁盘
    "disk_usage": ToolSpec(disk_usage, "READONLY"),
    "find_large_files": ToolSpec(find_large_files, "READONLY"),
    "dir_size": ToolSpec(dir_size, "READONLY"),
    "inode_usage": ToolSpec(inode_usage, "READONLY"),
    # 内存 / 系统
    "memory_info": ToolSpec(memory_info, "READONLY"),
    "system_load": ToolSpec(system_load, "READONLY"),
    "uptime_info": ToolSpec(uptime_info, "READONLY"),
    "service_status": ToolSpec(service_status, "READONLY"),
    "list_failed_units": ToolSpec(list_failed_units, "READONLY"),
    # 进程
    "list_processes": ToolSpec(list_processes, "READONLY"),
    "find_zombie_processes": ToolSpec(find_zombie_processes, "READONLY"),
    "process_detail": ToolSpec(process_detail, "READONLY"),
    # 网络
    "list_listening_ports": ToolSpec(list_listening_ports, "READONLY"),
    "check_port": ToolSpec(check_port, "READONLY"),
    "firewall_status": ToolSpec(firewall_status, "READONLY"),
    # 日志
    "tail_log": ToolSpec(tail_log, "READONLY"),
    "query_journal": ToolSpec(query_journal, "READONLY"),
    # 句柄
    "list_open_files": ToolSpec(list_open_files, "READONLY"),
    # 登录审计 / 定时任务（安全态势 + 周期性根因分析）
    "login_history": ToolSpec(login_history, "READONLY"),
    "list_cron_jobs": ToolSpec(list_cron_jobs, "READONLY"),
    # 漏洞情报 / 内核姿态（P1：内核漏洞遏制三件套之「时效化情报」+「主机姿态」）
    "query_vuln_intel": ToolSpec(query_vuln_intel, "READONLY"),
    "kernel_posture": ToolSpec(kernel_posture, "READONLY"),
}

__all__ = [
    "REGISTRY", "ToolSpec",
    "disk_usage", "find_large_files", "dir_size", "inode_usage",
    "memory_info", "system_load", "uptime_info", "service_status", "list_failed_units",
    "list_processes", "find_zombie_processes", "process_detail",
    "list_listening_ports", "check_port", "firewall_status",
    "tail_log", "query_journal", "list_open_files",
    "login_history", "list_cron_jobs",
    "query_vuln_intel", "kernel_posture",
]
