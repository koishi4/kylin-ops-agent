"""MCP 工具注册表。

每个工具是一个纯函数（便于直接 pytest），在此集中登记读写级别，
由 server.py 统一注册到 FastMCP，由护栏据 level 决定是否需二次确认。

level 取值见 mcp-tool-builder skill：READONLY / MUTATING / PRIVILEGED。
第 1 周仅 3 个 READONLY 工具，后续按 roadmap 第 2 周补全网络/日志/句柄/服务。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .disk import disk_usage
from .memory import memory_info
from .process import list_processes


@dataclass(frozen=True)
class ToolSpec:
    fn: Callable[..., dict]
    level: str  # READONLY / MUTATING / PRIVILEGED


# 工具名 → 规格。server.py 遍历此表注册；client/编排器据此判断是否自动放行。
REGISTRY: dict[str, ToolSpec] = {
    "disk_usage": ToolSpec(disk_usage, "READONLY"),
    "memory_info": ToolSpec(memory_info, "READONLY"),
    "list_processes": ToolSpec(list_processes, "READONLY"),
}

__all__ = ["REGISTRY", "ToolSpec", "disk_usage", "memory_info", "list_processes"]
