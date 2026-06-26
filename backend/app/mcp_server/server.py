"""MCP Server —— 工具层，对应评分①「OS 感知 + MCP 插件」。

把 tools/REGISTRY 里的纯函数注册成 MCP Tool，通过官方 mcp SDK 暴露。
独立进程，用 stdio 与后端（MCP client）通信，契合赛题「实现 MCP 协议」硬要求。

独立运行（可用 MCP Inspector / 后端 client 连接）：
    python -m app.mcp_server.server
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .tools import REGISTRY

mcp = FastMCP("kylin-ops-agent")

# 遍历注册表，把每个纯函数登记为 MCP 工具。
# 函数的 docstring 即工具描述，类型注解即 inputSchema，FastMCP 自动推导。
for _name, _spec in REGISTRY.items():
    mcp.tool(name=_name)(_spec.fn)


def main() -> None:
    """以 stdio 传输启动 MCP Server（后端以子进程方式拉起并经标准输入输出通信）。"""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
