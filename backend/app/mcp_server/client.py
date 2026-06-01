"""MCP 客户端封装 —— 后端通过它连接 MCP Server（工具层）。

后端不直接 import 工具函数，而是以 MCP 协议（stdio 子进程）连接 server，
这样工具层是真正独立的 MCP 插件，符合赛题要求，也便于演示「列工具/调工具」。

生命周期：FastAPI 启动时 connect()，关闭时 aclose()，全程复用一个 session。
"""
from __future__ import annotations

import json
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

# backend 根目录（app 包的上一级），确保子进程 `python -m app...` 能 import app
_BACKEND_ROOT = Path(__file__).resolve().parents[2]

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class MCPClient:
    """持有一个长连接的 MCP 会话，提供列工具 / 转 OpenAI schema / 调工具。"""

    def __init__(self) -> None:
        self._session: ClientSession | None = None
        self._stack: AsyncExitStack | None = None

    async def connect(self) -> None:
        """以子进程方式拉起 MCP Server 并完成握手。"""
        self._stack = AsyncExitStack()
        # 用当前解释器运行 server 模块，保证 venv 一致
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "app.mcp_server.server"],
            cwd=str(_BACKEND_ROOT),
        )
        read, write = await self._stack.enter_async_context(stdio_client(params))
        self._session = await self._stack.enter_async_context(ClientSession(read, write))
        await self._session.initialize()

    async def aclose(self) -> None:
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None
            self._session = None

    # 支持 async with，确保 connect/use/close 在同一 task 内完成
    # （anyio 的 cancel scope 要求进入与退出在同一 task；FastAPI lifespan 天然满足）
    async def __aenter__(self) -> "MCPClient":
        await self.connect()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    @property
    def session(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("MCPClient 未连接，请先调用 connect()")
        return self._session

    async def list_tools(self) -> list[dict]:
        """返回工具原始信息列表（name/description/inputSchema）。"""
        resp = await self.session.list_tools()
        return [
            {
                "name": t.name,
                "description": t.description or "",
                "inputSchema": t.inputSchema,
            }
            for t in resp.tools
        ]

    async def openai_tools(self) -> list[dict]:
        """把 MCP 工具转换成 OpenAI / DeepSeek function-calling 的 tools 格式。"""
        tools = await self.list_tools()
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["inputSchema"],
                },
            }
            for t in tools
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict:
        """调用一个 MCP 工具并把结果解析成 dict。

        FastMCP 对返回 dict 的工具会同时给出 structuredContent 与 JSON 文本，
        优先取 structuredContent，回退解析文本内容。
        """
        result = await self.session.call_tool(name, arguments or {})

        if result.structuredContent is not None:
            return _unwrap(result.structuredContent)

        # 回退：拼接文本内容并尝试 JSON 解析
        texts = [c.text for c in result.content if getattr(c, "type", None) == "text"]
        joined = "\n".join(texts)
        try:
            return json.loads(joined)
        except (json.JSONDecodeError, ValueError):
            return {"ok": not result.isError, "raw": joined}


def _unwrap(structured: Any) -> dict:
    """FastMCP 对非 dict 返回会包一层 {"result": ...}；dict 返回则原样。"""
    if isinstance(structured, dict) and set(structured.keys()) == {"result"}:
        inner = structured["result"]
        if isinstance(inner, dict):
            return inner
        return {"result": inner}
    return structured
