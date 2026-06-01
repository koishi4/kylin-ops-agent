"""MCP 协议闭环 + 编排器集成测试。
会真实拉起 MCP Server 子进程（stdio），验证「列工具 / 调工具」端到端可用，
并用离线 MockProvider 跑通「自然语言 → 选工具 → 执行 → 作答」整条链路。

注：MCPClient 用 async with 管理生命周期，保证 connect/use/close 在同一 task 内，
满足 anyio cancel scope 约束（与 FastAPI lifespan 的单 task 行为一致）。
"""
from __future__ import annotations

from app.core.orchestrator import Orchestrator
from app.llm.provider import MockProvider
from app.mcp_server.client import MCPClient


class TestMCPProtocol:
    async def test_list_tools(self):
        async with MCPClient() as client:
            tools = await client.list_tools()
        names = {t["name"] for t in tools}
        assert {"disk_usage", "memory_info", "list_processes"} <= names
        for t in tools:
            assert "inputSchema" in t  # 供 LLM function-calling

    async def test_openai_schema_conversion(self):
        async with MCPClient() as client:
            schema = await client.openai_tools()
        assert all(t["type"] == "function" for t in schema)
        assert all("parameters" in t["function"] for t in schema)

    async def test_call_tool_disk_usage(self):
        async with MCPClient() as client:
            r = await client.call_tool("disk_usage", {"path": "/"})
        assert r["ok"] is True
        assert r["level"] == "READONLY"
        assert "percent" in r


class TestOrchestratorLoop:
    async def test_disk_question_invokes_tool(self):
        async with MCPClient() as client:
            orch = Orchestrator(llm=MockProvider(), mcp=client)
            result = await orch.chat("帮我看看磁盘还剩多少空间")
        assert any(c["tool"] == "disk_usage" for c in result.tool_calls)
        assert result.answer
        stages = {s.stage for s in result.trace}
        assert "安全校验" in stages  # 护栏接入点
        assert "执行结果" in stages

    async def test_memory_question_invokes_tool(self):
        async with MCPClient() as client:
            orch = Orchestrator(llm=MockProvider(), mcp=client)
            result = await orch.chat("内存占用情况如何")
        assert any(c["tool"] == "memory_info" for c in result.tool_calls)
