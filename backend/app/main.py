"""FastAPI 应用入口（B/S 架构的 S 端）。

启动时拉起 MCP Server 子进程并建立 client 长连接、构造编排器；
关闭时优雅断开。运行：
    uvicorn app.main:app --reload --port 8000
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.orchestrator import Orchestrator
from app.llm.provider import get_llm
from app.mcp_server.client import MCPClient


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动：连接 MCP 工具层 + 装配编排器
    mcp = MCPClient()
    await mcp.connect()
    app.state.mcp = mcp
    app.state.orchestrator = Orchestrator(llm=get_llm(), mcp=mcp)
    try:
        yield
    finally:
        await mcp.aclose()


app = FastAPI(title="麒麟安全智能运维 Agent", version="0.1.0", lifespan=lifespan)

# 前端（Vite 默认 5173）跨域访问后端
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
