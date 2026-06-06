"""FastAPI 应用入口（B/S 架构的 S 端）。

启动时拉起 MCP Server 子进程并建立 client 长连接、构造编排器；
关闭时优雅断开。运行：
    uvicorn app.main:app --reload --port 8000
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.audit import store
from app.config import get_settings
from app.core.orchestrator import Orchestrator
from app.guardrail.privilege import is_running_as_root, least_privilege_check
from app.guardrail.tool_scan import scan_tools
from app.llm.provider import get_llm
from app.mcp_server.client import MCPClient

logger = logging.getLogger("kylin-ops-agent")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 最小权限启动闸门（审查整改②）：非必要不 root；以 root 跑默认告警，REFUSE_ROOT=true 则拒绝启动。
    refuse, msg = least_privilege_check(
        is_root=is_running_as_root(), refuse_root=get_settings().refuse_root)
    if refuse:
        raise RuntimeError("拒绝启动（最小权限）：" + msg)
    (logger.warning if is_running_as_root() else logger.info)(msg)

    # 启动：初始化审计库 + 连接 MCP 工具层 + 装配编排器
    store.init_db()
    mcp = MCPClient()
    await mcp.connect()
    app.state.mcp = mcp
    app.state.orchestrator = Orchestrator(llm=get_llm(), mcp=mcp)

    # P3-4 供应链防线：连接后立即静态扫描工具元数据（投毒/影子/隐形载荷），命中则告警。
    # 不信任工具元数据——与「不信任 LLM 输出 / 不信任外部数据」三位一体。
    try:
        report = scan_tools(await mcp.list_tools())
        app.state.tool_scan = report
        if report["flagged"]:
            logger.warning("MCP 工具供应链扫描命中 %d/%d 个可疑工具：%s",
                           report["flagged"], report["scanned"],
                           [t["name"] for t in report["tools"] if t["suspicious"]])
        else:
            logger.info("MCP 工具供应链扫描通过：%d 个工具元数据均无投毒/影子/隐形载荷。",
                        report["scanned"])
    except Exception as e:  # 扫描是旁路，失败不阻断启动
        logger.warning("MCP 工具供应链扫描失败（不阻断启动）：%s", e)

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
