"""HTTP 接口层：健康检查、列工具、对话。前端通过这些 REST 接口交互。"""
from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.config import get_settings

router = APIRouter()


class ChatRequest(BaseModel):
    message: str


@router.get("/health")
async def health() -> dict:
    """健康检查：确认服务存活及当前 LLM provider。"""
    return {"status": "ok", "llm_provider": get_settings().llm_provider}


@router.get("/tools")
async def list_tools(request: Request) -> dict:
    """列出 MCP Server 暴露的工具，对应评分①「列工具」可演示项。"""
    mcp = request.app.state.mcp
    return {"tools": await mcp.list_tools()}


@router.post("/chat")
async def chat(req: ChatRequest, request: Request) -> dict:
    """自然语言运维对话，返回最终答复 + 思维链 trace。"""
    orch = request.app.state.orchestrator
    result = await orch.chat(req.message)
    return {
        "answer": result.answer,
        "trace": [asdict(s) for s in result.trace],
        "tool_calls": result.tool_calls,
    }
