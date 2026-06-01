"""HTTP 接口层：健康检查、列工具、对话。前端通过这些 REST 接口交互。"""
from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.config import get_settings
from app.guardrail.engine import check_command
from app.guardrail.rules import RULES

router = APIRouter()


class ChatRequest(BaseModel):
    message: str


class GuardCheckRequest(BaseModel):
    command: str
    authorized: bool = False
    confirmed: bool = False


@router.get("/health")
async def health() -> dict:
    """健康检查：确认服务存活及当前 LLM provider。"""
    return {"status": "ok", "llm_provider": get_settings().llm_provider}


@router.get("/tools")
async def list_tools(request: Request) -> dict:
    """列出 MCP Server 暴露的工具，对应评分①「列工具」可演示项。"""
    mcp = request.app.state.mcp
    return {"tools": await mcp.list_tools()}


@router.get("/guardrail/rules")
async def guardrail_rules() -> dict:
    """列出护栏规则库，供前端「规则可视化」展示（评分③可演示项）。"""
    return {
        "count": len(RULES),
        "rules": [
            {"id": r.id, "category": r.category, "risk": r.risk.value,
             "action": r.action.value, "description": r.description}
            for r in RULES
        ],
    }


@router.post("/guardrail/check")
async def guardrail_check(req: GuardCheckRequest) -> dict:
    """对一条命令做护栏裁决（只校验、绝不执行）—— 危险命令拦截 demo 的后端入口。"""
    return check_command(req.command, authorized=req.authorized,
                         confirmed=req.confirmed).to_dict()


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
