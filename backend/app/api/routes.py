"""HTTP 接口层：健康检查、列工具、对话。前端通过这些 REST 接口交互。"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import asdict

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.audit import store
from app.config import get_settings
from app.core import actions, diagnosis
from app.guardrail.engine import check_command
from app.guardrail.rules import RULES

router = APIRouter()


class ChatRequest(BaseModel):
    message: str


class GuardCheckRequest(BaseModel):
    command: str
    authorized: bool = False
    confirmed: bool = False


class ActionRequest(BaseModel):
    action: str                 # truncate_log / kill_process / clean_path
    params: dict = {}           # 动作参数（path / pid+signal）
    confirmed: bool = False     # 用户是否二次确认（未确认绝不真执行）
    authorized: bool = False    # 是否对需提权操作显式授权（防线4）
    dry_run: bool = True        # 默认只校验不执行


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
    """自然语言运维对话，返回最终答复 + 思维链 trace（含 trace_id 供回放）。"""
    orch = request.app.state.orchestrator
    result = await orch.chat(req.message)
    return {
        "trace_id": result.trace_id,
        "answer": result.answer,
        "blocked": result.blocked,
        "intent": result.intent,
        "trace": [asdict(s) for s in result.trace],
        "tool_calls": result.tool_calls,
    }


@router.get("/traces")
async def traces(limit: int = 50) -> dict:
    """列出最近会话，供前端「思维链回放」历史列表（评分：可追溯闭环）。"""
    return {"traces": store.list_traces(limit=limit)}


@router.get("/traces/{trace_id}")
async def trace_detail(trace_id: str) -> dict:
    """按 trace_id 取完整思维链五段，供前端回放整条推理链路。"""
    t = store.get_trace(trace_id)
    if t is None:
        raise HTTPException(status_code=404, detail=f"trace 不存在: {trace_id}")
    return t


@router.get("/traces/{trace_id}/verify")
async def trace_verify(trace_id: str) -> dict:
    """校验思维链哈希链完整性（防篡改）：返回 valid 及断裂点，供前端展示「可信审计」。"""
    return store.verify_chain(trace_id)


@router.get("/diagnose")
async def diagnose(topic: str = "all", path: str = "/") -> dict:
    """智能根因分析（评分④）：disk/zombie/load/all。只分析给建议，绝不执行处置。"""
    return diagnosis.diagnose(topic=topic, path=path)


@router.post("/action/execute")
async def action_execute(req: ActionRequest) -> dict:
    """受控 MUTATING 动作端到端闭环（P0-3）：白名单动作 → 语义校验 → 护栏 → 执行。

    默认 dry_run / 未 confirmed 时只返回护栏裁决与 require_confirm 预览，绝不真正执行；
    每次动作产出五段思维链并落审计，可按返回的 trace_id 回放（评分②③④可演示项）。
    """
    trace_id = uuid.uuid4().hex
    # 动作内部会调 executor（同步子进程），放线程池避免阻塞事件循环
    result = await asyncio.to_thread(
        actions.run_action, req.action, req.params,
        confirmed=req.confirmed, authorized=req.authorized, dry_run=req.dry_run,
    )
    # 把这次动作也记进思维链（落库失败不阻断主流程）
    try:
        await asyncio.to_thread(
            store.save_trace, trace_id,
            f"[动作] {req.action} {req.params}",
            result.get("reason", ""),
            result.get("trace", []),
            intent="action",
            blocked=bool(result.get("blocked")),
            llm_provider=get_settings().llm_provider,
        )
    except Exception:  # noqa: BLE001 审计是旁路，绝不因落库失败中断动作
        pass
    result["trace_id"] = trace_id
    return result
