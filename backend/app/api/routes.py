"""HTTP 接口层：健康检查、列工具、对话。前端通过这些 REST 接口交互。"""
from __future__ import annotations

import asyncio
import secrets
import time
import uuid
from dataclasses import asdict, replace

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from app.audit import store
from app.config import get_settings
from app.core import actions, diagnosis
from app.guardrail.engine import check_command
from app.guardrail.rules import RULES, load_status, reload_rules
from app.guardrail.tool_scan import scan_tools
from app.guardrail.trifecta import capability_table

router = APIRouter()


def require_operator(authorization: str | None = Header(default=None)) -> None:
    """受控动作的最小鉴权（P0-4）：校验 `Authorization: Bearer <operator_token>`。

    刻意保持最小——只一个共享 operator token，不做账号/session/RBAC（见 IMPROVEMENTS-v3 P0-4）。
    设计取舍：
    - operator_token 未配置（空）→ 演示模式放行（配合默认只监听 127.0.0.1，本机可信控制台）；
    - 已配置 → 强制 Bearer 校验，缺失/不匹配返回 401；
    - 用 secrets.compare_digest 常量时间比较，避免计时侧信道。
    """
    token = get_settings().operator_token
    if not token:
        return  # 演示模式：未设 token 不强制（README 注明生产须配置）
    expected = f"Bearer {token}"
    if not authorization or not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="缺少或无效的 operator token（受控动作需鉴权）")


class ChatRequest(BaseModel):
    message: str


class GuardCheckRequest(BaseModel):
    command: str
    authorized: bool = False
    confirmed: bool = False


class ActionRequest(BaseModel):
    action: str                 # truncate_log / kill_process / clean_path
    # 用 default_factory 而非可变默认 {}（P0-5：可变默认会在实例间共享、是经典陷阱）
    params: dict = Field(default_factory=dict)  # 动作参数（path / pid+signal）
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


def _rules_payload() -> list[dict]:
    return [
        {"id": r.id, "category": r.category, "risk": r.risk.value,
         "action": r.action.value, "description": r.description, "pattern": r.pattern}
        for r in RULES
    ]


@router.get("/guardrail/rules")
async def guardrail_rules() -> dict:
    """列出护栏规则库，供前端「规则可视化」展示（评分③可演示项）。

    source/errors 反映规则来自 YAML 配置还是红线兜底集（P2-1 可配置化）。
    """
    st = load_status()
    return {
        "count": len(RULES),
        "source": st["source"],
        "errors": st["errors"],
        "rules": _rules_payload(),
    }


@router.post("/guardrail/rules/reload")
async def guardrail_rules_reload() -> dict:
    """热加载规则库：从 rules.yaml 重新读取并校验（P2-1 插件化/可扩展）。

    故障安全：校验不过则【不换入】、维持现有规则并回报 errors，护栏绝不因坏配置出现空窗。
    红线规则（CRITICAL+DENY 绝命操作）硬编码兜底，无法经配置削弱或删除。
    """
    st = reload_rules()
    return {
        "ok": not st["errors"],
        "source": st["source"],
        "count": st["count"],
        "applied": st["applied"],
        "errors": st["errors"],
        "rules": _rules_payload(),
    }


@router.get("/guardrail/tool-scan")
async def guardrail_tool_scan(request: Request) -> dict:
    """MCP 工具供应链扫描（P3-4）：静态检测工具元数据里的投毒/影子/隐形载荷。

    本地分析 name/description/schema，绝不上传文件或凭据（致敬 mcp-scan）。
    覆盖 2025 年 MCP 新攻击面：工具投毒（藏指令）、工具影子（跨工具篡改）、隐形 Unicode。
    """
    mcp = request.app.state.mcp
    return scan_tools(await mcp.list_tools())


@router.get("/guardrail/trifecta")
async def guardrail_trifecta() -> dict:
    """致命三要素 / Rule of Two 能力面板（P3-2）：每个工具/动作的三腿能力标签 + 结构性安全不变量。

    评委可见：感知层 15 工具全 READONLY、能力上限 ≤2 腿（无『改状态/外联』），第三条腿仅存于
    强制二次确认的动作层——任何可能集齐致命三要素的路径都必经人工闸门，Rule of Two 由架构强制。
    """
    return capability_table()


@router.post("/guardrail/check")
async def guardrail_check(req: GuardCheckRequest) -> dict:
    """对一条命令做护栏裁决（只校验、绝不执行）—— 危险命令拦截 demo 的后端入口。"""
    return check_command(req.command, authorized=req.authorized,
                         confirmed=req.confirmed).to_dict()


# 执行沙箱演示场景：**服务端预定义**的无害「吃资源」命令，绝不接受前端任意命令。
# 命令均为服务端常量、自限自灭（CPU 自旋撞超时 / 1GB 内存撞 RLIMIT_AS / echo 秒回），对宿主机无害。
# (args, 内存上限覆盖 MB 或 None, 墙钟超时秒, 说明)
_SANDBOX_DEMO = {
    "normal": (["echo", "sandbox-ok"], None, 5, "正常命令：秒回、不被误杀"),
    "cpu": (["python3", "-c", "while True: pass"], None, 2,
            "CPU 自旋失控：撞墙钟超时被整组击杀"),
    "memory": (["python3", "-c", "x=bytearray(1024*1024*1024)"], 128, 10,
               "申请 1GB 内存：撞 RLIMIT_AS 被限额阻断"),
}


@router.get("/guardrail/sandbox-demo")
async def guardrail_sandbox_demo(scenario: str = "cpu") -> dict:
    """执行沙箱演示（P4-3）：跑一条**服务端预定义**的无害吃资源命令，展示「失控进程被沙箱掐死」。

    只在固定场景白名单（normal/cpu/memory）里选，命令为服务端常量、不接受任意输入——
    护栏放行后真正落地的命令都套这层资源/权限沙箱（防线4 OS 级延伸，对应 OWASP LLM06）。
    """
    if scenario not in _SANDBOX_DEMO:
        raise HTTPException(
            status_code=400,
            detail=f"未知场景：{scenario!r}（可选 {', '.join(_SANDBOX_DEMO)}）")

    from app.core.sandbox import SandboxLimits, run_sandboxed

    args, mem_override, timeout, desc = _SANDBOX_DEMO[scenario]
    limits = SandboxLimits.from_settings(get_settings())
    if mem_override:
        limits = replace(limits, mem_mb=mem_override)

    t0 = time.time()
    res = await asyncio.to_thread(run_sandboxed, args, limits=limits, timeout=timeout)
    elapsed = round(time.time() - t0, 2)

    stderr = (res.get("stderr") or "").strip()
    return {
        "scenario": scenario,
        "description": desc,
        "command": " ".join(args),
        "backend": res.get("sandbox"),
        "limits": {"cpu_s": limits.cpu_seconds, "mem_mb": limits.mem_mb,
                   "max_procs": limits.max_procs, "fsize_mb": limits.fsize_mb,
                   "timeout_s": timeout},
        "ok": res.get("ok"),
        "sandbox_killed": res.get("sandbox_killed"),
        "limit_hit": res.get("limit_hit"),
        "stdout_tail": (res.get("stdout") or "").strip()[-200:],
        "stderr_tail": stderr.splitlines()[-1][-200:] if stderr else "",
        "elapsed_s": elapsed,
    }


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
        "tainted": result.tainted,
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
    """智能根因分析（评分④）：disk/zombie/load/all。只分析给建议，绝不执行处置。

    诊断含同步的磁盘扫描/lsof/采样等阻塞调用，放线程池避免阻塞事件循环（P0-5）。
    """
    return await asyncio.to_thread(diagnosis.diagnose, topic, path)


@router.post("/action/execute", dependencies=[Depends(require_operator)])
async def action_execute(req: ActionRequest) -> dict:
    """受控 MUTATING 动作端到端闭环（P0-3）：白名单动作 → 语义校验 → 护栏 → 执行。

    默认 dry_run / 未 confirmed 时只返回护栏裁决与 require_confirm 预览，绝不真正执行；
    每次动作产出五段思维链并落审计，可按返回的 trace_id 回放（评分②③④可演示项）。

    鉴权（P0-4）：本端点是唯一会真正改系统状态的入口，挂 require_operator 依赖，
    配置了 operator_token 时须带 `Authorization: Bearer <token>`。
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
            # P3-3：动作层不把外部不可信内容喂进任何决策/指令流（进程元数据仅用于确定性
            # 关键性校验，不驱动模型），故状态变更动作恒非污点——与编排路径恰成信息流分离。
            tainted=False,
            llm_provider=get_settings().llm_provider,
        )
    except Exception:  # noqa: BLE001 审计是旁路，绝不因落库失败中断动作
        pass
    result["trace_id"] = trace_id
    return result
