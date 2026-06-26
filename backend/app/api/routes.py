"""HTTP 接口层：健康检查、列工具、对话。前端通过这些 REST 接口交互。"""
from __future__ import annotations

import asyncio
import secrets
import time
import uuid
from dataclasses import asdict, replace
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, model_validator

from app.audit import store
from app.config import get_settings
from app.core import actions, diagnosis
from app.guardrail.engine import check_command
from app.guardrail.rules import RULES, load_status, reload_rules, rules_fingerprint
from app.guardrail.tool_scan import (
    baseline_fingerprint,
    save_baseline,
    scan_with_drift,
    tool_fingerprint,
)
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


# P1：请求模型加边界约束（min/max_length、Literal 动作名、按动作校验 params），
# 把畸形/超大入参挡在业务逻辑之外（早 422，不进护栏/动作层），收敛 DoS 与误用面。
class ChatRequest(BaseModel):
    """/chat 请求体：自然语言消息 + 深度思考开关。"""

    message: str = Field(min_length=1, max_length=4000)
    # 深度思考开关（前端可切）：on → 编排用 DeepSeek 推理模型，回放展示思维链，更慢；
    # off（默认）→ 用快速模型，低延迟。详见 orchestrator.chat(deep_thinking=...)。
    deep_thinking: bool = False


class GuardCheckRequest(BaseModel):
    """/guardrail/check 请求体：待裁决命令 + 授权/确认标志（只读预览，不执行）。"""

    command: str = Field(min_length=1, max_length=4000)
    authorized: bool = False
    confirmed: bool = False


class ActionRequest(BaseModel):
    """/action/execute 请求体：白名单动作名 + 参数 + 确认/授权/dry_run 标志。"""

    # Literal 收敛到白名单动作：未知动作名在入口即 422，不进 run_action。
    # 扩展实用性 = 往此白名单加参数化受控动作（每个都过语义闸门 + 二次确认 + executor 护栏），
    # 绝不放开自由 shell——见 core/actions.ACTIONS 与 CLAUDE.md §4.0。
    action: Literal[
        "truncate_log", "kill_process", "clean_path",
        "restart_service", "reload_config", "block_ip", "clean_journal",
    ]
    # 用 default_factory 而非可变默认 {}（P0-5：可变默认会在实例间共享、是经典陷阱）
    params: dict = Field(default_factory=dict)  # 动作参数（path / pid+signal / unit / ip / size|time）
    confirmed: bool = False     # 用户是否二次确认（未确认绝不真执行）
    authorized: bool = False    # 是否对需提权操作显式授权（防线4）
    dry_run: bool = True        # 默认只校验不执行

    @model_validator(mode="after")
    def _check_params(self) -> ActionRequest:
        """按动作校验 params 形状（独立 schema 的轻量落地）：缺必填项即 422。

        细粒度语义校验（关键性/受保护进程/信号白名单/单元关键性/IP 范围/vacuum 格式）仍在
        actions.py，比 schema 更全。
        """
        if self.action in ("truncate_log", "clean_path"):
            p = self.params.get("path")
            if not isinstance(p, str) or not p:
                raise ValueError(f"{self.action} 需要非空字符串参数 path")
        elif self.action == "kill_process":
            if "pid" not in self.params:
                raise ValueError("kill_process 需要参数 pid")
        elif self.action in ("restart_service", "reload_config"):
            u = self.params.get("unit")
            if not isinstance(u, str) or not u:
                raise ValueError(f"{self.action} 需要非空字符串参数 unit")
        elif self.action == "block_ip":
            ip = self.params.get("ip")
            if not isinstance(ip, str) or not ip:
                raise ValueError("block_ip 需要非空字符串参数 ip")
        elif self.action == "clean_journal":
            if not (self.params.get("size") or self.params.get("time")):
                raise ValueError("clean_journal 需要参数 size 或 time 之一")
        return self


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

    source/errors 反映规则来自 YAML 配置还是红线兜底集（P2-1 可配置化）；
    fingerprint 是当前生效规则集的内容指纹（P1：答辩证明此刻在用哪一版规则）。
    """
    st = load_status()
    return {
        "count": len(RULES),
        "source": st["source"],
        "errors": st["errors"],
        "fingerprint": rules_fingerprint(),
        "rules": _rules_payload(),
    }


@router.post("/guardrail/rules/reload", dependencies=[Depends(require_operator)])
async def guardrail_rules_reload() -> dict:
    """热加载规则库：从 rules.yaml 重新读取并校验（P2-1 插件化/可扩展）。

    故障安全：校验不过则【不换入】、维持现有规则并回报 errors，护栏绝不因坏配置出现空窗。
    红线规则（CRITICAL+DENY 绝命操作）硬编码兜底，无法经配置削弱或删除。

    P1 加固：① 挂 require_operator——改变生效护栏是敏感操作，须 operator 鉴权（demo 模式豁免）；
    ② 结果写审计（actor/时间/prev→new 指纹/applied/errors），谁在何时换了哪版规则可回放追责。
    """
    prev_fp = rules_fingerprint()
    st = reload_rules()
    new_fp = rules_fingerprint()

    # 把这次热加载写审计：规则是护栏的「法律」，改它必须留痕（who/when/prev→new/applied/errors）。
    try:
        trace_id = uuid.uuid4().hex
        steps = [
            {"stage": "接收指令", "detail": {
                "action": "guardrail.rules.reload", "actor": "operator(token-authenticated)"}},
            {"stage": "安全校验", "detail": {
                "prev_fingerprint": prev_fp, "new_fingerprint": new_fp,
                "applied": st["applied"], "source": st["source"], "errors": st["errors"]}},
            {"stage": "执行结果", "detail": {
                "count": st["count"], "applied": st["applied"],
                "changed": prev_fp != new_fp}},
        ]
        await asyncio.to_thread(
            store.save_trace, trace_id, "[护栏规则热加载]",
            "applied" if st["applied"] else "rejected(kept previous)",
            steps, intent="rules_reload", blocked=not st["applied"],
            tainted=False, llm_provider=get_settings().llm_provider)
    except Exception:  # noqa: BLE001 审计旁路失败不阻断热加载本身
        trace_id = ""

    return {
        "ok": not st["errors"],
        "source": st["source"],
        "count": st["count"],
        "applied": st["applied"],
        "errors": st["errors"],
        "fingerprint": new_fp,
        "prev_fingerprint": prev_fp,
        "changed": prev_fp != new_fp,
        "trace_id": trace_id,
        "rules": _rules_payload(),
    }


@router.get("/guardrail/tool-scan")
async def guardrail_tool_scan(request: Request) -> dict:
    """MCP 工具供应链扫描 + 处置（P3-4 + P0-C + P2 rug-pull）。

    静态检测工具元数据里的投毒/影子/隐形载荷，并对比已锚定基线检测 schema 漂移（rug-pull /
    运行期新增工具），标注每个工具的处置档位（已隔离 isolated / 需人工复核 review / 已放行 cleared）。
    本地分析 name/description/schema，绝不上传文件或凭据（致敬 mcp-scan）。
    覆盖 2025 年 MCP 新攻击面：工具投毒（藏指令）、工具影子（跨工具篡改）、隐形 Unicode、
    rug-pull（获信任后悄改 description/schema）。返回的 isolated 名单即「fail-closed 不进 LLM
    上下文」的工具，与编排器实际过滤口径一致；drift 段汇报相对基线的 new/changed/removed。
    """
    mcp = request.app.state.mcp
    return await asyncio.to_thread(
        scan_with_drift, await mcp.list_tools(),
        allow_medium=get_settings().quarantine_allow_medium)


@router.post("/guardrail/tool-scan/pin", dependencies=[Depends(require_operator)])
async def guardrail_tool_scan_pin(request: Request) -> dict:
    """把当前 MCP 工具集锚定为新基线（P2 rug-pull）：合法工具升级后由 operator 重锚。

    敏感操作（改变「可信工具基线」），挂 require_operator 鉴权。锚定后再次扫描即以新内容为准，
    旧的 rug-pull 告警随之消除——这是「合法变更」与「恶意变脸」的人工分界。
    """
    mcp = request.app.state.mcp
    tools = await mcp.list_tools()
    fingerprints = {t.get("name", ""): tool_fingerprint(
        t.get("name", ""), t.get("description", ""), t.get("inputSchema")) for t in tools}
    meta = await asyncio.to_thread(save_baseline, fingerprints)
    return {"ok": True, "pinned": meta["count"], "pinned_at": meta["pinned_at"],
            "path": meta["path"], "tools": sorted(fingerprints)}


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


@router.get("/guardrail/sandbox-demo", dependencies=[Depends(require_operator)])
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
    """自然语言运维对话，返回最终答复 + 执行链 trace（含 trace_id 供回放）。"""
    orch = request.app.state.orchestrator
    result = await orch.chat(req.message, deep_thinking=req.deep_thinking)
    return {
        "trace_id": result.trace_id,
        "answer": result.answer,
        "blocked": result.blocked,
        "intent": result.intent,
        "tainted": result.tainted,
        "deep_thinking": req.deep_thinking,  # 回显本轮是否启用深度思考
        "trace": [asdict(s) for s in result.trace],
        "tool_calls": result.tool_calls,
    }


@router.get("/traces")
async def traces(limit: int = 50) -> dict:
    """列出最近会话，供前端「执行链回放」历史列表（评分：可追溯闭环）。"""
    return {"traces": store.list_traces(limit=limit)}


@router.get("/traces/{trace_id}")
async def trace_detail(trace_id: str) -> dict:
    """按 trace_id 取完整执行链五段，供前端回放整条推理链路。"""
    t = store.get_trace(trace_id)
    if t is None:
        raise HTTPException(status_code=404, detail=f"trace 不存在: {trace_id}")
    return t


@router.get("/traces/{trace_id}/verify")
async def trace_verify(trace_id: str) -> dict:
    """校验执行链哈希链完整性（防篡改）：返回 valid 及断裂点，供前端展示「可信审计」。"""
    return store.verify_chain(trace_id)


@router.get("/traces/{trace_id}/evidence", dependencies=[Depends(require_operator)])
async def trace_evidence(trace_id: str) -> dict:
    """导出一条 trace 的自封口审计证据包（P2）：完整五段 + verify + 规则/schema 指纹 + HMAC 封口（seal）。

    用途：把可追溯性从「本系统内回放」升级为「可离线核验的取证材料」。证据包用同一 HMAC 密钥封口，
    任何导出后的改动都会令 seal 失配（verify_evidence 检出）——与库内哈希链双重防篡改。
    含完整 trace 明文（已脱敏），属敏感导出，挂 require_operator 鉴权。
    """
    st = load_status()
    components = {
        "rules": {"fingerprint": rules_fingerprint(), "count": st["count"], "source": st["source"]},
        "tool_schema_baseline": {"fingerprint": baseline_fingerprint()},
        "app": {"name": "kylin-ops-agent", "version": "0.1.0"},
    }
    pack = await asyncio.to_thread(store.export_evidence, trace_id, components=components)
    if not pack.get("ok"):
        raise HTTPException(status_code=404, detail=pack.get("error", f"trace 不存在: {trace_id}"))
    return pack


@router.get("/vuln-intel", dependencies=[Depends(require_operator)])
async def vuln_intel(component: str | None = None, cve: str | None = None,
                     live: bool = False) -> dict:
    """漏洞情报检索（P1-1）：把内核新漏洞的『时效』从训练问题变检索问题。

    默认离线读本地种子库；live=true 时联网（OSV.dev）增强、失败回退本地。READONLY。
    """
    from app.mcp_server.tools.vuln_intel import query_vuln_intel
    return await asyncio.to_thread(query_vuln_intel, component, cve, live)


@router.get("/posture", dependencies=[Depends(require_operator)])
async def posture(live: bool = False) -> dict:
    """内核 / 主机安全姿态检查（P1-2）：本机内核+已加载模块比对情报，命中给缓解建议。

    只研判、只建议，绝不自动执行缓解（缓解须走 /action/execute 护栏 + 二次确认）。READONLY。
    """
    from app.core import posture as posture_mod
    return await asyncio.to_thread(posture_mod.check_posture, live)


@router.get("/diagnose", dependencies=[Depends(require_operator)])
async def diagnose(topic: str = "all", path: str = "/", pin: bool = False) -> dict:
    """智能根因分析（评分④）：disk/zombie/load/io/memory/configdrift/all。只分析给建议，绝不处置。

    - memory：内存压力/泄漏关联（RSS 增长泄漏信号 + swap 颠簸，证据链 + 置信度）。
    - configdrift：配置文件漂移（赛题场景）。TOFU 锚定关键配置基线，之后报 changed/removed/added；
      确认变更合法后用 pin=true 重锚。
    诊断含同步的磁盘扫描/lsof/采样等阻塞调用，放线程池避免阻塞事件循环（P0-5）。
    """
    return await asyncio.to_thread(diagnosis.diagnose, topic, path, pin=pin)


@router.post("/action/execute", dependencies=[Depends(require_operator)])
async def action_execute(req: ActionRequest) -> dict:
    """受控 MUTATING 动作端到端闭环（P0-3）：白名单动作 → 语义校验 → 护栏 → 执行。

    默认 dry_run / 未 confirmed 时只返回护栏裁决与 require_confirm 预览，绝不真正执行；
    每次动作产出五段执行链并落审计，可按返回的 trace_id 回放（评分②③④可演示项）。

    鉴权（P0-4）：本端点是唯一会真正改系统状态的入口，挂 require_operator 依赖，
    配置了 operator_token 时须带 `Authorization: Bearer <token>`。
    """
    trace_id = uuid.uuid4().hex
    provider = get_settings().llm_provider
    summary = f"[动作] {req.action} {req.params}"

    # P0-D 审计先于执行：只有真正会改系统状态的调用（已确认且非 dry_run）才需先落 pending 审计；
    # 若 pending 审计写不下去（审计存储不可用），则**拒绝执行**——无法留痕的破坏性操作绝不放行。
    # dry_run / 未确认的预览不改状态，沿用执行后 best-effort 审计即可。
    will_change_state = req.confirmed and not req.dry_run
    if will_change_state:
        pending = [{"stage": "接收指令", "detail": {
            "action": req.action, "params": req.params,
            "confirmed": req.confirmed, "authorized": req.authorized, "dry_run": req.dry_run,
            "audit": "pending —— 审计先于执行：先记录意图，落痕成功后才执行状态变更"}}]
        try:
            await asyncio.to_thread(
                store.save_trace, trace_id, summary, "（执行中：已落 pending 审计）",
                pending, intent="action", blocked=False, tainted=False, llm_provider=provider)
        except Exception as e:  # noqa: BLE001 审计是改状态动作的前置条件，落不下就 fail-closed
            return {
                "ok": False, "action": req.action, "executed": False, "blocked": True,
                "require_confirm": False, "dry_run": False,
                "reason": f"审计存储不可用，已拒绝执行受控动作（审计先于执行：无法留痕则不执行）：{e}",
                "command": None, "precheck": None, "guard": None, "privilege": None,
                "output": None, "trace": pending, "trace_id": trace_id,
            }

    # 动作内部会调 executor（同步子进程），放线程池避免阻塞事件循环
    result = await asyncio.to_thread(
        actions.run_action, req.action, req.params,
        confirmed=req.confirmed, authorized=req.authorized, dry_run=req.dry_run,
    )
    # 落最终结果审计（同 trace_id 覆盖 pending）。改状态动作此时状态已变，最终审计失败不回滚——
    # pending 审计已留痕，仅在结果里标注 audit_warning。dry_run/预览路径同样 best-effort。
    try:
        await asyncio.to_thread(
            store.save_trace, trace_id, summary,
            result.get("reason", ""), result.get("trace", []),
            intent="action", blocked=bool(result.get("blocked")),
            # P3-3：动作层不把外部不可信内容喂进任何决策/指令流（进程元数据仅用于确定性
            # 关键性校验，不驱动模型），故状态变更动作恒非污点——与编排路径恰成信息流分离。
            tainted=False, llm_provider=provider,
        )
    except Exception:  # noqa: BLE001 最终审计是旁路（pending 已留痕），不因落库失败中断
        result["audit_warning"] = "最终结果审计落库失败（pending 审计已留痕）"
    result["trace_id"] = trace_id
    return result
