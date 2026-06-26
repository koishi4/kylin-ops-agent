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
from app.guardrail.privilege import is_running_as_root, least_privilege_check, privilege_posture
from app.guardrail.tool_scan import scan_with_drift
from app.guardrail.trifecta import assert_perception_isolation
from app.llm.provider import get_llm
from app.mcp_server.client import MCPClient

logger = logging.getLogger("kylin-ops-agent")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期：启动时跑失败安全/最小权限闸门、扫描并隔离工具、建 MCP 连接，退出时清理。"""
    settings = get_settings()

    # 失败安全启动守卫（P0-D，DEMO/PROD 分界）：非回环绑定（联网/生产）下若 operator_token 为空
    # 或 audit_hmac_key 仍是默认值 → 直接拒绝启动并报清晰错误。本机 demo（127.0.0.1）保持顺滑不变。
    prod_errs = settings.production_config_errors()
    if prod_errs:
        raise RuntimeError("拒绝启动（失败安全默认）：" + "；".join(prod_errs))

    # 最小权限启动闸门（审查整改②）：非必要不 root；以 root 跑默认告警，REFUSE_ROOT=true 则拒绝启动。
    refuse, msg = least_privilege_check(
        is_root=is_running_as_root(), refuse_root=settings.refuse_root)
    if refuse:
        raise RuntimeError("拒绝启动（最小权限）：" + msg)
    (logger.warning if is_running_as_root() else logger.info)(msg)

    # 最小权限「落地身份」启动播报（评审整改）：把"变更动作会以谁的身份落地"这个静默缺口显性化——
    # 以 root 跑且 exec_user 账户不存在/未配 → 变更动作将以 root 落地，明确告警并给出处置；
    # 生产可置 REQUIRE_PRIVILEGE_DROP=true 让动作层 fail-closed 拒绝以 root 落地的变更。
    posture = privilege_posture(settings.exec_user, drops_privilege=True)
    if posture["elevated_landing"]:
        logger.warning("最小权限提醒：%s 生产建议 REQUIRE_PRIVILEGE_DROP=true（强制拒绝 root 落地），"
                       "或创建 exec_user 受限账户 / 改用非 root 启动后端。", posture["reason"])
    else:
        logger.info("最小权限落地身份：%s", posture["reason"])

    # 结构性不变量闸门：感知层（LLM 可达的 MCP 工具）必须无『状态变更』能力腿——状态变更只能走
    # 强制二次确认的受控动作层。一旦回归（误把可变工具接进 REGISTRY / 误打 state_change 标签），
    # 启动即 fail-closed 拒绝，而非寄望某个污点请求恰好撞上运行时门控才暴露（评审整改）。
    assert_perception_isolation()
    logger.info("感知层能力隔离不变量校验通过：MCP 工具均无状态变更能力，状态变更仅存于受控动作层。")

    # 启动：初始化审计库 + 连接 MCP 工具层 + 装配编排器
    store.init_db()
    mcp = MCPClient()
    await mcp.connect()
    app.state.mcp = mcp
    app.state.orchestrator = Orchestrator(llm=get_llm(), mcp=mcp)

    # P3-4 + P0-C + P2 供应链防线：连接后立即静态扫描工具元数据（投毒/影子/隐形载荷），
    # 并对比 schema 指纹基线检测 rug-pull（首次启动即 TOFU 锚定基线）。
    # 命中后**隔离**（fail-closed：可疑/已变脸工具不进 LLM 上下文），而非只告警。
    # 不信任工具元数据——与「不信任 LLM 输出 / 不信任外部数据」三位一体。
    try:
        report = scan_with_drift(await mcp.list_tools(),
                                 allow_medium=get_settings().quarantine_allow_medium)
        app.state.tool_scan = report
        drift = report.get("drift", {})
        if drift.get("changed"):
            logger.warning("MCP 工具基线漂移（rug-pull）：%s 的 description/schema 较基线已变，已隔离。",
                           drift["changed"])
        elif drift.get("first_pin"):
            logger.info("MCP 工具 schema 基线首次锚定（TOFU）：%d 个可信工具。", drift.get("unchanged") and len(drift["unchanged"]) or report["scanned"])
        # 编排器据此过滤工具：被隔离的可疑工具绝不进入喂给模型的 tools 列表。
        app.state.orchestrator.quarantined_tools = set(report["quarantined"])
        if report["quarantined"]:
            logger.warning("MCP 工具投毒扫描：隔离 %d 个可疑工具（不进 LLM 上下文）：%s；需人工复核：%s",
                           len(report["quarantined"]), report["quarantined"], report["review"])
        elif report["flagged"]:
            logger.warning("MCP 工具投毒扫描：%d 个工具命中弱信号（low，告警但可用）。",
                           report["flagged"])
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


if __name__ == "__main__":
    # `python -m app.main` 启动时遵循 API_BIND_HOST（默认 127.0.0.1，只监听回环）。
    # 直接用 `uvicorn app.main:app` 亦可，uvicorn 默认同样绑 127.0.0.1（P0-4）。
    import uvicorn

    st = get_settings()
    uvicorn.run("app.main:app", host=st.api_bind_host, port=8000)
