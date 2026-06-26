"""致命三要素 / Meta「Agents Rule of Two」能力面板（改进v2 P3-2）。

理论锚点（写进答辩/报告的「对标前沿」）：
- Simon Willison「Lethal Trifecta（致命三要素）」2025-06：当一个 Agent 同时具备
  ①接触不可信内容 ②访问敏感/私有数据 ③改变状态或对外通信，就必然可被提示词注入利用来窃取/破坏。
- Meta「Agents Rule of Two」2025-10：一个会话内，Agent 在上述三项里**至多满足两项**；
  若三项都需要，**必须人在回路（human-in-the-loop）审批**。灵感源自 Chromium 安全策略与致命三要素。

本模块把这套框架变成项目里**可度量、可演示**的一等公民：
1. 给每个 MCP 工具 / 受控动作打三条「能力腿」布尔标签（TOOL_CAPS）；
2. `evaluate_path()` 对一条执行路径做能力并集，判断是否集齐三要素、是否满足 Rule of Two；
3. 前端「能力面板」可视化每个工具的三腿标签与风险计数（差异化亮点，竞品多为只读/无此面板）。

本项目的结构性安全论证（这是真正拿分的点）：
- 全部 MCP 工具（22 个）**一律 READONLY**，没有任何一个具备「改状态/外联」(C) 这条腿——感知层路径的
  能力上限恒为 A+B（≤2 腿），结构上不可能单独凑齐致命三要素。**扩工具只增不破此不变量**。
- 带 (C) 的只存在于动作层的受控动作（truncate_log/kill_process/clean_path/restart_service/
  reload_config/block_ip/clean_journal），而它们**一律强制二次确认**（human-in-loop）。
  实用性靠「加受控动作」增长，C 腿始终被人工闸门挡在感知路径之外。
- 故任何可能触及第三条腿的路径，都必然穿过一道人工闸门——**Rule of Two 由架构强制保证，而非靠提醒**。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from app.core.actions import ACTIONS
from app.mcp_server.tools import REGISTRY


class Capability(str, Enum):
    """致命三要素的三条能力腿。"""
    UNTRUSTED = "untrusted_input"      # A 接触不可信内容（外部可控的日志/文件/命令输出/进程命令行）
    SENSITIVE = "sensitive_access"     # B 访问敏感/私有数据（可能含口令/PII/拓扑，外泄即危害）
    STATE_CHANGE = "state_change"      # C 改变系统状态或对外通信


CAP_LABEL: dict[Capability, str] = {
    Capability.UNTRUSTED: "接触不可信内容",
    Capability.SENSITIVE: "访问敏感/私有数据",
    Capability.STATE_CHANGE: "改变状态或对外通信",
}

_ALL = (Capability.UNTRUSTED, Capability.SENSITIVE, Capability.STATE_CHANGE)


@dataclass(frozen=True)
class ToolCaps:
    """一个工具/动作的三条能力腿标签。"""
    untrusted: bool = False
    sensitive: bool = False
    state_change: bool = False

    def legs(self) -> set[Capability]:
        """返回该工具/动作实际具备的能力腿集合（致命三要素计数用）。"""
        s: set[Capability] = set()
        if self.untrusted:
            s.add(Capability.UNTRUSTED)
        if self.sensitive:
            s.add(Capability.SENSITIVE)
        if self.state_change:
            s.add(Capability.STATE_CHANGE)
        return s

    def to_dict(self) -> dict:
        """序列化为 dict（含能力腿计数），供前端「致命三要素」面板渲染。"""
        return {"untrusted": self.untrusted, "sensitive": self.sensitive,
                "state_change": self.state_change, "leg_count": len(self.legs())}


# ---------------------------------------------------------------------------
# 能力标签库：每个工具/动作据「它返回什么 / 它做什么」打标，附判定理由。
# 判定原则：A=输出含外部可控内容；B=输出含可外泄的敏感信息；C=会落地改系统/外联。
# ---------------------------------------------------------------------------
TOOL_CAPS: dict[str, ToolCaps] = {
    # —— 纯指标类：数值/状态，不含外部可控内容也无敏感外泄面 ——
    "disk_usage": ToolCaps(),
    "dir_size": ToolCaps(),
    "memory_info": ToolCaps(),
    "system_load": ToolCaps(),
    "uptime_info": ToolCaps(),
    "service_status": ToolCaps(),
    "check_port": ToolCaps(),
    # —— 文件名/路径外部可控：A（攻击者可用文件名夹带诱导）——
    "find_large_files": ToolCaps(untrusted=True),
    # —— 网络拓扑：B（暴露在听服务/端口，外泄助攻）——
    "list_listening_ports": ToolCaps(sensitive=True),
    # —— 进程类：命令行外部可控(A) + 可能含口令/PII(B) ——
    "list_processes": ToolCaps(untrusted=True, sensitive=True),
    "find_zombie_processes": ToolCaps(untrusted=True, sensitive=True),
    "process_detail": ToolCaps(untrusted=True, sensitive=True),
    # —— 日志/句柄类：经典不可信内容(A) + 常含敏感信息(B)，注入高发区 ——
    "tail_log": ToolCaps(untrusted=True, sensitive=True),
    "query_journal": ToolCaps(untrusted=True, sensitive=True),
    "list_open_files": ToolCaps(untrusted=True, sensitive=True),
    # —— 漏洞情报 / 内核姿态：引入外部情报内容(A)，无敏感外泄面、不改状态 ——
    "query_vuln_intel": ToolCaps(untrusted=True),
    "kernel_posture": ToolCaps(untrusted=True),
    # —— P1 扩展只读工具：同样无『改状态』腿，感知层能力上限仍 ≤2 ——
    "inode_usage": ToolCaps(),                                   # 纯 inode 指标，无能力腿
    "firewall_status": ToolCaps(sensitive=True),                 # 暴露防火墙拓扑/暴露面(B)
    "list_failed_units": ToolCaps(untrusted=True),               # 失败单元描述为自由文本(A)
    "login_history": ToolCaps(untrusted=True, sensitive=True),   # 用户/来源外部可控(A)+登录隐私(B)
    "list_cron_jobs": ToolCaps(untrusted=True, sensitive=True),  # cron 命令行外部可控(A)+可含敏感(B)
    # —— 受控 MUTATING 动作：改状态(C) + 需读取分类/进程/连接详情判定(B)；不接触外部不可信内容(A=F) ——
    "truncate_log": ToolCaps(sensitive=True, state_change=True),
    "kill_process": ToolCaps(sensitive=True, state_change=True),
    "clean_path": ToolCaps(sensitive=True, state_change=True),
    # —— P1 扩展受控动作：同为 B+C 两条腿、A=F，恒不集齐三要素，且强制二次确认 ——
    "restart_service": ToolCaps(sensitive=True, state_change=True),
    "reload_config": ToolCaps(sensitive=True, state_change=True),
    "block_ip": ToolCaps(sensitive=True, state_change=True),
    "clean_journal": ToolCaps(sensitive=True, state_change=True),
}


def caps_for(name: str) -> ToolCaps:
    """取某工具/动作的能力标签；未知名按「无能力」保守处理（不凭空赋能力腿）。"""
    return TOOL_CAPS.get(name, ToolCaps())


# ---------------------------------------------------------------------------
# 感知层能力隔离不变量 —— 启动期 fail-closed 闸门（把能力标签从「展示」升级为「强制」）
# ---------------------------------------------------------------------------
def perception_isolation_violations() -> list[str]:
    """核验项目第一安全保证的结构性不变量：**LLM 可达的感知层（MCP 工具注册表）无『改状态』能力腿**。

    背景与意义（这是把致命三要素/Rule-of-Two 能力模型真正「用起来」的地方）：
      编排器只把 `REGISTRY` 里的工具暴露给模型，且它们全 READONLY。由此「污点 ∧ 状态变更 恒不成立」
      这条不变量成立——危险动作不可能在编排路径上发生。过去它只靠人工纪律 + 单测维持，运行时的
      污点门控只在「有人误接了可变工具」时才会被某个污点请求**偶然**触发。本函数把它升级为
      **每次启动都强制核验**的静态闸门：一旦回归（把带 state_change 的工具接进 REGISTRY、或给
      MCP 工具误打 state_change 标签），启动即拒绝，不必等运行时撞上。

    返回违例描述列表（空 = 不变量成立）。纯函数，供启动 fail-closed 与测试调用。
    """
    violations: list[str] = []
    # ① 正向：注册给 LLM 的每个 MCP 工具都不得具备『改状态/对外通信』腿。
    for name in REGISTRY:
        if caps_for(name).state_change:
            violations.append(
                f"MCP 工具 {name!r} 标注具备『改状态/对外通信』能力腿，却暴露在 LLM 可达的感知层"
                "（REGISTRY）——违反『感知层无状态变更』不变量。状态变更只能走强制二次确认的受控"
                "动作层（core/actions.ACTIONS），不得作为 MCP 工具暴露。")
    # ② 反向：能力库里带 state_change 的名字必须都是受控动作，且不在 REGISTRY 里。
    for name, caps in TOOL_CAPS.items():
        if not caps.state_change:
            continue
        if name in REGISTRY:
            violations.append(
                f"{name!r} 同时标注 state_change 且登记在 MCP 工具注册表——状态变更能力泄漏到感知层。")
        if name not in ACTIONS:
            violations.append(
                f"{name!r} 标注 state_change 却不在受控动作白名单 ACTIONS——状态变更必须经动作层强制确认。")
    return violations


def assert_perception_isolation() -> None:
    """启动期 fail-closed：感知层能力隔离不变量不成立则抛 RuntimeError，拒绝启动。

    由 main.py 的 lifespan 在装配编排器前调用——与「最小权限/审计密钥」等失败安全启动守卫同级。
    """
    v = perception_isolation_violations()
    if v:
        raise RuntimeError("感知层能力隔离不变量被破坏（拒绝启动）：" + "；".join(v))


@dataclass
class TrifectaResult:
    """一条执行路径的致命三要素评估结果。"""
    tools: list[str]
    legs: list[str] = field(default_factory=list)       # 路径并集触及的能力腿（value）
    leg_labels: list[str] = field(default_factory=list)  # 中文标签
    leg_count: int = 0
    trifecta_complete: bool = False                      # 是否集齐三要素
    human_in_loop: bool = False                          # 是否处于人工在环
    rule_of_two_satisfied: bool = True
    recommendation: str = "allow"                        # allow / allow_with_oversight / require_human_approval
    reason: str = ""

    def to_dict(self) -> dict:
        """序列化整次 Rule-of-Two 评估为 dict，供审计与前端风险面板渲染。"""
        return {
            "tools": self.tools,
            "legs": self.legs,
            "leg_labels": self.leg_labels,
            "leg_count": self.leg_count,
            "trifecta_complete": self.trifecta_complete,
            "human_in_loop": self.human_in_loop,
            "rule_of_two_satisfied": self.rule_of_two_satisfied,
            "recommendation": self.recommendation,
            "reason": self.reason,
        }

    def to_trace(self) -> dict:
        """写入 trace「安全校验」段的能力面足迹（思维链回放可见 Rule of Two 结论）。"""
        return {"phase": "致命三要素 / Rule of Two 能力面评估", **self.to_dict()}


def evaluate_path(names: Iterable[str], *, human_in_loop: bool = False) -> TrifectaResult:
    """对一条执行路径（一组被调用的工具/动作）做能力并集与 Rule of Two 裁决。

    Args:
        names: 本路径调用到的工具/动作名。
        human_in_loop: 该路径是否处于人工在环（如动作层强制的二次确认）。
    Rule of Two：能力腿 ≤2 即满足；集齐三腿(=3)时，唯有 human_in_loop 才算满足，否则须人工审批。
    """
    names = list(names)
    present: set[Capability] = set()
    for n in names:
        present |= caps_for(n).legs()

    ordered = [c for c in _ALL if c in present]
    complete = len(present) == 3
    satisfied = (len(present) <= 2) or human_in_loop

    if complete and not human_in_loop:
        recommendation = "require_human_approval"
        reason = ("执行路径集齐致命三要素（接触不可信内容 + 访问敏感数据 + 改状态/外联），"
                  "按 Rule of Two 必须人工确认（human-in-the-loop）后方可继续。")
    elif complete and human_in_loop:
        recommendation = "allow_with_oversight"
        reason = "已集齐三要素，但处于人工在环（二次确认）之下，符合 Rule of Two 的兜底要求。"
    else:
        recommendation = "allow"
        reason = (f"执行路径最多触及 {len(present)}/3 条能力腿，未集齐致命三要素，"
                  "天然满足 Rule of Two。")

    return TrifectaResult(
        tools=names,
        legs=[c.value for c in ordered],
        leg_labels=[CAP_LABEL[c] for c in ordered],
        leg_count=len(present),
        trifecta_complete=complete,
        human_in_loop=human_in_loop,
        rule_of_two_satisfied=satisfied,
        recommendation=recommendation,
        reason=reason,
    )


def _level_of(name: str) -> str:
    """工具/动作的读写级别，供面板分组展示。"""
    spec = REGISTRY.get(name)
    if spec is not None:
        return spec.level
    if name in ACTIONS:
        return "MUTATING"
    return "UNKNOWN"


def capability_table() -> dict:
    """前端「能力面板」数据源：每个工具/动作的三腿标签 + 级别 + 腿数，附图例与结构性安全说明。"""
    rows = []
    for name in list(TOOL_CAPS):
        caps = TOOL_CAPS[name]
        rows.append({
            "name": name,
            "level": _level_of(name),
            **caps.to_dict(),
            "legs": [c.value for c in _ALL if c in caps.legs()],
        })
    # 按腿数降序，醒目地把「能力多」的工具排在前面
    rows.sort(key=lambda r: (-r["leg_count"], r["name"]))

    readonly_max = max((r["leg_count"] for r in rows if r["level"] == "READONLY"), default=0)
    has_state_change_readonly = any(r["state_change"] and r["level"] == "READONLY" for r in rows)

    return {
        "legend": [{"key": c.value, "label": CAP_LABEL[c]} for c in _ALL],
        "tools": rows,
        "invariant": {
            "readonly_max_legs": readonly_max,
            "readonly_has_state_change": has_state_change_readonly,
            "note": ("感知层（READONLY）能力腿上限恒为 2（无『改状态/外联』腿），"
                     "第三条腿仅存于强制二次确认的动作层——任何可能集齐致命三要素的路径都必经人工闸门，"
                     "Rule of Two 由架构强制保证。"),
        },
    }
