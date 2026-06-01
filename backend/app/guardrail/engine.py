"""护栏引擎 —— 把规则库的命中结果裁决成统一的放行/拦截/确认决定。

调用方（executor.py / 编排器）只跟 check_command 打交道，不直接碰规则。
裁决原则（见 safety-guardrail skill 风险分级）：
- CRITICAL：直接拒绝，不可覆盖
- HIGH + DENY：拦截，除非本次会话显式授权（authorized=True）
- HIGH/MEDIUM + CONFIRM：需用户二次确认（confirmed=True 后放行）
- LOW / 未命中：放行
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .rules import (
    Action,
    RiskLevel,
    Rule,
    hits_critical_path,
    match_rules,
    normalize,
)


@dataclass
class GuardResult:
    allowed: bool
    action: Action
    matched_rules: list[str] = field(default_factory=list)
    risk: RiskLevel = RiskLevel.LOW
    reason: str = ""
    require_confirm: bool = False

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "action": self.action.value,
            "matched_rules": self.matched_rules,
            "risk": self.risk.value,
            "reason": self.reason,
            "require_confirm": self.require_confirm,
        }


# realpath 命中关键路径时合成的虚拟规则，作为正则之外的兜底防线
_PATH_RULE = Rule(
    "PATH-001", "", RiskLevel.CRITICAL, Action.DENY,
    "命令参数经路径规范化后落在系统关键目录（防相对路径/软链接绕过）", "delete",
)


def check_command(cmd: str, *, authorized: bool = False, confirmed: bool = False) -> GuardResult:
    """对单条候选命令做护栏裁决。

    Args:
        cmd: 待执行的命令字符串（LLM 生成或用户给定）
        authorized: 本次会话是否对 HIGH 风险操作显式授权（防线4 接入点）
        confirmed: 用户是否已对 CONFIRM 类操作二次确认
    """
    hits: list[Rule] = list(match_rules(cmd))

    # 第二重：路径规范化命中关键目录（捕获正则难覆盖的变形）
    path_hits = hits_critical_path(cmd)
    if path_hits and _PATH_RULE.id not in {r.id for r in hits}:
        hits.append(_PATH_RULE)

    if not hits:
        return GuardResult(
            allowed=True, action=Action.ALLOW, risk=RiskLevel.LOW,
            reason="未命中任何高危规则，命令视为安全。",
        )

    highest = max(hits, key=lambda r: r.risk.order)
    matched_ids = [r.id for r in hits]
    detail = "；".join(f"[{r.id}] {r.description}" for r in hits)
    if path_hits:
        detail += f"（规范化路径：{', '.join(path_hits)}）"

    risk = highest.risk

    if risk is RiskLevel.CRITICAL:
        return GuardResult(False, Action.DENY, matched_ids, risk,
                           f"已拦截【严重风险】操作，不可执行：{detail}", False)

    if risk is RiskLevel.HIGH:
        if highest.action is Action.CONFIRM and not confirmed:
            return GuardResult(False, Action.CONFIRM, matched_ids, risk,
                               f"【高风险】操作需二次确认：{detail}", True)
        if highest.action is Action.DENY and not authorized:
            return GuardResult(False, Action.DENY, matched_ids, risk,
                               f"已拦截【高风险】操作，需显式授权后才可执行：{detail}", False)
        return GuardResult(True, Action.ALLOW, matched_ids, risk,
                           f"高风险操作已获授权/确认，放行：{detail}", False)

    if risk is RiskLevel.MEDIUM:
        if confirmed:
            return GuardResult(True, Action.ALLOW, matched_ids, risk,
                               f"中风险操作已确认，放行：{detail}", False)
        return GuardResult(False, Action.CONFIRM, matched_ids, risk,
                           f"【中风险】操作需二次确认：{detail}", True)

    # LOW
    return GuardResult(True, Action.ALLOW, matched_ids, risk,
                       f"低风险，记录后放行：{detail}", False)


def scan_injection(text: str) -> GuardResult:
    """防线3 接入点：只扫描注入类规则，用于检查用户输入 / 被当作上下文的文件内容。

    与命令裁决分开，便于编排器在接收指令阶段先做一次注入体检。
    """
    hits = [r for r in match_rules(text) if r.category == "inject"]
    if not hits:
        return GuardResult(True, Action.ALLOW, [], RiskLevel.LOW, "未检测到提示词注入特征。")
    highest = max(hits, key=lambda r: r.risk.order)
    detail = "；".join(f"[{r.id}] {r.description}" for r in hits)
    return GuardResult(False, Action.DENY, [r.id for r in hits], highest.risk,
                       f"检测到疑似提示词注入，已拒绝该请求：{detail}", False)
