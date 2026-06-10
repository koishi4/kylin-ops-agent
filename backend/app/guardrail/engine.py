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

from .ast_analyzer import analyze_command_ast, ast_synthetic_rules
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
    # 防线2 增强：Bash AST 结构分析的逐项发现（供前端思维链「正则判定 / AST 结构分析」两栏对比）。
    ast_findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "action": self.action.value,
            "matched_rules": self.matched_rules,
            "risk": self.risk.value,
            "reason": self.reason,
            "require_confirm": self.require_confirm,
            "ast_findings": self.ast_findings,
        }


# realpath 命中关键路径时合成的虚拟规则，作为正则之外的兜底防线
_PATH_RULE = Rule(
    "PATH-001", "", RiskLevel.CRITICAL, Action.DENY,
    "命令参数经路径规范化后落在系统关键目录（防相对路径/软链接绕过）", "delete",
)


def check_command(cmd: str, *, authorized: bool = False, confirmed: bool = False) -> GuardResult:
    """对单条候选命令做护栏裁决（正则规则 + realpath 路径兜底 + Bash AST 结构分析）。

    三重判定**保守合并取更严**：把三者的命中都并入同一 hits 列表，再按「最高风险 + 授权/确认」
    统一裁决。这从结构上保证 AST/路径兜底只能把判定抬高，绝不会把规则已判的 CRITICAL/DENY 调低。

    Args:
        cmd: 待执行的命令字符串（LLM 生成或用户给定）
        authorized: 本次会话是否对 HIGH 风险操作显式授权（防线4 接入点）
        confirmed: 用户是否已对 CONFIRM 类操作二次确认
    """
    hits: list[Rule] = list(match_rules(cmd))

    # 第二重：路径规范化命中关键目录（捕获正则难覆盖的相对路径/软链接变形）
    path_hits = hits_critical_path(cmd)
    if path_hits and _PATH_RULE.id not in {r.id for r in hits}:
        hits.append(_PATH_RULE)

    # 第三重：Bash AST 结构分析（管道接 shell / 命令替换 / 重定向写关键路径 / 命令链 等）。
    # 发现转成合成规则并入 hits，与正则共用裁决逻辑——只能升级，不能放松（见 ast_analyzer）。
    ast = analyze_command_ast(cmd)
    hits.extend(ast_synthetic_rules(ast))
    ast_dicts = ast.to_dict()["findings"]

    if not hits:
        return GuardResult(
            allowed=True, action=Action.ALLOW, risk=RiskLevel.LOW,
            reason="未命中任何高危规则，且 AST 结构分析未发现 shell 危险结构，命令视为安全。",
            ast_findings=ast_dicts,
        )

    result = _decide(hits, path_hits, authorized=authorized, confirmed=confirmed)
    result.ast_findings = ast_dicts
    if ast.findings:
        structs = "、".join(sorted({f.structure for f in ast.findings}))
        result.reason += f" | AST 结构分析：检出 shell 结构（{structs}），需分解为结构化工具或显式确认。"
    return result


# 同风险等级内动作的「严格度」排序，破平局时取更严（DENY > CONFIRM > ALLOW），
# 确保 AST 的 HIGH/CONFIRM 发现绝不会把同级正则规则的 HIGH/DENY 裁决降格。
_ACTION_SEVERITY = {Action.DENY: 2, Action.CONFIRM: 1, Action.ALLOW: 0}

# 风险等级的中文标签，供裁决理由按实际等级措辞（不再把 MEDIUM 说成「高风险」）。
_RISK_LABEL = {RiskLevel.CRITICAL: "严重风险", RiskLevel.HIGH: "高风险",
               RiskLevel.MEDIUM: "中风险", RiskLevel.LOW: "低风险"}


def _decide(hits: list[Rule], path_hits: list[str], *,
            authorized: bool, confirmed: bool) -> GuardResult:
    """按命中规则集做四级裁决（正则/路径兜底/AST 合成规则统一走这里）。

    裁决由「最高风险等级 + 该等级最严动作」共同决定（HIGH 与 MEDIUM 走同一套 action 门控）：
    - CRITICAL：无条件拒绝，授权/确认都不可覆盖。
    - HIGH / MEDIUM：按命中的 action 门控——DENY 需显式授权、CONFIRM 需二次确认、ALLOW 记录放行。
      （此前 MEDIUM 分支无视 action，会把配置里的 medium+deny 静默降级成 confirm；现已统一，消除
       「可配置 ≠ 可削弱」叙事的这处缺口。）
    - LOW：记录后放行。
    """
    highest = max(hits, key=lambda r: (r.risk.order, _ACTION_SEVERITY[r.action]))
    matched_ids = [r.id for r in hits]
    detail = "；".join(f"[{r.id}] {r.description}" for r in hits)
    if path_hits:
        detail += f"（规范化路径：{', '.join(path_hits)}）"

    risk = highest.risk
    label = _RISK_LABEL[risk]

    if risk is RiskLevel.CRITICAL:
        return GuardResult(False, Action.DENY, matched_ids, risk,
                           f"已拦截【{label}】操作，不可执行：{detail}", False)

    if risk in (RiskLevel.HIGH, RiskLevel.MEDIUM):
        if highest.action is Action.CONFIRM and not confirmed:
            return GuardResult(False, Action.CONFIRM, matched_ids, risk,
                               f"【{label}】操作需二次确认：{detail}", True)
        if highest.action is Action.DENY and not authorized:
            return GuardResult(False, Action.DENY, matched_ids, risk,
                               f"已拦截【{label}】操作，需显式授权后才可执行：{detail}", False)
        return GuardResult(True, Action.ALLOW, matched_ids, risk,
                           f"{label}操作已获授权/确认，放行：{detail}", False)

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
