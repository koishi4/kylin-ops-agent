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
from .effect_analyzer import EffectSet, analyze_effects
from .rules import (
    Action,
    RiskLevel,
    Rule,
    hits_critical_path,
    match_rules,
)


@dataclass
class GuardResult:
    """护栏对一条命令的最终裁决：是否放行、命中规则、风险等级、是否需二次确认、AST 发现。"""

    allowed: bool
    action: Action
    matched_rules: list[str] = field(default_factory=list)
    risk: RiskLevel = RiskLevel.LOW
    reason: str = ""
    require_confirm: bool = False
    # 防线2 增强：Bash AST 结构分析的逐项发现（供前端思维链「正则判定 / AST 结构分析」两栏对比）。
    ast_findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        """序列化为 dict，供审计落库与前端思维链回放。"""
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


def effect_synthetic_rules(effects: EffectSet) -> list[Rule]:
    """把「副作用集」分析（effect_analyzer）的硬结论转成合成规则，并入 hits 走统一裁决。

    这是「按效果判定」对「按字面拦串」的根治在裁决层的落地：只要一条命令**实际会**写/删
    关键路径、或建立外联通道，无论它长什么样、用了哪个动词，都据效果升级——与 AST 合成规则
    同样的「只升级、绝不降级」语义（合成规则只追加进 hits，由 _decide 取最高风险，永远不会把
    规则已判的 CRITICAL/DENY 调低）。

    刻意与既有正则/AST 规则**部分重叠不冲突**：重叠时只是多一条同向（更严或等严）发现，
    不会产生矛盾；本模块的真正价值是抓既有规则漏掉的「按效果应拦」（如 install/cp/mv/tee
    把内容落进 /etc、/boot、sudoers 等关键区）。
    """
    out: list[Rule] = []
    if effects.egress:
        out.append(Rule(
            "EFFECT-EGRESS", "", RiskLevel.CRITICAL, Action.DENY,
            "效果分析：命令会建立外联/反弹 shell 通道（/dev/tcp·udp、nc -e、socat EXEC 等），"
            "构成远程代码执行与数据外泄风险", "egress"))
    if effects.deletes:
        out.append(Rule(
            "EFFECT-DELETE-CRITICAL", "", RiskLevel.CRITICAL, Action.DENY,
            f"效果分析：命令实际会删除/截断系统关键路径（{', '.join(effects.deletes)}），"
            "不可逆数据/系统损坏", "delete"))
    if effects.writes:
        out.append(Rule(
            "EFFECT-WRITE-CRITICAL", "", RiskLevel.HIGH, Action.DENY,
            f"效果分析：命令实际会写/覆盖系统关键路径（{', '.join(effects.writes)}），"
            "可致越权改配置/植入文件/系统损坏", "config"))
    if effects.fetches_to_critical:
        out.append(Rule(
            "EFFECT-FETCH-TO-CRITICAL", "", RiskLevel.CRITICAL, Action.DENY,
            f"效果分析：命令把远端下载内容直接写入系统关键路径（{', '.join(effects.fetches_to_critical)}），"
            f"远端代码落入可执行/持久化位置，是两段式攻击的落地段（下载→驻留），硬拦。", "exfil"))
    # 「读敏感凭据」能力标签——补 held-out 真盲区（cp /etc/shadow 式凭据外泄），呼应 Rule-of-Two：
    #   读敏感（敏感数据腿）+ 外发（egress 反弹 / net_send 外送）= 双腿 → 主动外泄，CRITICAL/DENY；
    #   仅读敏感（单腿）= 外泄前置 → MEDIUM/CONFIRM，要求人在环确认操作意图（admin 偶有正当需求，
    #   故不直接 DENY，但绝不静默放行）。组合门控保证广度安全：既读凭据又外发，无论意图都该被拦。
    if effects.reads_sensitive:
        if effects.egress or effects.net_send:
            out.append(Rule(
                "EFFECT-CRED-EXFIL", "", RiskLevel.CRITICAL, Action.DENY,
                f"效果分析：命令读出敏感凭据（{', '.join(effects.reads_sensitive)}）并经网络外发，"
                "构成凭据窃取/数据外泄（读敏感 + 外联双腿，违反 Rule-of-Two）", "exfil"))
        else:
            out.append(Rule(
                "EFFECT-CRED-READ", "", RiskLevel.MEDIUM, Action.CONFIRM,
                f"效果分析：命令读取/复制敏感凭据文件（{', '.join(effects.reads_sensitive)}），"
                "是凭据窃取与外泄的前置动作，需二次确认操作意图", "exfil"))
    return out


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

    # 第四重：副作用集（EffectSet）分析——「按效果判定」对「按字面拦串」的根治。
    # 静态推导命令实际会写/删哪些路径、是否外联；当效果落在关键区或构成外联时合成高/严风险并入
    # hits（只升级，绝不降级）。判不准/写非关键路径时沉默——保「误杀率 0%」不变（见 effect_analyzer）。
    effects = analyze_effects(cmd)
    hits.extend(effect_synthetic_rules(effects))

    if not hits:
        reason = ("未命中任何高危规则，AST 结构分析未发现 shell 危险结构，"
                  "副作用分析未发现触及关键区的写/删/外联，命令视为安全。")
        if effects.fetches_remote and not effects.fetches_to_critical:  # 下载到盘不升级（架构上无自由执行路径），但如实标注供审计
            reason += " | 副作用分析：抓取远端产物落盘（两段式攻击第一段，已标注审计，未升级）。"
        return GuardResult(
            allowed=True, action=Action.ALLOW, risk=RiskLevel.LOW,
            reason=reason, ast_findings=ast_dicts,
        )

    result = _decide(hits, path_hits, authorized=authorized, confirmed=confirmed)
    result.ast_findings = ast_dicts
    if ast.findings:
        structs = "、".join(sorted({f.structure for f in ast.findings}))
        result.reason += f" | AST 结构分析：检出 shell 结构（{structs}），需分解为结构化工具或显式确认。"
    if effects.hits_critical:
        parts = []
        if effects.writes:
            parts.append(f"写关键路径 {', '.join(effects.writes)}")
        if effects.deletes:
            parts.append(f"删/截断关键路径 {', '.join(effects.deletes)}")
        if effects.egress:
            parts.append("建立外联/反弹 shell 通道")
        result.reason += f" | 副作用分析：{'；'.join(parts)}（据实际效果升级，非字面匹配）。"
    if effects.reads_sensitive:
        tail = "，并经网络外发（凭据外泄）" if effects.is_credential_exfil else "（外泄前置，需确认意图）"
        result.reason += f" | 副作用分析：读出敏感凭据 {', '.join(effects.reads_sensitive)}{tail}。"
    if effects.fetches_to_critical:
        result.reason += (" | 副作用分析：远端下载内容落盘到系统关键路径 "
                          f"{', '.join(effects.fetches_to_critical)}（落入可执行/持久化位置，据效果升级 DENY）。")
    elif effects.fetches_remote:
        result.reason += " | 副作用分析：抓取远端产物落盘（两段式攻击第一段，已标注审计，未升级）。"
    return result


# 风险等级的中文标签，供裁决理由按实际等级措辞（不再把 MEDIUM 说成「高风险」）。
_RISK_LABEL = {RiskLevel.CRITICAL: "严重风险", RiskLevel.HIGH: "高风险",
               RiskLevel.MEDIUM: "中风险", RiskLevel.LOW: "低风险"}


def _decide(hits: list[Rule], path_hits: list[str], *,
            authorized: bool, confirmed: bool) -> GuardResult:
    """按命中规则集做四级裁决（正则/路径兜底/AST 合成规则统一走这里）。

    风险等级与门控动作【各自独立】取最严，而非绑定到「单条最高规则」：
    - 风险标签 = 命中里最高的风险等级（仅决定措辞 + 是否 CRITICAL 红线）。
    - 门控 = 命中里【所有】要求授权(DENY)/确认(CONFIRM) 的规则之并集，逐一兑现、任一未兑现即拦。

    为什么不再取「单条最高 (risk, action) 规则」的 action（修复的masking缺陷）：
      取单条会让一条 HIGH+CONFIRM 规则**遮蔽**同时命中的 MEDIUM+DENY 规则——最终只判 CONFIRM
      （用户点一下确认即过），丢掉了 DENY 要求的「需显式授权」这道更强门控。改为门控并集后，
      只要命中集里有任一 DENY，就必须 authorized=True；有任一 CONFIRM，就必须 confirmed=True；
      两者可叠加。严格「只升不降」，杜绝「高风险弱门控遮蔽低风险强门控」。

    裁决：
    - CRITICAL：无条件拒绝，授权/确认都不可覆盖。
    - HIGH / MEDIUM：DENY(需授权) 严于 CONFIRM(需确认)，按并集逐一兑现。
    - LOW：记录后放行（与历史一致，LOW 命中不据 action 升级）。
    """
    matched_ids = [r.id for r in hits]
    detail = "；".join(f"[{r.id}] {r.description}" for r in hits)
    if path_hits:
        detail += f"（规范化路径：{', '.join(path_hits)}）"

    # RiskLevel 是普通 Enum（无原生序），按 .order 取最高风险。
    risk = max((r.risk for r in hits), key=lambda x: x.order)
    label = _RISK_LABEL[risk]

    if risk is RiskLevel.CRITICAL:
        return GuardResult(False, Action.DENY, matched_ids, risk,
                           f"已拦截【{label}】操作，不可执行：{detail}", False)

    if risk in (RiskLevel.HIGH, RiskLevel.MEDIUM):
        # 门控并集：命中集里任一 DENY/CONFIRM 都必须被对应地清除（DENY 严于 CONFIRM）。
        needs_auth = any(r.action is Action.DENY for r in hits)
        needs_confirm = any(r.action is Action.CONFIRM for r in hits)
        if needs_auth and not authorized:
            return GuardResult(False, Action.DENY, matched_ids, risk,
                               f"已拦截【{label}】操作，需显式授权后才可执行：{detail}", False)
        if needs_confirm and not confirmed:
            return GuardResult(False, Action.CONFIRM, matched_ids, risk,
                               f"【{label}】操作需二次确认：{detail}", True)
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
