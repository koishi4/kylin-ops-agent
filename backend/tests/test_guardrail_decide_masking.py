"""防线2 裁决回归测试：风险等级与门控动作【各自独立】取最严，杜绝跨等级门控遮蔽。

被修复的缺陷：旧 `_decide` 取「单条最高 (risk, action) 规则」的 action 作裁决，于是一条
HIGH+CONFIRM 规则会**遮蔽**同时命中的 MEDIUM+DENY 规则——最终只判 CONFIRM（用户点确认即过），
丢掉了 DENY 要求的「需显式授权」这道更强门控。修复后改为门控并集：命中集里任一 DENY 必须
authorized=True、任一 CONFIRM 必须 confirmed=True，可叠加，严格「只升不降」。

这里直接喂合成 Rule 给 `_decide`，把这条不变量与具体正则规则集解耦地钉死。
"""
from __future__ import annotations

from app.guardrail.engine import _decide
from app.guardrail.rules import Action, RiskLevel, Rule


def _r(rid: str, risk: RiskLevel, action: Action) -> Rule:
    return Rule(rid, "", risk, action, f"desc-{rid}", "test")


HIGH_CONFIRM = _r("H-CONFIRM", RiskLevel.HIGH, Action.CONFIRM)
MED_DENY = _r("M-DENY", RiskLevel.MEDIUM, Action.DENY)
MED_CONFIRM = _r("M-CONFIRM", RiskLevel.MEDIUM, Action.CONFIRM)
HIGH_DENY = _r("H-DENY", RiskLevel.HIGH, Action.DENY)
LOW_ALLOW = _r("L-ALLOW", RiskLevel.LOW, Action.ALLOW)
CRIT_DENY = _r("C-DENY", RiskLevel.CRITICAL, Action.DENY)


class TestNoCrossRiskActionMasking:
    def test_high_confirm_does_not_mask_medium_deny(self):
        """HIGH+CONFIRM 与 MEDIUM+DENY 同时命中：未授权时必须按 DENY 拦（需显式授权），
        绝不被 HIGH+CONFIRM「降格」成一键确认即过。"""
        hits = [HIGH_CONFIRM, MED_DENY]
        # 仅二次确认（点了确认但未授权）→ DENY 门控仍未兑现 → 拦截
        res = _decide(hits, [], authorized=False, confirmed=True)
        assert res.allowed is False
        assert res.action is Action.DENY
        assert res.require_confirm is False
        assert "显式授权" in res.reason
        # 风险标签取最高（HIGH），但门控取最严（DENY）——二者独立
        assert res.risk is RiskLevel.HIGH

    def test_both_gates_must_be_cleared(self):
        """DENY 与 CONFIRM 门控叠加：必须同时 authorized ∧ confirmed 才放行。"""
        hits = [HIGH_CONFIRM, MED_DENY]
        # 授权但未确认 → CONFIRM 门控未兑现 → 需确认
        r1 = _decide(hits, [], authorized=True, confirmed=False)
        assert r1.allowed is False and r1.action is Action.CONFIRM and r1.require_confirm is True
        # 授权且确认 → 两道门控都兑现 → 放行
        r2 = _decide(hits, [], authorized=True, confirmed=True)
        assert r2.allowed is True and r2.action is Action.ALLOW

    def test_deny_unaffected_by_confirm_only(self):
        """单 DENY 命中：confirmed=True 不能替代授权（确认 ≠ 授权）。"""
        res = _decide([HIGH_DENY], [], authorized=False, confirmed=True)
        assert res.allowed is False and res.action is Action.DENY

    def test_single_rule_behavior_preserved(self):
        """单规则裁决与历史一致（修复不改单命中语义）。"""
        # HIGH+CONFIRM 未确认 → 需确认
        assert _decide([HIGH_CONFIRM], [], authorized=False, confirmed=False).action is Action.CONFIRM
        # HIGH+CONFIRM 已确认 → 放行
        assert _decide([HIGH_CONFIRM], [], authorized=False, confirmed=True).allowed is True
        # MEDIUM+CONFIRM 已确认 → 放行
        assert _decide([MED_CONFIRM], [], authorized=False, confirmed=True).allowed is True

    def test_critical_unconditional(self):
        """CRITICAL 命中：授权 + 确认都不可覆盖。"""
        res = _decide([CRIT_DENY, HIGH_CONFIRM], [], authorized=True, confirmed=True)
        assert res.allowed is False and res.action is Action.DENY
        assert res.risk is RiskLevel.CRITICAL

    def test_low_only_allows(self):
        """纯 LOW 命中：记录后放行（LOW 不据 action 升级，保历史语义）。"""
        res = _decide([LOW_ALLOW], [], authorized=False, confirmed=False)
        assert res.allowed is True and res.risk is RiskLevel.LOW

    def test_label_uses_highest_risk_gate_uses_strictest_action(self):
        """风险标签随最高风险、门控随最严动作——两个维度解耦。"""
        # MEDIUM+DENY 单独命中：标签 MEDIUM、门控 DENY
        res = _decide([MED_DENY], [], authorized=False, confirmed=False)
        assert res.risk is RiskLevel.MEDIUM and res.action is Action.DENY
