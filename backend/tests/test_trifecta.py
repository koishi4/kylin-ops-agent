"""致命三要素 / Meta Rule of Two 能力面测试（改进v2 P3-2）。

被测安全性质：
  1. 能力标签覆盖全部工具/动作；未知名保守按「无能力」；没有任何单点集齐三要素。
  2. **结构性不变量**：感知层（READONLY）任意路径能力上限 ≤2 腿、永不含『改状态/外联』，
     故单靠只读工具结构上不可能凑齐致命三要素。
  3. evaluate_path 的 Rule of Two 裁决：≤2 腿放行；集齐三腿且无人工在环 → 须人工审批；
     有人工在环（动作层二次确认）→ 允许（带监督）。
  4. 面板数据 capability_table 自洽（图例 3 条、工具数=15+3、不变量正确）。
"""
from __future__ import annotations

from app.core.actions import ACTIONS
from app.guardrail.trifecta import (
    TOOL_CAPS,
    Capability,
    capability_table,
    caps_for,
    evaluate_path,
)
from app.mcp_server.tools import REGISTRY

_READONLY = list(REGISTRY)            # 15 个只读工具
_STATE = Capability.STATE_CHANGE.value


class TestTagging:
    def test_every_tool_and_action_tagged(self):
        for name in _READONLY:
            assert name in TOOL_CAPS, f"只读工具未打能力标签：{name}"
        for name in ACTIONS:
            assert name in TOOL_CAPS, f"动作未打能力标签：{name}"

    def test_unknown_name_has_no_caps(self):
        c = caps_for("不存在的工具")
        assert c.legs() == set()

    def test_no_single_tool_completes_trifecta(self):
        """没有任何单个工具/动作自己就集齐三要素——三要素只能由路径『组合』出来。"""
        for name, caps in TOOL_CAPS.items():
            assert len(caps.legs()) < 3, f"{name} 单点即集齐三要素，违反最小能力原则"


class TestReadonlyInvariant:
    def test_readonly_path_never_changes_state(self):
        for name in _READONLY:
            assert caps_for(name).state_change is False, f"只读工具竟带改状态腿：{name}"

    def test_full_readonly_path_caps_at_two_legs(self):
        """把所有只读工具凑成一条路径，能力并集仍 ≤2 腿且不含改状态、不集齐三要素。"""
        r = evaluate_path(_READONLY)
        assert r.leg_count <= 2
        assert _STATE not in r.legs
        assert r.trifecta_complete is False
        assert r.rule_of_two_satisfied is True
        assert r.recommendation == "allow"


class TestRuleOfTwo:
    def test_single_readonly_allows(self):
        r = evaluate_path(["disk_usage"])
        assert r.recommendation == "allow"
        assert r.trifecta_complete is False

    def test_lone_action_is_two_legs(self):
        """单个动作 = 访问敏感(B) + 改状态(C) = 2 腿，满足 Rule of Two。"""
        r = evaluate_path(["kill_process"])
        assert set(r.legs) == {Capability.SENSITIVE.value, _STATE}
        assert r.trifecta_complete is False
        assert r.recommendation == "allow"

    def test_trifecta_requires_human_when_complete(self):
        """读不可信日志(A,B) + 改状态动作(B,C) 凑齐三要素，无人工在环 → 须人工审批。"""
        r = evaluate_path(["tail_log", "kill_process"], human_in_loop=False)
        assert set(r.legs) == {Capability.UNTRUSTED.value, Capability.SENSITIVE.value, _STATE}
        assert r.trifecta_complete is True
        assert r.rule_of_two_satisfied is False
        assert r.recommendation == "require_human_approval"

    def test_trifecta_allowed_with_human_in_loop(self):
        """同一路径若处于人工在环（动作层强制二次确认）→ 允许（带监督）。"""
        r = evaluate_path(["tail_log", "kill_process"], human_in_loop=True)
        assert r.trifecta_complete is True
        assert r.rule_of_two_satisfied is True
        assert r.recommendation == "allow_with_oversight"


class TestPanel:
    def test_capability_table_shape(self):
        t = capability_table()
        assert len(t["legend"]) == 3
        assert len(t["tools"]) == len(_READONLY) + len(ACTIONS)
        # 按腿数降序：首行腿数 >= 末行腿数
        legs = [row["leg_count"] for row in t["tools"]]
        assert legs == sorted(legs, reverse=True)

    def test_invariant_block(self):
        inv = capability_table()["invariant"]
        assert inv["readonly_max_legs"] == 2
        assert inv["readonly_has_state_change"] is False
