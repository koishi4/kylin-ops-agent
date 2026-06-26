"""感知层能力隔离不变量（启动期 fail-closed 闸门）测试。

把项目第一安全保证「LLM 可达的感知层无状态变更能力」从「人工纪律 + 散文」升级为
「每次启动强制核验」。本文件钉死：① 生产配置下不变量成立、启动闸门放行；② 一旦回归
（把带 state_change 的工具接进 REGISTRY），闸门必须捕获并拒绝启动。
"""
from __future__ import annotations

import pytest
from app.core.actions import ACTIONS
from app.guardrail.trifecta import (
    TOOL_CAPS,
    ToolCaps,
    assert_perception_isolation,
    caps_for,
    perception_isolation_violations,
)
from app.mcp_server.tools import REGISTRY


def test_invariant_holds_in_production():
    """当前代码库：不变量成立，启动闸门放行（不抛）。"""
    assert perception_isolation_violations() == []
    assert_perception_isolation()


def test_every_registry_tool_has_no_state_change_leg():
    """编排器可达的每个 MCP 工具都不得具备『改状态/对外通信』腿。"""
    for name in REGISTRY:
        assert caps_for(name).state_change is False, f"{name} 不应具备状态变更能力"


def test_state_change_names_are_controlled_actions_only():
    """能力库里带 state_change 的名字必须都是受控动作、且不在 MCP 注册表里。"""
    for name, caps in TOOL_CAPS.items():
        if caps.state_change:
            assert name in ACTIONS, f"{name} 带 state_change 却不在受控动作白名单"
            assert name not in REGISTRY, f"{name} 带 state_change 却暴露为 MCP 工具"


def test_regression_state_change_tool_in_registry_is_refused(monkeypatch):
    """模拟回归：把一个带 state_change 的伪造工具塞进 REGISTRY → 闸门必须捕获并 fail-closed。"""
    sample_spec = REGISTRY[next(iter(REGISTRY))]
    monkeypatch.setitem(REGISTRY, "rogue_mutator", sample_spec)
    monkeypatch.setitem(TOOL_CAPS, "rogue_mutator", ToolCaps(state_change=True))

    violations = perception_isolation_violations()
    assert any("rogue_mutator" in v for v in violations)
    with pytest.raises(RuntimeError, match="能力隔离不变量"):
        assert_perception_isolation()


def test_regression_mislabeled_registry_tool_is_refused(monkeypatch):
    """模拟回归：给一个真实存在的 MCP 工具误打 state_change 标签 → 同样被闸门拒绝。"""
    victim = next(iter(REGISTRY))
    monkeypatch.setitem(TOOL_CAPS, victim, ToolCaps(untrusted=True, state_change=True))
    violations = perception_isolation_violations()
    assert any(victim in v for v in violations)
    with pytest.raises(RuntimeError):
        assert_perception_isolation()


def test_action_trace_carries_rule_of_two_at_mutation_point(tmp_path, monkeypatch):
    """受控动作的「安全校验」段必须带 Rule of Two 能力评估，且 state_change(C) 腿在此、
    处于人工在环（confirmed）之下——证明能力模型被用在真实状态变更点，而非只在只读编排路径。"""
    from app.core import actions
    from app.core.diagnosis import FileClass

    # 隔离路径关键性启发式：本测试只验「能力评估是否落在状态变更点」，不验 classify_file 本身。
    monkeypatch.setattr(actions, "classify_file",
                        lambda p: (FileClass.CLEANABLE, "test-cleanable"))
    f = tmp_path / "app.log"
    f.write_text("x" * 50)

    r = actions.run_action("truncate_log", {"path": str(f)}, confirmed=True, dry_run=True)
    details = [s["detail"] for s in r["trace"]
               if s["stage"] == "安全校验" and isinstance(s["detail"], dict)]
    rot = [d["rule_of_two"] for d in details if "rule_of_two" in d]
    assert rot, "动作链的安全校验段应内嵌 rule_of_two 能力评估"
    cap = rot[-1]
    assert "state_change" in cap["legs"], "状态变更点必须标注 state_change(C) 能力腿"
    assert cap["human_in_loop"] is True, "confirmed=True 应体现为人工在环"
    assert cap["rule_of_two_satisfied"] is True
    assert cap["trifecta_complete"] is False  # 动作不接触不可信内容(A)，永不集齐三要素
