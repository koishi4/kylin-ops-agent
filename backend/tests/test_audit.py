"""审计存储测试：思维链 trace 落 SQLite 后能按 trace_id 完整回放（可追溯闭环）。"""
from __future__ import annotations

import pytest

from app.audit import store


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """把审计库指向临时文件，避免污染真实 audit.sqlite。"""
    db = tmp_path / "audit_test.sqlite"
    monkeypatch.setattr(store, "_db_path", lambda: str(db))
    store.init_db()
    return db


def _steps():
    return [
        {"stage": "接收指令", "detail": "查看磁盘使用率"},
        {"stage": "感知环境", "detail": {"available_tools": ["disk_usage"]}},
        {"stage": "推理决策", "detail": {"tool": "disk_usage", "arguments": {"path": "/"}}},
        {"stage": "安全校验", "detail": {"intent": "white", "decision": "auto_approve"}},
        {"stage": "执行结果", "detail": {"percent": 42.0}},
    ]


def test_save_and_get_roundtrip(tmp_db):
    store.save_trace("t-001", "查看磁盘使用率", "磁盘使用率 42%", _steps(),
                     intent="white", blocked=False, llm_provider="mock")
    t = store.get_trace("t-001")
    assert t is not None
    assert t["user_input"] == "查看磁盘使用率"
    assert t["intent"] == "white" and t["blocked"] is False
    # 五段齐全且按序
    assert [s["stage"] for s in t["steps"]] == \
        ["接收指令", "感知环境", "推理决策", "安全校验", "执行结果"]
    # 结构化 detail 能还原
    assert t["steps"][1]["detail"]["available_tools"] == ["disk_usage"]


def test_list_traces_orders_recent_first(tmp_db):
    store.save_trace("t-a", "a", "ans-a", _steps())
    store.save_trace("t-b", "b", "ans-b", _steps())
    rows = store.list_traces(limit=10)
    ids = [r["trace_id"] for r in rows]
    assert "t-a" in ids and "t-b" in ids
    # list 不返回 steps（轻量）
    assert "steps" not in rows[0]


def test_resave_replaces_steps(tmp_db):
    store.save_trace("t-x", "q", "a1", _steps())
    store.save_trace("t-x", "q", "a2", _steps()[:2])  # 重存，段数变少
    t = store.get_trace("t-x")
    assert t["answer"] == "a2"
    assert len(t["steps"]) == 2  # 旧段已被清理，无残留


def test_blocked_trace_recorded(tmp_db):
    store.save_trace("t-blk", "格式化磁盘", "已拦截", _steps()[:1],
                     intent="black", blocked=True)
    t = store.get_trace("t-blk")
    assert t["blocked"] is True and t["intent"] == "black"


def test_missing_trace_returns_none(tmp_db):
    assert store.get_trace("nope") is None
