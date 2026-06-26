"""审计存储测试：思维链 trace 落 SQLite 后能按 trace_id 完整回放（可追溯闭环）。"""
from __future__ import annotations

import sqlite3

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


class TestHashChain:
    """P1-3 审计防篡改：HMAC 哈希链，任何事后篡改都断链。"""

    def test_valid_chain_passes(self, tmp_db):
        store.save_trace("h-ok", "查看磁盘", "42%", _steps())
        v = store.verify_chain("h-ok")
        assert v["valid"] is True
        assert v["steps"] == 5 and v["broken_at"] is None
        assert v["head_hash"]

    def test_get_trace_exposes_hashes(self, tmp_db):
        store.save_trace("h-hash", "q", "a", _steps())
        t = store.get_trace("h-hash")
        assert t["head_hash"]
        assert t["steps"][0]["prev_hash"] == store._GENESIS
        # 链接：后一条的 prev_hash == 前一条的 step_hash
        assert t["steps"][1]["prev_hash"] == t["steps"][0]["step_hash"]
        assert t["steps"][-1]["step_hash"] == t["head_hash"]

    def test_tampering_detail_breaks_chain(self, tmp_db):
        store.save_trace("h-tamper", "q", "a", _steps())
        # 直接改库：篡改第 4 段（安全校验）的内容，模拟事后抹除被拦记录
        with sqlite3.connect(str(tmp_db)) as raw:
            raw.execute(
                "UPDATE steps SET detail = ? WHERE trace_id = ? AND seq = ?",
                ('{"intent": "white", "decision": "auto_approve_FORGED"}', "h-tamper", 3),
            )
            raw.commit()
        v = store.verify_chain("h-tamper")
        assert v["valid"] is False
        assert v["broken_at"] == 3
        assert "篡改" in v["reason"] or "断链" in v["reason"]

    def test_deleting_tail_step_breaks_head(self, tmp_db):
        store.save_trace("h-del", "q", "a", _steps())
        with sqlite3.connect(str(tmp_db)) as raw:
            raw.execute("DELETE FROM steps WHERE trace_id = ? AND seq = ?", ("h-del", 4))
            raw.commit()
        v = store.verify_chain("h-del")
        assert v["valid"] is False                 # 尾段被删 → head 封口不匹配

    def test_deleting_middle_step_breaks_order(self, tmp_db):
        store.save_trace("h-mid", "q", "a", _steps())
        with sqlite3.connect(str(tmp_db)) as raw:
            raw.execute("DELETE FROM steps WHERE trace_id = ? AND seq = ?", ("h-mid", 2))
            raw.commit()
        v = store.verify_chain("h-mid")
        assert v["valid"] is False
        assert v["broken_at"] == 2                  # seq 出现缺口

    def test_wrong_key_invalidates(self, tmp_db, monkeypatch):
        """换密钥后旧链一律校验失败——印证「无密钥无法重算合法哈希」。"""
        store.save_trace("h-key", "q", "a", _steps())
        assert store.verify_chain("h-key")["valid"] is True
        monkeypatch.setattr(store, "_hmac_key", lambda: b"a-different-key")
        assert store.verify_chain("h-key")["valid"] is False

    def test_verify_missing_trace(self, tmp_db):
        v = store.verify_chain("does-not-exist")
        assert v["valid"] is False and "不存在" in v["reason"]


def test_audit_redacts_credentials(tmp_db):
    """P1：落库前脱敏——token/Authorization/password/私钥不得以明文进审计库。"""
    secret_steps = [
        {"stage": "接收指令", "detail": {
            "headers": {"Authorization": "Bearer s3cr3t-operator-token-abcdef"},
            "token": "live-key-9876543210", "password": "hunter2",
            "note": "private key below",
            "pem": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3Nz\n-----END OPENSSH PRIVATE KEY-----"}},
    ]
    store.save_trace("t-redact", "登录", "ok", secret_steps,
                     intent="action", llm_provider="mock")
    t = store.get_trace("t-redact")
    blob = str(t["steps"][0]["detail"])
    assert "s3cr3t-operator-token-abcdef" not in blob
    assert "live-key-9876543210" not in blob
    assert "hunter2" not in blob
    assert "AAAAB3Nz" not in blob
    assert "***REDACTED***" in blob
    # 脱敏后哈希链仍自洽（脱敏发生在计哈希之前）
    assert store.verify_chain("t-redact")["valid"] is True
