"""审计证据包导出 / 核验测试（P2）。

固化「自封口证据包」的关键性质，防回归：
1. 导出包含完整 trace + verify 结果 + 导出时护栏/工具版本(components) + HMAC seal。
2. 未改动的证据包：verify_evidence 判 valid（seal 匹配且链有效）。
3. 导出后篡改包内任意字段（trace/answer/components）→ seal 失配 → verify_evidence 判无效。
4. 库内哈希链被破坏后再导出：seal 仍匹配（包本身没改），但 chain_valid=False（双层防篡改各司其职）。
5. 不存在的 trace 导出 → ok=False。
"""
from __future__ import annotations

import pytest

from app.audit import store


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    db = tmp_path / "audit_test.sqlite"
    monkeypatch.setattr(store, "_db_path", lambda: str(db))
    store.init_db()
    return db


def _steps():
    return [
        {"stage": "接收指令", "detail": "清空 /var/log/app.log"},
        {"stage": "感知环境", "detail": {"classify": "cleanable"}},
        {"stage": "推理决策", "detail": {"command": "os.ftruncate(0)"}},
        {"stage": "安全校验", "detail": {"passed": True}},
        {"stage": "执行结果", "detail": {"executed": True}},
    ]


def _save(trace_id="ev-1"):
    store.save_trace(trace_id, "清空日志", "已清空", _steps(),
                     intent="action", blocked=False, llm_provider="mock")
    return trace_id


_COMPONENTS = {"rules": {"fingerprint": "abc123", "count": 20},
               "tool_schema_baseline": {"fingerprint": "def456"},
               "app": {"name": "kylin-ops-agent", "version": "0.1.0"}}


def test_export_shape(tmp_db):
    tid = _save()
    pack = store.export_evidence(tid, components=_COMPONENTS)
    assert pack["ok"] is True
    ev = pack["evidence"]
    assert ev["kind"] == store.EVIDENCE_KIND
    assert ev["trace_id"] == tid
    assert ev["seal"] and len(ev["seal"]) == 64       # HMAC-SHA256 hex
    assert [s["stage"] for s in ev["trace"]["steps"]] == \
        ["接收指令", "感知环境", "推理决策", "安全校验", "执行结果"]
    assert ev["verify"]["valid"] is True
    assert ev["components"] == _COMPONENTS


def test_verify_untouched_pack_valid(tmp_db):
    pack = store.export_evidence(_save(), components=_COMPONENTS)
    v = store.verify_evidence(pack)
    assert v["valid"] is True and v["seal_matches"] is True and v["chain_valid"] is True


def test_tamper_trace_breaks_seal(tmp_db):
    pack = store.export_evidence(_save(), components=_COMPONENTS)
    # 导出后偷改 answer
    pack["evidence"]["trace"]["answer"] = "（被偷改）"
    v = store.verify_evidence(pack)
    assert v["seal_matches"] is False and v["valid"] is False


def test_tamper_components_breaks_seal(tmp_db):
    pack = store.export_evidence(_save(), components=_COMPONENTS)
    pack["evidence"]["components"]["rules"]["fingerprint"] = "tampered"
    assert store.verify_evidence(pack)["seal_matches"] is False


def test_db_chain_broken_then_export(tmp_db):
    """库内某段被改 → 再导出：包封口完好（seal 匹配），但 chain_valid=False。"""
    tid = _save()
    import sqlite3
    conn = sqlite3.connect(str(tmp_db))
    conn.execute("UPDATE steps SET detail = ? WHERE trace_id = ? AND seq = 2",
                 ('{"command": "rm -rf /"}', tid))
    conn.commit()
    conn.close()

    pack = store.export_evidence(tid, components=_COMPONENTS)
    v = store.verify_evidence(pack)
    assert v["seal_matches"] is True       # 证据包本身没被改
    assert v["chain_valid"] is False       # 但库内链已断
    assert v["valid"] is False


def test_export_missing_trace(tmp_db):
    pack = store.export_evidence("does-not-exist")
    assert pack["ok"] is False and "不存在" in pack["error"]
