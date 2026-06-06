"""演示剧本（scripts/demo.py，IMPROVEMENTS P1-4）的冒烟与素材回归测试。

P1-4 的价值是「录制前不会临场崩」+「每个评分子项都真演到」。所以测两层：
1. 剧本素材回归：固定素材（危险命令清单 / IO 告警信号）确实能演出我们宣称的效果
   （全部被拦 / 关联出高置信根因）——「演示即用例」，素材改了用例就会发现。
2. 整场冒烟：mock 离线跑完 7 幕零失败，杜绝录制时翻车。

审计落库经 monkeypatch 指向临时库，测试 hermetic，不污染真实 audit.sqlite。
"""
from __future__ import annotations

import pytest

from app.audit import store
from app.core.diagnosis import correlate_io_signals
from app.guardrail.engine import check_command
from app.llm.provider import MockProvider
from scripts import demo


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """把审计库重定向到临时文件，避免演示落库污染真实历史。"""
    db = tmp_path / "demo-audit.sqlite"
    monkeypatch.setattr(store, "_db_path", lambda: str(db))
    return db


class TestDemoMaterial:
    """剧本固定素材的回归：演示宣称的效果必须真实成立。"""

    def test_all_dangerous_commands_are_blocked(self):
        # 幕3 列出的每条危险命令都必须被护栏拦死，否则演示会「演翻车」
        for cmd in demo.DANGEROUS_COMMANDS:
            g = check_command(cmd)
            assert not g.allowed, f"危险命令未被拦截：{cmd}"

    def test_io_signals_yield_high_confidence_root_cause(self):
        # 幕2 的告警信号必须关联出高置信、critical 的根因 + 证据链 + 建议
        r = correlate_io_signals(demo.IO_INCIDENT_SIGNALS)
        assert r["ok"] and r["severity"] == "critical"
        assert r["confidence"] >= 0.7 and r["confidence_label"] == "高"
        assert r["chain"] and r["suggestions"]
        # 建议须体现「truncate 止血而非 rm」这一真实运维经验
        assert any("truncate" in sug for sug in r["suggestions"])

    def test_scene_table_covers_all_four_scoring_items(self):
        # 七幕的评分标注合起来要覆盖评分①②③④四子项
        tags = " ".join(scoring for _, scoring, _ in demo.SCENES)
        for item in ("①", "②", "③", "④"):
            assert item in tags, f"剧本未覆盖评分子项 {item}"


class TestDemoHelpers:
    def test_make_provider_mock(self):
        assert isinstance(demo._make_provider("mock"), MockProvider)

    def test_make_provider_unknown_raises(self):
        with pytest.raises(ValueError):
            demo._make_provider("gpt-99")

    def test_parse_only(self):
        assert demo._parse_only("2,5") == [2, 5]
        assert demo._parse_only(" 3 ") == [3]
        assert demo._parse_only(None) is None
        assert demo._parse_only("abc") is None


class TestDemoRun:
    """整场冒烟：mock 离线必须零失败跑完。"""

    async def test_full_script_runs_without_failure(self, tmp_db):
        result = await demo.run_demo(provider="mock", auto=True, color=False)
        assert result["ran"] == list(range(1, len(demo.SCENES) + 1))
        assert result["failures"] == [], f"有幕出错：{result['failures']}"

    async def test_only_subset_runs(self, tmp_db):
        result = await demo.run_demo(provider="mock", auto=True, only=[2, 3], color=False)
        assert result["ran"] == [2, 3]
        assert result["failures"] == []

    async def test_tamper_demo_trace_is_cleaned_up(self, tmp_db):
        # 幕8 自建的篡改演示记录跑完应被清理，不残留损坏链在审计库
        await demo.run_demo(provider="mock", auto=True, only=[8], color=False)
        leftover = [t for t in store.list_traces(limit=100)
                    if t["trace_id"].startswith("demo-tamper-")]
        assert leftover == [], f"演示残留了篡改记录：{leftover}"

    async def test_sandbox_demo_trace_is_cleaned_up(self, tmp_db):
        # 幕7 自建的沙箱演示记录跑完应被清理，不残留在审计库
        await demo.run_demo(provider="mock", auto=True, only=[7], color=False)
        leftover = [t for t in store.list_traces(limit=100)
                    if t["trace_id"].startswith("demo-sandbox-")]
        assert leftover == [], f"演示残留了沙箱记录：{leftover}"
