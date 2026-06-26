"""根因分析扩展测试（评分④加厚）：内存压力/泄漏关联 + 配置文件漂移（赛题明示场景）。

设计同既有 IO 关联：correlate_* 是纯函数（构造信号 → 确定性断言根因/置信度/证据链），
采集入口只做只读采全后喂纯函数。配置漂移用 monkeypatch 把监控集换成临时文件，端到端可控复测。
"""
from __future__ import annotations

from app.core import diagnosis as d

# =============================== 内存关联 ===============================

class TestMemoryCorrelation:
    def test_leak_scenario_is_critical_with_chain(self):
        rep = d.correlate_memory_signals({
            "mem_percent": 96, "mem_warn": 85, "available_mb": 200, "swap_percent": 45,
            "top": {"pid": 4242, "name": "java", "rss_mb": 6800,
                    "rss_grew_bytes": 50_000_000, "interval_s": 0.5},
            "swap_thrashing": True})
        assert rep["severity"] == "critical"
        assert rep["confidence"] >= 0.7
        assert "泄漏" in rep["root_cause"] and "java" in rep["root_cause"]
        assert len(rep["chain"]) == 5          # 五信号全证据链
        assert len(rep["evidence"]) == 5

    def test_pressure_without_growth_is_not_leak(self):
        rep = d.correlate_memory_signals({
            "mem_percent": 90, "mem_warn": 85, "swap_percent": 10,
            "top": {"pid": 10, "name": "redis", "rss_mb": 1200, "rss_grew_bytes": 0,
                    "interval_s": 0.5}})
        assert rep["severity"] == "warning"
        # 非泄漏：根因不应把它**判定**为泄漏（措辞里"而非单进程泄漏"是否定用法，故查正向特征）
        assert "占用最高" in rep["root_cause"]
        assert "rss_growing" not in [e["signal"] for e in rep["evidence"]]

    def test_swap_thrashing_only(self):
        rep = d.correlate_memory_signals({
            "mem_percent": 80, "mem_warn": 85, "swap_percent": 60,
            "top": {}, "swap_thrashing": True})
        assert rep["severity"] == "warning"
        assert "颠簸" in rep["root_cause"]

    def test_normal_is_ok(self):
        rep = d.correlate_memory_signals(
            {"mem_percent": 35, "mem_warn": 85, "swap_percent": 0, "top": {}})
        assert rep["severity"] == "ok" and rep["confidence"] == 0.0

    def test_low_confidence_adds_caveat(self):
        rep = d.correlate_memory_signals(
            {"mem_percent": 86, "mem_warn": 85, "swap_percent": 0, "top": {}})
        # 仅一个弱信号 → 低置信度，建议里应提示多采样
        assert rep["confidence"] < 0.4
        assert any("置信度低" in s or "多采样" in s for s in rep["suggestions"])

    def test_live_collector_readonly(self):
        rep = d.diagnose_memory(grow_interval=0.0)   # 跳过采样窗，纯快照
        assert rep["topic"] == "memory" and "severity" in rep and "confidence" in rep


# =============================== 配置漂移 ===============================

class TestConfigDriftPure:
    def test_classifies_changed_removed_added(self):
        base = {"/etc/passwd": {"exists": True, "sha256": "a"},
                "/etc/hosts": {"exists": True, "sha256": "h"},
                "/etc/old": {"exists": True, "sha256": "o"}}
        cur = {"/etc/passwd": {"exists": True, "sha256": "A"},   # changed
               "/etc/hosts": {"exists": True, "sha256": "h"},    # unchanged
               "/etc/old": {"exists": False},                    # removed
               "/etc/new": {"exists": True, "sha256": "n"}}      # added
        cmp = d.compare_config_fingerprints(base, cur)
        assert cmp["changed"] == ["/etc/passwd"]
        assert cmp["removed"] == ["/etc/old"]
        assert cmp["added"] == ["/etc/new"]
        assert cmp["unchanged"] == ["/etc/hosts"]
        assert cmp["severity"] == "critical"          # passwd 是关键配置
        assert "/etc/passwd" in cmp["critical_drift"]

    def test_noncritical_change_is_warning(self):
        base = {"/etc/hosts": {"exists": True, "sha256": "h"}}
        cur = {"/etc/hosts": {"exists": True, "sha256": "H"}}
        cmp = d.compare_config_fingerprints(base, cur)
        assert cmp["severity"] == "warning" and cmp["critical_drift"] == []

    def test_metadata_fallback_when_unreadable(self):
        # 无内容哈希时用元数据三元组比较：size/mtime/mode 变即 changed
        base = {"/etc/shadow": {"exists": True, "sha256": None, "size": 100, "mtime": 1, "mode": "0640"}}
        cur = {"/etc/shadow": {"exists": True, "sha256": None, "size": 120, "mtime": 2, "mode": "0640"}}
        cmp = d.compare_config_fingerprints(base, cur)
        assert cmp["changed"] == ["/etc/shadow"]


class TestConfigDriftEndToEnd:
    def test_tofu_pin_then_detect_drift(self, tmp_path, monkeypatch):
        f1 = tmp_path / "a.conf"
        f1.write_text("alpha")
        f2 = tmp_path / "b.conf"
        f2.write_text("beta")
        monkeypatch.setattr(d, "_WATCHED_CONFIGS", [str(f1), str(f2)])
        monkeypatch.setattr(d, "_CRITICAL_CONFIGS", {str(f1)})
        bp = str(tmp_path / "base.json")

        # 首次 → TOFU 锚定，不报漂移
        r1 = d.diagnose_config_drift(baseline_path=bp)
        assert r1["baseline_pinned"] is True and r1["severity"] == "ok"

        # 无改动 → ok
        r2 = d.diagnose_config_drift(baseline_path=bp)
        assert r2["severity"] == "ok" and r2["changed"] == []

        # 改关键文件 → critical，列出 changed
        f1.write_text("ALPHA-tampered")
        r3 = d.diagnose_config_drift(baseline_path=bp)
        assert str(f1) in r3["changed"] and r3["severity"] == "critical"
        assert str(f1) in r3["critical_drift"]

        # 删非关键文件 → removed
        f2.unlink()
        r4 = d.diagnose_config_drift(baseline_path=bp)
        assert str(f2) in r4["removed"]

        # 确认合法后重锚 → 之后回到 ok
        d.diagnose_config_drift(baseline_path=bp, pin=True)
        r6 = d.diagnose_config_drift(baseline_path=bp)
        assert r6["severity"] == "ok"


# =============================== 调度入口 ===============================

class TestDispatcher:
    def test_memory_topic(self):
        assert d.diagnose("memory")["topic"] == "memory"

    def test_configdrift_topic(self, tmp_path, monkeypatch):
        monkeypatch.setattr(d, "_WATCHED_CONFIGS", [str(tmp_path / "x.conf")])
        bp = str(tmp_path / "b.json")
        monkeypatch.setattr("app.config.get_settings",
                            lambda: _FakeSettings(bp))
        rep = d.diagnose("configdrift")
        assert rep["topic"] == "configdrift" and rep["baseline_pinned"] is True

    def test_all_includes_memory(self, tmp_path):
        # 用小目录作磁盘扫描路径，避免从 / 全盘扫描拖慢测试
        rep = d.diagnose("all", path=str(tmp_path))
        topics = {r["topic"] for r in rep["reports"]}
        assert "memory" in topics and "disk" in topics

    def test_unknown_topic(self):
        assert d.diagnose("nope")["ok"] is False


class _FakeSettings:
    def __init__(self, p):
        self.config_baseline_path = p
