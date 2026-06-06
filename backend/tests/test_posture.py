"""内核 / 主机姿态检查测试（P1-2）。

固化：命中（内核范围 + 模块已加载）告警、未命中不误报、覆盖边界诚实标注、缓解不自动执行。
用构造数据测纯函数 assess_posture（确定性），再对真实 check_posture 做结构性冒烟。
"""
from __future__ import annotations

from app.core import posture
from app.core.posture import assess_posture, check_posture

# 构造一条「Dirty Frag 风格」情报：有受影响模块 + 内核范围
_DIRTY_FRAG = {
    "cve": "CVE-2026-43284", "aliases": ["Dirty Frag"], "title": "test",
    "severity": "critical", "modules": ["esp4", "esp6", "rxrpc"],
    "kernel_min": "5.10", "kernel_max": "6.12.30",
    "summary": "s", "mitigations": ["modprobe -r esp4 esp6 rxrpc"], "references": [],
}
# 无关联模块（Copy Fail 风格）：只能按内核范围判
_COPY_FAIL = {
    "cve": "CVE-2026-31431", "aliases": ["Copy Fail"], "title": "t2",
    "severity": "high", "modules": [], "kernel_min": "6.1", "kernel_max": "6.11.8",
    "summary": "s2", "mitigations": ["升级内核"], "references": [],
}


class TestAssessPosture:
    def test_module_loaded_and_kernel_in_range_is_exposed(self):
        r = assess_posture("6.6.50-generic", {"esp4", "xfs"}, [_DIRTY_FRAG])
        assert r["severity"] == "critical"
        m = r["matches"][0]
        assert m["status"] == "exposed"
        assert "esp4" in m["loaded_modules_hit"]

    def test_kernel_in_range_module_not_loaded_is_kernel_only(self):
        r = assess_posture("6.6.50-generic", {"xfs", "ext4"}, [_DIRTY_FRAG])
        assert r["severity"] == "warning"
        assert r["matches"][0]["status"] == "kernel_only"

    def test_patched_kernel_clears(self):
        """内核已升出受影响范围（即便模块仍加载）→ 不告警。"""
        r = assess_posture("6.13.0-generic", {"esp4"}, [_DIRTY_FRAG])
        assert r["severity"] == "ok"
        assert r["matches"] == []

    def test_unparseable_kernel_with_module_is_conservative(self):
        """内核串解析不出但相关模块已加载 → 保守按 module_only 告警，宁可多提醒。"""
        r = assess_posture("weird-kernel-string", {"esp4"}, [_DIRTY_FRAG])
        assert r["matches"][0]["status"] == "module_only"
        assert r["severity"] in ("warning", "critical")

    def test_no_module_advisory_uses_kernel_range(self):
        r_hit = assess_posture("6.5.0", set(), [_COPY_FAIL])
        assert r_hit["matches"][0]["status"] == "exposed"
        r_clear = assess_posture("6.13.0", set(), [_COPY_FAIL])
        assert r_clear["matches"] == []

    def test_scope_and_remediation_policy_present(self):
        r = assess_posture("6.6.50", {"esp4"}, [_DIRTY_FRAG])
        assert "0-day" in r["scope_note"]               # 诚实标注不覆盖未披露 0-day
        assert "二次确认" in r["remediation_policy"]      # 缓解须人工确认、不自动执行
        assert r["matches"][0]["mitigations"]            # 给了缓解候选文本


class TestCheckPostureSmoke:
    def test_real_check_structure(self):
        """真实采集冒烟：不论本机是否命中，结构完整、不抛异常、只读不改系统。"""
        r = check_posture()
        assert r["ok"] is True and r["topic"] == "posture"
        assert "kernel" in r and "matches" in r and "scope_note" in r
        assert r["severity"] in ("ok", "warning", "critical")

    def test_loaded_modules_returns_set(self):
        assert isinstance(posture._loaded_modules(), set)
