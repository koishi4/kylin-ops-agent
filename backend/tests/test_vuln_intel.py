"""漏洞情报感知工具测试（P1-1）。

固化：本地种子库可检索（按 CVE / 组件 / 别名过滤）、离线默认不联网、联网失败优雅回退本地。
"""
from __future__ import annotations

from app.mcp_server.tools import vuln_intel
from app.mcp_server.tools.vuln_intel import query_vuln_intel


class TestLocalFeed:
    def test_lists_all_seeded(self):
        r = query_vuln_intel()
        assert r["ok"] is True and r["level"] == "READONLY"
        assert r["live"] is False
        assert r["count"] >= 3                       # 至少 Dirty Frag×2 + Copy Fail
        assert r["source"] == "local"

    def test_filter_by_cve(self):
        r = query_vuln_intel(cve="CVE-2026-43284")
        assert r["count"] == 1
        assert r["advisories"][0]["cve"] == "CVE-2026-43284"
        assert "Dirty Frag" in r["advisories"][0]["aliases"]

    def test_filter_by_module_component(self):
        r = query_vuln_intel(component="esp4")
        cves = {a["cve"] for a in r["advisories"]}
        assert "CVE-2026-43284" in cves          # esp4 是 Dirty Frag 的受影响模块

    def test_filter_by_alias(self):
        r = query_vuln_intel(component="Dirty Frag")
        assert r["count"] >= 2                     # 别名命中同族两条
        assert all("Dirty Frag" in a["aliases"] for a in r["advisories"])

    def test_unknown_component_empty(self):
        r = query_vuln_intel(component="definitely-not-a-module")
        assert r["count"] == 0
        assert r["ok"] is True                      # 空结果也结构化、不报错

    def test_advisory_has_mitigations(self):
        r = query_vuln_intel(cve="CVE-2026-43284")
        adv = r["advisories"][0]
        assert adv["mitigations"]                    # 缓解步骤齐
        assert any("modprobe" in m or "blacklist" in m for m in adv["mitigations"])


class TestLiveFallback:
    def test_live_failure_falls_back_local(self, monkeypatch):
        """联网失败（_fetch 返回 None）→ 回退本地、标注 live_error、仍 ok。"""
        monkeypatch.setattr(vuln_intel, "_fetch_osv_cve", lambda cve, timeout: None)
        r = query_vuln_intel(cve="CVE-2026-43284", live=True)
        assert r["ok"] is True
        assert r["live"] is False
        assert r["live_error"] is not None
        assert r["count"] == 1                       # 仍拿到本地那条

    def test_live_success_merges(self, monkeypatch):
        """联网成功 → 标 live=True、来源含 osv.dev。"""
        fake = {"cve": "CVE-2099-00001", "aliases": [], "title": "x", "summary": "y",
                "components": [], "modules": [], "mitigations": [], "references": [],
                "source": "osv.dev", "severity": "unknown"}
        monkeypatch.setattr(vuln_intel, "_fetch_osv_cve", lambda cve, timeout: fake)
        r = query_vuln_intel(cve="CVE-2099-00001", live=True)
        assert r["live"] is True
        assert r["source"] == "osv.dev+local"
        assert any(a["cve"] == "CVE-2099-00001" for a in r["advisories"])

    def test_live_off_never_calls_network(self, monkeypatch):
        """live=False 绝不触网。"""
        called = {"n": 0}
        monkeypatch.setattr(vuln_intel, "_fetch_osv_cve",
                            lambda *a, **k: called.__setitem__("n", called["n"] + 1) or None)
        query_vuln_intel(cve="CVE-2026-43284", live=False)
        assert called["n"] == 0
