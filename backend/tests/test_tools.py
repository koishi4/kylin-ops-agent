"""MCP 只读工具单元测试（纯函数层）。
测试用例表可直接导出到课程报告第 5 章「系统测试」。
"""
from __future__ import annotations

from app.mcp_server.tools import disk_usage, list_processes, memory_info


class TestDiskUsage:
    def test_root_returns_structure(self):
        r = disk_usage("/")
        assert r["ok"] is True
        assert r["level"] == "READONLY"
        for k in ("total_gb", "used_gb", "free_gb", "percent"):
            assert k in r
        assert 0 <= r["percent"] <= 100

    def test_nonexistent_path_graceful_error(self):
        r = disk_usage("/no/such/path/xyz")
        assert r["ok"] is False
        assert "error" in r  # 优雅返回错误而非抛异常


class TestMemoryInfo:
    def test_structure(self):
        r = memory_info()
        assert r["ok"] is True
        assert r["level"] == "READONLY"
        assert r["total_gb"] > 0
        assert 0 <= r["percent"] <= 100


class TestListProcesses:
    def test_default_top_n(self):
        r = list_processes(top_n=5)
        assert r["ok"] is True
        assert r["level"] == "READONLY"
        assert len(r["processes"]) <= 5
        if r["processes"]:
            assert {"pid", "name", "cpu_percent", "memory_percent"} <= set(r["processes"][0])

    def test_sort_by_memory(self):
        r = list_processes(top_n=3, sort_by="memory")
        assert r["ok"] is True
        mems = [p["memory_percent"] for p in r["processes"]]
        assert mems == sorted(mems, reverse=True)

    def test_invalid_sort_by_graceful_error(self):
        r = list_processes(sort_by="banana")
        assert r["ok"] is False
        assert "error" in r
