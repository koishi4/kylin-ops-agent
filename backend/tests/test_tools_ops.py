"""P1 扩展只读工具测试：inode_usage / list_failed_units / firewall_status /
login_history / list_cron_jobs。

只读工具铁律：给合法/非法入参都返回带 level 的结构化 dict，绝不抛异常。环境相关的工具
（依赖 systemd/firewalld/last 是否可用、是否 root）只断言「结构正确」，不强求 ok=True，
这样在 WSL/容器/非 root CI 下也稳定通过（与既有 test_tools_extended 同范式）。
"""
from __future__ import annotations

from app.mcp_server.tools.auth import login_history
from app.mcp_server.tools.disk import inode_usage
from app.mcp_server.tools.network import firewall_status
from app.mcp_server.tools.schedule import list_cron_jobs
from app.mcp_server.tools.system import list_failed_units


class TestInodeUsage:
    def test_root_mount_ok(self):
        r = inode_usage("/")
        assert r["ok"] is True and r["level"] == "READONLY"
        assert {"inodes_total", "inodes_used", "inodes_free", "percent"} <= r.keys()
        assert 0.0 <= r["percent"] <= 100.0
        # used 由 total-free 定义，字段须自洽
        assert r["inodes_used"] == r["inodes_total"] - r["inodes_free"]

    def test_nonexistent_path_errors_gracefully(self):
        r = inode_usage("/no/such/path/xyz123")
        assert r["ok"] is False and r["level"] == "READONLY" and "error" in r


class TestListFailedUnits:
    def test_returns_structured(self):
        r = list_failed_units()
        assert r["level"] == "READONLY" and "ok" in r
        if r["ok"]:
            assert isinstance(r["failed"], list)
            assert r["count"] == len(r["failed"])
            for u in r["failed"]:
                assert {"unit", "load", "active", "sub"} <= u.keys()


class TestFirewallStatus:
    def test_returns_structured(self):
        r = firewall_status()
        assert r["level"] == "READONLY" and "ok" in r
        if r["ok"]:
            assert r["backend"] in ("firewalld", "nftables", "iptables")
            assert isinstance(r["rules"], list)
        else:
            assert "error" in r  # 无 root / 无防火墙后端时结构化报错


class TestLoginHistory:
    def test_returns_structured(self):
        r = login_history(limit=10)
        assert r["level"] == "READONLY" and "ok" in r
        if r["ok"]:
            assert isinstance(r["recent"], list) and r["recent_count"] == len(r["recent"])
            assert isinstance(r["failed"], list) and r["failed_count"] == len(r["failed"])

    def test_limit_robust_to_garbage(self):
        # 非数字 limit 不应崩溃（内部夹断到默认值）
        r = login_history(limit="not-a-number")
        assert r["level"] == "READONLY" and "ok" in r


class TestListCronJobs:
    def test_returns_structured(self):
        r = list_cron_jobs()
        # 聚合 best-effort：单个来源读不到也整体 ok（结构恒齐全）
        assert r["ok"] is True and r["level"] == "READONLY"
        assert isinstance(r["timers"], list)
        assert isinstance(r["system_cron"], list)
        assert isinstance(r["user_cron"], list)
