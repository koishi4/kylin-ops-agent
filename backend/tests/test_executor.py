"""执行器统一出口测试：核心是「危险命令拦截 demo」——护栏不放行就绝不执行。"""
from __future__ import annotations

from app.core.executor import execute


class TestExecutorBlocking:
    def test_rm_rf_root_blocked_dry_run(self):
        r = execute("rm -rf /", dry_run=True)
        assert r["executed"] is False
        assert r["blocked"] is True
        assert r["guard"]["risk"] == "critical"

    def test_rm_rf_root_blocked_real(self):
        # 即使非 dry_run，CRITICAL 命令也必须被拦在执行之前
        r = execute("rm -rf /")
        assert r["executed"] is False
        assert r["blocked"] is True

    def test_critical_not_overridable(self):
        r = execute("rm -rf /", authorized=True, confirmed=True)
        assert r["executed"] is False
        assert r["blocked"] is True

    def test_confirm_required_then_dry_run_allowed(self):
        cmd = "sudo systemctl restart nginx"
        r1 = execute(cmd, dry_run=True)
        assert r1["blocked"] is True and r1["require_confirm"] is True
        r2 = execute(cmd, confirmed=True, dry_run=True)
        assert r2["blocked"] is False and r2.get("dry_run") is True


class TestExecutorAllowed:
    def test_safe_command_executes(self):
        r = execute("echo guardrail-ok")
        assert r["blocked"] is False
        assert r["executed"] is True
        assert "guardrail-ok" in r.get("stdout", "")
