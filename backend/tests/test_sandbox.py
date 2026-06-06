"""执行沙箱测试（P4-3）：护栏放行后「真正落地」命令的资源/权限保险丝。

固化四组性质，防回归：
1. 已知超限命令被沙箱掐死（CPU 自旋撞墙钟超时 / 内存吃光撞 RLIMIT_AS），断言 sandbox_killed/limit_hit。
2. 正常快命令（echo / df）正常返回，未被误杀。
3. 沙箱机制不可用（preexec/rlimit 被禁）时优雅降级：仍返回结构化结果、绝不抛异常。
4. executor.execute 的真正执行路径确实走了沙箱（monkeypatch run_sandboxed 断言被调用）。

铁律（CLAUDE.md §6）：只用消耗资源/无害命令验证「被限制」，绝不在测试里跑任何破坏性命令。
"""
from __future__ import annotations

import subprocess

import pytest

from app.core import sandbox as sb
from app.core.executor import execute
from app.core.sandbox import SandboxLimits, run_sandboxed

# 必备返回字段：无论走哪条降级分支，结构都一致，调用方可无脑取用。
_REQUIRED_KEYS = {"ok", "sandbox_killed", "limit_hit", "sandbox"}


# ============ 1. 超限命令被沙箱掐死 ============

class TestLimitsKill:
    def test_cpu_spin_killed_by_wall_timeout(self):
        """CPU 自旋 → 墙钟超时被整组击杀。墙钟超时不依赖任何 rlimit，是跨环境硬保证。"""
        r = run_sandboxed(["python3", "-c", "while True: pass"],
                          limits=SandboxLimits(cpu_seconds=999), timeout=2)
        assert r["ok"] is False
        assert r["sandbox_killed"] is True
        assert r["limit_hit"] == "timeout"

    def test_cpu_rlimit_kills_spin(self):
        """CPU 自旋 → 撞 RLIMIT_CPU 被信号杀（软限 SIGXCPU / 硬限 SIGKILL）。"""
        r = run_sandboxed(["python3", "-c", "while True: pass"],
                          limits=SandboxLimits(cpu_seconds=1), timeout=30)
        if r["ok"] is True:
            pytest.skip("本环境未强制 RLIMIT_CPU（容器/CI 常见）；墙钟超时用例已兜底覆盖")
        assert r["sandbox_killed"] is True
        assert r["limit_hit"] in ("cpu", "killed")

    def test_memory_hog_is_limited(self):
        """申请 1GB 内存 → 撞 256MB→128MB 的 RLIMIT_AS。Python 捕获 MemoryError 退出，
        归因为 limit_hit=memory（非被信号杀）。环境若不强制 AS 限则跳过。"""
        r = run_sandboxed(["python3", "-c", "x=bytearray(1024*1024*1024)"],
                          limits=SandboxLimits(mem_mb=128), timeout=10)
        if r["ok"] is True:
            pytest.skip("本环境未强制 RLIMIT_AS；内存限额不可测，CPU/超时用例已兜底")
        assert r["sandbox_killed"] is True or r["limit_hit"] is not None
        assert r["limit_hit"] in ("memory", "killed")


# ============ 2. 正常命令不被误杀 ============

class TestBenignNotKilled:
    @pytest.mark.parametrize("args", [
        ["echo", "hi"],
        ["df", "-h", "/"],
        ["true"],
    ])
    def test_fast_command_ok(self, args):
        r = run_sandboxed(args, limits=SandboxLimits(), timeout=5)
        assert _REQUIRED_KEYS <= r.keys()
        assert r["sandbox_killed"] is False
        assert r["limit_hit"] is None

    def test_echo_stdout_intact(self):
        r = run_sandboxed(["echo", "guardrail-ok"], limits=SandboxLimits(), timeout=5)
        assert r["ok"] is True
        assert "guardrail-ok" in r["stdout"]

    def test_command_not_found_structured(self):
        r = run_sandboxed(["definitely_no_such_cmd_42"], limits=SandboxLimits(), timeout=5)
        assert r["ok"] is False
        assert "not found" in r["error"]
        assert r["sandbox_killed"] is False


# ============ 3. 机制不可用时优雅降级（不崩溃、仍结构化） ============

class TestGracefulDegradation:
    def test_preexec_build_failure_degrades(self, monkeypatch):
        """模拟 resource/preexec 不可用（_build_preexec 抛错）→ 退化为无 preexec，
        命令仍正常执行、返回结构化结果，绝不抛异常。"""
        monkeypatch.setattr(sb, "_build_preexec",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no rlimit")))
        r = run_sandboxed(["echo", "still-ok"], limits=SandboxLimits(), timeout=5)
        assert r["ok"] is True
        assert "still-ok" in r["stdout"]

    def test_popen_preexec_rejected_retries_without(self, monkeypatch):
        """模拟受限 CI 拒绝带 preexec 的 Popen（首次抛 PermissionError）→ 自动退回
        无 preexec 重试一次，仍拿到结果。"""
        real_popen = subprocess.Popen
        calls = {"n": 0}

        def flaky_popen(*args, **kwargs):
            calls["n"] += 1
            if kwargs.get("preexec_fn") is not None:
                raise PermissionError("preexec not permitted here")
            return real_popen(*args, **kwargs)

        monkeypatch.setattr(sb.subprocess, "Popen", flaky_popen)
        r = run_sandboxed(["echo", "retry-ok"], limits=SandboxLimits(), timeout=5)
        assert r["ok"] is True
        assert "retry-ok" in r["stdout"]
        assert calls["n"] >= 2  # 第一次带 preexec 被拒，第二次无 preexec 成功

    def test_empty_args_no_crash(self):
        r = run_sandboxed([], limits=SandboxLimits(), timeout=5)
        assert r["ok"] is False
        assert _REQUIRED_KEYS <= r.keys()

    def test_never_raises_on_weird_input(self):
        for args in ([], [""], ["echo"], ["true"]):
            run_sandboxed(args, limits=SandboxLimits(), timeout=5)  # 不抛即通过


# ============ 4. executor 真正执行路径确实走沙箱 ============

class TestExecutorUsesSandbox:
    def test_real_exec_routes_through_sandbox(self, monkeypatch):
        """护栏放行 + 非 dry_run 的真正执行，必须经 run_sandboxed（资源限额生效的保证）。"""
        captured = {}

        def fake_sandboxed(args, *, limits, timeout):
            captured["args"] = args
            captured["limits"] = limits
            return {"ok": True, "stdout": "sandboxed!", "stderr": "",
                    "sandbox_killed": False, "limit_hit": None, "sandbox": "rlimit"}

        monkeypatch.setattr(sb, "run_sandboxed", fake_sandboxed)
        r = execute("echo hi")          # 护栏放行的安全命令，真正执行
        assert r["executed"] is True
        assert captured["args"] == ["echo", "hi"], "execute 未把命令交给沙箱"
        assert isinstance(captured["limits"], SandboxLimits)
        assert r.get("stdout") == "sandboxed!"

    def test_dry_run_does_not_invoke_sandbox(self, monkeypatch):
        """dry_run 只做护栏校验、不落地，不该触碰沙箱。"""
        called = {"n": 0}
        monkeypatch.setattr(sb, "run_sandboxed",
                            lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})
        execute("echo hi", dry_run=True)
        assert called["n"] == 0

    def test_blocked_command_never_reaches_sandbox(self, monkeypatch):
        """被护栏拦截的危险命令绝不进入沙箱（拦在执行之前）。"""
        called = {"n": 0}
        monkeypatch.setattr(sb, "run_sandboxed",
                            lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})
        r = execute("rm -rf /")
        assert r["blocked"] is True
        assert called["n"] == 0


# ============ 5. /guardrail/sandbox-demo 端点：前端「沙箱击杀」演示的数据源 ============

class TestSandboxDemoEndpoint:
    """服务端预定义的无害场景：normal 放行、cpu 失控被掐死、未知场景 400。"""

    def _call(self, scenario):
        import asyncio
        from app.api import routes
        return asyncio.run(routes.guardrail_sandbox_demo(scenario=scenario))

    def test_normal_scenario_not_killed(self):
        r = self._call("normal")
        assert r["ok"] is True
        assert r["sandbox_killed"] is False and r["limit_hit"] is None
        assert "sandbox-ok" in r["stdout_tail"]
        assert r["command"] and r["limits"]["timeout_s"] >= 1

    def test_cpu_scenario_killed(self):
        r = self._call("cpu")
        assert r["ok"] is False
        assert r["sandbox_killed"] is True
        assert r["limit_hit"] == "timeout"

    def test_unknown_scenario_400(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            self._call("bogus")
        assert ei.value.status_code == 400
