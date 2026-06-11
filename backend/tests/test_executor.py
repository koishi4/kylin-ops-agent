"""执行器统一出口测试：核心是「危险命令拦截 demo」——护栏不放行就绝不执行。"""
from __future__ import annotations

import getpass

from app.core.executor import execute, execute_argv


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
        # 仅确认还不够：sudo 是提权操作，防线4 要求显式授权
        r2 = execute(cmd, confirmed=True, dry_run=True)
        assert r2["blocked"] is True
        assert r2["privilege"]["needs_privilege"] is True
        # 确认 + 授权 双满足，才放行（dry_run 不真正执行）
        r3 = execute(cmd, confirmed=True, authorized=True, dry_run=True)
        assert r3["blocked"] is False and r3.get("dry_run") is True

    def test_privilege_blocks_unauthorized_service_restart(self):
        # 不在高危规则库、但需 root 的命令，由防线4 兜底拦截
        cmd = "systemctl restart nginx"
        r = execute(cmd, dry_run=True)
        assert r["blocked"] is True
        assert r["privilege"]["needs_privilege"] is True
        # 授权后放行
        r2 = execute(cmd, authorized=True, dry_run=True)
        assert r2["blocked"] is False


class TestExecutorAllowed:
    def test_safe_command_executes(self):
        r = execute("echo guardrail-ok")
        assert r["blocked"] is False
        assert r["executed"] is True
        assert "guardrail-ok" in r.get("stdout", "")


class TestAllowPathLandsThroughSandbox:
    """端到端「放行路径真落地」回归（第三方评审「三.2」整改）。

    评审指出红队评测全程 dry_run（这是 §6 安全铁律——绝不真跑破坏命令），故"放行的良性命令是否
    真的过全栈 executor→沙箱 正确落地"缺端到端覆盖（block-path 在 dry_run 测、bomb-path 在
    test_sandbox 测，唯独 allow-path 真落地没端到端测）。这里用**安全命令**补上：不违 §6。
    """

    def test_allowed_command_actually_runs_inside_sandbox(self):
        # 一条护栏放行的安全命令：必须真执行，且**经沙箱包裹**（结果带 sandbox 后端字段），
        # 证明放行路径走的是全栈 executor→run_cmd(sandbox=True)→run_sandboxed，而非裸 subprocess。
        r = execute("echo guardrail-allow-e2e")
        assert r["blocked"] is False and r["executed"] is True
        assert "guardrail-allow-e2e" in r.get("stdout", "")
        assert "sandbox" in r, "放行命令未经沙箱落地（缺 sandbox 后端字段）"

    def test_what_guardrail_judged_is_what_executes(self):
        """「所审即所执」不变量的执行侧证据：execute_argv 用权威 argv 直接执行（shell=False），
        命令替换等 shell 元字符被原样当字面传参、绝不二次解释——堵住"护栏看到的串 ≠ 真正执行的
        argv"这道 execve 分叉缝（评审「三.2」担心的方向）。"""
        r = execute_argv(["echo", "$(whoami)"])
        assert r["executed"] is True and r["blocked"] is False
        out = r.get("stdout", "")
        assert "$(whoami)" in out, "命令替换未被当字面——疑似经过了 shell 二次解释"
        assert getpass.getuser() not in out, "$(whoami) 被真实求值——执行侧发生了 shell 解释（越界）"
