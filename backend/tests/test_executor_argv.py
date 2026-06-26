"""execute_argv 结构化入口测试（P0-A.4：executor argv 原生化）。

GPT 第二轮 review 提的「executor 改 argv 原生接口、不把『命令字符串』当统一执行对象」的落地。
固化四条性质，防回归：
1. 危险 argv 同样被护栏拦死（与字符串入口等价），且绝不进沙箱。
2. 放行后执行的就是传入的 argv 本身（exact match），并确实走沙箱（资源保险丝生效）。
3. **「所审即所执」**：含 shell 元字符/空格的 token 原样到达 run_sandboxed，不被二次解析、不被拆成多条命令。
4. 入参防御：非 list[str] / 空 argv 直接结构化报错，绝不执行。

铁律（CLAUDE.md §6）：只用无害命令（echo/printf）验证执行路径，绝不在测试里真跑破坏性命令。
"""
from __future__ import annotations

import shlex

import pytest
from app.core import sandbox as sb
from app.core.executor import execute, execute_argv

# ============ 1. 危险 argv 被护栏拦死，等价于字符串入口 ============

class TestArgvBlocksDangerous:
    def test_rm_rf_root_blocked(self, monkeypatch):
        """execute_argv(['rm','-rf','/']) 必须被拦，且绝不触碰沙箱。"""
        called = {"n": 0}
        monkeypatch.setattr(sb, "run_sandboxed",
                            lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})
        r = execute_argv(["rm", "-rf", "/"])
        assert r["blocked"] is True
        assert r["executed"] is False
        assert called["n"] == 0  # 拦在执行之前

    def test_argv_equivalent_to_string_for_block(self):
        """同一危险命令，argv 入口与字符串入口给出一致的护栏裁决（同源裁决）。"""
        r_argv = execute_argv(["rm", "-rf", "/"])
        r_str = execute("rm -rf /")
        assert r_argv["blocked"] is True and r_str["blocked"] is True
        assert r_argv["guard"]["risk"] == r_str["guard"]["risk"]

    def test_interpreter_inline_argv_blocked(self, monkeypatch):
        """P0-A 的解释器+内联代码：经 argv 入口（shlex.join 还原结构）同样判 CRITICAL/DENY。"""
        called = {"n": 0}
        monkeypatch.setattr(sb, "run_sandboxed",
                            lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})
        r = execute_argv(["bash", "-c", "rm -rf /"])
        assert r["blocked"] is True
        assert called["n"] == 0


# ============ 2. 放行后执行的就是传入的 argv，且走沙箱 ============

class TestArgvExecutesExactly:
    def _patch_capture(self, monkeypatch):
        captured = {}

        def fake_sandboxed(args, *, limits, timeout):
            captured["args"] = args
            captured["limits"] = limits
            return {"ok": True, "stdout": "ok", "stderr": "",
                    "sandbox_killed": False, "limit_hit": None, "sandbox": "rlimit"}

        monkeypatch.setattr(sb, "run_sandboxed", fake_sandboxed)
        return captured

    def test_safe_argv_executes_with_exact_args(self, monkeypatch):
        captured = self._patch_capture(monkeypatch)
        r = execute_argv(["echo", "hi"])
        assert r["executed"] is True
        assert captured["args"] == ["echo", "hi"], "执行的 argv 必须与传入一致"

    def test_dry_run_does_not_execute(self, monkeypatch):
        called = {"n": 0}
        monkeypatch.setattr(sb, "run_sandboxed",
                            lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})
        r = execute_argv(["echo", "hi"], dry_run=True)
        assert r.get("dry_run") is True
        assert r["executed"] is False
        assert called["n"] == 0


# ============ 3. 所审即所执：元字符 token 原样到达沙箱，不被二次解析 ============

class TestInspectEqualsExecute:
    def test_metachar_token_passed_verbatim(self, monkeypatch):
        """含 `;`、空格的单个 token 必须原样进 run_sandboxed，绝不被拆成第二条命令。

        这是 argv 原生化的核心收益：护栏看到 shlex.join(argv)，执行用 argv 本身，
        二者由 `shlex.split(shlex.join(x)) == x`（良构 argv 恒等）保证一致——无再解析分叉。
        """
        captured = {}
        monkeypatch.setattr(sb, "run_sandboxed",
                            lambda args, *, limits, timeout: captured.update(args=args)
                            or {"ok": True, "stdout": "", "stderr": "",
                                "sandbox_killed": False, "limit_hit": None, "sandbox": "rlimit"})
        # 用无害但含 `;`+空格的 token：若被当 shell 串再解析，会被拆成多条命令/多个 token。
        # （内容无害是刻意的——铁律不在测试里跑破坏性命令；要验证的是「不拆分」而非「危险」。）
        payload = "hello ; world"
        r = execute_argv(["printf", "%s", payload])
        assert r["executed"] is True
        # 关键断言：带元字符的 token 仍是「一个」参数，内容逐字保留，未被拆分/未被 shell 解释
        assert captured["args"] == ["printf", "%s", payload]
        assert captured["args"][-1] == payload

    def test_join_split_is_identity(self):
        """显式固化底层恒等式：shlex.split(shlex.join(argv)) == argv（所审即所执的数学根据）。"""
        for argv in (["rm", "-f", "/tmp/a b"], ["kill", "-15", "1234"],
                     ["printf", "%s", "x ; y"], ["echo", "$(whoami)"]):
            assert shlex.split(shlex.join(argv)) == argv


# ============ 4. 入参防御 ============

class TestArgvInputValidation:
    @pytest.mark.parametrize("bad", ["rm -rf /", ["rm", 1], 123, None])
    def test_non_list_str_rejected(self, bad, monkeypatch):
        called = {"n": 0}
        monkeypatch.setattr(sb, "run_sandboxed",
                            lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})
        r = execute_argv(bad)
        assert r["executed"] is False
        assert "error" in r
        assert called["n"] == 0

    def test_empty_argv_rejected(self):
        r = execute_argv([])
        assert r["executed"] is False
        assert "error" in r
