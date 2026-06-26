"""受控 MUTATING 动作层测试（P0-3）：truncate_log / kill_process / clean_path。

覆盖每个动作的「放行路径」与「拦截路径」，并验证纵深防御：
- 动作层语义校验（关键性/受保护进程）拦在 executor 之前；
- 即便动作层判「可清理」，命令层护栏（PATH-001）仍独立兜底（rm on /var）。

铁律（CLAUDE.md §6）：绝不真实执行破坏性系统命令。
真实执行只针对「测试自己创建的临时文件」和「测试自己 spawn 的子进程」，对系统无害。
"""
from __future__ import annotations

import os
import subprocess

from app.core import actions

# ----------------------------- truncate_log -----------------------------

class TestTruncateLog:
    def test_truncate_cleanable_log_executes(self, tmp_path):
        """放行路径：可清理日志，确认+非 dry_run → 真正清空（对临时文件，无害）。"""
        f = tmp_path / "app.log"
        f.write_text("x" * 1000)
        r = actions.run_action("truncate_log", {"path": str(f)},
                               confirmed=True, dry_run=False)
        assert r["executed"] is True
        assert r["blocked"] is False
        assert r["ok"] is True
        assert f.stat().st_size == 0  # 已被清空
        assert "ftruncate" in r["command"]  # P0-B：fd-safe os.ftruncate 落地，不再走 truncate 命令

    def test_truncate_requires_confirm(self, tmp_path):
        """未确认：只预览不执行，require_confirm=True，文件不动。"""
        f = tmp_path / "svc.log"
        f.write_text("data")
        r = actions.run_action("truncate_log", {"path": str(f)},
                               confirmed=False, dry_run=False)
        assert r["executed"] is False
        assert r["require_confirm"] is True
        assert r["blocked"] is False
        assert f.stat().st_size == len("data")  # 未被改动

    def test_truncate_critical_blocked(self):
        """拦截路径：关键文件（/etc/passwd）被动作层语义校验拦死，绝不进 executor。"""
        r = actions.run_action("truncate_log", {"path": "/etc/passwd"},
                               confirmed=True, dry_run=False)
        assert r["blocked"] is True
        assert r["executed"] is False
        assert r["precheck"]["classify"] == "critical"
        assert r["guard"] is None  # 没进到 executor 护栏

    def test_truncate_unknown_blocked(self):
        """拦截路径：无法判定关键性（unknown）也拒，宁保守不误清。"""
        r = actions.run_action("truncate_log", {"path": "/opt/myapp/data.bin"},
                               confirmed=True, dry_run=False)
        assert r["blocked"] is True
        assert r["precheck"]["classify"] == "unknown"

    def test_truncate_nonexistent_blocked(self, tmp_path):
        """可清理但文件不存在：拒绝（truncate 会误建空文件）。"""
        ghost = tmp_path / "ghost.log"
        r = actions.run_action("truncate_log", {"path": str(ghost)},
                               confirmed=True, dry_run=False)
        assert r["blocked"] is True
        assert ghost.exists() is False  # 没被误建

    def test_truncate_missing_path(self):
        r = actions.run_action("truncate_log", {}, confirmed=True)
        assert r["blocked"] is True

    def test_executed_truncate_is_fd_safe_no_sandbox(self, tmp_path):
        """P0-B：truncate 落地走 fd-safe os.ftruncate（O_NOFOLLOW），不经子进程沙箱。

        output 应表明 fd_safe + method=os.ftruncate，且**不**含 sandbox 字段
        （ftruncate 是 syscall、不会失控，无需沙箱；这是把防护放到正确层的体现）。
        """
        f = tmp_path / "app.log"
        f.write_text("x" * 200)
        r = actions.run_action("truncate_log", {"path": str(f)},
                               confirmed=True, dry_run=False)
        assert r["executed"] is True
        out = r["output"]
        assert out.get("fd_safe") is True and out.get("method") == "os.ftruncate"
        assert "sandbox" not in out   # fd-safe 落地不经子进程沙箱


# ----------------------------- kill_process -----------------------------

class TestKillProcess:
    def test_kill_init_blocked(self):
        """拦截路径：PID 1（init/systemd）一律禁止。"""
        r = actions.run_action("kill_process", {"pid": 1}, confirmed=True, dry_run=False)
        assert r["blocked"] is True
        assert r["executed"] is False

    def test_kill_self_blocked(self):
        """拦截路径：禁止终止 Agent 自身。"""
        r = actions.run_action("kill_process", {"pid": os.getpid()},
                               confirmed=True, dry_run=False)
        assert r["blocked"] is True

    def test_kill_nonexistent_blocked(self):
        r = actions.run_action("kill_process", {"pid": 2_000_000},
                               confirmed=True, dry_run=False)
        assert r["blocked"] is True

    def test_kill_invalid_pid_blocked(self):
        r = actions.run_action("kill_process", {"pid": "abc"}, confirmed=True)
        assert r["blocked"] is True

    def test_kill_bad_signal_blocked(self, tmp_path):
        r = actions.run_action("kill_process", {"pid": os.getpid(), "signal": "SIGEVIL"},
                               confirmed=True)
        assert r["blocked"] is True

    def test_kill_critical_service_blocked(self, monkeypatch):
        """拦截路径：进程名命中关键服务集 → 拒绝（用 monkeypatch 构造 sshd）。"""
        monkeypatch.setattr(actions, "process_detail",
                            lambda pid: {"ok": True, "pid": pid, "name": "sshd",
                                         "username": "root"})
        r = actions.run_action("kill_process", {"pid": 4321},
                               confirmed=True, authorized=True, dry_run=False)
        assert r["blocked"] is True
        assert "sshd" in r["reason"]

    def test_kill_root_process_needs_authorization(self, monkeypatch):
        """root 进程：未授权拒（防线4），授权后放行。"""
        monkeypatch.setattr(actions, "process_detail",
                            lambda pid: {"ok": True, "pid": pid, "name": "mydaemon",
                                         "username": "root"})
        r1 = actions.run_action("kill_process", {"pid": 4321},
                                confirmed=True, authorized=False, dry_run=True)
        assert r1["blocked"] is True
        r2 = actions.run_action("kill_process", {"pid": 4321},
                                confirmed=True, authorized=True, dry_run=True)
        assert r2["blocked"] is False
        assert r2["executed"] is False  # dry_run

    def test_kill_child_process_executes(self):
        """放行路径：spawn 自己的 sleep 子进程并真正 SIGTERM 终止（对系统无害）。

        P0-2 环境兼容：以 root 跑测试时子进程归 root，动作层防线4 要求显式 authorized；
        故 authorized 按运行身份取（root → True），保证 root/非 root 下断言都成立。
        """
        proc = subprocess.Popen(["sleep", "60"])
        try:
            r = actions.run_action("kill_process", {"pid": proc.pid, "signal": "SIGTERM"},
                                   confirmed=True, authorized=os.geteuid() == 0,
                                   dry_run=False)
            assert r["executed"] is True
            assert r["blocked"] is False
            proc.wait(timeout=5)
            assert proc.poll() is not None  # 子进程已终止
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)


# ----------------------------- clean_path -----------------------------

class TestCleanPath:
    def test_clean_cleanable_file_executes(self, tmp_path):
        """放行路径：/tmp 风格可清理文件，确认+非 dry_run → 真正删除（临时文件，无害）。"""
        f = tmp_path / "junk.tmp"
        f.write_text("garbage")
        r = actions.run_action("clean_path", {"path": str(f)},
                               confirmed=True, dry_run=False)
        assert r["executed"] is True
        assert r["ok"] is True
        assert f.exists() is False

    def test_clean_critical_blocked(self):
        """拦截路径：关键文件（mysql 数据）被动作层拒。"""
        r = actions.run_action("clean_path", {"path": "/var/lib/mysql/ibdata1"},
                               confirmed=True, dry_run=False)
        assert r["blocked"] is True
        assert r["precheck"]["classify"] == "critical"
        assert r["guard"] is None

    def test_clean_var_log_blocked_by_command_guard(self):
        """纵深防御：动作层判 /var/log 日志为可清理，但 rm 作用于 /var 被命令层 PATH-001 独立拦死。

        这正是「日志走 truncate 不走 rm」的理由，也证明动作层放行 ≠ 最终放行。
        """
        r = actions.run_action("clean_path", {"path": "/var/log/app.log"},
                               confirmed=True, authorized=True, dry_run=False)
        assert r["precheck"]["classify"] == "cleanable"  # 动作层判可清理
        assert r["blocked"] is True                       # 命令层仍拦
        assert r["executed"] is False
        assert r["guard"]["risk"] == "critical"           # PATH-001

    def test_clean_requires_confirm(self, tmp_path):
        f = tmp_path / "tmp.tmp"
        f.write_text("x")
        r = actions.run_action("clean_path", {"path": str(f)},
                               confirmed=False, dry_run=False)
        assert r["require_confirm"] is True
        assert r["executed"] is False
        assert f.exists() is True  # 未确认不删

    def test_executed_output_carries_sandbox_fields(self, tmp_path):
        """clean_path 经 executor 子进程沙箱落地（rm -f），其 output 须带沙箱处置字段
        （P4-3 前端「执行结果」段可视化的数据来源；truncate 走 fd-safe 故由本测试承接沙箱断言）。"""
        f = tmp_path / "junk.tmp"
        f.write_text("x" * 200)
        r = actions.run_action("clean_path", {"path": str(f)},
                               confirmed=True, dry_run=False)
        assert r["executed"] is True
        out = r["output"]
        assert {"sandbox", "sandbox_killed", "limit_hit"} <= out.keys()
        assert out["sandbox_killed"] is False   # 无害 rm 不该触发限额


# ----------------------------- dispatcher -----------------------------

def test_unknown_action_blocked():
    r = actions.run_action("rm_everything", {"path": "/"})
    assert r["blocked"] is True
    assert "未知动作" in r["reason"]


def test_action_produces_five_stage_trace(tmp_path):
    """每个动作都应产出可回放的五段思维链。"""
    f = tmp_path / "x.log"
    f.write_text("y")
    r = actions.run_action("truncate_log", {"path": str(f)}, confirmed=True, dry_run=True)
    stages = [s["stage"] for s in r["trace"]]
    assert stages == ["接收指令", "感知环境", "推理决策", "安全校验", "执行结果"]


# ----------------------- 路由 + 审计落库集成 -----------------------

def test_action_endpoint_persists_replayable_trace(tmp_path, monkeypatch):
    """POST /action/execute：解析请求、产出 trace_id 并落审计，可按 id 回放。"""
    import asyncio

    from app.api import routes
    from app.audit import store

    db = tmp_path / "audit.sqlite"
    monkeypatch.setattr(store, "_db_path", lambda: str(db))

    req = routes.ActionRequest(action="truncate_log", params={"path": "/etc/passwd"},
                               confirmed=True, dry_run=False)
    result = asyncio.run(routes.action_execute(req))

    assert result["blocked"] is True          # 关键文件被动作层拦截
    assert result["executed"] is False
    assert "trace_id" in result

    t = store.get_trace(result["trace_id"])    # 落库且可回放
    assert t is not None
    assert t["intent"] == "action"
    assert t["blocked"] is True
    assert [s["stage"] for s in t["steps"]][0] == "接收指令"
