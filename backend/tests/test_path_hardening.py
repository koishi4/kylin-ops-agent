"""路径加固红队测试（审查整改 ③②⑤）。

固化三条被外部审查指出、且已修复的安全性质，防回归：
  ③ 软链绕过：classify_file 解析软链后判类，truncate_log 直接拒绝符号链接——
     杜绝「/var/log/x → /etc/passwd」这类『字面可清理、实指关键文件』的写穿。
  ② 最小权限启动自检：以 root 运行至少告警，REFUSE_ROOT 时拒绝启动。
  ⑤ tail_log 路径管控：仅允许读日志根下的文件，敏感文件（口令/私钥）一律拒读。
"""
from __future__ import annotations

import pytest
from app.core import actions
from app.core.diagnosis import FileClass, classify_file
from app.core.pathutil import is_path_within, path_under_any_root
from app.guardrail.privilege import is_running_as_root, least_privilege_check
from app.mcp_server.tools.log import tail_log

# ----------------------------- ③ 软链绕过：classify_file -----------------------------

class TestClassifyResolvesSymlink:
    def test_symlink_in_cleanable_dir_pointing_to_critical_is_critical(self, tmp_path):
        """字面落在可清理名（.log），但软链实指 /etc/passwd → 解析后判关键，绕过被堵死。"""
        link = tmp_path / "evil.log"
        link.symlink_to("/etc/passwd")
        cls, _ = classify_file(str(link))
        assert cls is FileClass.CRITICAL

    def test_symlink_to_critical_name_is_critical(self, tmp_path):
        """软链指向 *.db（关键名特征），即便链名是 .log 也判关键。"""
        target = tmp_path / "store.db"
        target.write_text("data")
        link = tmp_path / "access.log"
        link.symlink_to(target)
        assert classify_file(str(link))[0] is FileClass.CRITICAL

    def test_plain_cleanable_file_unchanged(self, tmp_path):
        """回归保护：普通非软链的可清理文件仍判可清理，加固不误伤正常路径。"""
        f = tmp_path / "app.log"
        f.write_text("x")
        assert classify_file(str(f))[0] is FileClass.CLEANABLE


# ----------------------------- ③ truncate_log 拒绝符号链接 -----------------------------

class TestTruncateRefusesSymlink:
    def test_symlink_blocked_and_target_intact(self, tmp_path):
        """对软链 truncate 会写穿真实文件：直接拒绝，且确认+真执行下目标内容毫发无损。"""
        target = tmp_path / "real.log"
        target.write_text("keep-me\n")
        link = tmp_path / "app.log"        # 链名可清理、链本身在 /tmp（可清理根）
        link.symlink_to(target)

        r = actions.run_action("truncate_log", {"path": str(link)},
                               confirmed=True, dry_run=False)

        assert r["blocked"] is True
        assert "符号链接" in r["reason"] or "软链" in r["reason"]
        assert target.read_text() == "keep-me\n"   # 未被清空，写穿被拦在执行之前

    def test_symlink_to_critical_blocked(self, tmp_path):
        """软链指向关键文件：被符号链接闸门拦下（执行前即拒，绝不触碰 /etc/passwd）。"""
        link = tmp_path / "x.log"
        link.symlink_to("/etc/passwd")
        r = actions.run_action("truncate_log", {"path": str(link)},
                               confirmed=True, dry_run=False)
        assert r["blocked"] is True and r["executed"] is False


# ----------------------------- ② 最小权限启动自检 -----------------------------

class TestLeastPrivilegeStartup:
    def test_non_root_allowed(self):
        refuse, msg = least_privilege_check(is_root=False, refuse_root=True)
        assert refuse is False and "非 root" in msg

    def test_root_warns_by_default(self):
        """默认（refuse_root=False）以 root 运行只告警、不阻断，避免误伤官方虚机演示。"""
        refuse, msg = least_privilege_check(is_root=True, refuse_root=False)
        assert refuse is False and "root" in msg and "最小权限" in msg

    def test_root_refused_when_configured(self):
        """隔离/生产环境置 REFUSE_ROOT=true → 以 root 启动被拒绝。"""
        refuse, _ = least_privilege_check(is_root=True, refuse_root=True)
        assert refuse is True

    def test_is_running_as_root_returns_bool(self):
        assert isinstance(is_running_as_root(), bool)


# ----------------------------- ⑤ tail_log 路径管控 -----------------------------

class TestTailLogPathControl:
    def test_allows_file_under_allowed_root(self, tmp_path):
        """tmp_path 落在 /tmp（允许的日志根）→ 正常读尾部。"""
        f = tmp_path / "svc.log"
        f.write_text("a\nb\nc\n")
        r = tail_log(str(f), lines=2)
        assert r["ok"] is True and r["lines"] == ["b", "c"]

    def test_refuses_outside_allowlist(self):
        """/etc/hostname 存在且可读，但不在允许日志根 → 拒读（防越权读任意文件）。"""
        r = tail_log("/etc/hostname")
        assert r["ok"] is False and "允许" in r["error"]

    def test_refuses_sensitive_even_in_allowed_root(self, tmp_path):
        """私钥落在 /tmp（允许根）内，仍命中敏感 denylist → 拒读（防口令/密钥泄露）。"""
        key = tmp_path / "id_rsa"
        key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        r = tail_log(str(key))
        assert r["ok"] is False and "敏感" in r["error"]

    def test_fd_safe_refuses_symlinked_final_component(self, tmp_path):
        """P0-B：末段是软链（即便指向允许根内的普通文件）也被 O_NOFOLLOW 拒——
        这正是 classify/allowlist 通过后「文件被换成软链」TOCTOU 调包的防线。"""
        real = tmp_path / "real.log"
        real.write_text("a\nb\nc\n")
        link = tmp_path / "app.log"          # 链名在 /tmp（允许根），realpath 仍落在 /tmp 内 → 过 allowlist
        link.symlink_to(real)
        r = tail_log(str(link))
        assert r["ok"] is False and "fd-safe" in r["error"]
        assert real.read_text() == "a\nb\nc\n"   # 真实文件未被触碰


# ----------------------------- P0-1 路径前缀 bug：兄弟目录不得误判 -----------------------------

class TestSiblingDirNotMatched:
    """startswith 把 /var/log2 当成 /var/log 子路径——commonpath 分量包含修掉它（P0-1）。"""

    @pytest.mark.parametrize("sibling", [
        "/var/log2/x.log",        # 兄弟目录，startswith('/var/log') 会误判
        "/tmpx/y.tmp",            # 兄弟目录，startswith('/tmp') 会误判
        "/var/lib/mysqlx/z",      # 兄弟目录，startswith('/var/lib/mysql') 会误判
    ])
    def test_sibling_dirs_not_within_roots(self, sibling):
        roots = ("/var/log", "/tmp", "/var/lib/mysql", "/var/cache")
        assert is_path_within(sibling, roots) is False

    @pytest.mark.parametrize("inside", [
        "/var/log/app.log",
        "/var/log/nginx/access.log",
        "/tmp/scratch/a",
        "/var/lib/mysql/ibdata1",
    ])
    def test_real_subpaths_still_within(self, inside):
        roots = ("/var/log", "/tmp", "/var/lib/mysql")
        assert is_path_within(inside, roots) is True

    def test_root_itself_is_within(self):
        assert is_path_within("/var/log", ("/var/log",)) is True

    def test_diagnosis_sibling_not_cleanable(self):
        """/var/log2 不再被根因分析误判为可清理（回归 P0-1 的真实影响面）。"""
        cls, _ = classify_file("/var/log2/whatever.bin")
        assert cls is not FileClass.CLEANABLE

    def test_diagnosis_var_log_still_cleanable(self):
        cls, _ = classify_file("/var/log/app.log")
        assert cls is FileClass.CLEANABLE

    def test_tail_log_rejects_sibling_dir(self, tmp_path, monkeypatch):
        """tail_log 白名单：/var/log2 这类兄弟目录被拒（即便文件存在）。"""
        # 构造一个名字以允许根字符串为前缀、但实为兄弟目录的文件
        sib = tmp_path.parent / (tmp_path.name + "_sib")
        sib.mkdir(exist_ok=True)
        f = sib / "fake.log"
        f.write_text("x\n")
        # 把允许根伪装成 tmp_path（则 sib = tmp_path+"_sib" 是其兄弟目录）
        import app.mcp_server.tools.log as logmod
        monkeypatch.setattr(logmod, "_ALLOWED_LOG_ROOTS", (str(tmp_path),))
        r = tail_log(str(f))
        assert r["ok"] is False and "允许" in r["error"]


class TestPathUnderAnyRootResolvesSymlink:
    def test_symlink_escaping_allowed_root_rejected(self, tmp_path):
        """字面在允许根、软链实指根外 → realpath 后判否（堵软链逃逸）。"""
        outside = tmp_path.parent / "outside_target.log"
        outside.write_text("secret\n")
        link = tmp_path / "inside.log"
        link.symlink_to(outside)
        assert path_under_any_root(str(link), (str(tmp_path),)) is False

    def test_plain_file_under_root_accepted(self, tmp_path):
        f = tmp_path / "real.log"
        f.write_text("a\n")
        assert path_under_any_root(str(f), (str(tmp_path),)) is True
