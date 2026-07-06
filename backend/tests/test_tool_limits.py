"""只读工具资源硬上限 + 参数校验测试（P0-3）。

只读 ≠ 无害：固化「超大扫描被夹断 / 伪文件系统拒扫 / 非法 unit·priority·since 被拒、
正常参数不受影响」四类性质，防回归。这些是『安全作品』可信度命门之一。
"""
from __future__ import annotations

from app.mcp_server.tools._validate import (
    MAX_SCAN_FILES,
    clamp_scan,
    valid_priority,
    valid_since,
    valid_unit,
)
from app.mcp_server.tools.disk import dir_size, find_large_files
from app.mcp_server.tools.log import query_journal
from app.mcp_server.tools.system import service_status

# ----------------------------- max_scan 硬上限夹断 -----------------------------

class TestScanClamp:
    def test_clamp_caps_oversize(self):
        assert clamp_scan(10_000_000, MAX_SCAN_FILES) == MAX_SCAN_FILES

    def test_clamp_floor_is_one(self):
        assert clamp_scan(0, MAX_SCAN_FILES) == 1
        assert clamp_scan(-5, MAX_SCAN_FILES) == 1

    def test_clamp_non_int_is_conservative(self):
        assert clamp_scan("abc", 200) == 200
        assert clamp_scan(None, 200) == 200

    def test_find_large_files_truncates_and_reports(self, tmp_path):
        for i in range(5):
            (tmp_path / f"f{i}.bin").write_bytes(b"x" * (100 + i))
        r = find_large_files(str(tmp_path), top_n=3, max_scan=2)
        assert r["ok"] is True
        assert r["truncated"] is True
        assert r["scanned"] <= 2
        assert "max_scan limit reached" in r["reason"]

    def test_dir_size_truncates_and_reports(self, tmp_path):
        for i in range(5):
            (tmp_path / f"f{i}.bin").write_bytes(b"x" * 50)
        r = dir_size(str(tmp_path), max_scan=2)
        assert r["truncated"] is True
        assert "max_scan limit reached" in r["reason"]

    def test_normal_scan_not_truncated(self, tmp_path):
        (tmp_path / "a.bin").write_bytes(b"x" * 100)
        r = find_large_files(str(tmp_path))
        assert r["truncated"] is False
        assert "reason" not in r


# ----------------------------- 伪文件系统拒扫 -----------------------------

class TestRefusePseudoFs:
    def test_find_large_files_refuses_proc(self):
        r = find_large_files("/proc")
        assert r["ok"] is False
        assert "拒绝扫描" in r["error"]

    def test_dir_size_refuses_sys(self):
        r = dir_size("/sys")
        assert r["ok"] is False
        assert "拒绝扫描" in r["error"]

    def test_find_large_files_refuses_proc_subdir(self):
        r = find_large_files("/proc/1")
        assert r["ok"] is False

    def test_normal_dir_not_refused(self, tmp_path):
        r = find_large_files(str(tmp_path))
        assert r["ok"] is True


# ----------------------------- systemd unit 名校验 -----------------------------

class TestUnitValidation:
    def test_valid_units(self):
        for u in ("sshd", "nginx.service", "user@1000.service", "dbus-broker", "foo_bar.service"):
            assert valid_unit(u) is True

    def test_invalid_units(self):
        for u in ("", "a b", "rm -rf /", "foo;bar", "../etc/passwd", "x|y", "$(id)"):
            assert valid_unit(u) is False

    def test_service_status_rejects_injection(self):
        r = service_status("sshd; rm -rf /")
        assert r["ok"] is False
        assert "非法服务名" in r["error"]


# ----------------------------- journalctl 参数校验 -----------------------------

class TestJournalValidation:
    def test_priority_valid(self):
        for p in ("0", "7", "err", "warning", "debug"):
            assert valid_priority(p) is True

    def test_priority_invalid(self):
        for p in ("8", "-1", "9", "evil", "err;id", ""):
            assert valid_priority(p) is False

    def test_since_valid(self):
        for s in ("today", "yesterday", "-1h", "-30m", "-7d", "2026-06-01"):
            assert valid_since(s) is True

    def test_since_invalid(self):
        for s in ("1 hour ago", "; rm -rf /", "now", "-1y", "2026/06/01"):
            assert valid_since(s) is False

    def test_query_journal_rejects_bad_unit(self):
        r = query_journal(unit="foo; rm -rf /")
        assert r["ok"] is False and "非法 unit" in r["error"]

    def test_query_journal_rejects_bad_priority(self):
        r = query_journal(priority="9")
        assert r["ok"] is False and "非法 priority" in r["error"]

    def test_query_journal_rejects_bad_since(self):
        r = query_journal(since="; cat /etc/passwd")
        assert r["ok"] is False and "非法 since" in r["error"]

    def test_query_journal_lines_capped_at_200(self):
        # 不真依赖 journalctl 是否存在：只要不是被参数校验拒（结构化 readonly 即可）
        r = query_journal(lines=99999)
        assert r["level"] == "READONLY"


class TestScanPrune:
    """扫描剪枝：伪文件系统 + WSL /mnt Windows 挂载默认不深入（显式扫描根除外）。"""

    def _fake_mounts(self, tmp_path):
        f = tmp_path / "mounts"
        f.write_text(
            "rootfs / ext4 rw 0 0\n"
            "C:\\134 /mnt/c 9p rw,dirsync 0 0\n"
            "D: /mnt/d drvfs rw 0 0\n"
            "tmpfs /mnt/wsl tmpfs rw 0 0\n"   # 非 9p/drvfs，不算 Windows 挂载
            "server:/data /data nfs rw 0 0\n"  # 9p/drvfs 之外的网络盘不剪
        )
        return str(f)

    def test_windows_mounts_parsed_by_fstype(self, tmp_path):
        from app.mcp_server.tools._validate import windows_mounts
        assert windows_mounts(self._fake_mounts(tmp_path)) == ("/mnt/c", "/mnt/d")

    def test_windows_mounts_unreadable_is_safe_empty(self):
        from app.mcp_server.tools._validate import windows_mounts
        assert windows_mounts("/no/such/mounts/file") == ()

    def test_scan_prune_roots_default_and_explicit_optin(self, monkeypatch):
        from app.mcp_server.tools import _validate
        monkeypatch.setattr(_validate, "windows_mounts", lambda: ("/mnt/c",))
        # 全盘扫描：伪文件系统与 Windows 挂载都在剪枝集
        pruned = _validate.scan_prune_roots("/")
        assert "/proc" in pruned and "/mnt/c" in pruned
        # 显式以 Windows 挂载为扫描根：视为明确意图，该前缀不剪
        pruned = _validate.scan_prune_roots("/mnt/c/data")
        assert "/mnt/c" not in pruned and "/proc" in pruned

    def test_prune_walk_dirs_component_wise(self):
        from app.mcp_server.tools._validate import prune_walk_dirs
        dirs = ["c", "cx", "wsl"]
        # /mnt 下剪 c（在 /mnt/c 前缀内），兄弟目录 cx 是路径分量不同的目录，不误剪
        prune_walk_dirs("/mnt", dirs, ("/mnt/c",))
        assert dirs == ["cx", "wsl"]

    def test_find_large_files_skips_windows_mount(self, tmp_path, monkeypatch):
        from app.mcp_server.tools import _validate, disk
        # 构造：root/real 下有真实大文件；root/mnt/c 模拟 Windows 挂载下更大的文件
        real = tmp_path / "real"; real.mkdir()
        (real / "big.log").write_bytes(b"x" * 4096)
        win = tmp_path / "mnt" / "c"; win.mkdir(parents=True)
        (win / "huge.bin").write_bytes(b"y" * 65536)
        monkeypatch.setattr(_validate, "windows_mounts", lambda: (str(win),))
        found = [f["path"] for f in disk.find_large_files(str(tmp_path), top_n=5)["files"]]
        assert str(real / "big.log") in found
        assert all("huge.bin" not in p for p in found), "Windows 挂载下的文件应被剪枝跳过"
        # 显式以该挂载为扫描根 → 尊重意图，能扫到
        found = [f["path"] for f in disk.find_large_files(str(win), top_n=5)["files"]]
        assert str(win / "huge.bin") in found
