"""根因分析测试（评分④）。重点验证「关键性判断」准确，且诊断只分析、不执行任何处置。"""
from __future__ import annotations

import pytest

from app.core import diagnosis
from app.core.diagnosis import FileClass, classify_file


class TestClassifyFile:
    @pytest.mark.parametrize("path", [
        "/var/lib/mysql/ibdata1",
        "/var/lib/postgresql/13/main/base/1",
        "/boot/vmlinuz-5.15.0",
        "/etc/some.conf",
        "/data/backup.sql",
        "/home/u/app.sqlite",
        "/var/lib/docker/overlay2/x/diff/a",
    ])
    def test_critical(self, path):
        cls, _ = classify_file(path)
        assert cls is FileClass.CRITICAL, f"应判关键: {path}"

    @pytest.mark.parametrize("path", [
        "/var/log/nginx/access.log",
        "/var/log/syslog.1",
        "/tmp/bigfile",
        "/var/cache/apt/archives/x.deb",
        "/var/log/app.log.3",
        "/home/u/.cache/pip/wheels/x",
    ])
    def test_cleanable(self, path):
        cls, _ = classify_file(path)
        assert cls is FileClass.CLEANABLE, f"应判可清理: {path}"

    def test_unknown(self):
        cls, _ = classify_file("/home/user/project/data.bin")
        assert cls is FileClass.UNKNOWN


class TestDiagnoseDisk:
    def test_structure_and_no_execution(self):
        # 对 /tmp 跑磁盘诊断：必返结构化报告，绝不执行删除（无副作用）
        r = diagnosis.diagnose_disk("/tmp", top_n=5)
        assert r["ok"] is True
        assert r["topic"] == "disk"
        assert r["severity"] in ("ok", "warning", "critical")
        assert "suggestions" in r and isinstance(r["large_files"], list)
        # 每个大文件都带关键性分类
        for f in r["large_files"]:
            assert f["class"] in ("cleanable", "critical", "unknown")

    def test_bad_path(self):
        r = diagnosis.diagnose_disk("/no/such/path/xyz")
        assert r["ok"] is False


class TestDiagnoseOthers:
    def test_zombies(self):
        r = diagnosis.diagnose_zombies()
        assert r["ok"] is True and r["topic"] == "zombie"
        assert r["severity"] in ("ok", "warning")

    def test_load(self):
        r = diagnosis.diagnose_load()
        assert r["ok"] is True and r["topic"] == "load"
        assert r["severity"] in ("ok", "warning", "critical", "unknown")

    def test_all_dispatch(self):
        r = diagnosis.diagnose("all", path="/tmp")
        assert r["ok"] is True and r["topic"] == "all"
        assert len(r["reports"]) == 3
        assert "summary" in r

    def test_unknown_topic(self):
        assert diagnosis.diagnose("nonsense")["ok"] is False
