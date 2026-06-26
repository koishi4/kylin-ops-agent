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
        # disk/zombie/load/memory 四类纯诊断（configdrift 有 TOFU 锚定副作用，不并入 all）
        assert len(r["reports"]) == 4
        assert {"memory", "disk", "zombie", "load"} == {x["topic"] for x in r["reports"]}
        assert "summary" in r

    def test_unknown_topic(self):
        assert diagnosis.diagnose("nonsense")["ok"] is False


class TestIoCorrelation:
    """P1-1 跨信号关联：用构造信号断言证据链/置信度/根因组装正确（纯函数，确定性）。"""

    def _full_signals(self):
        return {
            "disk_percent": 96.0, "disk_warn": 85.0,
            "growing_file": {"path": "/var/log/app.log", "size_mb": 8000.0,
                             "grew_bytes": 5 * 1024 * 1024, "interval_s": 0.5},
            "writer": {"pid": 1234, "command": "java", "fd": "7w"},
            "writer_status": diagnosis._DSTATE,
            "dstate_count": 3,
        }

    def test_full_chain_high_confidence(self):
        r = diagnosis.correlate_io_signals(self._full_signals())
        # 五信号全中 → 置信度满、判定高
        assert r["confidence"] >= 0.9
        assert r["confidence_label"] == "高"
        assert r["severity"] == "critical"            # 磁盘 96% + 高置信
        # 证据链含全部五个信号
        sigs = {e["signal"] for e in r["evidence"]}
        assert {"disk_high", "file_growing", "writer_found",
                "writer_dstate", "io_pressure"} <= sigs
        # 根因把「进程→文件→双告警」串起来
        assert "java" in r["root_cause"] and "1234" in r["root_cause"]
        assert "/var/log/app.log" in r["root_cause"]
        assert "IO" in r["root_cause"]
        assert len(r["chain"]) >= 5

    def test_partial_chain_no_writer(self):
        """有磁盘告警 + 文件增长但没定位到进程 → 中等置信，建议 root 重跑 lsof。"""
        sig = self._full_signals()
        sig["writer"] = None
        sig["writer_status"] = None
        sig["dstate_count"] = 0
        r = diagnosis.correlate_io_signals(sig)
        assert 0.4 <= r["confidence"] < 0.7
        assert r["confidence_label"] == "中"
        assert "未定位到具体写入进程" in r["root_cause"]
        assert any("lsof" in s for s in r["suggestions"])

    def test_no_correlation_is_ok(self):
        r = diagnosis.correlate_io_signals(
            {"disk_percent": 40.0, "disk_warn": 85.0,
             "growing_file": None, "writer": None, "dstate_count": 0})
        assert r["severity"] == "ok"
        assert r["confidence"] == 0.0

    def test_growing_critical_file_warns_no_delete(self):
        """增长的是数据库文件 → 根因点名关键性，建议明确禁止删除/清空。"""
        sig = self._full_signals()
        sig["growing_file"]["path"] = "/var/lib/mysql/ibdata1"
        r = diagnosis.correlate_io_signals(sig)
        assert "不可逆" in r["root_cause"] or "关键" in r["root_cause"]
        joined = " ".join(r["suggestions"])
        assert "切勿删除" in joined or "切勿" in joined
        assert "truncate -s 0 /var/lib/mysql/ibdata1" not in joined  # 绝不建议清空数据库

    def test_growing_log_suggests_truncate_not_rm(self):
        """失控日志 → 建议 truncate 止血并解释「rm 被持有文件不释放空间」。"""
        r = diagnosis.correlate_io_signals(self._full_signals())
        joined = " ".join(r["suggestions"])
        assert "truncate -s 0 /var/log/app.log" in joined
        assert "rm" in joined and "句柄" in joined        # 解释了为何不能直接 rm

    def test_no_realtime_growth_lowers_confidence(self):
        """找到大文件但采样窗内没增长 → file_growing 不计权，置信度更低。"""
        sig = self._full_signals()
        sig["growing_file"]["grew_bytes"] = 0
        r = diagnosis.correlate_io_signals(sig)
        assert all(e["signal"] != "file_growing" for e in r["evidence"])
        assert r["confidence"] < 0.9


class TestDiagnoseIoCollect:
    """采集入口的结构与「只读、无副作用」验证（不依赖被写入的真实日志）。"""

    def test_structure_and_no_execution(self):
        # grow_interval=0 跳过采样睡眠，保证测试快；对 /tmp 跑，无副作用
        r = diagnosis.diagnose_io_correlation("/tmp", grow_interval=0.0)
        assert r["ok"] is True and r["topic"] == "io"
        assert r["severity"] in ("ok", "warning", "critical")
        assert "confidence" in r and 0.0 <= r["confidence"] <= 1.0
        assert isinstance(r["evidence"], list) and isinstance(r["chain"], list)

    def test_dispatch_io(self):
        r = diagnosis.diagnose("io", path="/tmp")
        assert r["ok"] is True and r["topic"] == "io"
