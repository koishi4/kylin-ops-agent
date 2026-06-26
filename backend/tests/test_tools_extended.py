"""第 2 周补全的 MCP 工具单元测试（纯函数层）。
对系统命令依赖较强的工具（systemctl/lsof/journalctl）只断言「优雅返回结构化结果、不崩溃」，
因为 WSL/容器/无 root 环境下它们可能不可用——这正是工具必须返回结构化错误而非抛异常的原因。
"""
from __future__ import annotations

import os

from app.mcp_server.tools import (
    check_port,
    dir_size,
    find_large_files,
    find_zombie_processes,
    list_listening_ports,
    list_open_files,
    process_detail,
    query_journal,
    service_status,
    system_load,
    tail_log,
    uptime_info,
)


def assert_readonly(r: dict):
    assert isinstance(r, dict)
    assert r.get("level") == "READONLY"
    assert "ok" in r  # 必有 ok 字段，失败也结构化


class TestSystem:
    def test_system_load(self):
        r = system_load()
        assert r["ok"] is True
        assert r["cpu_count"] >= 1

    def test_uptime(self):
        r = uptime_info()
        assert r["ok"] is True
        assert r["uptime_seconds"] >= 0
        assert "天" in r["uptime_human"]

    def test_service_status_graceful(self):
        # systemd 可能不在（WSL），只要求结构化不崩溃
        assert_readonly(service_status("sshd"))


class TestProcess:
    def test_find_zombies_structure(self):
        r = find_zombie_processes()
        assert r["ok"] is True
        assert isinstance(r["zombies"], list)

    def test_process_detail_self(self):
        r = process_detail(os.getpid())
        assert r["ok"] is True
        assert r["pid"] == os.getpid()
        assert r["name"]

    def test_process_detail_missing(self):
        r = process_detail(2_000_000_000)  # 几乎不可能存在的 pid
        assert r["ok"] is False
        assert "error" in r


class TestNetwork:
    def test_list_listening_ports(self):
        assert_readonly(list_listening_ports())

    def test_check_port_invalid(self):
        r = check_port(99999)
        assert r["ok"] is False

    def test_check_port_structure(self):
        r = check_port(65000)  # 大概率空闲
        assert_readonly(r)
        if r["ok"]:
            assert "in_use" in r


class TestDisk:
    def test_find_large_files(self, tmp_path):
        (tmp_path / "small.txt").write_bytes(b"x" * 100)
        (tmp_path / "big.bin").write_bytes(b"x" * 50_000)
        r = find_large_files(str(tmp_path), top_n=2)
        assert r["ok"] is True
        assert r["files"][0]["path"].endswith("big.bin")  # 最大的排第一

    def test_find_large_files_bad_path(self):
        r = find_large_files("/no/such/dir")
        assert r["ok"] is False

    def test_dir_size(self, tmp_path):
        (tmp_path / "a.txt").write_bytes(b"x" * 1000)
        (tmp_path / "b.txt").write_bytes(b"x" * 2000)
        r = dir_size(str(tmp_path))
        assert r["ok"] is True
        assert r["file_count"] == 2
        assert r["total_mb"] >= 0


class TestLog:
    def test_tail_log(self, tmp_path):
        f = tmp_path / "app.log"
        f.write_text("\n".join(f"line{i}" for i in range(100)) + "\n")
        r = tail_log(str(f), lines=10)
        assert r["ok"] is True
        assert r["lines"][-1] == "line99"
        assert len(r["lines"]) == 10

    def test_tail_log_missing(self):
        r = tail_log("/no/such/file.log")
        assert r["ok"] is False

    def test_query_journal_graceful(self):
        assert_readonly(query_journal(lines=5))


class TestHandle:
    def test_list_open_files_graceful(self, tmp_path):
        f = tmp_path / "held.txt"
        f.write_text("data")
        assert_readonly(list_open_files(str(f)))
