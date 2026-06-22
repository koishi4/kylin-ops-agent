"""P1 扩展受控动作测试：restart_service / reload_config / block_ip / clean_journal。

覆盖三类路径：① 动作层语义闸门拦截（guard=None，未进 executor）；② 防线4 最小权限拦截
（进了 executor 才被拦，guard 非空、privilege.allowed=False）；③ 授权+确认+dry_run 放行预览。

铁律（CLAUDE.md §6）：绝不真实执行 restart/封禁/vacuum——全部走 dry_run 或拦截路径，对系统无害。
"""
from __future__ import annotations

import pytest

from app.core import actions


# --------------------------- restart_service / reload_config ---------------------------

class TestManageService:
    def test_critical_unit_refused_by_semantic_gate(self):
        """关键单元（sshd）被动作层语义闸门拦死，绝不进 executor（guard=None）。"""
        r = actions.run_action("restart_service", {"unit": "sshd"},
                               confirmed=True, authorized=True, dry_run=True)
        assert r["blocked"] is True and r["executed"] is False
        assert r["guard"] is None
        assert "关键系统服务" in r["reason"]

    def test_invalid_unit_refused(self):
        """非法 unit 名（夹带注入）被白名单校验拒。"""
        r = actions.run_action("restart_service", {"unit": "ng; rm -rf /"},
                               confirmed=True, authorized=True, dry_run=True)
        assert r["blocked"] is True and r["guard"] is None

    def test_missing_unit_refused(self):
        r = actions.run_action("restart_service", {}, confirmed=True, authorized=True)
        assert r["blocked"] is True

    def test_needs_authorization_priv_gate(self):
        """非关键服务、已确认但未授权 → 防线4（管理 systemd 服务需提权）在 executor 拦下。"""
        r = actions.run_action("restart_service", {"unit": "nginx"},
                               confirmed=True, authorized=False, dry_run=True)
        assert r["blocked"] is True
        assert r["guard"] is not None          # 进了 executor 才被拦（区别于语义层 guard=None）
        assert r["privilege"] is not None and r["privilege"]["allowed"] is False

    def test_authorized_dryrun_passes(self):
        """非关键服务 + 授权 + 二次确认 + dry_run → 护栏放行、未真正执行。"""
        r = actions.run_action("restart_service", {"unit": "nginx"},
                               confirmed=True, authorized=True, dry_run=True)
        assert r["blocked"] is False and r["executed"] is False
        assert "systemctl restart nginx" in r["command"]

    def test_reload_uses_reload_verb(self):
        r = actions.run_action("reload_config", {"unit": "nginx"},
                               confirmed=True, authorized=True, dry_run=True)
        assert r["blocked"] is False
        assert "systemctl reload nginx" in r["command"]

    def test_five_stage_trace_on_pass_path(self):
        r = actions.run_action("restart_service", {"unit": "nginx"},
                               confirmed=True, authorized=True, dry_run=True)
        assert [s["stage"] for s in r["trace"]] == \
            ["接收指令", "感知环境", "推理决策", "安全校验", "执行结果"]


# --------------------------------- block_ip ---------------------------------

class TestBlockIp:
    def test_valid_ip_authorized_dryrun_passes(self, monkeypatch):
        monkeypatch.delenv("SSH_CONNECTION", raising=False)
        r = actions.run_action("block_ip", {"ip": "203.0.113.45"},
                               confirmed=True, authorized=True, dry_run=True)
        assert r["blocked"] is False and r["executed"] is False
        assert "iptables" in r["command"] and "203.0.113.45" in r["command"]

    def test_missing_ip_refused(self):
        r = actions.run_action("block_ip", {}, confirmed=True, authorized=True)
        assert r["blocked"] is True and r["guard"] is None

    def test_invalid_ip_refused(self):
        r = actions.run_action("block_ip", {"ip": "999.999.1.1"},
                               confirmed=True, authorized=True)
        assert r["blocked"] is True and r["guard"] is None

    def test_cidr_subnet_refused(self):
        """拒绝封整段子网（防误伤大范围/自锁）。"""
        r = actions.run_action("block_ip", {"ip": "10.0.0.0/8"},
                               confirmed=True, authorized=True)
        assert r["blocked"] is True and "网段" in r["reason"]

    def test_loopback_refused(self):
        r = actions.run_action("block_ip", {"ip": "127.0.0.1"},
                               confirmed=True, authorized=True)
        assert r["blocked"] is True and r["guard"] is None

    def test_ssh_source_self_lock_refused(self, monkeypatch):
        """封禁当前 SSH 来源会自锁——必须拒。"""
        monkeypatch.setenv("SSH_CONNECTION", "198.51.100.7 51000 198.51.100.1 22")
        r = actions.run_action("block_ip", {"ip": "198.51.100.7"},
                               confirmed=True, authorized=True)
        assert r["blocked"] is True and "自锁" in r["reason"]

    def test_needs_authorization_priv_gate(self, monkeypatch):
        monkeypatch.delenv("SSH_CONNECTION", raising=False)
        r = actions.run_action("block_ip", {"ip": "203.0.113.45"},
                               confirmed=True, authorized=False, dry_run=True)
        assert r["blocked"] is True
        assert r["privilege"] is not None and r["privilege"]["allowed"] is False


# -------------------------------- clean_journal --------------------------------

class TestCleanJournal:
    def test_size_dryrun_passes(self):
        r = actions.run_action("clean_journal", {"size": "200M"},
                               confirmed=True, dry_run=True)
        assert r["blocked"] is False and r["executed"] is False
        assert "--vacuum-size=200M" in r["command"]

    def test_time_dryrun_passes(self):
        r = actions.run_action("clean_journal", {"time": "7d"},
                               confirmed=True, dry_run=True)
        assert r["blocked"] is False
        assert "--vacuum-time=7d" in r["command"]

    def test_requires_exactly_one_of_size_time(self):
        both = actions.run_action("clean_journal", {"size": "200M", "time": "7d"},
                                  confirmed=True, dry_run=True)
        assert both["blocked"] is True and both["guard"] is None
        none = actions.run_action("clean_journal", {}, confirmed=True, dry_run=True)
        assert none["blocked"] is True

    def test_invalid_size_refused(self):
        r = actions.run_action("clean_journal", {"size": "lots; rm -rf /"},
                               confirmed=True, dry_run=True)
        assert r["blocked"] is True and r["guard"] is None

    def test_requires_confirm(self):
        r = actions.run_action("clean_journal", {"size": "200M"},
                               confirmed=False, dry_run=False)
        assert r["require_confirm"] is True and r["executed"] is False


# --------------------------- 白名单 / schema 一致性 ---------------------------

def test_new_actions_registered_and_isolated():
    """新动作都在 ACTIONS 白名单、都有 handler，且绝不出现在 MCP 工具注册表（感知层隔离不变量）。"""
    from app.mcp_server.tools import REGISTRY
    for name in ("restart_service", "reload_config", "block_ip", "clean_journal"):
        assert name in actions.ACTIONS
        assert name in actions._HANDLERS
        assert name not in REGISTRY


@pytest.mark.parametrize("action,params", [
    ("restart_service", {"unit": "nginx"}),
    ("reload_config", {"unit": "nginx"}),
    ("block_ip", {"ip": "203.0.113.45"}),
    ("clean_journal", {"size": "100M"}),
])
def test_unconfirmed_never_executes(action, params, monkeypatch):
    """未二次确认：一律不真正执行（require_confirm 或被拦），是受控动作的硬保证。"""
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    r = actions.run_action(action, params, confirmed=False, authorized=True, dry_run=False)
    assert r["executed"] is False
