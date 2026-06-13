"""最小权限「落地身份」态势 + fail-closed 裁决测试（评审整改 · 最小权限默认）。

钉死：① privilege_posture 在 非root / root+账户存在 / root+账户缺失 / 进程内不降权 四种情形的判定；
② 动作层 REQUIRE_PRIVILEGE_DROP 开启时对「会以 root 落地」的变更动作 fail-closed 拒绝、文件不被改；
③ 默认（未开）只把落地身份写进 trace、不拦（demo 顺滑）。

CI 以非 root 运行，故 root 情形用 monkeypatch 模拟 is_running_as_root / pwd.getpwnam。
"""
from __future__ import annotations

import pwd

import pytest

from app.guardrail import privilege
from app.guardrail.privilege import privilege_posture


class _Ent:
    pw_uid = 1500
    pw_gid = 1500


def test_posture_nonroot_is_minimal():
    p = privilege_posture("opsagent", drops_privilege=True)
    if p["running_as_root"]:
        pytest.skip("测试宿主以 root 运行，跳过非 root 断言")
    assert p["elevated_landing"] is False
    assert "非 root" in p["reason"]


def test_posture_root_with_existing_account_downgrades(monkeypatch):
    monkeypatch.setattr(privilege, "is_running_as_root", lambda: True)
    monkeypatch.setattr(pwd, "getpwnam", lambda u: _Ent())
    p = privilege_posture("opsagent", drops_privilege=True)
    assert p["running_as_root"] is True
    assert p["drop_usable"] is True and p["elevated_landing"] is False
    assert "降权" in p["reason"]


def test_posture_root_missing_account_lands_as_root(monkeypatch):
    monkeypatch.setattr(privilege, "is_running_as_root", lambda: True)

    def boom(u):
        raise KeyError(u)

    monkeypatch.setattr(pwd, "getpwnam", boom)
    p = privilege_posture("ghost-account", drops_privilege=True)
    assert p["drop_usable"] is False and p["elevated_landing"] is True
    assert "不存在" in p["reason"]


def test_posture_inprocess_lands_as_root_even_with_account(monkeypatch):
    """进程内 syscall（drops_privilege=False，如 truncate 的 ftruncate）：即便账户存在也无法降权。"""
    monkeypatch.setattr(privilege, "is_running_as_root", lambda: True)
    monkeypatch.setattr(pwd, "getpwnam", lambda u: _Ent())
    p = privilege_posture("opsagent", drops_privilege=False)
    assert p["elevated_landing"] is True
    assert "进程内" in p["reason"]


# --------------------------- 动作层 fail-closed 裁决 --------------------------- #

_ELEVATED = {"running_as_root": True, "euid": 0, "exec_user": "opsagent",
             "drop_target": None, "drop_usable": False,
             "elevated_landing": True, "reason": "模拟以 root 落地"}


def _force_posture(monkeypatch, require_drop: bool):
    from app.config import Settings
    from app.core import actions
    from app.core.diagnosis import FileClass
    monkeypatch.setattr(actions, "privilege_posture",
                        lambda exec_user, *, drops_privilege: dict(_ELEVATED))
    monkeypatch.setattr(actions, "get_settings",
                        lambda: Settings(require_privilege_drop=require_drop,
                                         exec_user="opsagent", llm_provider="mock"))
    monkeypatch.setattr(actions, "classify_file", lambda p: (FileClass.CLEANABLE, "t"))


def test_truncate_failclosed_refuses_root_landing(monkeypatch, tmp_path):
    """REQUIRE_PRIVILEGE_DROP=true 且会以 root 落地 → 真执行被拒、文件不被清空。"""
    _force_posture(monkeypatch, require_drop=True)
    from app.core import actions
    f = tmp_path / "app.log"
    f.write_text("x" * 50)
    r = actions.run_action("truncate_log", {"path": str(f)}, confirmed=True, dry_run=False)
    assert r["executed"] is False and r["blocked"] is True
    assert "REQUIRE_PRIVILEGE_DROP" in r["reason"]
    assert f.stat().st_size == 50  # 未被执行清空——fail-closed


def test_clean_path_failclosed_refuses_root_landing(monkeypatch, tmp_path):
    _force_posture(monkeypatch, require_drop=True)
    from app.core import actions
    f = tmp_path / "junk.dat"
    f.write_text("x" * 50)
    r = actions.run_action("clean_path", {"path": str(f)}, confirmed=True, dry_run=False)
    assert r["executed"] is False and r["blocked"] is True
    assert "REQUIRE_PRIVILEGE_DROP" in r["reason"]
    assert f.exists()  # 未被删除


def test_default_annotates_but_does_not_block(monkeypatch, tmp_path):
    """默认（REQUIRE_PRIVILEGE_DROP 未开）：落地身份写进 trace 但不拦（demo 顺滑）。"""
    _force_posture(monkeypatch, require_drop=False)
    from app.core import actions
    f = tmp_path / "app.log"
    f.write_text("x" * 50)
    r = actions.run_action("truncate_log", {"path": str(f)}, confirmed=True, dry_run=True)
    assert r["blocked"] is False
    details = [s["detail"] for s in r["trace"]
               if s["stage"] == "安全校验" and isinstance(s["detail"], dict)]
    postures = [d["privilege_posture"] for d in details if "privilege_posture" in d]
    assert postures and postures[-1]["elevated_landing"] is True  # 如实标注以 root 落地
