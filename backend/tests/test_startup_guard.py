"""P0-D：DEMO/PROD 失败安全启动守卫 + 审计先于执行。

固化两条「失败安全默认」不变量：
1. 非回环绑定（联网/生产）下，operator_token 为空或 audit_hmac_key 仍是默认值 → 拒绝启动；
   本机 demo（127.0.0.1 + 空 token + 默认密钥）保持顺滑放行。
2. 真正改系统状态的受控动作「审计先于执行」：pending 审计写不下去就不执行——无法留痕则不放行。
"""
from __future__ import annotations

import asyncio

from app.config import _DEFAULT_AUDIT_HMAC_KEY, Settings


class TestProductionStartupGuard:
    def test_loopback_demo_ok(self):
        """本机回环 + 空 token + 默认密钥 = 演示模式，不拦。"""
        s = Settings(api_bind_host="127.0.0.1", operator_token="",
                     audit_hmac_key=_DEFAULT_AUDIT_HMAC_KEY, llm_provider="mock")
        assert s.is_loopback_bind is True
        assert s.production_config_errors() == []

    def test_public_bind_empty_token_refused(self):
        s = Settings(api_bind_host="0.0.0.0", operator_token="",
                     audit_hmac_key="a-strong-unique-key", llm_provider="mock")
        errs = s.production_config_errors()
        assert errs and any("OPERATOR_TOKEN" in e for e in errs)

    def test_public_bind_default_hmac_refused(self):
        """联网绑定 + 配了 token 但 hmac 仍是默认值 → 仍拒绝（审计链可伪造）。"""
        s = Settings(api_bind_host="0.0.0.0", operator_token="tok",
                     audit_hmac_key=_DEFAULT_AUDIT_HMAC_KEY, llm_provider="mock")
        errs = s.production_config_errors()
        assert errs and any("AUDIT_HMAC_KEY" in e for e in errs)

    def test_public_bind_fully_configured_ok(self):
        s = Settings(api_bind_host="0.0.0.0", operator_token="tok",
                     audit_hmac_key="a-strong-unique-key", llm_provider="mock")
        assert s.production_config_errors() == []


class TestAuditBeforeExecute:
    def test_refuses_state_change_when_audit_unavailable(self, tmp_path, monkeypatch):
        """改状态动作（confirmed + 非 dry_run）：pending 审计写入失败 → 拒绝执行、文件不被清空。"""
        from app.api import routes
        from app.audit import store

        f = tmp_path / "app.log"
        f.write_text("x" * 100)

        def boom(*a, **k):
            raise RuntimeError("audit store down")

        monkeypatch.setattr(store, "save_trace", boom)

        req = routes.ActionRequest(action="truncate_log", params={"path": str(f)},
                                   confirmed=True, dry_run=False)
        result = asyncio.run(routes.action_execute(req))

        assert result["executed"] is False
        assert result["blocked"] is True
        assert "审计" in result["reason"]
        assert f.stat().st_size == 100   # 未被执行清空——无法留痕则不执行

    def test_dry_run_preview_not_blocked_by_audit_failure(self, tmp_path, monkeypatch):
        """dry_run 预览不改状态，审计失败只是 best-effort，不应阻断预览（不退化演示顺滑性）。"""
        from app.api import routes
        from app.audit import store

        f = tmp_path / "app.log"
        f.write_text("x" * 100)
        monkeypatch.setattr(store, "save_trace",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))

        req = routes.ActionRequest(action="truncate_log", params={"path": str(f)},
                                   confirmed=True, dry_run=True)
        result = asyncio.run(routes.action_execute(req))
        # 审计失败被吞（标注 audit_warning），但 dry_run 预览本身正常返回（未被审计前置拦死）
        assert result["executed"] is False
        assert result.get("audit_warning")
        assert f.stat().st_size == 100   # dry_run 本就不改文件
