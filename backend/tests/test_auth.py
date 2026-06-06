"""受控动作最小鉴权测试（P0-4）。

/action/execute 是唯一会真正改系统状态的入口。固化：配置了 operator_token 时，
缺失/错误 token 一律 401；正确 token 放行；未配置 token 时为本机可信控制台演示模式放行。

刻意只测「鉴权闸门」本身——不做账号/session/RBAC（见 IMPROVEMENTS-v3 P0-4「就到此为止」）。
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import routes
from app.audit import store
from app.config import Settings


@pytest.fixture
def client(tmp_path, monkeypatch):
    # 审计落临时库，避免污染；用裸 app 挂 router（不触发主 app 的 MCP lifespan）
    monkeypatch.setattr(store, "_db_path", lambda: str(tmp_path / "audit.sqlite"))
    app = FastAPI()
    app.include_router(routes.router)
    return TestClient(app)


def _set_token(monkeypatch, token: str) -> None:
    monkeypatch.setattr(routes, "get_settings",
                        lambda: Settings(operator_token=token, llm_provider="mock"))


# 用关键文件做载荷：鉴权通过后会被动作层拦（blocked），便于区分「401 鉴权失败」与「业务拒绝」
_PAYLOAD = {"action": "truncate_log", "params": {"path": "/etc/passwd"}, "dry_run": True}


class TestOperatorAuth:
    def test_missing_token_rejected(self, client, monkeypatch):
        _set_token(monkeypatch, "s3cret-token")
        r = client.post("/action/execute", json=_PAYLOAD)
        assert r.status_code == 401

    def test_wrong_token_rejected(self, client, monkeypatch):
        _set_token(monkeypatch, "s3cret-token")
        r = client.post("/action/execute", json=_PAYLOAD,
                        headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401

    def test_malformed_header_rejected(self, client, monkeypatch):
        _set_token(monkeypatch, "s3cret-token")
        r = client.post("/action/execute", json=_PAYLOAD,
                        headers={"Authorization": "s3cret-token"})  # 缺 Bearer 前缀
        assert r.status_code == 401

    def test_correct_token_passes(self, client, monkeypatch):
        _set_token(monkeypatch, "s3cret-token")
        r = client.post("/action/execute", json=_PAYLOAD,
                        headers={"Authorization": "Bearer s3cret-token"})
        assert r.status_code == 200
        # 鉴权已过：拿到业务响应（关键文件被动作层拦），而非 401
        assert r.json()["blocked"] is True

    def test_demo_mode_no_token_allows(self, client, monkeypatch):
        _set_token(monkeypatch, "")   # 未配置 token → 演示模式放行
        r = client.post("/action/execute", json=_PAYLOAD)
        assert r.status_code == 200
