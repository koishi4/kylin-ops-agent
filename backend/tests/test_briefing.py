"""运维简报（日报/周报）测试：聚合口径、Markdown 渲染、AI 导语降级、活动统计。

重点验证三条纪律：
1. 简报是**只读聚合**——不触发任何动作/执行路径；
2. **确定性优先**——不传 LLM 也能产出完整报告（离线/CI 可跑）；
3. AI 导语**只升不坏**——LLM 异常/返回空时自动降级为确定性导语，绝不丢报告。
"""
from __future__ import annotations

import time

import pytest
from app.audit import store
from app.core import briefing


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """把审计库指向临时文件，避免污染真实 audit.sqlite。"""
    db = tmp_path / "audit_test.sqlite"
    monkeypatch.setattr(store, "_db_path", lambda: str(db))
    store.init_db()
    return db


def _fake_diagnose(topic, path="/", **_):
    """确定性诊断桩：一项 warning 问题 + 建议，避免真实全盘扫描拖慢测试。"""
    assert topic == "all"
    return {
        "ok": True, "topic": "all", "summary": "共 1 项需关注。",
        "reports": [
            {"topic": "disk", "severity": "warning",
             "findings": ["挂载点 / 使用率 91%。"],
             "suggestions": ["清理 /var/log 下的旧日志（约可释放 1.2GB）"]},
            {"topic": "zombie", "severity": "ok", "findings": [], "suggestions": []},
        ],
    }


def _fake_posture(live=False):
    """确定性态势桩：命中一条情报。"""
    return {
        "kernel": "6.6.0-test", "severity": "warning", "intel_source": "seed",
        "matches": [
            {"cve": "CVE-2099-0001", "status": "affected",
             "mitigations": ["升级内核至 6.6.1+"]},
            {"cve": "CVE-2099-0002", "status": "not_affected", "mitigations": []},
        ],
    }


@pytest.fixture
def stubbed(monkeypatch, tmp_db):
    """给 briefing 模块打上确定性数据源桩（诊断/态势），审计库用临时库。"""
    monkeypatch.setattr(briefing.diagnosis, "diagnose", _fake_diagnose)
    monkeypatch.setattr(briefing.posture, "check_posture", _fake_posture)
    return tmp_db


class TestActivityStats:
    def test_window_and_counters(self, tmp_db):
        now = time.time()
        steps = [{"stage": "接收指令", "detail": "x"}]
        store.save_trace("t-in-1", "查磁盘", "42%", steps, intent="white")
        store.save_trace("t-in-2", "rm -rf /", "已拦截", steps, intent="black", blocked=True)
        store.save_trace("t-act", "[动作] truncate_log", "ok", steps, intent="action")
        st = store.activity_stats(now - 60)
        assert st["total"] == 3
        assert st["blocked"] == 1 and st["actions"] == 1
        assert st["by_intent"]["white"] == 1
        # 拦截样例带 trace_id，可回放
        assert st["blocked_samples"][0]["trace_id"] == "t-in-2"

    def test_window_excludes_old(self, tmp_db):
        store.save_trace("t-old", "旧会话", "a", [{"stage": "接收指令", "detail": "x"}])
        # 窗口起点设在未来 → 一条都不该统计进来
        st = store.activity_stats(time.time() + 3600)
        assert st["total"] == 0 and st["blocked_samples"] == []


class TestGenerateBriefing:
    def test_deterministic_full_report(self, stubbed):
        """不传 LLM：完整结构 + Markdown 六节齐全，导语为确定性模板。"""
        b = briefing.generate_briefing("daily")
        assert b["ok"] is True and b["period_label"] == "运维日报"
        assert b["ai_overview_used"] is False
        # 聚合口径：诊断问题/建议、态势命中（not_affected 被过滤）、活动统计
        assert b["diagnosis"]["issues"][0]["topic"] == "disk"
        assert [h["cve"] for h in b["posture"]["hits"]] == ["CVE-2099-0001"]
        md = b["markdown"]
        for section in ("一、导语", "二、系统概况", "三、健康诊断",
                        "四、安全态势", "五、运维活动", "六、待办与建议"):
            assert section in md
        # 待办含诊断建议与情报缓解，且是复选框格式
        assert "- [ ] 清理 /var/log 下的旧日志" in md
        assert "- [ ] 升级内核至 6.6.1+" in md

    def test_weekly_label_and_unknown_period(self, stubbed):
        assert briefing.generate_briefing("weekly")["period_label"] == "运维周报"
        bad = briefing.generate_briefing("monthly")
        assert bad["ok"] is False and "monthly" in bad["error"]

    def test_ai_overview_used_and_grounded_by_prompt(self, stubbed):
        """传 LLM：导语来自模型输出；prompt 无工具（结构上不给工具调用面）。"""
        seen = {}

        class FakeLLM:
            def chat(self, messages, tools=None, model=None):
                seen["tools"] = tools
                seen["system"] = messages[0]["content"]
                return {"role": "assistant", "content": "系统总体平稳，磁盘偏高需关注。"}

        b = briefing.generate_briefing("daily", llm=FakeLLM())
        assert b["ai_overview_used"] is True
        assert b["overview"] == "系统总体平稳，磁盘偏高需关注。"
        assert seen["tools"] is None            # 导语撰写绝不带工具
        assert "禁止编造" in seen["system"]      # 数据约束写进角色提示

    @pytest.mark.parametrize("bad_llm", [
        # 抛异常 / 返回空内容，都必须降级为确定性导语而非丢报告
        type("Boom", (), {"chat": lambda self, m, t=None, model=None:
             (_ for _ in ()).throw(RuntimeError("网络抖动"))})(),
        type("Empty", (), {"chat": lambda self, m, t=None, model=None:
             {"role": "assistant", "content": "  "}})(),
    ])
    def test_ai_failure_degrades_safely(self, stubbed, bad_llm):
        b = briefing.generate_briefing("daily", llm=bad_llm)
        assert b["ok"] is True and b["ai_overview_used"] is False
        assert "护栏拦截" in b["overview"]  # 确定性导语陈述活动统计

    def test_activity_flows_into_markdown(self, stubbed):
        """审计窗口统计进入「运维活动」一节，拦截样例带可回放 trace_id 片段。"""
        store.save_trace("t-blocked-xyz", "把数据库目录清了",
                         "已拦截", [{"stage": "接收指令", "detail": "x"}],
                         intent="gray", blocked=True)
        md = briefing.generate_briefing("daily")["markdown"]
        assert "护栏拦截 1 次" in md
        assert "t-blocked-xyz"[:12] in md


class TestBriefingAPI:
    def test_endpoint_returns_markdown_and_audits(self, stubbed, monkeypatch):
        """GET /briefing：返回完整简报 + 落一条 intent=briefing 的审计 trace。"""
        from app.main import app
        from fastapi.testclient import TestClient

        with TestClient(app) as client:
            r = client.get("/briefing", params={"period": "daily"})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True and "markdown" in data
        # 简报生成本身留痕，可按 trace_id 回放
        t = store.get_trace(data["trace_id"])
        assert t is not None and t["intent"] == "briefing"

    def test_endpoint_rejects_unknown_period(self, stubbed):
        from app.main import app
        from fastapi.testclient import TestClient

        with TestClient(app) as client:
            r = client.get("/briefing", params={"period": "monthly"})
        assert r.status_code == 422  # Literal 校验在入口即拒绝
