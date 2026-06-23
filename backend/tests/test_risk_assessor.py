"""双层意图理解测试（P0-1）：规则粗筛 + LLM 风险研判 + 保守合并。

正面回答赛题灵魂命题「AI 推理不可控」：
- AI 能识别「规则漏网但语义危险」的委婉高危意图（如委婉删库），把风险升级；
- 但 AI **永远不能翻案放行** 规则已判危险的操作（保守合并取更严）；
- 正常运维不被误升级；
- mock / 无 LLM / 模型故障 → 退回纯规则，CI 不依赖网络、线上不误拦。
"""
from __future__ import annotations

import json

from app.core.orchestrator import Orchestrator
from app.guardrail.risk_assessor import Verdict, assess_risk
from app.llm.provider import LLMProvider


class _AssessLLM(LLMProvider):
    """安全研判桩：每次 chat 返回预置内容（dict 自动转 JSON，str 原样返回）。"""

    def __init__(self, payload):
        self.payload = (payload if isinstance(payload, str)
                        else json.dumps(payload, ensure_ascii=False))
        self.calls = 0

    def chat(self, messages, tools=None, model=None):
        self.calls += 1
        return {"role": "assistant", "content": self.payload, "tool_calls": None}


class _BoomLLM(LLMProvider):
    """模拟模型/网络故障：研判调用必抛异常。"""

    def chat(self, messages, tools=None, model=None):
        raise RuntimeError("network down")


# ----------------------------- 合并逻辑单元 -----------------------------

class TestAssessRiskMerge:
    def test_ai_upgrades_euphemistic_delete(self):
        """委婉删库：规则只判灰(放行)，AI 研判为 critical → 升级为拒绝。"""
        llm = _AssessLLM({"risk_level": "critical",
                          "suspected_intent": "疑似删除数据库数据目录",
                          "reasons": ["『没用的大家伙』疑指数据库/大数据文件", "『清理掉』即删除"],
                          "recommend": "deny"})
        a = assess_risk("把那个没用的大家伙清理掉", llm=llm)
        assert a.ai_used is True
        assert a.rule_verdict == Verdict.ALLOW       # 规则没看出危险
        assert a.ai_verdict == Verdict.DENY          # AI 看出来了
        assert a.final_verdict == Verdict.DENY
        assert a.blocked is True
        assert a.upgraded is True                     # 拿分点：AI 升级了规则判定
        assert a.suspected_intent

    def test_normal_op_not_upgraded(self):
        """正常运维（重启服务）：AI 判 low → 不误升级。"""
        llm = _AssessLLM({"risk_level": "low",
                          "suspected_intent": "重启 nginx 服务",
                          "reasons": ["常规服务重启，可逆"], "recommend": "allow"})
        a = assess_risk("帮我重启一下 nginx 服务", llm=llm)
        assert a.final_verdict == Verdict.ALLOW
        assert a.upgraded is False
        assert a.blocked is False

    def test_rules_cannot_be_overruled_by_ai(self):
        """命令级规则判黑(拒绝)时，即便 AI 说放行，也必须保持拒绝（LLM 不能翻案）。

        注：意图层 2026-06-11 起不再对破坏话术明文判黑（明文匹配可被 base64/小语种/GCG 绕开、
        对正常运维词误杀）。规则侧确定性的 DENY 来自**命令产物侧**的 防线2（realpath+AST+效果），
        混淆到这一步已被「编译掉」——这正是「明文匹配在产物侧才有牙」之处。本用例据此驱动 DENY。
        """
        llm = _AssessLLM({"risk_level": "low", "suspected_intent": "无害",
                          "reasons": ["看起来没问题"], "recommend": "allow"})
        a = assess_risk("帮我清理一下", command="rm -rf /", llm=llm)
        assert a.rule_verdict == Verdict.DENY         # 命令级护栏（防线2）判黑
        assert a.ai_verdict == Verdict.ALLOW
        assert a.final_verdict == Verdict.DENY        # 取更严：命令级护栏兜底，AI 不能翻案
        assert a.upgraded is False
        assert a.blocked is True

    def test_command_confirm_flows_into_baseline(self):
        """传入命令时，命令级护栏的『需确认』并入规则基线，AI 不降级。"""
        llm = _AssessLLM({"risk_level": "low", "reasons": [], "recommend": "allow"})
        a = assess_risk("重启服务", command="sudo systemctl restart nginx", llm=llm)
        assert a.rule_verdict == Verdict.CONFIRM      # PRIV-001 sudo → 需确认
        assert a.final_verdict == Verdict.CONFIRM     # AI allow 不能把它降回放行
        assert a.require_confirm is True

    def test_ai_medium_upgrades_to_confirm(self):
        """规则放行、AI 判 medium → 升级为『需确认』而非直接拒绝。"""
        llm = _AssessLLM({"risk_level": "medium", "suspected_intent": "删除单个大文件",
                          "reasons": ["可逆但需谨慎"], "recommend": "confirm"})
        a = assess_risk("把那个大文件清掉腾点地方", llm=llm)
        assert a.final_verdict == Verdict.CONFIRM
        assert a.upgraded is True
        assert a.blocked is False


# ----------------------------- 退化 / 鲁棒性 -----------------------------

class TestFallback:
    def test_no_llm_falls_back_to_rules(self):
        a = assess_risk("清理一下日志", llm=None)
        assert a.ai_used is False
        assert a.final_verdict == a.rule_verdict       # 纯规则
        assert a.blocked is False

    def test_llm_failure_falls_back_not_block(self):
        """模型故障：吞掉异常、退回规则，绝不因抖动而误拦正常运维。"""
        a = assess_risk("清理掉那个大文件", llm=_BoomLLM())
        assert a.ai_used is False
        assert a.final_verdict == a.rule_verdict
        assert a.blocked is False

    def test_unparseable_response_falls_back(self):
        a = assess_risk("清理缓存", llm=_AssessLLM("我无法以 JSON 回答，但这看起来很危险"))
        assert a.ai_used is False                       # 解析失败=未采信 AI

    def test_parses_json_in_code_fence(self):
        """模型用 ```json 包裹也能抠出来。"""
        fenced = "```json\n{\"risk_level\": \"medium\", \"recommend\": \"confirm\", \"reasons\": []}\n```"
        a = assess_risk("清理点东西", llm=_AssessLLM(fenced))
        assert a.ai_used is True
        assert a.ai_risk_level == "medium"

    def test_to_trace_has_two_columns(self):
        llm = _AssessLLM({"risk_level": "critical", "suspected_intent": "删库",
                          "reasons": ["x"], "recommend": "deny"})
        t = assess_risk("把那个老东西彻底干掉", llm=llm).to_trace()
        assert "rule_judgment" in t and "ai_judgment" in t   # 规则 vs AI 两栏
        assert t["final_verdict"] == Verdict.DENY
        assert t["upgraded_by_ai"] is True


# ----------------------------- orchestrator 集成 -----------------------------

class _StubMCP:
    async def openai_tools(self):
        return []

    async def call_tool(self, name, args):
        return {}


async def test_orchestrator_blocks_euphemistic_delete(tmp_path, monkeypatch):
    """编排器对委婉删库：AI 研判升级→拦截，且『双层意图研判』进 trace 可回放。"""
    monkeypatch.setattr("app.audit.store._db_path", lambda: str(tmp_path / "a.sqlite"))
    llm = _AssessLLM({"risk_level": "critical", "suspected_intent": "疑似删除数据库",
                      "reasons": ["委婉表述掩盖删库意图"], "recommend": "deny"})
    orch = Orchestrator(llm=llm, mcp=_StubMCP())
    result = await orch.chat("把那个没用的大家伙清理掉")

    assert result.blocked is True
    assert "AI 语义研判" in result.answer
    assert llm.calls == 1                               # 只做了研判，没进工具/作答轮
    two_layer = [s.detail for s in result.trace
                 if s.stage == "安全校验" and isinstance(s.detail, dict)
                 and s.detail.get("phase") == "双层意图研判"]
    assert two_layer and two_layer[0]["final_verdict"] == Verdict.DENY
    assert two_layer[0]["upgraded_by_ai"] is True


async def test_orchestrator_white_query_skips_assessor(tmp_path, monkeypatch):
    """只读查询：跳过 AI 研判（省一次往返），trace 不出现『双层意图研判』。"""
    monkeypatch.setattr("app.audit.store._db_path", lambda: str(tmp_path / "b.sqlite"))
    # 该桩对只读直接作答（无 tool_calls），用于验证主链路不触发研判层
    llm = _AssessLLM("magic-should-not-be-parsed")
    orch = Orchestrator(llm=llm, mcp=_StubMCP())
    result = await orch.chat("看看磁盘使用率")

    assert result.blocked is False
    assert not any(isinstance(s.detail, dict)
                   and s.detail.get("phase") == "双层意图研判"
                   for s in result.trace if s.stage == "安全校验")
