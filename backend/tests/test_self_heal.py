"""工具调用失败自愈（IMPROVEMENTS P2-2）的测试。

价值：提升「自然语言交互准确性」鲁棒性——模型偶尔会臆造工具名、给坏参数，
或工具临时报错。编排器把错误结构化回喂、让模型换策略重试（有限次），
而不是一调用失败就崩或空转耗尽轮次。

用脚本化 provider（按序吐出预设的模型回复）+ 假 MCP（可配置抛异常/返回失败/正常），
确定性地复现四类失败并断言「先失败 → 自愈重试 → 收敛」，以及超预算优雅收场。
"""
from __future__ import annotations

import json

from app.core.orchestrator import MAX_TOOL_RETRIES, Orchestrator
from app.llm.provider import MockProvider


# ScriptedProvider 继承 MockProvider：使 orchestrator 的灰意图研判走规则回退（不消费脚本），
# 脚本只在工具调用循环里被 achat 逐条取用。
class ScriptedProvider(MockProvider):
    def __init__(self, script):
        self._script = list(script)
        self.calls = 0

    def chat(self, messages, tools=None, model=None):
        self.calls += 1
        if self._script:
            return self._script.pop(0)
        return {"role": "assistant", "content": "[scripted] 脚本耗尽", "tool_calls": None}


class FakeMCP:
    """假 MCP：openai_tools 暴露给定工具名；call_tool 按 behavior 决定抛异常/返回失败/正常。"""

    def __init__(self, tools, behavior=None):
        self._tools = tools
        self._behavior = behavior or {}

    async def openai_tools(self):
        return [
            {"type": "function",
             "function": {"name": n, "description": n,
                          "parameters": {"type": "object", "properties": {}}}}
            for n in self._tools
        ]

    async def call_tool(self, name, args):
        b = self._behavior.get(name)
        if b == "raise":
            raise RuntimeError("模拟工具内部异常")
        return b if b is not None else {"ok": True, "echo": args}


def _tool_call(name, args="{}", call_id="c1"):
    return {"role": "assistant", "content": None,
            "tool_calls": [{"id": call_id, "type": "function",
                            "function": {"name": name, "arguments": args}}]}


def _final(text):
    return {"role": "assistant", "content": text, "tool_calls": None}


def _self_heal_steps(result):
    return [s.detail for s in result.trace
            if isinstance(s.detail, dict) and "self_heal" in s.detail]


USER = "查看磁盘使用情况"  # 只读类，确保不被入口护栏拦下


class TestSelfHealRecovers:
    """四类失败各自能「回喂错误 → 模型换策略 → 收敛到正确答复」。"""

    async def test_unknown_tool_name_recovers(self):
        # 第一次臆造了不存在的工具名 → 第二次改用正确工具 → 收敛
        llm = ScriptedProvider([
            _tool_call("disk_usagee"),     # 拼错的工具名
            _tool_call("disk_usage"),
            _final("磁盘使用率 70%"),
        ])
        mcp = FakeMCP(["disk_usage"], {"disk_usage": {"ok": True, "percent": 70}})
        result = await Orchestrator(llm, mcp).chat(USER)

        assert result.answer == "磁盘使用率 70%"
        assert not result.blocked
        heals = _self_heal_steps(result)
        assert any("不存在" in h["self_heal"]["reason"] for h in heals)
        # 最终真正成功调用了正确工具
        assert any(c["tool"] == "disk_usage" for c in result.tool_calls)

    async def test_bad_json_args_recovers(self):
        llm = ScriptedProvider([
            _tool_call("disk_usage", args="{not valid json"),
            _tool_call("disk_usage", args="{}"),
            _final("已取得磁盘数据"),
        ])
        mcp = FakeMCP(["disk_usage"], {"disk_usage": {"ok": True}})
        result = await Orchestrator(llm, mcp).chat(USER)

        assert result.answer == "已取得磁盘数据"
        heals = _self_heal_steps(result)
        assert any("JSON" in h["self_heal"]["reason"] for h in heals)

    async def test_tool_exception_recovers(self):
        # disk_usage 抛异常 → 改用 memory_info → 收敛（异常不致整条对话崩）
        llm = ScriptedProvider([
            _tool_call("disk_usage"),
            _tool_call("memory_info"),
            _final("已改用内存工具完成"),
        ])
        mcp = FakeMCP(["disk_usage", "memory_info"],
                      {"disk_usage": "raise", "memory_info": {"ok": True}})
        result = await Orchestrator(llm, mcp).chat(USER)

        assert result.answer == "已改用内存工具完成"
        heals = _self_heal_steps(result)
        assert any("异常" in h["self_heal"]["reason"] for h in heals)

    async def test_tool_error_result_recovers(self):
        # 工具返回 ok=False/error → 回喂错误原因 → 模型换工具 → 收敛
        llm = ScriptedProvider([
            _tool_call("disk_usage"),
            _tool_call("memory_info"),
            _final("已规避错误并完成"),
        ])
        mcp = FakeMCP(["disk_usage", "memory_info"],
                      {"disk_usage": {"ok": False, "error": "路径不存在"},
                       "memory_info": {"ok": True}})
        result = await Orchestrator(llm, mcp).chat(USER)

        assert result.answer == "已规避错误并完成"
        heals = _self_heal_steps(result)
        assert any("路径不存在" in h["self_heal"]["reason"] for h in heals)


class TestSelfHealBudget:
    async def test_gives_up_after_retry_budget(self):
        # 连续臆造工具名，超出重试预算后优雅收场，而非空转耗尽 MAX_ROUNDS
        llm = ScriptedProvider([_tool_call(f"ghost_{i}") for i in range(MAX_TOOL_RETRIES + 3)])
        mcp = FakeMCP(["disk_usage"])
        result = await Orchestrator(llm, mcp).chat(USER)

        assert "停止自动重试" in result.answer
        assert not result.blocked
        # 给出失败计数（超过预算）
        budget_step = next(s.detail for s in result.trace
                           if isinstance(s.detail, dict) and "tool_failures" in s.detail)
        assert budget_step["tool_failures"] > MAX_TOOL_RETRIES
        # 没有把所有轮次都耗光（自愈在预算耗尽时就停了）
        assert llm.calls <= MAX_TOOL_RETRIES + 1


class TestNoRegression:
    async def test_success_path_has_no_self_heal(self):
        # 一次成功调用 + 收尾，不应产生任何自愈记录（不影响正常路径）
        llm = ScriptedProvider([_tool_call("disk_usage"), _final("一切正常")])
        mcp = FakeMCP(["disk_usage"], {"disk_usage": {"ok": True, "percent": 30}})
        result = await Orchestrator(llm, mcp).chat(USER)

        assert result.answer == "一切正常"
        assert _self_heal_steps(result) == []
        assert any(c["tool"] == "disk_usage" for c in result.tool_calls)
