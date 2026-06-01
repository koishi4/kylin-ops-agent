"""编排器 —— 评分②「自然语言交互准确性」的落点。

闭环：自然语言 → LLM 选 MCP 工具 → 执行工具 → LLM 据结果作答。
同时产出一个轻量 trace（接收指令 / 感知环境 / 推理决策 / 安全校验 / 执行结果），
为第 3 周「思维链溯源」打基础；本周护栏尚未接入，READONLY 工具自动放行。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from app.llm.provider import LLMProvider
from app.mcp_server.client import MCPClient
from app.mcp_server.tools import REGISTRY

SYSTEM_PROMPT = (
    "你是部署在麒麟操作系统上的智能运维助手。"
    "用户用自然语言描述运维需求，你应优先调用提供的工具获取真实系统数据，"
    "再用简洁中文给出结论与建议。没有合适工具时如实说明，不要编造系统数据。"
)

MAX_ROUNDS = 5  # 防止工具调用死循环


@dataclass
class TraceStep:
    stage: str          # 接收指令 / 感知环境 / 推理决策 / 安全校验 / 执行结果
    detail: Any


@dataclass
class ChatResult:
    answer: str
    trace: list[TraceStep] = field(default_factory=list)
    tool_calls: list[dict] = field(default_factory=list)  # 本轮实际调用的工具与参数


class Orchestrator:
    def __init__(self, llm: LLMProvider, mcp: MCPClient) -> None:
        self.llm = llm
        self.mcp = mcp

    async def chat(self, user_input: str) -> ChatResult:
        trace: list[TraceStep] = [TraceStep("接收指令", user_input)]
        tool_calls_log: list[dict] = []

        tools = await self.mcp.openai_tools()
        trace.append(TraceStep("感知环境", {"available_tools": [t["function"]["name"] for t in tools]}))

        messages: list[dict] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_input},
        ]

        for _ in range(MAX_ROUNDS):
            msg = await self.llm.achat(messages, tools)
            calls = msg.get("tool_calls") or []

            if not calls:
                answer = msg.get("content") or "(模型未返回内容)"
                trace.append(TraceStep("推理决策", "直接作答，无需调用工具"))
                trace.append(TraceStep("执行结果", answer))
                return ChatResult(answer=answer, trace=trace, tool_calls=tool_calls_log)

            # 模型决定调用工具
            messages.append(_assistant_msg_for_history(msg, calls))
            for call in calls:
                name = call["function"]["name"]
                try:
                    args = json.loads(call["function"].get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                trace.append(TraceStep("推理决策", {"tool": name, "arguments": args}))

                # —— 安全校验段（第 1 周占位）——
                # 本周工具均为 READONLY，自动放行；MUTATING/PRIVILEGED 将在此接入护栏。
                spec = REGISTRY.get(name)
                level = spec.level if spec else "UNKNOWN"
                trace.append(TraceStep("安全校验",
                                       {"tool": name, "level": level, "decision": "auto_approve (READONLY)"}))

                result = await self.mcp.call_tool(name, args)
                tool_calls_log.append({"tool": name, "arguments": args, "result": result})
                trace.append(TraceStep("执行结果", {"tool": name, "result": result}))

                messages.append({
                    "role": "tool",
                    "tool_call_id": call["id"],
                    "content": json.dumps(result, ensure_ascii=False),
                })
            # 带着工具结果再问一轮，让模型总结

        # 轮次用尽仍未给出最终答复
        trace.append(TraceStep("执行结果", "达到最大工具调用轮次，未能收敛"))
        return ChatResult(answer="处理超出最大轮次，请简化需求后重试。",
                          trace=trace, tool_calls=tool_calls_log)


def _assistant_msg_for_history(msg: dict, calls: list[dict]) -> dict:
    """构造回写进 messages 的 assistant 消息，保留 tool_calls 以满足 OpenAI 协议。"""
    return {
        "role": "assistant",
        "content": msg.get("content"),
        "tool_calls": [
            {
                "id": c["id"],
                "type": "function",
                "function": {
                    "name": c["function"]["name"],
                    "arguments": c["function"].get("arguments") or "{}",
                },
            }
            for c in calls
        ],
    }
