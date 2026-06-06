"""LLM 抽象层：deepseek（云端）/ ollama（本地 Qwen3）/ mock（离线测试）三模式。
通过 LLM_PROVIDER 切换。开发录屏用 deepseek，答辩断网用 ollama，CI/测试用 mock。
这是项目「国产化 + 可离线」创新点的代码落点。

统一接口 chat(messages, tools) -> dict（OpenAI message 结构，含可能的 tool_calls）。
提供 async achat 包装，供 FastAPI 异步路由调用，避免阻塞事件循环。
"""
from __future__ import annotations

import asyncio
import json
from abc import ABC, abstractmethod

from openai import OpenAI

from app.config import get_settings


class LLMProvider(ABC):
    """统一接口：给定对话与可用工具，返回模型决策（含工具调用）。"""

    @abstractmethod
    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        ...

    async def achat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        """同步 SDK 放到线程池执行，避免阻塞 FastAPI 事件循环。"""
        return await asyncio.to_thread(self.chat, messages, tools)


class _OpenAICompatProvider(LLMProvider):
    """DeepSeek 与 Ollama 都走 OpenAI 兼容接口，逻辑相同，差异仅在 base_url/key/model。"""

    def __init__(self, *, api_key: str, base_url: str, model: str) -> None:
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=tools or None,
            temperature=0.0,
        )
        return resp.choices[0].message.model_dump()


class DeepSeekProvider(_OpenAICompatProvider):
    """云端 DeepSeek。开发与录屏默认。"""

    def __init__(self) -> None:
        s = get_settings()
        if not s.deepseek_api_key:
            raise RuntimeError(
                "未配置 DEEPSEEK_API_KEY。请在 backend/.env 填写，"
                "或设 LLM_PROVIDER=ollama / mock。"
            )
        super().__init__(
            api_key=s.deepseek_api_key,
            base_url=s.deepseek_base_url,
            model=s.deepseek_model,
        )


class OllamaProvider(_OpenAICompatProvider):
    """本地 Ollama 跑 Qwen3-8B。答辩 / 离线演示用，国产化加分。"""

    def __init__(self) -> None:
        s = get_settings()
        super().__init__(
            api_key="ollama",  # 占位，本地端点不校验
            base_url=s.ollama_base_url,
            model=s.ollama_model,
        )


class MockProvider(LLMProvider):
    """离线 Mock：不连任何模型，用关键词规则模拟「选工具」。

    目的：无 key / 无网 / CI 也能跑通整条闭环与测试，保证项目永远可演示。
    规则极简，仅覆盖第 1 周的 3 个只读工具；真实推理交给 deepseek/ollama。
    """

    KEYWORD_TOOL = [
        (("磁盘", "硬盘", "空间", "disk", "df"), "disk_usage", {}),
        (("内存", "memory", "ram", "swap"), "memory_info", {}),
        (("进程", "cpu", "process", "占用", "top"), "list_processes", {}),
        # 内核漏洞遏制三件套也接入确定性路由，保证离线 mock 下「评委模式」演示可走通（P1-6）
        (("漏洞", "cve", "情报", "advisory"), "query_vuln_intel", {}),
        (("内核", "posture", "姿态", "dirty frag", "提权", "模块"), "kernel_posture", {}),
    ]

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        # 若上一条是工具结果，则进入「总结」回合，直接给自然语言答复
        if messages and messages[-1].get("role") == "tool":
            return {"role": "assistant",
                    "content": f"[mock] 已根据工具返回整理结果：{messages[-1].get('content', '')[:300]}",
                    "tool_calls": None}

        user_text = next(
            (m.get("content", "") for m in reversed(messages) if m.get("role") == "user"),
            "",
        ).lower()
        available = {t["function"]["name"] for t in (tools or [])}
        for keywords, tool_name, args in self.KEYWORD_TOOL:
            if tool_name in available and any(k in user_text for k in keywords):
                return {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": f"mock_{tool_name}",
                            "type": "function",
                            "function": {"name": tool_name, "arguments": json.dumps(args)},
                        }
                    ],
                }
        return {"role": "assistant",
                "content": "[mock] 未匹配到可用工具，请描述磁盘/内存/进程相关的运维需求。",
                "tool_calls": None}


def get_llm() -> LLMProvider:
    provider = get_settings().llm_provider.lower()
    if provider == "ollama":
        return OllamaProvider()
    if provider == "mock":
        return MockProvider()
    return DeepSeekProvider()
