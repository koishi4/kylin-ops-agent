"""LLM 抽象层：deepseek（云端）/ ollama（本地 Qwen3）双模式。
通过环境变量 LLM_PROVIDER 切换。开发录屏用 deepseek，答辩断网用 ollama。
这是项目"国产化 + 可离线"创新点的代码落点。
"""
from __future__ import annotations
import os
from abc import ABC, abstractmethod
from openai import OpenAI


class LLMProvider(ABC):
    """统一接口：给定对话与可用工具，返回模型决策（含工具调用）。"""

    @abstractmethod
    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        ...


class DeepSeekProvider(LLMProvider):
    """云端 DeepSeek，OpenAI 兼容接口。开发默认。"""

    def __init__(self) -> None:
        self.client = OpenAI(
            api_key=os.environ["DEEPSEEK_API_KEY"],
            base_url="https://api.deepseek.com",
        )
        self.model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        resp = self.client.chat.completions.create(
            model=self.model, messages=messages, tools=tools, temperature=0.0,
        )
        return resp.choices[0].message.model_dump()


class OllamaProvider(LLMProvider):
    """本地 Ollama 跑 Qwen3-8B，OpenAI 兼容端点。答辩/离线用。
    4070 Laptop 8GB 显存可流畅跑 qwen3:8b。
    """

    def __init__(self) -> None:
        self.client = OpenAI(
            api_key="ollama",  # 占位
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        )
        self.model = os.getenv("OLLAMA_MODEL", "qwen3:8b")

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        resp = self.client.chat.completions.create(
            model=self.model, messages=messages, tools=tools, temperature=0.0,
        )
        return resp.choices[0].message.model_dump()


def get_llm() -> LLMProvider:
    provider = os.getenv("LLM_PROVIDER", "deepseek").lower()
    if provider == "ollama":
        return OllamaProvider()
    return DeepSeekProvider()
