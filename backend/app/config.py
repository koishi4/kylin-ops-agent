"""全局配置：用 pydantic-settings 从环境变量 / .env 读取。
集中管理 LLM 切换、审计库、执行账户等，避免在各处散落 os.getenv。
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # 大模型切换：deepseek（云端，开发默认）/ ollama（本地，答辩用）/ mock（离线测试）
    llm_provider: str = "deepseek"

    # DeepSeek 云端（OpenAI 兼容）
    deepseek_api_key: str = ""
    deepseek_model: str = "deepseek-chat"
    deepseek_base_url: str = "https://api.deepseek.com"

    # 本地 Ollama（Qwen3-8B，OpenAI 兼容端点）
    ollama_base_url: str = "http://localhost:11434/v1"
    ollama_model: str = "qwen3:8b"

    # 审计库（第 3 周接入思维链溯源）
    audit_db: str = "./audit.sqlite"
    # 审计哈希链密钥（防篡改）：用 HMAC 串联每条 step，无密钥无法重算合法哈希。
    # 生产应经环境变量注入并妥善保管（KMS/密钥库）；此默认值仅供开发与演示。
    audit_hmac_key: str = "kylin-ops-agent-audit-chain-v1"

    # 执行账户（最小权限，非 root）
    exec_user: str = "opsagent"

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )


@lru_cache
def get_settings() -> Settings:
    """单例，避免重复解析 .env。测试可通过 get_settings.cache_clear() 重置。"""
    return Settings()
