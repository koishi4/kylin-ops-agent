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

    # 受控动作鉴权（P0-4，最小版，刻意不做 RBAC/账号体系）。
    # operator_token 为空 → 演示模式：本机可信控制台，不强制鉴权（配合默认只监听 127.0.0.1）。
    # 生产/联网演示务必在 .env 设强随机 token；前端经 VITE_OPERATOR_TOKEN 注入同值。
    operator_token: str = ""
    # 后端默认只监听本机回环，避免受控动作端点暴露到外网（生产如需对外须显式改并配 token）。
    api_bind_host: str = "127.0.0.1"

    # MCP 工具投毒处置（P0-C）：扫描命中的可疑工具默认 fail-closed 不进 LLM 上下文。
    # high 无条件隔离；medium 默认隔离，置 true 才作为 operator override 降级为「需人工复核」放行。
    quarantine_allow_medium: bool = False

    # 执行账户（最小权限，非 root）
    exec_user: str = "opsagent"
    # 以 root 运行时是否拒绝启动（最小权限启动闸门，审查整改②）。
    # 默认仅告警不阻断（避免误伤官方虚机/容器里的 root 演示）；隔离/生产环境置 true 强制拒绝。
    refuse_root: bool = False

    # 执行沙箱（护栏放行后真正落地命令时套的资源/权限保险丝，P4-3）。
    # 机制按可用性自动降级：bwrap/nsjail → 纯 rlimit 兜底（见 core/sandbox.py）。
    sandbox_enabled: bool = True        # 总开关；关掉则真正执行退回无限额（仅排障用）
    sandbox_cpu_seconds: int = 5        # RLIMIT_CPU：单命令 CPU 秒上限（防自旋）
    sandbox_mem_mb: int = 256           # RLIMIT_AS：地址空间≈内存上限（防吃光内存）
    sandbox_max_procs: int = 64         # RLIMIT_NPROC：进程/线程数上限（防 fork 炸弹）
    sandbox_fsize_mb: int = 16          # RLIMIT_FSIZE：可写文件大小上限（防写爆磁盘）

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )


@lru_cache
def get_settings() -> Settings:
    """单例，避免重复解析 .env。测试可通过 get_settings.cache_clear() 重置。"""
    return Settings()
