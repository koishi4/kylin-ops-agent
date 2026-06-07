"""全局配置：用 pydantic-settings 从环境变量 / .env 读取。
集中管理 LLM 切换、审计库、执行账户等，避免在各处散落 os.getenv。
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

# 审计哈希链密钥默认值（仅开发/演示用）。生产须经环境变量覆盖；启动守卫会据此判定是否仍是默认。
_DEFAULT_AUDIT_HMAC_KEY = "kylin-ops-agent-audit-chain-v1"
# 视为「本机回环 / 演示模式」的绑定地址；其余地址视为联网/生产，触发失败安全前置校验。
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


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
    audit_hmac_key: str = _DEFAULT_AUDIT_HMAC_KEY

    # 受控动作鉴权（P0-4，最小版，刻意不做 RBAC/账号体系）。
    # operator_token 为空 → 演示模式：本机可信控制台，不强制鉴权（配合默认只监听 127.0.0.1）。
    # 生产/联网演示务必在 .env 设强随机 token；前端经 VITE_OPERATOR_TOKEN 注入同值。
    operator_token: str = ""
    # 后端默认只监听本机回环，避免受控动作端点暴露到外网（生产如需对外须显式改并配 token）。
    api_bind_host: str = "127.0.0.1"

    # MCP 工具投毒处置（P0-C）：扫描命中的可疑工具默认 fail-closed 不进 LLM 上下文。
    # high 无条件隔离；medium 默认隔离，置 true 才作为 operator override 降级为「需人工复核」放行。
    quarantine_allow_medium: bool = False

    # MCP 工具 schema 指纹基线（P2：rug-pull / 工具变脸检测）。TOFU：首次扫描通过即锚定，
    # 之后工具 description/schema 被悄改→指纹变→自动隔离；合法升级经 /guardrail/tool-scan/pin 重锚。
    tool_baseline_path: str = "./tool_baseline.json"

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

    @property
    def is_loopback_bind(self) -> bool:
        """绑定地址是否为本机回环（演示模式）。非回环视为联网/生产。"""
        return self.api_bind_host in _LOOPBACK_HOSTS

    def production_config_errors(self) -> list[str]:
        """失败安全启动守卫（P0-D）：非回环绑定（联网/生产）下，弱默认配置一律拒绝启动。

        本机 demo（127.0.0.1 + 空 token + 默认密钥）返回空列表，保持顺滑不变。
        """
        if self.is_loopback_bind:
            return []
        errs: list[str] = []
        if not self.operator_token:
            errs.append(
                f"API_BIND_HOST={self.api_bind_host} 非回环（联网/生产）但 OPERATOR_TOKEN 为空："
                "受控动作端点将无鉴权暴露，拒绝启动；请在 .env 配置强随机 OPERATOR_TOKEN。")
        if self.audit_hmac_key == _DEFAULT_AUDIT_HMAC_KEY:
            errs.append(
                f"API_BIND_HOST={self.api_bind_host} 非回环（联网/生产）但 AUDIT_HMAC_KEY 仍是默认值："
                "审计哈希链可被伪造，拒绝启动；请在 .env 配置独立的 AUDIT_HMAC_KEY。")
        return errs


@lru_cache
def get_settings() -> Settings:
    """单例，避免重复解析 .env。测试可通过 get_settings.cache_clear() 重置。"""
    return Settings()
