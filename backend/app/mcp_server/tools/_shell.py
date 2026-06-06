"""外部命令统一封装。底线：shell=False + 参数列表，绝不字符串拼接 + shell=True。
所有需要调用 lsof/ss/journalctl/df 的工具都必须经过 run_cmd，禁止裸 subprocess。
"""
from __future__ import annotations

import subprocess


def run_cmd(args: list[str], timeout: int = 10, sandbox: bool = False) -> dict:
    """执行外部命令并返回结构化结果。

    Args:
        args: 已拆分的参数列表，如 ["df", "-h", "/"]
        timeout: 超时秒数
        sandbox: 是否套轻量沙箱（资源/权限限额，护栏放行后真正落地命令时用，P4-3）。
                 只读固定探针（df/ss/lsof）默认不套，保持零开销。
    Returns:
        {"ok": bool, "stdout": str, "stderr": str} 或 {"ok": False, "error": str}；
        走沙箱时额外带 sandbox_killed / limit_hit / sandbox 字段。
    """
    if sandbox:
        # 延迟导入：只在真正需要落地危险命令时才拉起沙箱依赖，保持只读工具轻量。
        from app.config import get_settings
        from app.core.sandbox import SandboxLimits, run_sandboxed

        st = get_settings()
        if st.sandbox_enabled:
            return run_sandboxed(args, limits=SandboxLimits.from_settings(st),
                                 timeout=timeout)
        # 沙箱被配置关闭（仅排障）→ 落回普通执行
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, shell=False
        )
        return {"ok": r.returncode == 0, "stdout": r.stdout, "stderr": r.stderr}
    except FileNotFoundError:
        return {"ok": False, "error": f"command not found: {args[0]}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout after {timeout}s"}
    except Exception as e:  # 工具绝不向 Agent 抛异常，统一返回结构化错误
        return {"ok": False, "error": str(e)}
