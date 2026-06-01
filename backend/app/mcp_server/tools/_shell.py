"""外部命令统一封装。底线：shell=False + 参数列表，绝不字符串拼接 + shell=True。
所有需要调用 lsof/ss/journalctl/df 的工具都必须经过 run_cmd，禁止裸 subprocess。
"""
from __future__ import annotations

import subprocess


def run_cmd(args: list[str], timeout: int = 10) -> dict:
    """执行外部命令并返回结构化结果。

    Args:
        args: 已拆分的参数列表，如 ["df", "-h", "/"]
        timeout: 超时秒数
    Returns:
        {"ok": bool, "stdout": str, "stderr": str} 或 {"ok": False, "error": str}
    """
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
