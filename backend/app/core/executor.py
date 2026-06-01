"""执行器 —— 所有「LLM 生成 / 可变」命令的唯一出口（CLAUDE.md §6 硬纪律）。

任何要落到系统上的命令都必须经此函数，执行前强制过护栏；护栏不放行就绝不执行。
这样即使别处逻辑有漏洞，护栏仍是最后一道闸门。

边界说明：
- 本执行器面向「LLM 生成 / 自由形态」命令（可能危险），执行前必经 guardrail。
- MCP 只读工具里的固定参数系统探针（df/ss/lsof，见 tools/_shell.run_cmd）属只读采集，
  参数写死、不接受 LLM 自由拼接，不走本执行器；二者职责不同。
"""
from __future__ import annotations

import shlex

from app.guardrail.engine import GuardResult, check_command
from app.mcp_server.tools._shell import run_cmd


def execute(
    cmd: str,
    *,
    authorized: bool = False,
    confirmed: bool = False,
    dry_run: bool = False,
    timeout: int = 10,
) -> dict:
    """护栏校验 + （放行后）执行命令。

    Args:
        cmd: 候选命令字符串
        authorized: 是否对 HIGH 风险显式授权（防线4）
        confirmed: 用户是否已二次确认（CONFIRM 类）
        dry_run: 仅做护栏校验、不真正执行（演示/测试用）
        timeout: 执行超时秒数
    Returns:
        统一结构 dict：executed / blocked / guard(护栏裁决) / 以及执行输出或拦截原因
    """
    guard: GuardResult = check_command(cmd, authorized=authorized, confirmed=confirmed)

    if not guard.allowed:
        # 被拦截：绝不执行，向调用方/用户解释原因（写入审计的「安全校验」段）
        return {
            "executed": False,
            "blocked": True,
            "require_confirm": guard.require_confirm,
            "reason": guard.reason,
            "guard": guard.to_dict(),
        }

    if dry_run:
        return {
            "executed": False,
            "blocked": False,
            "dry_run": True,
            "reason": "护栏放行（dry_run，未真正执行）",
            "guard": guard.to_dict(),
        }

    # 护栏放行后才执行；shell=False + shlex 拆分，杜绝 shell 元字符二次解释
    try:
        args = shlex.split(cmd)
    except ValueError as e:
        return {"executed": False, "blocked": False, "error": f"命令解析失败：{e}",
                "guard": guard.to_dict()}
    if not args:
        return {"executed": False, "blocked": False, "error": "空命令",
                "guard": guard.to_dict()}

    result = run_cmd(args, timeout=timeout)
    return {"executed": True, "blocked": False, "guard": guard.to_dict(), **result}
