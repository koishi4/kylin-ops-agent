"""执行器 —— 所有「LLM 生成 / 可变」命令的唯一出口（CLAUDE.md §6 硬纪律）。

任何要落到系统上的命令都必须经此函数，执行前强制过护栏；护栏不放行就绝不执行。
这样即使别处逻辑有漏洞，护栏仍是最后一道闸门。

两个入口（P0-A.4 argv 原生化）：
- `execute(cmd: str)`：自由形态字符串入口（兼容老调用方 / 测试 / LLM 自由命令）。
  护栏在**原始字符串**上裁决；放行后 `shlex.split` 拆成 argv 执行。字符串里若含解释器+内联代码
  等结构，靠 P0-A 的命令护栏（规则库 + AST）拦死。
- `execute_argv(argv: list[str])`：**结构化入口（受控调用方首选，如 core/actions.py）**。
  argv 是权威执行对象，护栏在 `shlex.join(argv)` 上裁决——因 `shlex.split(shlex.join(x)) == x`
  对良构 argv 恒等，**「所审即所执」可证**：不存在「护栏看到的字符串」与「真正执行的 argv」
  因再解析而分叉的歧义。这是 GPT 第二轮 review 提的「executor 改 argv 原生接口」的落地：
  受控变更路径（唯一真实生产路径）不再把命令当「字符串再拆分」，从源头消除拼接/再解析面。

边界说明：
- 本执行器面向「LLM 生成 / 自由形态」命令（可能危险），执行前必经 guardrail。
- MCP 只读工具里的固定参数系统探针（df/ss/lsof，见 tools/_shell.run_cmd）属只读采集，
  参数写死、不接受 LLM 自由拼接，不走本执行器；二者职责不同。
"""
from __future__ import annotations

import shlex

from app.guardrail.engine import GuardResult, check_command
from app.guardrail.privilege import check_privilege
from app.mcp_server.tools._shell import run_cmd


def execute(
    cmd: str,
    *,
    authorized: bool = False,
    confirmed: bool = False,
    dry_run: bool = False,
    timeout: int = 10,
) -> dict:
    """自由形态字符串命令入口：护栏在原始字符串上裁决，放行后 shlex.split 执行。

    结构化调用方应优先用 `execute_argv`，避免「字符串 → argv」再解析的歧义面。

    Args:
        cmd: 候选命令字符串
        authorized: 是否对 HIGH 风险显式授权（防线4）
        confirmed: 用户是否已二次确认（CONFIRM 类）
        dry_run: 仅做护栏校验、不真正执行（演示/测试用）
        timeout: 执行超时秒数
    Returns:
        统一结构 dict：executed / blocked / guard(护栏裁决) / 以及执行输出或拦截原因
    """
    # argv=None → 走「护栏放行后再 shlex.split」的兼容路径
    return _execute(cmd, None, authorized=authorized, confirmed=confirmed,
                    dry_run=dry_run, timeout=timeout)


def execute_argv(
    argv: list[str],
    *,
    authorized: bool = False,
    confirmed: bool = False,
    dry_run: bool = False,
    timeout: int = 10,
) -> dict:
    """结构化 argv 入口：argv 即权威执行对象，护栏在 shlex.join(argv) 上裁决。

    与 `execute` 的关键区别：执行的就是传入的 argv 本身，**不再** `shlex.split` 二次解析——
    故护栏所审字符串与真正执行的 argv 严格一致（所审即所执）。受控动作层（actions.py）用它。
    """
    if not isinstance(argv, (list, tuple)) or not all(isinstance(a, str) for a in argv):
        return {"executed": False, "blocked": False,
                "error": "execute_argv 需要 list[str] 形式的 argv（结构化执行对象）"}
    if not argv:
        return {"executed": False, "blocked": False, "error": "空 argv"}
    # 护栏裁决用的字符串由 argv 反推得到，与执行对象同源，杜绝再解析分叉。
    guard_str = shlex.join(argv)
    return _execute(guard_str, list(argv), authorized=authorized, confirmed=confirmed,
                    dry_run=dry_run, timeout=timeout)


def _execute(
    guard_str: str,
    argv: list[str] | None,
    *,
    authorized: bool,
    confirmed: bool,
    dry_run: bool,
    timeout: int,
) -> dict:
    """护栏校验 + （放行后）执行的共享内核。

    Args:
        guard_str: 供护栏（规则库 + AST + 最小权限）裁决的命令字符串。
        argv: 结构化执行对象；为 None 时（字符串入口）在护栏放行后由 guard_str shlex.split 得到。
        authorized: 是否对 HIGH 风险/提权显式授权（防线4）。
        confirmed: 用户是否已二次确认（CONFIRM 类）。
        dry_run: 仅做护栏校验、不真正执行（演示/测试用）。
        timeout: 执行超时秒数。
    """
    guard: GuardResult = check_command(guard_str, authorized=authorized, confirmed=confirmed)

    if not guard.allowed:
        # 被拦截：绝不执行，向调用方/用户解释原因（写入审计的「安全校验」段）
        return {
            "executed": False,
            "blocked": True,
            "require_confirm": guard.require_confirm,
            "reason": guard.reason,
            "guard": guard.to_dict(),
        }

    # 防线4 最小权限：危险规则放行后，再校验是否需要提权、会话是否授权。
    # 命令不在高危规则库、却仍需 root（如普通 systemctl restart）时，这一层兜底拦截。
    priv = check_privilege(guard_str, authorized=authorized)
    if not priv.allowed:
        return {
            "executed": False,
            "blocked": True,
            "require_confirm": False,
            "reason": priv.reason,
            "guard": guard.to_dict(),
            "privilege": priv.to_dict(),
        }

    if dry_run:
        return {
            "executed": False,
            "blocked": False,
            "dry_run": True,
            "reason": "护栏放行（dry_run，未真正执行）",
            "guard": guard.to_dict(),
            "privilege": priv.to_dict(),
        }

    # 护栏放行后才执行。
    # - argv 入口：直接用权威 argv（所审即所执，无再解析）。
    # - 字符串入口：此刻才 shlex.split，shell=False 杜绝 shell 元字符二次解释。
    if argv is None:
        try:
            argv = shlex.split(guard_str)
        except ValueError as e:
            return {"executed": False, "blocked": False, "error": f"命令解析失败：{e}",
                    "guard": guard.to_dict()}
        if not argv:
            return {"executed": False, "blocked": False, "error": "空命令",
                    "guard": guard.to_dict()}

    # 真正落地：套轻量沙箱（资源/权限限额），即便护栏误放行也炸不了宿主机（P4-3）。
    result = run_cmd(argv, timeout=timeout, sandbox=True)
    return {"executed": True, "blocked": False, "guard": guard.to_dict(),
            "privilege": priv.to_dict(), **result}
