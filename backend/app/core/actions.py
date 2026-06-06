"""受控 MUTATING 动作层 —— 让护栏从「空跑」变「实战」的端到端落点（IMPROVEMENTS P0-3）。

定位：赛题招牌场景「清理垃圾 → 识别关键性 → 安全执行」缺的就是「执行」这一环。
根因分析（diagnosis）只给建议不执行；本层把「建议」接成「用户确认后、经护栏的安全执行」闭环。

设计原则（CLAUDE.md §6 + safety-guardrail skill）：
1. **不做自由 shell，只做白名单参数化动作**（truncate_log / kill_process / clean_path）。
   收敛攻击面：前端/调用方只能触发这几个固定语义的动作，不能拼任意命令。
2. **动作层在 executor 护栏之上再加一层「语义校验」**：用 classify_file 判文件关键性、
   process_detail 判进程关键性——这是正则规则表达不了的语义，是纵深防御的上层闸门。
   典型：`truncate`/`kill` 不在防线2 规则库也不需提权，命令层会放行，真正拦它们的是本层语义校验。
3. **语义校验通过 ≠ 放行**：所有真正落系统的命令仍唯一经 `executor.execute`
   （防线2 规则库 + 防线4 最小权限）。任一层不过即不执行。
   典型：`rm` 作用于 /var 下「可清理」文件，本层判 CLEANABLE，命令层仍会被 PATH-001 独立拦死——
   这正是「规则保可靠」的多层防御，故日志一律走 truncate 不走 rm。
4. **二次确认 + 默认 dry_run**：未确认（confirmed=False）绝不真正执行，只返回护栏裁决供前端预览，
   并置 require_confirm=True；演示只演「安全清理可清理项」与「危险项被拦」，绝不演破坏。

本层不被 LLM 当作可调用工具（MCP 工具全 READONLY）：变更动作只能由用户显式触发，
经 /action/execute 进入，避免模型自主发起 kill/删除。每次动作产出五段 trace 落审计，可回放。
"""
from __future__ import annotations

import os
import shlex
from typing import Any, Callable

from app.core import executor
from app.core.diagnosis import FileClass, classify_file
from app.mcp_server.tools.process import process_detail

# 白名单动作名
ACTIONS = ("truncate_log", "kill_process", "clean_path")

# 受保护 PID：一律禁止终止（即便护栏命令规则未覆盖 kill）。0=内核占位，1=init/systemd。
_PROTECTED_PIDS = {0, 1}

# 关键系统进程名：禁止贸然终止，杀掉会导致系统/会话崩溃。
_CRITICAL_PROC_NAMES = {
    "systemd", "init", "kthreadd", "sshd", "dbus-daemon", "dbus",
    "NetworkManager", "systemd-journald", "systemd-logind", "rsyslogd",
    "agetty", "login", "containerd", "dockerd",
}

# 允许的终止信号白名单（名称 → 信号号）。默认用温和的 SIGTERM。
_ALLOWED_SIGNALS = {
    "SIGTERM": 15, "SIGINT": 2, "SIGHUP": 1, "SIGQUIT": 3, "SIGKILL": 9,
}


def run_action(
    action: str,
    params: dict | None = None,
    *,
    confirmed: bool = False,
    authorized: bool = False,
    dry_run: bool = True,
) -> dict:
    """受控动作统一入口。

    Args:
        action: 动作名，见 ACTIONS。
        params: 动作参数（如 {"path": ...} / {"pid": ..., "signal": ...}）。
        confirmed: 用户是否已二次确认。未确认绝不真正执行（仅返回预览 + require_confirm）。
        authorized: 是否对需提权操作显式授权（防线4）。
        dry_run: 仅校验不执行（演示/预览用）。
    Returns:
        统一结构 dict（含 ok/executed/blocked/require_confirm/guard/precheck/trace 等）。
    """
    handler: Callable[..., dict] | None = _HANDLERS.get(action)
    if handler is None:
        trace = [{"stage": "接收指令", "detail": {"action": action, "params": params}}]
        return _refuse(action, trace,
                       f"未知动作：{action!r}（可选 {', '.join(ACTIONS)}）。")
    return handler(params or {}, confirmed=confirmed, authorized=authorized, dry_run=dry_run)


# ---------------------------------------------------------------------------
# 各动作实现：先做语义校验（只读），通过后构造白名单命令交 executor 护栏裁决。
# ---------------------------------------------------------------------------

def _truncate_log(params: dict, *, confirmed: bool, authorized: bool, dry_run: bool) -> dict:
    """清空日志文件（truncate -s 0）。仅允许「可清理」类，关键/未知一律拒。"""
    path = params.get("path")
    trace = [_recv("truncate_log", {"path": path}, confirmed, authorized, dry_run)]
    if not path or not isinstance(path, str):
        return _refuse("truncate_log", trace, "缺少参数 path，无法清空日志。")

    # 审查整改③：truncate 会跟随软链写入其指向的真实文件——先无条件拒绝符号链接，
    # 杜绝「软链指向关键文件」的写穿，并消除 classify→执行 之间换链的 TOCTOU 窗口。
    if os.path.islink(path):
        real = os.path.realpath(path)
        trace.append({"stage": "感知环境", "detail": {"is_symlink": True, "realpath": real}})
        return _refuse("truncate_log", trace,
                       f"目标是符号链接（→ {real}），truncate 会写其指向的真实文件；"
                       "为防『软链指向关键文件』绕过关键性判断，拒绝对符号链接清空。",
                       precheck={"is_symlink": True, "realpath": real})

    cls, why = classify_file(path)
    exists = os.path.isfile(path)
    size = os.path.getsize(path) if exists else None
    trace.append({"stage": "感知环境", "detail": {
        "classify": cls.value, "classify_reason": why, "exists": exists, "size_bytes": size}})
    precheck = {"classify": cls.value, "reason": why, "exists": exists}

    if cls is not FileClass.CLEANABLE:
        return _refuse("truncate_log", trace,
                       f"目标判定为「{cls.value}」非可清理类：{why} 已拒绝 truncate。",
                       precheck=precheck)
    if not exists:
        return _refuse("truncate_log", trace,
                       "目标文件不存在，truncate 会新建空文件，已拒绝以免误建。",
                       precheck=precheck)

    command = f"truncate -s 0 {shlex.quote(path)}"
    rationale = ("可清理日志 → 用 truncate -s 0 清空而非 rm，保留文件 inode/句柄，"
                 "写日志的进程无需重启即可继续写（与 diagnosis 建议同源）。")
    return _guarded_finish("truncate_log", trace, command, rationale, precheck,
                           confirmed=confirmed, authorized=authorized, dry_run=dry_run)


def _kill_process(params: dict, *, confirmed: bool, authorized: bool, dry_run: bool) -> dict:
    """终止进程（默认 SIGTERM）。禁止杀 init/systemd、自身/父进程、关键服务；root 进程需授权。"""
    sig_name = str(params.get("signal", "SIGTERM")).upper()
    trace = [_recv("kill_process", {"pid": params.get("pid"), "signal": sig_name},
                   confirmed, authorized, dry_run)]

    try:
        pid = int(params.get("pid"))
    except (TypeError, ValueError):
        return _refuse("kill_process", trace, f"非法 pid：{params.get('pid')!r}。")
    if sig_name not in _ALLOWED_SIGNALS:
        return _refuse("kill_process", trace,
                       f"不支持的信号 {sig_name}（仅允许 {', '.join(_ALLOWED_SIGNALS)}）。")
    signum = _ALLOWED_SIGNALS[sig_name]

    if pid in _PROTECTED_PIDS:
        return _refuse("kill_process", trace,
                       f"PID {pid} 为 init/systemd 等关键进程，终止会导致系统崩溃，禁止。")
    if pid in (os.getpid(), os.getppid()):
        return _refuse("kill_process", trace,
                       f"PID {pid} 为 Agent 自身/父进程，禁止自杀式终止。")

    detail = process_detail(pid)
    trace.append({"stage": "感知环境", "detail": {"process": detail}})
    if not detail.get("ok"):
        return _refuse("kill_process", trace,
                       detail.get("error", f"无法获取进程 {pid} 信息。"))

    name = detail.get("name") or ""
    username = detail.get("username")
    precheck = {"pid": pid, "name": name, "username": username, "signal": sig_name}

    if name in _CRITICAL_PROC_NAMES:
        return _refuse("kill_process", trace,
                       f"PID {pid}（{name}）为关键系统服务，禁止贸然终止。", precheck=precheck)
    if username == "root" and not authorized:
        return _refuse("kill_process", trace,
                       f"目标进程 {pid}（{name}）属 root，按最小权限原则需显式授权后方可终止。",
                       precheck=precheck)

    command = f"kill -{signum} {pid}"
    rationale = (f"向进程 {pid}（{name}）发送 {sig_name}；已确认非 init/自身/关键服务，"
                 "优先温和信号给进程自清理的机会。")
    return _guarded_finish("kill_process", trace, command, rationale, precheck,
                           confirmed=confirmed, authorized=authorized, dry_run=dry_run)


def _clean_path(params: dict, *, confirmed: bool, authorized: bool, dry_run: bool) -> dict:
    """删除单个「可清理」文件（rm -f）。关键/未知拒；非普通文件拒；命令仍经护栏兜底。"""
    path = params.get("path")
    trace = [_recv("clean_path", {"path": path}, confirmed, authorized, dry_run)]
    if not path or not isinstance(path, str):
        return _refuse("clean_path", trace, "缺少参数 path，无法清理。")

    cls, why = classify_file(path)
    exists = os.path.exists(path)
    isfile = os.path.isfile(path)
    trace.append({"stage": "感知环境", "detail": {
        "classify": cls.value, "classify_reason": why, "exists": exists, "is_file": isfile}})
    precheck = {"classify": cls.value, "reason": why, "exists": exists, "is_file": isfile}

    if cls is not FileClass.CLEANABLE:
        return _refuse("clean_path", trace,
                       f"目标判定为「{cls.value}」非可清理类：{why} 已拒绝删除。",
                       precheck=precheck)
    if exists and not isfile:
        return _refuse("clean_path", trace,
                       "目标不是普通文件（疑似目录/设备），clean_path 仅清理单个文件，已拒绝。",
                       precheck=precheck)

    command = f"rm -f {shlex.quote(path)}"
    rationale = ("可清理的非日志文件 → rm -f 删除单个文件；"
                 "命令仍过护栏，落在系统关键路径（如 /var）的 rm 会被 PATH-001 独立拦截。")
    return _guarded_finish("clean_path", trace, command, rationale, precheck,
                           confirmed=confirmed, authorized=authorized, dry_run=dry_run)


_HANDLERS: dict[str, Callable[..., dict]] = {
    "truncate_log": _truncate_log,
    "kill_process": _kill_process,
    "clean_path": _clean_path,
}


# ---------------------------------------------------------------------------
# 公共装配：trace 五段、护栏裁决翻译、拒绝结果。
# ---------------------------------------------------------------------------

def _recv(action: str, params: dict, confirmed: bool, authorized: bool, dry_run: bool) -> dict:
    """构造「接收指令」段。"""
    return {"stage": "接收指令", "detail": {
        "action": action, **params,
        "confirmed": confirmed, "authorized": authorized, "dry_run": dry_run}}


def _refuse(action: str, trace: list[dict], reason: str, *, precheck: Any = None) -> dict:
    """动作层语义校验未通过：补齐安全校验/执行结果两段，返回拦截结果（绝不进 executor）。"""
    trace = list(trace)
    trace.append({"stage": "安全校验", "detail": {
        "layer": "动作语义校验（关键性/受保护进程判断）",
        "passed": False, "precheck": precheck, "reason": reason}})
    trace.append({"stage": "执行结果", "detail": {
        "executed": False, "blocked": True, "reason": reason}})
    return {
        "ok": False, "action": action, "executed": False, "blocked": True,
        "require_confirm": False, "dry_run": False, "reason": reason,
        "command": None, "precheck": precheck, "guard": None, "privilege": None,
        "output": None, "trace": trace,
    }


def _guarded_finish(action: str, trace: list[dict], command: str, rationale: str,
                    precheck: Any, *, confirmed: bool, authorized: bool, dry_run: bool) -> dict:
    """语义校验通过后：构造命令 → 经 executor 护栏裁决 → 据结果装配剩余 trace。"""
    trace = list(trace)
    trace.append({"stage": "推理决策", "detail": {"command": command, "rationale": rationale}})

    # 未确认绝不真执行：强制 dry_run，仅取护栏裁决供前端预览。
    effective_dry = dry_run or not confirmed
    res = executor.execute(command, confirmed=confirmed, authorized=authorized, dry_run=effective_dry)
    decided = _decide(res, confirmed=confirmed, dry_run=dry_run)

    trace.append({"stage": "安全校验", "detail": {
        "layer": "executor 护栏（防线2 规则库 + 防线4 最小权限）",
        "passed": not res.get("blocked"),
        "precheck": precheck,
        "guard": res.get("guard"),
        "privilege": res.get("privilege"),
        "require_confirm": decided["require_confirm"]}})

    output = None
    if decided["executed"]:
        # 含沙箱处置字段（sandbox_killed/limit_hit/sandbox，P4-3）：让前端「执行结果」段
        # 能展示「这条命令是在资源/权限沙箱内落地的，是否触发限额」。
        output = {k: res[k] for k in
                  ("ok", "stdout", "stderr", "error",
                   "sandbox_killed", "limit_hit", "sandbox") if k in res}
    trace.append({"stage": "执行结果", "detail": {
        "executed": decided["executed"], "blocked": decided["blocked"],
        "require_confirm": decided["require_confirm"], "reason": decided["reason"],
        "output": output}})

    return {
        "ok": decided["ok"], "action": action,
        "executed": decided["executed"], "blocked": decided["blocked"],
        "require_confirm": decided["require_confirm"], "dry_run": effective_dry,
        "reason": decided["reason"], "command": command, "precheck": precheck,
        "guard": res.get("guard"), "privilege": res.get("privilege"),
        "output": output, "trace": trace,
    }


def _decide(res: dict, *, confirmed: bool, dry_run: bool) -> dict:
    """把 executor 返回的护栏裁决翻译成动作层状态。"""
    if res.get("blocked"):
        return {"executed": False, "blocked": True,
                "require_confirm": bool(res.get("require_confirm")),
                "ok": False, "reason": res.get("reason", "护栏拦截，未执行。")}
    # 护栏放行
    if not confirmed:
        return {"executed": False, "blocked": False, "require_confirm": True, "ok": False,
                "reason": "护栏校验通过，等待用户二次确认后执行。"}
    if dry_run:
        return {"executed": False, "blocked": False, "require_confirm": False, "ok": True,
                "reason": "护栏校验与二次确认均通过（dry_run，未真正执行）。"}
    executed = bool(res.get("executed"))
    ok = executed and bool(res.get("ok", True))
    if executed:
        reason = "动作已安全执行。" if ok else \
            f"已执行但返回非零：{res.get('stderr') or res.get('error') or '未知错误'}"
    else:
        reason = f"执行失败：{res.get('error') or '未知错误'}"
    return {"executed": executed, "blocked": False, "require_confirm": False,
            "ok": ok, "reason": reason}
