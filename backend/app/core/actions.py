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

import ipaddress
import os
import shlex
import stat
from typing import Any, Callable

from app.config import get_settings
from app.core import executor
from app.core.diagnosis import FileClass, classify_file
from app.guardrail.privilege import privilege_posture
from app.mcp_server.tools._validate import valid_unit, valid_vacuum_size, valid_vacuum_time
from app.mcp_server.tools.process import process_detail

# 白名单动作名。扩展实用性的正确方向：往此表加【参数化受控动作】（每个都过语义闸门 + 二次确认 +
# executor 护栏 + 审计），而非给 LLM 自由 shell——能力随之增长而不破坏「LLM 够不到危险路径」的不变量。
ACTIONS = ("truncate_log", "kill_process", "clean_path",
           "restart_service", "reload_config", "block_ip", "clean_journal")

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

# 关键 systemd 单元：禁止 restart/reload（重启会中断会话、拖垮系统）。按去掉 .service 后缀的基名小写比对。
_CRITICAL_UNITS = {
    "systemd", "init", "sshd", "ssh", "dbus", "dbus-broker",
    "systemd-journald", "systemd-logind", "systemd-networkd", "systemd-resolved",
    "networkmanager", "network", "polkit", "polkitd", "getty", "serial-getty",
    "rescue", "emergency", "firewalld",
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

    # P0-B：真实落地用 fd-safe 的 os.ftruncate，**不再调外部 `truncate` 命令**。
    # 理由有二：① 消除 classify→执行 之间「软链/文件被换」的 TOCTOU（O_NOFOLLOW + fstat 普通文件，
    #   在同一个 fd 上截断，校验与操作绑定同一 inode）；② P0-A 后 `truncate -s 0 /var/log/...` 会被
    #   命令护栏判 CRITICAL（/var 关键路径），白名单动作的安全性本就应由**动作层语义闸门 + fd-safe 落地**
    #   保证，而非依赖「truncate 恰好不被命令护栏拦」。这是把防护放到正确的层（Action-Selector 范式）。
    command = f"os.ftruncate(0): {path}"
    rationale = ("可清理日志 → fd-safe os.ftruncate 原子清空（O_NOFOLLOW + fstat 普通文件，"
                 "消除 TOCTOU），保留 inode/句柄，写日志进程无需重启即可继续写（与 diagnosis 建议同源）。")
    return _fd_truncate_finish("truncate_log", trace, path, command, rationale, precheck,
                               confirmed=confirmed, dry_run=dry_run)


def _fd_safe_truncate(path: str) -> dict:
    """以 fd 级防护原子清空文件：O_NOFOLLOW 拒绝软链、fstat 确认普通文件、同 fd 上 ftruncate(0)。

    若 path 在前面的 classify/symlink 校验之后被换成软链或特殊文件，open(O_NOFOLLOW)/fstat
    会在此直接拒绝——校验与操作绑定同一 fd/inode，攻击者无法在中间「换文件」。
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
    except OSError as e:   # ELOOP=是软链；ENOENT/EACCES=不存在/无权限
        return {"ok": False, "fd_safe": True, "method": "os.ftruncate",
                "error": f"fd-safe 打开失败（{e.__class__.__name__}）：{e}"}
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return {"ok": False, "fd_safe": True, "method": "os.ftruncate",
                    "error": "目标经 fd 校验不是普通文件（疑似设备/管道/被换），拒绝清空。"}
        os.ftruncate(fd, 0)
        return {"ok": True, "fd_safe": True, "method": "os.ftruncate", "bytes_after": 0}
    except OSError as e:
        return {"ok": False, "fd_safe": True, "method": "os.ftruncate", "error": str(e)}
    finally:
        os.close(fd)


def _fd_truncate_finish(action: str, trace: list[dict], path: str, command: str,
                        rationale: str, precheck: Any, *,
                        confirmed: bool, dry_run: bool) -> dict:
    """truncate_log 专用收尾：动作层语义校验已过 → 据 confirmed/dry_run 决定是否 fd-safe 落地。

    与 _guarded_finish 的区别：不经命令护栏/子进程沙箱（ftruncate 是 syscall，不会失控，无需沙箱），
    安全性由动作层语义闸门 + fd-safe 落地共同保证；guard/privilege 字段为 None（如实表示未走命令护栏）。
    """
    trace = list(trace)
    trace.append({"stage": "推理决策", "detail": {"command": command, "rationale": rationale}})

    # 最小权限落地态势：truncate 走进程内 os.ftruncate（syscall，不经子进程，无法 setuid 降权）→
    # drops_privilege=False：以 root 运行时它就是以 root 落地。如实标注，并接受 REQUIRE_PRIVILEGE_DROP 裁决。
    will_execute = confirmed and not dry_run
    posture, priv_refuse = _privilege_gate(action, drops_privilege=False, will_execute=will_execute)

    output = None
    if priv_refuse:
        decided = {"executed": False, "blocked": True, "require_confirm": False, "ok": False,
                   "reason": priv_refuse}
    elif not confirmed:
        decided = {"executed": False, "blocked": False, "require_confirm": True, "ok": False,
                   "reason": "动作语义校验通过，等待用户二次确认后执行。"}
    elif dry_run:
        decided = {"executed": False, "blocked": False, "require_confirm": False, "ok": True,
                   "reason": "动作语义校验与二次确认均通过（dry_run，未真正执行）。"}
    else:
        res = _fd_safe_truncate(path)
        output = res
        if res["ok"]:
            decided = {"executed": True, "blocked": False, "require_confirm": False, "ok": True,
                       "reason": "日志已 fd-safe 清空（os.ftruncate，O_NOFOLLOW 防软链写穿）。"}
        else:
            decided = {"executed": False, "blocked": True, "require_confirm": False, "ok": False,
                       "reason": f"fd-safe 清空失败：{res.get('error')}"}

    trace.append({"stage": "安全校验", "detail": {
        "layer": "动作语义校验（关键性/软链/存在性）+ fd-safe 落地（O_NOFOLLOW + fstat 普通文件，消除 TOCTOU）",
        "passed": not decided["blocked"], "precheck": precheck,
        "guard": None, "privilege": None, "require_confirm": decided["require_confirm"],
        # 最小权限「落地身份」态势：truncate 进程内 syscall，以 root 运行即以 root 落地（如实可见）。
        "privilege_posture": posture,
        # 致命三要素 / Rule of Two 在真实状态变更点的能力面评估（C 腿在此、且在二次确认之下）。
        "rule_of_two": _rule_of_two_detail(action, confirmed=confirmed)}})
    trace.append({"stage": "执行结果", "detail": {
        "executed": decided["executed"], "blocked": decided["blocked"],
        "require_confirm": decided["require_confirm"], "reason": decided["reason"],
        "output": output}})

    return {
        "ok": decided["ok"], "action": action,
        "executed": decided["executed"], "blocked": decided["blocked"],
        "require_confirm": decided["require_confirm"], "dry_run": dry_run or not confirmed,
        "reason": decided["reason"], "command": command, "precheck": precheck,
        "guard": None, "privilege": None, "output": output, "trace": trace,
    }


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

    # P0-A.4：结构化 argv（signum/pid 均为整数，从根上无拼接/注入面），不再拼成字符串。
    argv = ["kill", f"-{signum}", str(pid)]
    rationale = (f"向进程 {pid}（{name}）发送 {sig_name}；已确认非 init/自身/关键服务，"
                 "优先温和信号给进程自清理的机会。")
    return _guarded_finish("kill_process", trace, argv, rationale, precheck,
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

    # P0-A.4：结构化 argv —— path 作为独立 token 原样进 argv，不经「quote 进字符串再 split」往返，
    # 含空格/元字符的路径也不会被二次解释；展示/审计字符串由 shlex.join 反推（同源）。
    argv = ["rm", "-f", path]
    rationale = ("可清理的非日志文件 → rm -f 删除单个文件；"
                 "命令仍过护栏，落在系统关键路径（如 /var）的 rm 会被 PATH-001 独立拦截。")
    return _guarded_finish("clean_path", trace, argv, rationale, precheck,
                           confirmed=confirmed, authorized=authorized, dry_run=dry_run)


# ---------------------------------------------------------------------------
# 扩展受控动作（P1 实用性扩展）——服务处置 / 安全封禁 / 日志清盘。
# 同一纪律：动作层语义闸门（白名单/范围/关键性）→ 结构化 argv → _guarded_finish 过 executor
# （防线2 规则库 + 防线4 最小权限）+ 强制二次确认 + 五段 trace 落审计。一律不进 MCP 注册表。
# ---------------------------------------------------------------------------

def _manage_service(params: dict, *, verb: str, action: str,
                    confirmed: bool, authorized: bool, dry_run: bool) -> dict:
    """systemctl <verb> <unit> 的共享实现（restart_service / reload_config）。

    语义闸门：① unit 名白名单校验（防注入）；② 关键单元（sshd/systemd/dbus/网络…）一律拒——
    重启它们会断会话/搞挂系统。管理服务必然需提权，故命令经 executor 时由防线4 要求显式 authorized，
    未授权即拦（这正是赛题「核心运维动作需显式授权运行」的可演示证据）。
    """
    unit = params.get("unit")
    trace = [_recv(action, {"unit": unit, "verb": verb}, confirmed, authorized, dry_run)]
    if not unit or not isinstance(unit, str) or not valid_unit(unit):
        return _refuse(action, trace,
                       f"非法或缺失的服务名 unit={unit!r}"
                       "（仅允许字母数字与 . _ @ : -，可选 .service 后缀）。")

    base = unit[:-len(".service")] if unit.endswith(".service") else unit
    is_critical = base.lower() in _CRITICAL_UNITS
    precheck = {"unit": unit, "verb": verb, "base": base, "critical": is_critical}
    trace.append({"stage": "感知环境", "detail": {
        "unit": unit, "base": base, "is_critical_unit": is_critical}})
    if is_critical:
        return _refuse(action, trace,
                       f"单元 {unit!r} 属关键系统服务（restart/reload 会中断会话或拖垮系统），已拒绝。",
                       precheck=precheck)

    argv = ["systemctl", verb, unit]
    rationale = (f"对非关键服务 {unit!r} 执行 systemctl {verb}；管理服务需提权，"
                 "命令经 executor 由防线4 校验显式授权，并经沙箱降权落地。")
    return _guarded_finish(action, trace, argv, rationale, precheck,
                           confirmed=confirmed, authorized=authorized, dry_run=dry_run)


def _restart_service(params: dict, *, confirmed: bool, authorized: bool, dry_run: bool) -> dict:
    """重启 systemd 服务（systemctl restart）。关键单元拒；需显式授权（防线4）。"""
    return _manage_service(params, verb="restart", action="restart_service",
                           confirmed=confirmed, authorized=authorized, dry_run=dry_run)


def _reload_config(params: dict, *, confirmed: bool, authorized: bool, dry_run: bool) -> dict:
    """重载 systemd 服务配置（systemctl reload，不中断服务）。关键单元拒；需显式授权（防线4）。"""
    return _manage_service(params, verb="reload", action="reload_config",
                           confirmed=confirmed, authorized=authorized, dry_run=dry_run)


def _block_ip(params: dict, *, confirmed: bool, authorized: bool, dry_run: bool) -> dict:
    """封禁来源 IP（iptables -I INPUT -s <ip> -j DROP）。安全运维：发现爆破→封禁。

    语义闸门（防自锁/防误伤大范围）：只允许单个主机 IP；拒绝整段子网(CIDR)、回环/未指定/组播/
    链路本地地址、以及当前 SSH 来源（封它=把自己锁在门外）。iptables 改防火墙需提权，命令经
    executor 由防线4 要求显式 authorized。
    """
    ip = params.get("ip")
    trace = [_recv("block_ip", {"ip": ip}, confirmed, authorized, dry_run)]
    if not ip or not isinstance(ip, str):
        return _refuse("block_ip", trace, "缺少参数 ip，无法封禁。")
    if "/" in ip:
        return _refuse("block_ip", trace,
                       f"拒绝封禁网段 {ip!r}：只允许单个主机 IP，封整段子网易误伤/自锁。")
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return _refuse("block_ip", trace, f"非法 IP 地址：{ip!r}。")

    is_special = (addr.is_loopback or addr.is_unspecified
                  or addr.is_multicast or addr.is_link_local)
    precheck = {"ip": ip, "version": addr.version, "is_special": is_special}
    trace.append({"stage": "感知环境", "detail": {
        "ip": ip, "version": addr.version, "is_special": is_special}})
    if is_special:
        return _refuse("block_ip", trace,
                       f"拒绝封禁特殊地址 {ip!r}（回环/未指定/组播/链路本地），封禁无意义且可能自锁。",
                       precheck=precheck)
    # 当前 SSH 来源：SSH_CONNECTION = "客户端IP 客户端口 服务端IP 服务端口"。封它会把自己锁在门外。
    ssh_conn = os.environ.get("SSH_CONNECTION", "")
    peer = ssh_conn.split()[0] if ssh_conn else ""
    if peer and peer == ip:
        return _refuse("block_ip", trace,
                       f"{ip!r} 是当前 SSH 登录来源，封禁会导致自锁（把自己关在门外），已拒绝。",
                       precheck=precheck)

    argv = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
    rationale = (f"在 INPUT 链头部插入 DROP 规则封禁来源 {ip!r}（已确认非网段/特殊地址/当前 SSH 来源）；"
                 "改防火墙需提权，命令经 executor 由防线4 校验授权。")
    return _guarded_finish("block_ip", trace, argv, rationale, precheck,
                           confirmed=confirmed, authorized=authorized, dry_run=dry_run)


def _clean_journal(params: dict, *, confirmed: bool, authorized: bool, dry_run: bool) -> dict:
    """按大小或时间安全回收 systemd 日志（journalctl --vacuum-size/--vacuum-time）。

    比 clean_path 更 systemd 原生的清盘：journalctl --vacuum 只回收**已轮转的旧日志**，保留近期
    日志、不影响正在写入的服务。语义闸门：size/time 二选一且格式白名单校验，杜绝任意串透传给 journalctl。
    """
    size = params.get("size")
    time_spec = params.get("time")
    trace = [_recv("clean_journal", {"size": size, "time": time_spec},
                   confirmed, authorized, dry_run)]

    provided = [k for k, v in (("size", size), ("time", time_spec)) if v]
    if len(provided) != 1:
        return _refuse("clean_journal", trace,
                       "需且仅需提供 size 或 time 之一（如 size=200M 或 time=7d）。")

    if size:
        if not valid_vacuum_size(size):
            return _refuse("clean_journal", trace,
                           f"非法 size={size!r}（应形如 100M / 1G / 500K：数字 + 可选 K/M/G/T）。")
        argv = ["journalctl", f"--vacuum-size={size}"]
        rationale = f"journalctl --vacuum-size={size}：把 journal 总量回收到不超过 {size}，仅删旧日志。"
        precheck = {"mode": "size", "value": size}
    else:
        if not valid_vacuum_time(time_spec):
            return _refuse("clean_journal", trace,
                           f"非法 time={time_spec!r}（应形如 7d / 2weeks / 30min）。")
        argv = ["journalctl", f"--vacuum-time={time_spec}"]
        rationale = f"journalctl --vacuum-time={time_spec}：删除早于 {time_spec} 的旧日志。"
        precheck = {"mode": "time", "value": time_spec}

    trace.append({"stage": "感知环境", "detail": precheck})
    return _guarded_finish("clean_journal", trace, argv, rationale, precheck,
                           confirmed=confirmed, authorized=authorized, dry_run=dry_run)


_HANDLERS: dict[str, Callable[..., dict]] = {
    "truncate_log": _truncate_log,
    "kill_process": _kill_process,
    "clean_path": _clean_path,
    "restart_service": _restart_service,
    "reload_config": _reload_config,
    "block_ip": _block_ip,
    "clean_journal": _clean_journal,
}


# ---------------------------------------------------------------------------
# 公共装配：trace 五段、护栏裁决翻译、拒绝结果。
# ---------------------------------------------------------------------------

def _recv(action: str, params: dict, confirmed: bool, authorized: bool, dry_run: bool) -> dict:
    """构造「接收指令」段。"""
    return {"stage": "接收指令", "detail": {
        "action": action, **params,
        "confirmed": confirmed, "authorized": authorized, "dry_run": dry_run}}


def _rule_of_two_detail(action: str, *, confirmed: bool) -> dict:
    """致命三要素 / Rule of Two 在【真实状态变更点】的能力面评估。

    （评审整改：把能力模型用到真正会改系统的动作层，而非只在只读编排路径上展示一串恒 ≤2 腿的数字。）
    受控动作具备『改状态』(C) + 『访问敏感/私有数据』(B) 两条能力腿，但**不接触不可信内容**(A=False)——
    故最多触及 2/3 腿，天然满足 Rule of Two；human_in_loop=confirmed 让 C 腿始终处于人工二次确认之下。
    第三条腿(A)只存于感知层只读工具、与 C 腿永不同路（该隔离已由 trifecta.assert_perception_isolation
    在启动期 fail-closed 强制）。

    返回 detail 字典（**并入**动作层既有的「安全校验」段，不另起一段——保动作链恰好五段的不变量），
    让思维链在状态变更点也能看见 Rule of Two 结论，而非只在感知路径。
    """
    from app.guardrail.trifecta import evaluate_path  # 延迟导入，避免 actions↔trifecta 循环依赖

    tri = evaluate_path([action], human_in_loop=confirmed)
    return {
        **tri.to_trace(),
        "human_in_loop_source": "动作层强制二次确认（confirmed）",
        "note": ("受控动作携带『改状态』(C)+『访问敏感』(B) 两条能力腿、不接触不可信内容(A)；"
                 "≤2 腿满足 Rule of Two，且 C 腿始终在二次确认之下。A 腿（不可信内容）只存于感知层"
                 "只读工具，与 C 腿永不同路——该隔离由启动期不变量强制（perception_isolation）。"),
    }


def _privilege_gate(action: str, *, drops_privilege: bool, will_execute: bool) -> tuple[dict, str | None]:
    """变更动作的「落地权限」态势 + fail-closed 裁决（评审整改 · 最小权限默认）。

    返回 (posture, refuse_reason|None)：
    - posture 始终如实写进「安全校验」段——让思维链 per-action 看见「这条变更以什么身份落地」
      （非 root / 降权到 opsagent / 以 root 落地），是赛题需求④「核心运维动作在受限 Account 下运行」
      的**可演示证据**，而非只靠部署配置口头保证。
    - 仅当 REQUIRE_PRIVILEGE_DROP=true 且本动作**确会以 root 落地**且**确要执行**时给出拒绝原因
      （fail-closed）。默认（未开该开关）只标注不拦，保 demo 顺滑（与 refuse_root/operator_token 同范式）。
    """
    settings = get_settings()
    posture = privilege_posture(settings.exec_user, drops_privilege=drops_privilege)
    if will_execute and settings.require_privilege_drop and posture["elevated_landing"]:
        return posture, ("已启用 REQUIRE_PRIVILEGE_DROP（强制最小权限落地），但本变更动作会以 root 落地："
                         + posture["reason"] + " → fail-closed 拒绝执行。")
    return posture, None


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


def _guarded_finish(action: str, trace: list[dict], argv: list[str], rationale: str,
                    precheck: Any, *, confirmed: bool, authorized: bool, dry_run: bool) -> dict:
    """语义校验通过后：构造 argv → 经 executor 护栏裁决 → 据结果装配剩余 trace。

    P0-A.4：动作层直接给出结构化 argv，经 `executor.execute_argv` 落地——argv 即权威执行对象，
    护栏在 `shlex.join(argv)` 上裁决，「所审即所执」，不再有「命令字符串 → argv」再解析的歧义。
    trace/前端展示用的 `command` 字符串由同一 argv 反推（shlex.join），与执行对象同源。
    """
    trace = list(trace)
    command = shlex.join(argv)  # 仅供展示/审计：与真正执行的 argv 同源，不再被二次解析
    trace.append({"stage": "推理决策", "detail": {"command": command, "rationale": rationale}})

    # 未确认绝不真执行：强制 dry_run，仅取护栏裁决供前端预览。
    effective_dry = dry_run or not confirmed
    # 最小权限落地态势 + fail-closed 裁决（kill/clean 经沙箱子进程，可 setuid 降权 → drops_privilege=True）。
    will_execute = confirmed and not dry_run
    posture, priv_refuse = _privilege_gate(action, drops_privilege=True, will_execute=will_execute)

    # 强制降权开启且本动作会以 root 落地 → 只取护栏 dry_run 裁决供展示，绝不真正执行（fail-closed）。
    res = executor.execute_argv(argv, confirmed=confirmed, authorized=authorized,
                                dry_run=effective_dry or bool(priv_refuse))
    if priv_refuse:
        decided = {"executed": False, "blocked": True, "require_confirm": False,
                   "ok": False, "reason": priv_refuse}
    else:
        decided = _decide(res, confirmed=confirmed, dry_run=dry_run)

    trace.append({"stage": "安全校验", "detail": {
        "layer": "executor 护栏（防线2 规则库 + 防线4 最小权限）",
        "passed": not res.get("blocked") and not priv_refuse,
        "precheck": precheck,
        "guard": res.get("guard"),
        "privilege": res.get("privilege"),
        # 最小权限「落地身份」态势：本变更以 root / 降权账户 / 非 root 落地（赛题需求④可演示证据）。
        "privilege_posture": posture,
        "require_confirm": decided["require_confirm"],
        # 致命三要素 / Rule of Two 在真实状态变更点的能力面评估（C 腿在此、且在二次确认之下）。
        "rule_of_two": _rule_of_two_detail(action, confirmed=confirmed)}})

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
