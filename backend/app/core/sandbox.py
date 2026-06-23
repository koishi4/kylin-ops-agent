"""执行沙箱 —— 护栏放行后「真正落地」的最后一层物理兜底（防线4 的 OS 级延伸）。

护栏（防线1~3 规则/AST/注入）回答「这条命令该不该执行」；沙箱回答「就算放行了、
它也炸不了宿主机」。二者纵深叠加：规则可能有盲区、LLM 可能被绕过，但失控进程
（吃光内存、CPU 自旋、fork 炸弹、写爆磁盘）会被内核硬限额当场掐死。

对应 OWASP LLM06「过度代理（Excessive Agency）」：给 Agent 的执行能力套上资源/权限
的「保险丝」，让最坏情况的爆炸半径收敛到一个被限额的子进程，而非整台机器。

P1-3「沙箱即攻击面削减」——遏制对未知漏洞也有效：除资源限额外，再削减执行 runner 的
**能力面**（drop CAP_NET_ADMIN/CAP_NET_RAW/CAP_SYS_MODULE/CAP_SYS_PTRACE、设 no_new_privs、
以 root 运行时降权到非特权账户、bwrap 断网+丢全部能力）。这直接移除「看似无害的新内核
漏洞利用」（如 Dirty Frag：需 esp/rxrpc 接口 + splice 操纵页缓存）的**前提条件**——
一个非 root、无 CAP_NET_RAW/CAP_SYS_MODULE、断网的 runner，**在不认识该漏洞的前提下**
就打不开 raw/xfrm 套接字、加载不了模块，遏制因此对未披露 0-day 同样成立。

隔离机制按可用性自动降级（绝不硬依赖，竞赛虚机/CI 容器都能跑）：
  1. 优先：系统装有 bubblewrap(bwrap) 或 nsjail → 用其包裹（只读 rootfs + tmpfs /tmp
     + 断网 + 丢能力 + 独立 PID 空间）。靠 shutil.which 探测，没有就跳过。
  2. 兜底（必有，纯标准库）：subprocess 的 preexec_fn 里用 resource.setrlimit 施加
     RLIMIT_CPU（CPU 秒）/ RLIMIT_AS（地址空间≈内存）/ RLIMIT_NPROC（进程数，挡 fork 炸弹）
     / RLIMIT_FSIZE（输出文件大小），叠加 subprocess 超时；以 root 运行且配了 exec_user
     时，preexec 内 setgid/setuid 降权到该非特权账户、并 close 多余 fd。
  3. 任一机制不可用（CI 禁用 setrlimit/NPROC/setuid 等）→ try/except best-effort，
     记录到返回结构里，但绝不崩溃、绝不抛异常、绝不让调用方失败。

LoongArch / 麒麟 V11 说明：resource 是 Linux 标准库，LoongArch 原生可用；bwrap/nsjail
虚机里可能没装，故必须自动探测并退回 rlimit —— 零外部依赖也能在虚机上跑。

铁律（CLAUDE.md §6）：本模块只「限制」命令的资源/权限，绝不放宽护栏裁决，更不真跑
任何破坏性命令；测试只用消耗资源/无害命令验证「被限制」。
"""
from __future__ import annotations

import ctypes
import logging
import os
import shutil
import signal
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable

logger = logging.getLogger("kylin-ops-agent.sandbox")

# ---------------------------------------------------------------------------
# 运行时能力削减（P1-3）：prctl 常量 + 要丢弃的高危能力
# ---------------------------------------------------------------------------
# 在父进程加载 libc 句柄（CDLL(None) 拿主程序符号，含 libc 的 prctl）；preexec 里只调
# prctl 这个纯系统调用包装，不做内存分配，post-fork 安全。加载失败则降级为 None。
try:
    _LIBC: ctypes.CDLL | None = ctypes.CDLL(None, use_errno=True)
except Exception:  # noqa: BLE001 非 glibc/异构平台 → 没有 prctl，能力削减整体跳过
    _LIBC = None

_PR_SET_NO_NEW_PRIVS = 38   # 置 1 后即便 exec setuid 程序也无法提权
_PR_CAPBSET_DROP = 24       # 从能力 bounding set 永久丢弃某能力

# 与「内核 LPE 看似无害利用」前提相关的高危能力（Dirty Frag 需 NET_RAW/NET_ADMIN + 模块面）：
#   CAP_NET_ADMIN=12  CAP_NET_RAW=13  CAP_SYS_MODULE=16  CAP_SYS_PTRACE=19
_DROP_CAPS = (12, 13, 16, 19)

# ---------------------------------------------------------------------------
# 限额配置
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxLimits:
    """单条命令的资源/权限上限。给保守默认，可由 config.Settings 覆盖。"""
    cpu_seconds: int = 5          # RLIMIT_CPU：CPU 时间上限（防 CPU 自旋）
    mem_mb: int = 256             # RLIMIT_AS：地址空间≈内存上限（防内存吃光）
    max_procs: int = 64           # RLIMIT_NPROC：本 uid 进程/线程数（防 fork 炸弹）
    fsize_mb: int = 16            # RLIMIT_FSIZE：可写文件大小（防写爆磁盘）
    exec_user: str = ""           # 以 root 运行时降权到的非特权账户；空则不降权

    @classmethod
    def from_settings(cls, st) -> "SandboxLimits":
        """从全局 Settings 构造（集中配置，避免 os.getenv 散落）。"""
        return cls(
            cpu_seconds=st.sandbox_cpu_seconds,
            mem_mb=st.sandbox_mem_mb,
            max_procs=st.sandbox_max_procs,
            fsize_mb=st.sandbox_fsize_mb,
            exec_user=st.exec_user,
        )


# ---------------------------------------------------------------------------
# 隔离后端探测（bwrap / nsjail / 纯 rlimit），结果缓存
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _isolation_backend() -> tuple[str, str | None]:
    """探测可用的隔离后端，并做【功能性自检】——不止探测「装没装」，更验证「能不能用」。返回 (name, path)：

    - ("bwrap", "/usr/bin/bwrap")   有 bubblewrap 且自检通过
    - ("nsjail", "/usr/bin/nsjail") 有 nsjail 且自检通过
    - ("rlimit", None)              无可用命名空间后端 → 纯 rlimit 兜底（必然可用）

    为何不能只看 `shutil.which`（曾经的 bug，麒麟/LoongArch VM 实测踩到）：bwrap/nsjail 可能
    「装了却不可用」——典型是内核禁用了 unprivileged user namespace（`kernel.unprivileged_userns_clone=0`
    或 LoongArch 内核未开），bwrap 会在建命名空间阶段就**非零退出、内层命令根本没跑**，导致每条被
    包裹的命令静默失败（空 stdout、rc≠0）。只探测存在性会让沙箱「假装在用 bwrap」却条条命令失败，
    且不会降级。故对每个候选后端用与生产一致的包裹参数真跑一条无害命令，不可用即跳过、最终退回 rlimit。
    （这正是模块开头铁律「隔离机制按可用性自动降级，绝不硬依赖」的应有之义。）
    """
    for name in ("bwrap", "nsjail"):
        path = shutil.which(name)
        if not path:
            continue
        if _backend_functional(name, path):
            logger.info("执行沙箱隔离后端：%s（%s），功能性自检通过。", name, path)
            return name, path
        logger.warning(
            "检测到 %s（%s）但功能性自检失败（多为内核禁用 unprivileged userns，"
            "常见于麒麟/LoongArch 虚机）：跳过该后端，回退纯 rlimit 资源限额兜底。", name, path)
    logger.info("执行沙箱隔离后端：rlimit（无可用的命名空间隔离后端，使用资源限额 + 可选降权兜底）。")
    return "rlimit", None


def _backend_functional(name: str, path: str) -> bool:
    """功能性自检：用候选后端、以与生产一致的包裹参数（含 --unshare-net/--ro-bind 等）真正跑一条
    `echo <token>`，确认它在本内核/本架构上既能建命名空间、又能把内层命令的 stdout 正常透传出来。

    判定：returncode==0 且预期 token 出现在 stdout 才算可用。任何异常/超时/非零/无预期输出一律判
    「不可用」→ 降级（best-effort，绝不抛、绝不阻断）。宁可误降级到 rlimit（命令仍能跑、限额仍在），
    也不要误判可用却条条命令失败。结果随 _isolation_backend 一并被 lru_cache，仅探测一次。
    """
    token = "kylin-sandbox-probe-ok"
    probe = _wrap_with_isolation(["echo", token], name, path)
    try:
        r = subprocess.run(probe, capture_output=True, text=True, timeout=5)
    except Exception:  # noqa: BLE001 探测失败即视为不可用
        return False
    return r.returncode == 0 and token in (r.stdout or "")


def _wrap_with_isolation(args: list[str], backend: str, path: str | None) -> list[str]:
    """把命令用 bwrap/nsjail 包一层（只读 rootfs + tmpfs /tmp + 断网 + 独立 PID）。

    设计取舍：系统目录只读、/tmp 可写、断网、独立 PID 空间、随父进程消亡。既挡住
    「放行命令偷偷联网下载/外传」，又不破坏读型运维命令（df/ss/lsof）。rlimit 仍叠加
    在外层（rlimit 经 exec 继承，对包裹后的整棵子树同样生效），双保险。
    """
    if backend == "bwrap" and path:
        return [
            path,
            "--ro-bind", "/", "/",        # 整个根只读绑定
            "--tmpfs", "/tmp",            # /tmp 给一块可写 tmpfs
            "--proc", "/proc",
            "--dev", "/dev",              # 最小化 /dev，屏蔽宿主设备节点
            "--unshare-net",              # 断网：放行命令也无法联网、打不开 raw/xfrm 套接字（P1-3）
            "--unshare-pid",              # 独立 PID 空间
            "--unshare-ipc",              # 独立 IPC（隔离共享内存/信号量）
            "--unshare-uts",              # 独立 UTS（主机名隔离）
            "--cap-drop", "ALL",          # 丢弃全部 capability（含 SYS_MODULE/NET_RAW，P1-3）
            "--die-with-parent",          # 父死子亡，杜绝游离子进程
            "--new-session",              # 独立 session，防 TIOCSTI 注入
            "--",
        ] + args
    if backend == "nsjail" and path:
        return [
            path, "-Mo",                  # once 模式：执行一次即退
            "--disable_proc", "--rlimit_as", "soft",
            "--really_quiet",
            "-N",                         # 断网（network namespace）
            "--", *args,
        ]
    return args  # rlimit 兜底：不包裹，仅靠 setrlimit


# ---------------------------------------------------------------------------
# 降权目标解析（仅以 root 运行且配了 exec_user 时才降权）
# ---------------------------------------------------------------------------


def _resolve_drop_target(exec_user: str) -> tuple[int, int] | None:
    """解析降权目标 (uid, gid)。仅当前为 root 且账户存在时返回，否则 None（不降权）。

    在父进程里解析（getpwnam 在 fork 后调用不安全）；preexec 只做 setgid/setuid 系统调用。
    """
    if not exec_user:
        return None
    try:
        if os.geteuid() != 0:           # 非 root 无从降权，跳过（最小权限本就满足）
            return None
        import pwd
        ent = pwd.getpwnam(exec_user)
        return ent.pw_uid, ent.pw_gid
    except (KeyError, AttributeError, OSError):
        return None                      # 账户不存在 / 非 POSIX → best-effort 跳过


def _apply_runtime_hardening() -> None:
    """preexec 内的能力削减（P1-3）：no_new_privs + 丢弃高危 capability。best-effort，绝不抛。

    - PR_SET_NO_NEW_PRIVS：之后即便 exec 一个 setuid 程序也无法借此提权。
    - PR_CAPBSET_DROP：把 NET_ADMIN/NET_RAW/SYS_MODULE/SYS_PTRACE 从 bounding set 永久丢弃，
      与「降权到非 root」叠加，确保放行命令打不开 raw/xfrm 套接字、加载不了模块、ptrace 不了别人——
      移除 Dirty Frag 这类内核 LPE 的利用前提（不依赖认识具体漏洞）。
    """
    if _LIBC is None:
        return
    try:
        _LIBC.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    except Exception:
        pass
    for cap in _DROP_CAPS:
        try:
            _LIBC.prctl(_PR_CAPBSET_DROP, cap, 0, 0, 0)
        except Exception:
            pass


def _build_preexec(limits: SandboxLimits,
                   drop_to: tuple[int, int] | None) -> Callable[[], None]:
    """构造 preexec_fn：在 fork 之后、exec 之前，于子进程内施加 rlimit + 可选降权。

    关键：preexec 运行在 fork 后的子进程，禁止 log / 申请锁（可能死锁）；每个限额各自
    try/except，单项不可用不影响其余；整体绝不抛异常（抛了父进程 subprocess 会失败）。
    """
    import resource  # Linux 标准库；放函数内避免非 Linux import 期报错

    cpu = limits.cpu_seconds
    mem_bytes = limits.mem_mb * 1024 * 1024
    nproc = limits.max_procs
    fsize_bytes = limits.fsize_mb * 1024 * 1024

    def preexec() -> None:
        # 先降权：先 setgid 再 setuid（顺序不可反，反了就没权限改 gid 了）
        if drop_to is not None:
            uid, gid = drop_to
            try:
                os.setgroups([])
            except Exception:
                pass
            try:
                os.setgid(gid)
            except Exception:
                pass
            try:
                os.setuid(uid)
            except Exception:
                pass
        # 再逐项施加资源上限（单项失败不影响其余）
        for res, soft_hard in (
            (resource.RLIMIT_CPU, (cpu, cpu + 1)),          # 软限发 SIGXCPU，留 1s 硬限兜底
            (resource.RLIMIT_AS, (mem_bytes, mem_bytes)),
            (getattr(resource, "RLIMIT_NPROC", None), (nproc, nproc)),
            (resource.RLIMIT_FSIZE, (fsize_bytes, fsize_bytes)),
        ):
            if res is None:
                continue
            try:
                resource.setrlimit(res, soft_hard)
            except Exception:   # 该项不可用（如 CI 禁用某 rlimit）→ 跳过，不影响其余
                pass
        # 最后做能力削减（P1-3）：在 exec 前丢弃高危 capability 并设 no_new_privs
        _apply_runtime_hardening()

    return preexec


# ---------------------------------------------------------------------------
# 退出码归因：判断进程是否被限额掐死、命中了哪条限
# ---------------------------------------------------------------------------

# 信号→限额含义。被这些信号杀掉即视为「沙箱限额触发」。
_SIGNAL_LIMIT = {
    int(signal.SIGKILL): "killed",     # 内存硬限/超时强杀/CPU 硬限
    int(signal.SIGXCPU): "cpu",        # RLIMIT_CPU 软限
    int(signal.SIGXFSZ): "fsize",      # RLIMIT_FSIZE
    int(signal.SIGSEGV): "memory",     # 内存受限下的非法访问
}
# 进程自报内存不足（如 Python 捕获 MemoryError 后正常退出，非被信号杀）
_MEM_TOKENS = ("memoryerror", "cannot allocate memory",
               "out of memory", "std::bad_alloc", "killed")


def _classify_exit(returncode: int, stderr: str) -> tuple[bool, str | None]:
    """归因退出码 → (sandbox_killed, limit_hit)。

    - returncode < 0：被信号 -returncode 直接杀（Popen 对直接子进程的约定）。
    - returncode > 128：经 shell 中转时 shell 以 128+signal 上报子进程的信号死亡。
    - 否则进程正常退出，但 stderr 自报内存不足也算命中内存限（被信号杀=killed，
      自己 MemoryError 退出=未被杀但 limit_hit=memory）。
    """
    sig = None
    if returncode < 0:
        sig = -returncode
    elif returncode > 128:
        sig = returncode - 128
    if sig in _SIGNAL_LIMIT:
        return True, _SIGNAL_LIMIT[sig]

    if returncode != 0 and stderr:
        low = stderr.lower()
        if any(tok in low for tok in _MEM_TOKENS):
            return False, "memory"
    return False, None


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------


def _hardening_profile(backend: str, drop_to: tuple[int, int] | None,
                       preexec_ok: bool) -> dict:
    """本次执行实际套用的攻击面削减画像（P1-3），供前端/演示展示「runner 被削到什么程度」。"""
    boxed = backend in ("bwrap", "nsjail")
    return {
        "backend": backend,
        "network": "unshared" if boxed else "inherited（非 root 本就无法开 raw/xfrm 套接字）",
        "no_new_privs": preexec_ok and _LIBC is not None,
        "dropped_caps": list(_DROP_CAPS) if (preexec_ok and _LIBC is not None) else [],
        "dropped_to_uid": drop_to[0] if drop_to else None,
        "rationale": ("削减 runner 能力面以移除内核 LPE（如 Dirty Frag）的利用前提——"
                      "对未披露 0-day 同样有效，因为遏制不依赖认识具体漏洞。"),
    }


def run_sandboxed(args: list[str], *, limits: SandboxLimits, timeout: int) -> dict:
    """在轻量沙箱内执行命令，返回与 _shell.run_cmd 一致的结构（外加沙箱字段）。

    Args:
        args: 已 shlex 拆分的参数列表（shell=False，绝不字符串拼接）。
        limits: 资源/权限上限。
        timeout: 超时秒数（与 rlimit 双保险：rlimit 限 CPU 时间，timeout 限墙钟时间）。
    Returns:
        {"ok", "stdout", "stderr", "sandbox_killed", "limit_hit", "sandbox"} 或
        {"ok": False, "error", "sandbox_killed", "limit_hit", "sandbox"}。
        sandbox_killed: 进程是否被限额/超时掐死；limit_hit: 命中的限额名或 None。
    """
    if not args:
        return {"ok": False, "error": "空命令",
                "sandbox_killed": False, "limit_hit": None, "sandbox": "none"}

    backend, path = _isolation_backend()
    drop_to = _resolve_drop_target(limits.exec_user)
    try:
        preexec = _build_preexec(limits, drop_to)
    except Exception:  # 极端：连 resource 都 import 不了 → 退化为无 preexec（仍有 timeout）
        preexec = None
    final_args = _wrap_with_isolation(args, backend, path)
    hardening = _hardening_profile(backend, drop_to, preexec is not None)

    # start_new_session=True：子进程独立进程组，超时时可整组 SIGKILL（含 fork 出来的孙子进程）
    try:
        proc = subprocess.Popen(
            final_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, shell=False, close_fds=True,
            start_new_session=True, preexec_fn=preexec,
        )
    except FileNotFoundError:
        return {"ok": False, "error": f"command not found: {args[0]}",
                "sandbox_killed": False, "limit_hit": None, "sandbox": backend}
    except Exception as e:  # 沙箱不可用（如 CI 禁用 preexec）→ 降级重试一次「无 preexec」
        try:
            proc = subprocess.Popen(
                final_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, shell=False, close_fds=True, start_new_session=True,
            )
        except Exception:
            return {"ok": False, "error": f"sandbox 启动失败：{e}",
                    "sandbox_killed": False, "limit_hit": None, "sandbox": backend}

    killed_by_timeout = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        killed_by_timeout = True
        _kill_group(proc)
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except Exception:
            stdout, stderr = "", ""
    except Exception as e:
        _kill_group(proc)
        return {"ok": False, "error": f"沙箱执行异常：{e}",
                "sandbox_killed": False, "limit_hit": None, "sandbox": backend}

    rc = proc.returncode
    if killed_by_timeout:
        return {"ok": False, "stdout": stdout or "", "stderr": stderr or "",
                "error": f"timeout after {timeout}s（沙箱墙钟超时，进程已被杀）",
                "sandbox_killed": True, "limit_hit": "timeout", "sandbox": backend,
                "hardening": hardening}

    sandbox_killed, limit_hit = _classify_exit(rc, stderr or "")
    result = {"ok": rc == 0, "stdout": stdout or "", "stderr": stderr or "",
              "sandbox_killed": sandbox_killed, "limit_hit": limit_hit,
              "sandbox": backend, "hardening": hardening}
    if limit_hit and rc != 0:
        result["error"] = f"命中沙箱限额（{limit_hit}），进程未正常完成（rc={rc}）"
    return result


def _kill_group(proc: subprocess.Popen) -> None:
    """超时/异常时整组击杀，连同 fork 出来的孙子进程一并清理；失败兜底杀主进程。"""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
