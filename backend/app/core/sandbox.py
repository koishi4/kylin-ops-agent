"""执行沙箱 —— 护栏放行后「真正落地」的最后一层物理兜底（防线4 的 OS 级延伸）。

护栏（防线1~3 规则/AST/注入）回答「这条命令该不该执行」；沙箱回答「就算放行了、
它也炸不了宿主机」。二者纵深叠加：规则可能有盲区、LLM 可能被绕过，但失控进程
（吃光内存、CPU 自旋、fork 炸弹、写爆磁盘）会被内核硬限额当场掐死。

对应 OWASP LLM06「过度代理（Excessive Agency）」：给 Agent 的执行能力套上资源/权限
的「保险丝」，让最坏情况的爆炸半径收敛到一个被限额的子进程，而非整台机器。

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

import os
import shutil
import signal
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable

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
    """探测可用的隔离后端。返回 (name, path)：

    - ("bwrap", "/usr/bin/bwrap")   有 bubblewrap
    - ("nsjail", "/usr/bin/nsjail") 有 nsjail
    - ("rlimit", None)              都没有 → 纯 rlimit 兜底（必然可用）
    """
    for name in ("bwrap", "nsjail"):
        path = shutil.which(name)
        if path:
            return name, path
    return "rlimit", None


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
            "--dev", "/dev",
            "--unshare-net",              # 断网：放行命令也无法联网
            "--unshare-pid",              # 独立 PID 空间
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
                "sandbox_killed": True, "limit_hit": "timeout", "sandbox": backend}

    sandbox_killed, limit_hit = _classify_exit(rc, stderr or "")
    result = {"ok": rc == 0, "stdout": stdout or "", "stderr": stderr or "",
              "sandbox_killed": sandbox_killed, "limit_hit": limit_hit,
              "sandbox": backend}
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
