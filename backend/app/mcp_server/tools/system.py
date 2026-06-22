"""系统总体状态 MCP 工具。对应评分①「OS 感知」。"""
from __future__ import annotations

import os
import time

import psutil


def system_load() -> dict:
    """查询系统负载与 CPU 使用率。READONLY。

    Returns:
        含 1/5/15 分钟平均负载、CPU 核数、整体 CPU 使用率的字典
    """
    try:
        load1, load5, load15 = os.getloadavg()
    except (OSError, AttributeError):
        load1 = load5 = load15 = None
    return {
        "ok": True,
        "level": "READONLY",
        "loadavg_1m": round(load1, 2) if load1 is not None else None,
        "loadavg_5m": round(load5, 2) if load5 is not None else None,
        "loadavg_15m": round(load15, 2) if load15 is not None else None,
        "cpu_count": psutil.cpu_count(logical=True),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
    }


def uptime_info() -> dict:
    """查询系统启动时间与已运行时长。READONLY。

    Returns:
        含 boot_time、uptime_seconds、uptime_human 的字典
    """
    boot = psutil.boot_time()
    up = int(time.time() - boot)
    days, rem = divmod(up, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    return {
        "ok": True,
        "level": "READONLY",
        "boot_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(boot)),
        "uptime_seconds": up,
        "uptime_human": f"{days}天{hours}小时{minutes}分",
    }


def service_status(name: str) -> dict:
    """查询 systemd 服务的运行状态（封装 systemctl is-active/is-enabled）。READONLY。

    Args:
        name: 服务名，如 "sshd"、"nginx"
    Returns:
        含 active(是否运行)、enabled(是否开机自启) 的字典
    """
    from ._shell import run_cmd
    from ._validate import valid_unit
    if not valid_unit(name):
        return {"ok": False, "level": "READONLY",
                "error": f"非法服务名: {name!r}（仅允许字母数字与 . _ @ : -，可选 .service 后缀）"}
    active = run_cmd(["systemctl", "is-active", name])
    enabled = run_cmd(["systemctl", "is-enabled", name])
    # is-active/is-enabled 返回码非 0 表示 inactive/disabled，属正常语义而非执行错误
    if active.get("error"):
        return {"ok": False, "level": "READONLY", "error": active["error"]}
    return {
        "ok": True,
        "level": "READONLY",
        "service": name,
        "active": (active.get("stdout") or "").strip(),
        "enabled": (enabled.get("stdout") or "").strip(),
    }


def list_failed_units() -> dict:
    """列出所有处于 failed 状态的 systemd 单元（封装 systemctl --failed）。READONLY。

    评分④根因分析：「哪些服务挂了」是排障第一问。systemctl --failed 直接给出失败单元清单，
    比逐个 service_status 查快得多，也是 service_status / query_journal 的天然入口（先看谁挂了，
    再去查它的日志）。

    Returns:
        含 failed 列表（unit/load/active/sub/description）与 count 的字典；
        systemd 不可用时优雅返回结构化错误
    """
    from ._shell import run_cmd
    # --plain 去掉项目符号、--no-legend 去掉表头脚注、--no-pager 防分页阻塞，便于稳定解析。
    r = run_cmd(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"])
    if not r["ok"] and r.get("error"):
        # command not found / 非 systemd 系统：结构化报错而非崩溃。
        return {"ok": False, "level": "READONLY",
                "error": r.get("error", "systemctl 不可用")}
    failed = []
    for line in (r.get("stdout") or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # 行格式：UNIT LOAD ACTIVE SUB DESCRIPTION（前四列定长，描述可含空格）
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit, load, active, sub = parts[:4]
        desc = parts[4] if len(parts) == 5 else ""
        failed.append({"unit": unit, "load": load, "active": active,
                       "sub": sub, "description": desc})
    return {"ok": True, "level": "READONLY", "count": len(failed), "failed": failed}
