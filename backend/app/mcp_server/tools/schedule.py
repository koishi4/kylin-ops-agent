"""定时任务 MCP 工具。对应评分①「OS 感知」与评分④根因分析。

封装 systemd timers（systemctl list-timers）+ 传统 cron（/etc/crontab、/etc/cron.d、用户 crontab）。
全部只读：列 timer、读 cron 配置文件、`crontab -l` 列当前用户任务。文件读取逐个 try/except，
命令一律走 run_cmd，绝不抛异常给 Agent。
"""
from __future__ import annotations

import os

from ._shell import run_cmd

# 传统 cron 的系统级配置位置（只读这些已知位置，不做任意路径遍历）。
_SYSTEM_CRON_FILES = ("/etc/crontab",)
_SYSTEM_CRON_DIRS = ("/etc/cron.d",)


def _read_cron_lines(path: str) -> list[str]:
    """读单个 cron 配置文件，返回去掉注释/空行后的有效任务行；不可读时返回空。"""
    out: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    out.append(s)
    except OSError:
        # 不存在 / 无权限 / 非普通文件：静默跳过，根因分析不因单个文件读不到而中断。
        pass
    return out


def list_cron_jobs() -> dict:
    """列出系统的定时任务（systemd timers + 传统 cron）。READONLY。

    评分④根因分析：「为什么负载半夜周期性飙高 / 磁盘被周期性写满」常常源于定时任务。
    把 timer 与 cron 摊开，是定位「周期性异常」的关键一手数据。

    Returns:
        含 timers(systemd) / system_cron(/etc/crontab、/etc/cron.d) / user_cron(当前用户 crontab) 的字典
    """
    # 1) systemd timers：--all 含未激活、--no-legend/--no-pager 便于稳定解析。
    timers: list[str] = []
    tr = run_cmd(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"])
    if tr.get("ok"):
        timers = [ln.strip() for ln in (tr.get("stdout") or "").splitlines() if ln.strip()]

    # 2) 传统 cron：系统级配置文件 + cron.d 目录下的片段。
    system_cron: list[dict] = []
    for fp in _SYSTEM_CRON_FILES:
        lines = _read_cron_lines(fp)
        if lines:
            system_cron.append({"file": fp, "entries": lines})
    for d in _SYSTEM_CRON_DIRS:
        try:
            names = sorted(os.listdir(d))
        except OSError:
            names = []
        for n in names:
            fp = os.path.join(d, n)
            lines = _read_cron_lines(fp)
            if lines:
                system_cron.append({"file": fp, "entries": lines})

    # 3) 当前用户 crontab：crontab -l（无任务时返回非零，属正常语义，不算错误）。
    user_cron: list[str] = []
    ur = run_cmd(["crontab", "-l"])
    if ur.get("ok"):
        user_cron = [ln.strip() for ln in (ur.get("stdout") or "").splitlines()
                     if ln.strip() and not ln.strip().startswith("#")]

    return {
        "ok": True, "level": "READONLY",
        "timers": timers, "timer_count": len(timers),
        "system_cron": system_cron,
        "user_cron": user_cron,
    }
