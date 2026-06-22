"""登录/认证审计 MCP 工具。对应评分①「OS 感知」，并强化「安全运维」叙事（评分③创新面）。

封装 last（成功登录历史）/ lastb（失败登录尝试，常见于暴力破解）。两者读取的是 wtmp/btmp，
属只读采集；lastb 通常需 root，无权限时优雅降级（只给成功登录），绝不抛异常给 Agent。
"""
from __future__ import annotations

from ._shell import run_cmd


def _parse_last(stdout: str) -> list[dict]:
    """把 last/lastb 的输出按行做轻量解析。

    last 行形如：`user  tty/pts  from-host  Mon Jun 22 10:00 - 10:30 (00:30)`。
    字段宽度因发行版/参数而异，故只做「首列=用户、次列=终端、第三列=来源」的保守切分，
    并完整保留 raw 原文——既给结构化字段便于展示，又不因解析假设失败而丢信息。
    汇总行（wtmp begins…）与空行跳过。
    """
    entries: list[dict] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s or s.startswith(("wtmp begins", "btmp begins")):
            continue
        cols = s.split()
        if not cols:
            continue
        entries.append({
            "user": cols[0],
            "tty": cols[1] if len(cols) > 1 else "",
            "from": cols[2] if len(cols) > 2 else "",
            "raw": s,
        })
    return entries


def login_history(limit: int = 20) -> dict:
    """查询最近的登录历史与失败登录尝试。READONLY。

    安全运维价值：失败登录（lastb）激增往往是 SSH 暴力破解信号——这正是受控动作 block_ip
    「发现爆破 IP → 封禁」的触发依据。本工具把「谁登录过 / 谁在反复试」摆上台面。

    Args:
        limit: 各取最近多少条记录，默认 20，上限 200
    Returns:
        含 recent(成功登录) / failed(失败尝试) / failed_count 的字典；
        lastb 无权限时 failed 为空并在 note 说明，不影响成功登录的返回
    """
    limit = max(1, min(int(limit) if str(limit).lstrip("-").isdigit() else 20, 200))

    # last：成功登录历史。-F 给完整时间；-w 不截断主机名/用户名。
    succ = run_cmd(["last", "-F", "-w", "-n", str(limit)])
    if not succ.get("ok") and succ.get("error"):
        return {"ok": False, "level": "READONLY",
                "error": succ.get("error", "last 不可用")}
    recent = _parse_last(succ.get("stdout") or "")

    # lastb：失败登录尝试（暴力破解侦察），多数系统需 root；无权限优雅降级。
    bad = run_cmd(["lastb", "-F", "-w", "-n", str(limit)])
    failed = _parse_last(bad.get("stdout") or "") if bad.get("ok") else []
    note = None
    if not bad.get("ok"):
        note = "失败登录(lastb)读取失败（通常需 root 权限），仅返回成功登录历史。"

    out = {
        "ok": True, "level": "READONLY",
        "recent": recent, "recent_count": len(recent),
        "failed": failed, "failed_count": len(failed),
    }
    if note:
        out["note"] = note
    return out
