"""日志相关 MCP 工具。对应评分①「OS 感知」，也是评分④根因分析的关键数据源。
journalctl 是 systemd 日志查询；tail_log 读普通日志文件尾部。
"""
from __future__ import annotations

import os
import re

from ._shell import run_cmd

# 审查整改⑤：tail_log 是「日志读取」工具，不是「任意文件读取」工具。
# 仅允许读这些日志根下的文件（按软链解析后的真实路径判定），把致命三要素
# 「访问敏感数据」这条腿的源头收敛——防被注入诱导去 tail /etc/shadow 等任意文件。
_ALLOWED_LOG_ROOTS = ("/var/log", "/tmp", "/var/tmp", "/run/log")
# 即便落在允许根下，命中这些敏感文件/目录一律拒读（口令影子/私钥/SSH 凭据）。
_SENSITIVE_RE = re.compile(
    r"(^|/)(shadow|gshadow|sudoers)(/|$)"      # 口令影子 / sudoers
    r"|/etc/ssl/private"                        # 私钥目录
    r"|(^|/)\.ssh(/|$)"                         # SSH 凭据目录
    r"|(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$"  # SSH 私钥/公钥
    r"|\.(pem|key|p12|pfx)$",                   # 证书/私钥文件
    re.IGNORECASE,
)


def tail_log(path: str, lines: int = 50) -> dict:
    """读取日志文件的尾部若干行。READONLY。

    Args:
        path: 日志文件路径（须落在允许的日志根下，且非敏感文件）
        lines: 读取末尾行数，默认 50，上限 1000
    Returns:
        含 lines 列表的字典；越权路径/敏感文件/文件不存在时优雅返回错误
    """
    lines = max(1, min(lines, 1000))
    # 路径管控按软链解析后的真实路径判定，杜绝软链跳出允许根或绕过 denylist
    real = os.path.realpath(path)
    if not real.startswith(_ALLOWED_LOG_ROOTS):
        return {"ok": False, "level": "READONLY",
                "error": f"拒绝读取：{path} 不在允许的日志目录"
                         f"（{', '.join(_ALLOWED_LOG_ROOTS)}）内，越权读取已被拦截。"}
    if _SENSITIVE_RE.search(real):
        return {"ok": False, "level": "READONLY",
                "error": f"拒绝读取：{path} 命中敏感文件名单（口令/私钥/SSH 凭据），不可读取。"}
    if not os.path.isfile(path):
        return {"ok": False, "level": "READONLY", "error": f"文件不存在或非普通文件: {path}"}
    try:
        # 高效读尾部：从文件末尾按块回读，避免整文件载入内存
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 8192
            data = b""
            pos = size
            while pos > 0 and data.count(b"\n") <= lines:
                step = min(block, pos)
                pos -= step
                f.seek(pos)
                data = f.read(step) + data
        text = data.decode("utf-8", errors="replace").splitlines()
        return {"ok": True, "level": "READONLY", "path": path,
                "lines": text[-lines:], "count": min(lines, len(text))}
    except OSError as e:
        return {"ok": False, "level": "READONLY", "error": str(e)}


def query_journal(unit: str | None = None, since: str | None = None,
                  priority: str | None = None, lines: int = 100) -> dict:
    """查询 systemd journal 日志（封装 journalctl）。READONLY。

    Args:
        unit: 服务单元名，如 "sshd"、"nginx.service"
        since: 起始时间，如 "1 hour ago"、"2026-06-01"
        priority: 优先级过滤，如 "err"、"warning"
        lines: 返回最多行数，默认 100，上限 1000
    Returns:
        含日志文本的字典
    """
    lines = max(1, min(lines, 1000))
    args = ["journalctl", "--no-pager", "-n", str(lines)]
    if unit:
        args += ["-u", unit]
    if since:
        args += ["--since", since]
    if priority:
        args += ["-p", priority]
    r = run_cmd(args, timeout=15)
    if not r["ok"]:
        return {"ok": False, "level": "READONLY",
                "error": r.get("error") or r.get("stderr", "journalctl 查询失败")}
    return {"ok": True, "level": "READONLY", "unit": unit,
            "lines": r["stdout"].splitlines()}
