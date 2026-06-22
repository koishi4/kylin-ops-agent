"""只读 MCP 工具的入参校验与资源夹断（P0-3）。

只读 ≠ 无害：超大目录树扫描会拖垮服务（事实上的 DoS），把非法 unit/priority/since
原样透传给 systemctl/journalctl 既无意义又扩大命令注入面。统一在此做**白名单式**校验
与**硬上限**夹断——宁可结构化报错，也不放任不受控的入参进入子进程或文件系统遍历。
"""
from __future__ import annotations

import re

from app.core.pathutil import path_under_any_root

# find_large_files / dir_size 的扫描文件数硬上限（防超大目录树拖垮服务）
MAX_SCAN_FILES = 200_000
MAX_SCAN_DIR = 500_000

# systemd unit 名：字母数字与 . _ @ : -，可选 .service 后缀。
# 拒绝空格/分号/管道/路径分隔符等可用于命令注入或越权的字符。
_UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]+(\.service)?$")

# journalctl --since 白名单：today/yesterday、-1h/-30m/-7d 这类相对量、或 ISO 日期。
# 不允许任意字符串透传给 journalctl，杜绝参数注入与开销失控。
_SINCE_RE = re.compile(r"^(today|yesterday|-\d{1,4}(s|m|h|d)|\d{4}-\d{2}-\d{2})$")

# journalctl -p 优先级：数字 0–7 或 syslog 级别名（二者 journalctl 都接受）。
_PRIORITY_NAMES = {"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

# 默认拒绝扫描的伪文件系统/运行时目录：/proc /sys 海量虚拟节点会卡死遍历，
# /dev 是设备节点、/run 是运行时套接字，扫它们既无意义又危险。
REFUSED_SCAN_ROOTS = ("/proc", "/sys", "/dev", "/run")


def clamp_scan(max_scan, hard_cap: int) -> int:
    """把 max_scan 夹断到 [1, hard_cap]；非整数输入按硬上限保守处理。"""
    try:
        n = int(max_scan)
    except (TypeError, ValueError):
        return hard_cap
    return max(1, min(n, hard_cap))


def is_refused_scan_root(path: str) -> bool:
    """path 是否落在伪文件系统/运行时目录（含软链解析），落在则拒绝扫描。"""
    return path_under_any_root(path, REFUSED_SCAN_ROOTS)


def valid_unit(name: str) -> bool:
    return bool(name) and len(name) <= 128 and bool(_UNIT_RE.match(name))


def valid_since(s: str) -> bool:
    return bool(_SINCE_RE.match(s))


def valid_priority(p: str) -> bool:
    p = str(p).strip()
    return (len(p) == 1 and p in "01234567") or p in _PRIORITY_NAMES


# journalctl --vacuum-size 取值：数字 + 可选单位 K/M/G/T（如 100M、1G、500K）。
# 受控动作 clean_journal 用，杜绝把任意字符串透传给 journalctl（参数注入/开销失控）。
_VACUUM_SIZE_RE = re.compile(r"^\d{1,6}[KMGT]?$")
# journalctl --vacuum-time 取值：数字 + 时间单位（s/m/h/days/weeks/months/years 等常见形态）。
_VACUUM_TIME_RE = re.compile(
    r"^\d{1,6}\s?(s|sec|second|seconds|m|min|minute|minutes|h|hour|hours|"
    r"d|day|days|week|weeks|month|months|year|years)$")


def valid_vacuum_size(s: str) -> bool:
    """journalctl --vacuum-size 合法性：100M / 1G / 500K（数字 + 可选 K/M/G/T）。"""
    return bool(_VACUUM_SIZE_RE.match(str(s).strip()))


def valid_vacuum_time(s: str) -> bool:
    """journalctl --vacuum-time 合法性：7d / 2weeks / 30min / 1month。"""
    return bool(_VACUUM_TIME_RE.match(str(s).strip()))
