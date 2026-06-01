"""护栏防线4：最小权限校验（见 safety-guardrail skill）。

原则：默认在受限账户执行，核心运维动作不用 root。
一条命令若需要提权（sudo/su、写系统路径、改服务），必须：
  ① 命中授权（本次会话 authorized=True）
  ② 记录提权原因
否则拦截，提示「按最小权限原则，该操作超出当前会话授权范围」。

与 rules.py 的区别：rules 判「这条命令危不危险」；本模块判「这条命令要不要 root、当前授权够不够」。
两者叠加：即便命令不在高危规则库里，只要它需要提权而会话未授权，也应拦下来。
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

# 需要 root/提权才能完成的特征
_PRIV_PATTERNS = [
    (r"(^|[\s;&|])(sudo|su)(\s|$)", "显式 sudo/su 提权"),
    (r"\b(systemctl|service)\s+(start|stop|restart|reload|enable|disable)\b", "管理 systemd 服务"),
    (r"\b(apt|apt-get|yum|dnf|dpkg|rpm)\s+(install|remove|purge|update|upgrade)\b", "包管理改动系统"),
    (r"\b(useradd|userdel|usermod|groupadd|passwd)\b", "管理用户/用户组/口令"),
    (r"\b(mount|umount|fdisk|parted|mkfs)\b", "挂载/分区/格式化"),
    (r"\b(iptables|nft|ufw|firewall-cmd)\b", "改防火墙规则"),
    (r">\s*/(etc|boot|usr|sys|proc)/", "写入系统关键目录"),
    (r"\b(chown|chmod)\s+.*\s/(etc|usr|var|boot|bin|sbin|lib|root)", "改系统目录属主/权限"),
]


@dataclass
class PrivilegeResult:
    needs_privilege: bool
    allowed: bool
    reason: str
    matched: list[str]  # 命中的提权特征说明

    def to_dict(self) -> dict:
        return {
            "needs_privilege": self.needs_privilege,
            "allowed": self.allowed,
            "reason": self.reason,
            "matched": self.matched,
        }


def requires_privilege(cmd: str) -> list[str]:
    """返回该命令命中的提权特征说明列表（空表示无需提权）。"""
    hits: list[str] = []
    for pat, why in _PRIV_PATTERNS:
        if re.search(pat, cmd, re.IGNORECASE):
            hits.append(why)
    return hits


def check_privilege(cmd: str, *, authorized: bool = False) -> PrivilegeResult:
    """最小权限裁决。

    Args:
        cmd: 候选命令
        authorized: 本次会话是否已对提权操作显式授权
    """
    hits = requires_privilege(cmd)
    if not hits:
        return PrivilegeResult(False, True,
                               "无需提权，可在受限账户执行（符合最小权限原则）。", [])

    if authorized:
        return PrivilegeResult(True, True,
                               f"操作需提权（{'; '.join(hits)}），本次会话已授权，记录提权原因后放行。", hits)

    return PrivilegeResult(True, False,
                           f"操作需 root 权限（{'; '.join(hits)}），但当前会话未授权。"
                           "按最小权限原则拦截：请确认必要性并显式授权后重试。", hits)


def is_running_as_root() -> bool:
    """自检：当前进程是否以 root 运行。演示「非 root 部署」时用于提示。"""
    try:
        import os
        return os.geteuid() == 0
    except AttributeError:  # 非 POSIX 平台
        return False


def _safe_tokens(cmd: str) -> list[str]:
    """容错分词，供调用方需要时使用。"""
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()
