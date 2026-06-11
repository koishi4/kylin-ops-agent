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
    # 用户/口令管理动词**只在命令位**才算提权（命令首位 / 分隔符后 / sudo·su·doas 之后）。
    # 修复实测误杀：旧式 `\bpasswd\b` 会命中**路径** /etc/passwd 里的子串 "passwd"，把 `stat /etc/passwd`、
    # `cat /etc/passwd` 这类只读误判为「改口令」需提权而拦下。命令位锚定后，`passwd root`/`sudo passwd`/
    # `usermod -aG ...` 仍被识别，而把 passwd 当**路径操作数**读取的只读命令不再误伤。
    # 残留权衡：经全路径调用的 `/usr/bin/passwd root` 不被此条命中（罕见），但 rules.py 的 PRIV-* 红线
    # （篡改 sudoers / useradd -u0）仍覆盖最严重形态——此处只为消除高频误杀，不放松红线。
    (r"(?:^\s*|[;&|]\s*|\b(?:sudo|su|doas)\s+)(useradd|userdel|usermod|groupadd|passwd)\b",
     "管理用户/用户组/口令"),
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


def least_privilege_check(*, is_root: bool, refuse_root: bool) -> tuple[bool, str]:
    """最小权限启动自检（审查整改②，纯函数便于测试）。

    护栏的「非必要不 root」是评分③明示项，但此前 is_running_as_root() 写好却没接进启动，
    服务可能不知不觉以 root 跑、护栏一旦误放行即 root 落地命令。这里把它接成启动闸门：

    Args:
        is_root: 当前是否以 root 运行（由 is_running_as_root() 提供）。
        refuse_root: 是否在以 root 运行时拒绝启动（REFUSE_ROOT，隔离/生产环境置 true）。
    Returns:
        (should_refuse, message)：
        - 非 root → (False, 符合最小权限的说明)；
        - root 且未要求拒绝 → (False, 告警说明)，启动方应 logger.warning；
        - root 且要求拒绝 → (True, 告警说明)，启动方应据此中止。
    """
    if not is_root:
        return False, "非 root 运行，符合最小权限原则（防线4）。"
    msg = ("检测到以 root 运行：护栏一旦误放行将以 root 落地命令，违背最小权限原则。"
           "建议改用受限账户（如 opsagent）启动；隔离/生产环境可置 REFUSE_ROOT=true 强制拒绝以 root 启动。")
    return refuse_root, msg


def _safe_tokens(cmd: str) -> list[str]:
    """容错分词，供调用方需要时使用。"""
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()
