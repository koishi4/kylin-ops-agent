"""防线4 最小权限：用户/口令管理动词只在「命令位」算提权，不被路径操作数误伤。

回归实测误杀（评审整改）：旧式 `\\bpasswd\\b` 会命中**路径** /etc/passwd 里的子串 "passwd"，
把 `stat /etc/passwd`、`cat /etc/passwd` 这类只读命令误判为「改口令、需 root」而拦下。
命令位锚定（命令首位 / 分隔符后 / sudo·su·doas 之后）后，危险调用仍识别、只读读取不再误伤。
"""
from __future__ import annotations

import pytest
from app.guardrail.privilege import check_privilege, requires_privilege

# 命令位调用用户/口令管理 → 必须仍判「需提权」（未授权应拦）
PRIV_COMMANDS = [
    "passwd root",
    "sudo passwd alice",
    "usermod -aG sudo attacker",
    "useradd -u 0 backdoor",
    "groupadd hackers",
    "echo hi; passwd root",        # 分隔符后的命令位
    "doas userdel bob",
]

# passwd/group 等作为**路径操作数**被只读命令读取 → 不得误判为提权
PASSWD_AS_PATH = [
    "stat /etc/passwd",
    "cat /etc/passwd",
    "grep root /etc/passwd",
    "ls -l /etc/passwd",
    "cp /etc/passwd /tmp/p",
    "tar -czf /tmp/p.tgz /etc/passwd",
    "wc -l /etc/group",
]


@pytest.mark.parametrize("cmd", PRIV_COMMANDS)
def test_usermgmt_command_position_still_flagged(cmd):
    assert requires_privilege(cmd), f"命令位用户/口令管理未判需提权：{cmd}"
    assert not check_privilege(cmd, authorized=False).allowed, f"未授权应拦：{cmd}"


@pytest.mark.parametrize("cmd", PASSWD_AS_PATH)
def test_passwd_as_path_operand_not_flagged(cmd):
    assert not requires_privilege(cmd), \
        f"路径操作数 /etc/passwd 被误判为提权命令（误杀）：{cmd}"
    assert check_privilege(cmd, authorized=False).allowed, f"只读读取被误拦：{cmd}"
