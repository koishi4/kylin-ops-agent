"""安全护栏规则库 —— 项目核心创新点。
对 LLM 生成的候选命令做独立的二次过滤，不信任 LLM 输出。
扩展规则时务必先读 .claude/skills/safety-guardrail/SKILL.md。
"""
from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(Enum):
    CRITICAL = "critical"   # 直接拒绝，不可覆盖
    HIGH = "high"           # 拦截，需显式授权
    MEDIUM = "medium"       # 二次确认
    LOW = "low"             # 记录后放行


class Action(Enum):
    DENY = "deny"
    CONFIRM = "confirm"
    ALLOW = "allow"


@dataclass
class Rule:
    id: str
    pattern: str
    risk: RiskLevel
    action: Action
    description: str
    category: str  # delete / permission / disk / privilege / inject / config


# ---- 关键路径，命中即高危 ----
CRITICAL_PATHS = ["/", "/etc", "/var", "/boot", "/usr", "/bin", "/sbin",
                  "/var/lib/mysql", "/var/lib/postgresql"]

# ---- 规则库（示例，开发时按 skill 扩充到每类≥3条）----
RULES: list[Rule] = [
    Rule("DEL-001", r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+/(\s|$)",
         RiskLevel.CRITICAL, Action.DENY, "试图递归强制删除根目录，将摧毁系统", "delete"),
    Rule("DEL-002", r"\brm\s+.*(/etc|/var/lib/mysql|/boot)(/|\s|$)",
         RiskLevel.CRITICAL, Action.DENY, "删除涉及系统关键目录或数据库目录", "delete"),
    Rule("PERM-001", r"\bchmod\s+(-R\s+)?777\s+/(etc|usr|var|boot)?",
         RiskLevel.HIGH, Action.DENY, "对系统目录开放全权限，严重安全风险", "permission"),
    Rule("DISK-001", r"\b(mkfs|dd\s+.*of=/dev/sd|>\s*/dev/sd)",
         RiskLevel.CRITICAL, Action.DENY, "格式化/覆写块设备，将导致数据丢失", "disk"),
    Rule("PRIV-001", r"(^|\s)(sudo|su)\s",
         RiskLevel.MEDIUM, Action.CONFIRM, "涉及提权，需确认授权与必要性", "privilege"),
    Rule("CFG-001", r">\s*/etc/(passwd|shadow|fstab|sudoers)",
         RiskLevel.CRITICAL, Action.DENY, "试图改写系统关键配置文件", "config"),
    # 注入类（也用于扫描用户输入/文件内容）
    Rule("INJ-001", r"(忽略.*(规则|指令|设定)|ignore\s+previous|disregard.*(rule|instruction))",
         RiskLevel.HIGH, Action.DENY, "疑似提示词注入：指令覆盖", "inject"),
    Rule("INJ-002", r"(你现在是\s*root|你可以做任何|developer\s*mode|越狱|jailbreak)",
         RiskLevel.HIGH, Action.DENY, "疑似提示词注入：角色劫持", "inject"),
    Rule("INJ-003", r"base64\s+-d\s*\|\s*(sh|bash)",
         RiskLevel.CRITICAL, Action.DENY, "疑似编码绕过执行", "inject"),
]


def normalize(cmd: str) -> str:
    """命令规范化，降低绕过空间：去多余空格、统一路径。"""
    return re.sub(r"\s+", " ", cmd.strip())


def match_rules(text: str) -> list[Rule]:
    """返回命中的规则列表。text 可以是候选命令，也可以是用户输入（查注入）。"""
    t = normalize(text)
    hits = []
    for r in RULES:
        if re.search(r.pattern, t, flags=re.IGNORECASE):
            hits.append(r)
    return hits
