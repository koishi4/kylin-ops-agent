"""安全护栏规则库 —— 项目核心创新点（评分③ + 创新分）。

对 LLM 生成的候选命令做独立的二次过滤，不信任 LLM 输出。
即使 LLM 被诱导生成 rm -rf /，本规则库也必须独立拦下来，逻辑与 LLM 完全解耦。

规则覆盖六类，命令类（删除/权限/磁盘/提权/配置）每类 ≥3 条，外加注入类。
匹配兼顾变形：-rf / -fr / -r -f、绝对/相对路径、引号包裹、命令拼接。
正则之外再用 realpath 做路径规范化双重判断（见 engine.py 调用 hits_critical_path）。

扩展规则前务必读 .claude/skills/safety-guardrail/SKILL.md。
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from enum import Enum


class RiskLevel(Enum):
    CRITICAL = "critical"   # 直接拒绝，不可覆盖
    HIGH = "high"           # 拦截，需显式授权
    MEDIUM = "medium"       # 二次确认
    LOW = "low"             # 记录后放行

    @property
    def order(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]


class Action(Enum):
    DENY = "deny"
    CONFIRM = "confirm"
    ALLOW = "allow"


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: str
    risk: RiskLevel
    action: Action
    description: str  # 命中后给用户/日志的人类可读解释
    category: str     # delete / permission / disk / privilege / config / inject


# 关键路径：rm / chmod / chown 命中这些（含其子路径）即按高危处理
CRITICAL_PATHS = [
    "/", "/etc", "/var", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/root", "/var/lib/mysql", "/var/lib/postgresql", "/var/lib/docker",
]

# rm 的递归强制标志变形：-rf / -fr / --recursive --force / -r -f
_RF = r"(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|-r\s+-f|-f\s+-r|--recursive|--force)"

RULES: list[Rule] = [
    # ---------- 删除类 ----------
    Rule("DEL-001", rf"\brm\s+{_RF}\s+/(\s|$)",
         RiskLevel.CRITICAL, Action.DENY, "递归强制删除根目录，将摧毁整个系统", "delete"),
    Rule("DEL-002", rf"\brm\s+.*{_RF}.*\s/\*",
         RiskLevel.CRITICAL, Action.DENY, "删除根目录下所有内容（/*），等同摧毁系统", "delete"),
    Rule("DEL-003", r"\brm\s+.*(/etc|/boot|/usr|/bin|/sbin|/lib|/var/lib/mysql|/var/lib/postgresql)(/|\s|\*|$)",
         RiskLevel.CRITICAL, Action.DENY, "删除涉及系统关键目录或数据库数据目录", "delete"),
    Rule("DEL-004", r"\brm\s+.*\.(db|sql|sqlite|frm|ibd|myd|myi)(\s|$)",
         RiskLevel.HIGH, Action.DENY, "删除数据库文件，可能造成不可逆数据丢失", "delete"),

    # ---------- 权限类 ----------
    Rule("PERM-001", r"\bchmod\s+(-R\s+)?0?777\s+/(etc|usr|var|boot|bin|sbin|lib|root)?(\s|/|$)",
         RiskLevel.HIGH, Action.DENY, "对系统目录开放 777 全权限，严重提权风险", "permission"),
    Rule("PERM-002", r"\bchmod\s+-R\s+\d*\s*/(etc|usr|var|boot|bin|sbin|lib)?(\s|/|$)",
         RiskLevel.HIGH, Action.DENY, "递归修改系统目录权限，可能破坏系统完整性", "permission"),
    Rule("PERM-003", r"\bchown\s+-R\s+\S+\s+/(etc|usr|var|boot|bin|sbin|lib)?(\s|/|$)",
         RiskLevel.HIGH, Action.DENY, "递归修改系统目录属主，可能导致服务失效", "permission"),
    Rule("PERM-004", r"\bchmod\s+.*\bu\+s\b",
         RiskLevel.HIGH, Action.CONFIRM, "设置 setuid 位，存在提权后门风险，需确认", "permission"),

    # ---------- 磁盘类 ----------
    Rule("DISK-001", r"\bmkfs(\.\w+)?\s",
         RiskLevel.CRITICAL, Action.DENY, "格式化文件系统，将清空目标设备数据", "disk"),
    Rule("DISK-002", r"\bdd\s+.*of=/dev/(sd|nvme|vd|hd|mmcblk)",
         RiskLevel.CRITICAL, Action.DENY, "用 dd 直接写裸块设备，将覆盖磁盘数据", "disk"),
    Rule("DISK-003", r">\s*/dev/(sd|nvme|vd|hd)",
         RiskLevel.CRITICAL, Action.DENY, "重定向覆写块设备，将损坏磁盘/分区", "disk"),
    Rule("DISK-004", r"\b(wipefs|fdisk|parted|sgdisk)\s",
         RiskLevel.HIGH, Action.CONFIRM, "分区/擦除工具，误用会破坏分区表，需确认", "disk"),

    # ---------- 提权类 ----------
    Rule("PRIV-001", r"(^|[\s;&|])(sudo|su)\s",
         RiskLevel.MEDIUM, Action.CONFIRM, "涉及提权，需确认授权与必要性（最小权限原则）", "privilege"),
    Rule("PRIV-002", r"\bpasswd\s+(root|-)",
         RiskLevel.HIGH, Action.DENY, "尝试修改 root 密码，越权操作", "privilege"),
    Rule("PRIV-003", r"(>>?\s*/etc/sudoers|\bvisudo\b|usermod\s+.*-aG?\s+(sudo|wheel|root))",
         RiskLevel.CRITICAL, Action.DENY, "篡改 sudoers / 提权用户组，严重权限越界", "privilege"),
    Rule("PRIV-004", r"\b(useradd|adduser)\s+.*(-u\s*0|--uid\s*0)",
         RiskLevel.CRITICAL, Action.DENY, "创建 UID=0 的等价 root 账户，提权后门", "privilege"),

    # ---------- 关键配置保护 ----------
    Rule("CFG-001", r">\s*/etc/(passwd|shadow|fstab|sudoers|group|gshadow)",
         RiskLevel.CRITICAL, Action.DENY, "改写系统关键配置文件，可致系统无法登录/启动", "config"),
    Rule("CFG-002", r"/etc/ssh/sshd_config",
         RiskLevel.HIGH, Action.CONFIRM, "修改 SSH 服务配置，可能影响远程登录安全，需确认", "config"),
    Rule("CFG-003", r">\s*/etc/(hosts|resolv\.conf)",
         RiskLevel.MEDIUM, Action.CONFIRM, "改写 hosts/DNS 解析，可能被用于流量劫持，需确认", "config"),
    Rule("CFG-004", r"\b(iptables\s+-F|systemctl\s+(stop|disable)\s+(firewalld|ufw))",
         RiskLevel.HIGH, Action.CONFIRM, "关闭/清空防火墙规则，暴露主机攻击面，需确认", "config"),

    # ---------- 注入类（也用于扫描用户输入 / 被当作上下文的文件内容）----------
    Rule("INJ-001", r"(忽略.*(以上|之前|前面).*(规则|指令|设定|提示)|ignore\s+(all\s+)?previous|disregard.*(rule|instruction)|forget.*(instruction|rule))",
         RiskLevel.HIGH, Action.DENY, "疑似提示词注入：指令覆盖（忽略既有规则）", "inject"),
    Rule("INJ-002", r"(你(现在)?(是|拥有|有了?)\s*root|拥有\s*root\s*权限|你(现在)?(可以|能)做任何|没有任何限制|developer\s*mode|开发者模式|越狱|jailbreak|act\s+as\s+root)",
         RiskLevel.HIGH, Action.DENY, "疑似提示词注入：角色劫持/越权扮演", "inject"),
    Rule("INJ-003", r"(base64\s+-d|base64\s+--decode|xxd\s+-r)\s*\|\s*(sh|bash|zsh)",
         RiskLevel.CRITICAL, Action.DENY, "编码绕过执行：解码后直接管道给 shell", "inject"),
    Rule("INJ-004", r"(curl|wget)\s+\S+\s*\|\s*(sudo\s+)?(sh|bash|zsh)",
         RiskLevel.CRITICAL, Action.DENY, "下载即执行：远程脚本直接管道给 shell，极高风险", "inject"),
    Rule("INJ-005", r"[;&|]\s*(rm|mkfs|dd|chmod|chown)\s",
         RiskLevel.HIGH, Action.DENY, "命令拼接夹带危险指令（; && | 后接破坏性命令）", "inject"),
]


def normalize(cmd: str) -> str:
    """命令规范化，压缩绕过空间：去首尾空白、折叠多空格、去掉成对引号包裹。"""
    t = cmd.strip()
    # 去掉整体被引号包裹的情况，如 "rm -rf /" → rm -rf /
    if len(t) >= 2 and t[0] == t[-1] and t[0] in ("'", '"'):
        t = t[1:-1]
    return re.sub(r"\s+", " ", t.strip())


def match_rules(text: str) -> list[Rule]:
    """返回命中的规则列表。text 可以是候选命令，也可以是用户输入（查注入）。"""
    t = normalize(text)
    return [r for r in RULES if re.search(r.pattern, t, flags=re.IGNORECASE)]


def _is_under_critical(resolved: str) -> bool:
    for cp in CRITICAL_PATHS:
        if cp == "/":
            if resolved == "/":
                return True
        elif resolved == cp or resolved.startswith(cp + "/"):
            return True
    return False


def hits_critical_path(cmd: str) -> list[str]:
    """正则之外的第二重判断：对 rm 删除命令提取路径参数并 realpath 规范化，
    捕获 `rm -rf /etc/../etc`、相对路径、软链接绕过等正则难覆盖的变形。

    只针对 rm（删除不可逆，是路径绕过攻击的高价值目标）；chmod/chown 可恢复，
    且已被 PERM-* 规则覆盖，若也在此升级为 CRITICAL 会误杀单文件 chmod 等正常运维。

    返回命中的关键路径列表（规范化后落在 CRITICAL_PATHS 内的路径）。
    """
    t = normalize(cmd)
    try:
        tokens = shlex.split(t)
    except ValueError:
        tokens = t.split()
    if not tokens or tokens[0] != "rm":
        return []

    hits: list[str] = []
    for tok in tokens[1:]:
        if tok.startswith("-"):
            continue
        if not (tok.startswith("/") or tok.startswith(".") or tok.startswith("~") or "/" in tok):
            continue
        expanded = os.path.expanduser(tok)
        resolved = os.path.normpath(os.path.realpath(expanded))
        if _is_under_critical(resolved):
            hits.append(resolved)
    return hits
