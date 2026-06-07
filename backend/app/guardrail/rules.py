"""安全护栏规则库 —— 项目核心创新点（评分③ + 创新分）。

对 LLM 生成的候选命令做独立的二次过滤，不信任 LLM 输出。
即使 LLM 被诱导生成 rm -rf /，本规则库也必须独立拦下来，逻辑与 LLM 完全解耦。

规则覆盖六类，命令类（删除/权限/磁盘/提权/配置）每类 ≥3 条，外加注入类。
匹配兼顾变形：-rf / -fr / -r -f、绝对/相对路径、引号包裹、命令拼接。
正则之外再用 realpath 做路径规范化双重判断（见 engine.py 调用 hits_critical_path）。

【P2-1 可配置化 / 插件化】规则与关键路径抽到同目录 rules.yaml，支持运行时热加载
（reload_rules() / POST /guardrail/rules/reload / 前端「重新加载」按钮）——增改规则只改 YAML，
不改代码、不重启进程，呼应赛题「插件化架构」。但「可配置 ≠ 可削弱护栏」，靠两条安全不变量保证：

  1. 红线兜底（_REDLINE_RULES）：CRITICAL+DENY 的绝命规则（删库/格式化/dd 覆盖磁盘/篡改 sudoers/
     下载即执行…）硬编码在本文件，加载时强制覆盖 YAML 中同 id 的项、并补回被删的项。
     即在 YAML 里把红线调松或删掉【无效】——配置层动不了核心红线。
  2. 故障安全（fail-safe，不是 fail-open）：YAML 缺失/损坏/任一规则校验不过（字段缺失、枚举非法、
     正则编不过、id 重复）→【拒绝换入】，维持上一份已生效规则；进程刚启动尚无规则时退回红线兜底集。
     护栏绝不因一次坏配置出现空窗或缺口。

扩展规则前务必读 .claude/skills/safety-guardrail/SKILL.md。
"""
from __future__ import annotations

import logging
import os
import re
import shlex
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


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


# rm 的递归强制标志变形：-rf / -fr / --recursive --force / -r -f
_RF = r"(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|-r\s+-f|-f\s+-r|--recursive|--force)"

# ---------------------------------------------------------------------------
# 安全不变量 1：红线兜底集（硬编码，不可被 YAML 配置削弱或删除）
# 选取标准：风险 CRITICAL 且动作 DENY 的「绝命操作」——一旦放行即不可逆的系统/数据灾难。
# 加载时这些规则会强制覆盖 YAML 中的同 id 项，并补回 YAML 里被删掉的项（见 _merge_redlines）。
# ---------------------------------------------------------------------------
_REDLINE_RULES: list[Rule] = [
    Rule("DEL-001", rf"\brm\s+{_RF}\s+/(\s|$)",
         RiskLevel.CRITICAL, Action.DENY, "递归强制删除根目录，将摧毁整个系统", "delete"),
    Rule("DEL-002", rf"\brm\s+.*{_RF}.*\s/\*",
         RiskLevel.CRITICAL, Action.DENY, "删除根目录下所有内容（/*），等同摧毁系统", "delete"),
    Rule("DEL-003", r"\brm\s+.*(/etc|/boot|/usr|/bin|/sbin|/lib|/var/lib/mysql|/var/lib/postgresql)(/|\s|\*|$)",
         RiskLevel.CRITICAL, Action.DENY, "删除涉及系统关键目录或数据库数据目录", "delete"),
    Rule("DISK-001", r"\bmkfs(\.\w+)?\s",
         RiskLevel.CRITICAL, Action.DENY, "格式化文件系统，将清空目标设备数据", "disk"),
    Rule("DISK-002", r"\bdd\s+.*of=/dev/(sd|nvme|vd|hd|mmcblk)",
         RiskLevel.CRITICAL, Action.DENY, "用 dd 直接写裸块设备，将覆盖磁盘数据", "disk"),
    Rule("DISK-003", r">\s*/dev/(sd|nvme|vd|hd)",
         RiskLevel.CRITICAL, Action.DENY, "重定向覆写块设备，将损坏磁盘/分区", "disk"),
    Rule("PRIV-003", r"(>>?\s*/etc/sudoers|\bvisudo\b|usermod\s+.*-aG?\s+(sudo|wheel|root))",
         RiskLevel.CRITICAL, Action.DENY, "篡改 sudoers / 提权用户组，严重权限越界", "privilege"),
    Rule("PRIV-004", r"\b(useradd|adduser)\s+.*(-u\s*0|--uid\s*0)",
         RiskLevel.CRITICAL, Action.DENY, "创建 UID=0 的等价 root 账户，提权后门", "privilege"),
    # P0-A：kill 命中 PID 1（init/systemd）或 PID -1（所有进程）→ 全系统崩溃，红线拒绝。
    # 信号旗标（-9 / -s KILL）被前段吞掉，只在目标位精确匹配 1 / -1，绝不误伤 kill 12345。
    Rule("KILL-001", r"\bkill\b(\s+-(\w+|s\s+\w+))*\s+(--\s+)?-?1(\s|$)",
         RiskLevel.CRITICAL, Action.DENY,
         "向 PID 1(init/systemd) 或 PID -1(所有进程) 发送信号，会导致系统/会话整体崩溃", "privilege"),
    Rule("CFG-001", r">\s*/etc/(passwd|shadow|fstab|sudoers|group|gshadow)",
         RiskLevel.CRITICAL, Action.DENY, "改写系统关键配置文件，可致系统无法登录/启动", "config"),
    Rule("INJ-003", r"(base64\s+-d|base64\s+--decode|xxd\s+-r)\s*\|\s*(sh|bash|zsh)",
         RiskLevel.CRITICAL, Action.DENY, "编码绕过执行：解码后直接管道给 shell", "inject"),
    Rule("INJ-004", r"(curl|wget)\s+\S+\s*\|\s*(sudo\s+)?(sh|bash|zsh)",
         RiskLevel.CRITICAL, Action.DENY, "下载即执行：远程脚本直接管道给 shell，极高风险", "inject"),
]

# YAML 缺失/损坏时退回的关键路径兜底集（与 rules.yaml 的 critical_paths 保持一致）
_FALLBACK_CRITICAL_PATHS: list[str] = [
    "/", "/etc", "/var", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/root", "/var/lib/mysql", "/var/lib/postgresql", "/var/lib/docker",
]

RULES_YAML_PATH = Path(__file__).with_name("rules.yaml")

# ---------------------------------------------------------------------------
# 运行时生效的规则集与关键路径：以「原地修改 list」的方式热加载（见 reload_rules），
# 这样已经 `from .rules import RULES` 的模块持有的引用始终指向最新内容，无需重新 import。
# ---------------------------------------------------------------------------
RULES: list[Rule] = []
CRITICAL_PATHS: list[str] = []

# 最近一次加载状态，供 /guardrail/rules/reload 与状态查询回报
_load_status: dict = {"source": "fallback", "count": 0, "errors": [], "applied": False}

_VALID_RISKS = {r.value for r in RiskLevel}
_VALID_ACTIONS = {a.value for a in Action}


def _parse_rule(d: object) -> Rule:
    """把 YAML 里的一条规则映射校验并转成 Rule；任何不合规都抛 ValueError。"""
    if not isinstance(d, dict):
        raise ValueError("规则项必须是映射（含 id/pattern/risk/action/description/category）")
    missing = [k for k in ("id", "pattern", "risk", "action", "description", "category")
               if d.get(k) in (None, "")]
    if missing:
        raise ValueError(f"缺少必填字段：{', '.join(missing)}")

    risk_raw = str(d["risk"]).strip().lower()
    if risk_raw not in _VALID_RISKS:
        raise ValueError(f"risk 非法：{d['risk']!r}（应为 critical/high/medium/low）")
    action_raw = str(d["action"]).strip().lower()
    if action_raw not in _VALID_ACTIONS:
        raise ValueError(f"action 非法：{d['action']!r}（应为 deny/confirm/allow）")

    pattern = str(d["pattern"])
    try:
        re.compile(pattern)
    except re.error as e:
        raise ValueError(f"正则编译失败：{e}")

    return Rule(str(d["id"]).strip(), pattern, RiskLevel(risk_raw), Action(action_raw),
                str(d["description"]).strip(), str(d["category"]).strip())


def _read_yaml_rules(path: Path) -> tuple[list[Rule], list[str], list[str]]:
    """读取并整体校验 YAML，返回 (rules, critical_paths, errors)。errors 非空即视为不可用。"""
    path = Path(path)
    if not path.exists():
        return [], [], [f"规则配置文件不存在：{path}"]
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        return [], [], [f"YAML 解析失败：{e}"]
    if not isinstance(raw, dict):
        return [], [], ["规则配置根节点必须是映射（含 rules / critical_paths 两个键）"]

    errors: list[str] = []
    rules: list[Rule] = []
    seen: set[str] = set()
    for i, item in enumerate(raw.get("rules") or [], start=1):
        try:
            r = _parse_rule(item)
        except ValueError as e:
            errors.append(f"第 {i} 条规则无效：{e}")
            continue
        if r.id in seen:
            errors.append(f"规则 id 重复：{r.id}")
            continue
        seen.add(r.id)
        rules.append(r)

    cps_raw = raw.get("critical_paths")
    if cps_raw is None:
        cps: list[str] = []
    elif isinstance(cps_raw, list) and all(isinstance(c, str) and c for c in cps_raw):
        cps = list(cps_raw)
    else:
        errors.append("critical_paths 必须是非空字符串的列表")
        cps = []

    if not rules and not errors:
        errors.append("配置中未定义任何规则（rules 为空）")
    return rules, cps, errors


def _merge_redlines(rules: list[Rule]) -> list[Rule]:
    """安全不变量 1：红线规则用硬编码版本强制覆盖 YAML 同 id 项，并补回被删的红线。
    保持 YAML 给出的顺序，仅替换/追加，使配置层无法把核心红线调松或删除。"""
    redline = {r.id: r for r in _REDLINE_RULES}
    out: list[Rule] = []
    seen: set[str] = set()
    for r in rules:
        out.append(redline.get(r.id, r))   # 同 id 是红线 → 强制用硬编码版本
        seen.add(r.id)
    for rid, r in redline.items():
        if rid not in seen:                # YAML 删掉了某条红线 → 强制补回
            out.append(r)
    return out


def load_rules(path: Path = RULES_YAML_PATH) -> tuple[list[Rule], list[str], list[str]]:
    """加载并校验规则。
    成功 → (合并红线后的规则, critical_paths, [])；
    失败 → (红线兜底集, 兜底关键路径, errors)。本函数不改全局状态，便于测试与预检。"""
    rules, cps, errors = _read_yaml_rules(path)
    if errors:
        return list(_REDLINE_RULES), list(_FALLBACK_CRITICAL_PATHS), errors
    return _merge_redlines(rules), (cps or list(_FALLBACK_CRITICAL_PATHS)), []


def reload_rules(path: Path = RULES_YAML_PATH) -> dict:
    """热加载：重新读 YAML 并（仅在校验通过时）原地换入当前规则集，返回加载状态。

    安全不变量 2（故障安全）：校验不过时【不换入】、维持现有规则；仅当进程刚启动、
    尚无任何规则时才退回红线兜底集兜住，护栏绝不出现空窗。原地改 list 而非重新赋值，
    避免已 `import RULES` 的模块拿到旧引用。
    """
    rules, cps, errors = load_rules(path)
    applied = (not errors) or (not RULES)   # 校验过→换入；启动期无规则→用兜底兜住
    if applied:
        RULES[:] = rules
        CRITICAL_PATHS[:] = cps
    _load_status.update(
        source=("yaml" if not errors else "fallback"),
        count=len(RULES),
        errors=errors,
        applied=applied,
    )
    if errors:
        logger.warning("规则热加载校验未通过（%s），维持现有 %d 条规则：%s",
                       path, len(RULES), "；".join(errors))
    return dict(_load_status)


def load_status() -> dict:
    """最近一次加载状态：{source, count, errors, applied}，供接口/前端展示。"""
    return dict(_load_status)


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


# P0-A：把 realpath 路径兜底从「只管 rm」推广到**一组不可逆的数据销毁动词**。
# 选取标准——操作即**不可逆数据丢失/覆写**，且其文件操作数就是销毁目标：
#   rm/unlink/rmdir 删除、shred 粉碎、truncate 截断、tee 覆写、dd 块写、mkfs 格式化、find -delete。
# **刻意不纳入 chmod/chown/chgrp/mv/cp**：前者是可恢复的元数据变更（危险变形 chmod 777 / 递归改权
#   已被 PERM-001/002/003 覆盖），把单文件 `chmod 644 /etc/hosts` 升级为 CRITICAL 会误杀常规运维、
#   破坏本项目「误杀率 0%」的硬指标；后者(mv/cp/install) 操作数兼有「源(只读)/目的(写)」二义性，
#   一律按目标拦会对读源产生假阳性。这是「保守合并取更严」的**有判断的**落地，非黑名单跑步机。
#   详见 docs/dev-log.md 与 docs/security-design.md「为何不把 chmod/chown 一并升级 CRITICAL」。
_DESTRUCTIVE_PATH_VERBS = {"rm", "unlink", "rmdir", "shred", "truncate", "tee"}
# find 的销毁动作（-delete / -exec rm 等）才触发路径兜底；只读 find 不受影响。
_FIND_EXEC_DESTRUCTIVE = {"rm", "unlink", "shred", "truncate", "dd", "mkfs"}


def _looks_like_path(tok: str) -> bool:
    return tok.startswith(("/", ".", "~")) or "/" in tok


def _plain_path_operands(args: list[str]) -> list[str]:
    """取像路径的操作数：跳过旗标与非路径取值（如 truncate -s 0 里的 0）。"""
    return [a for a in args if not a.startswith("-") and _looks_like_path(a)]


def _find_is_destructive(tokens: list[str]) -> bool:
    """find 表达式是否含 -delete 或 -exec/-execdir 接销毁命令。"""
    if "-delete" in tokens:
        return True
    for i, tk in enumerate(tokens):
        if tk in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(tokens):
            if os.path.basename(tokens[i + 1]) in _FIND_EXEC_DESTRUCTIVE:
                return True
    return False


def _destruction_operands(tokens: list[str]) -> list[str]:
    """按动词取「真正会被销毁/覆写」的路径操作数；非销毁动词或只读 find 返回空。"""
    verb = os.path.basename(tokens[0])
    rest = tokens[1:]
    if verb in _DESTRUCTIVE_PATH_VERBS:
        return _plain_path_operands(rest)
    if verb == "dd":                                   # dd 只有 of=PATH 是写目标
        return [a[len("of="):] for a in rest if a.startswith("of=")]
    if verb == "mkfs" or verb.startswith("mkfs."):
        return _plain_path_operands(rest)
    if verb == "find":
        return _plain_path_operands(rest) if _find_is_destructive(tokens) else []
    return []


def hits_critical_path(cmd: str) -> list[str]:
    """正则之外的第二重判断：对**不可逆数据销毁动词**提取路径操作数并 realpath 规范化，
    捕获 `rm -rf /etc/../etc`、`truncate -s 0 /etc/passwd`、`find / -delete`、相对路径、
    软链接绕过等正则难覆盖的变形。动词集与取舍见 _DESTRUCTIVE_PATH_VERBS 注释。

    返回命中的关键路径列表（规范化后落在 CRITICAL_PATHS 内的路径）。
    """
    t = normalize(cmd)
    try:
        tokens = shlex.split(t)
    except ValueError:
        tokens = t.split()
    if not tokens:
        return []

    hits: list[str] = []
    for tok in _destruction_operands(tokens):
        expanded = os.path.expanduser(tok)
        resolved = os.path.normpath(os.path.realpath(expanded))
        if _is_under_critical(resolved):
            hits.append(resolved)
    return hits


# 进程启动即从 YAML 加载一次；失败则退回红线兜底集（永不空窗）。
reload_rules()
