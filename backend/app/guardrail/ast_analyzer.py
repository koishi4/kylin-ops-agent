"""护栏防线2 增强：Bash 语法树（AST）结构分析 —— 正面回答评委必问的「你的正则能被变形绕过吗」。

正则规则库（rules.py）快、确定、可解释，但本质是「字符串模式匹配」，对**语法结构**层面的
变形天然吃力：把危险命令藏进命令替换 `$(...)`、用管道喂给 shell `... | sh`、把第二条命令
拼在 `;`/`&&` 之后、用进程替换 `<(...)` 引入额外执行……这些都能让「按字面写正则」的规则
出现盲区。本模块用 **bashlex**（纯 Python 解析器，无原生编译，LoongArch 无障碍）把命令解析成
语法树，从**结构**而非字面去识别这些高危构造。

与执行模型对齐的关键判断（这是本模块的设计灵魂）：
executor.py 执行时用 `shlex.split + shell=False`，根本不经过 shell。也就是说——
**一条命令但凡依赖 shell 解释结构（管道/重定向/命令替换/命令链/子shell），要么不会按预期执行、
要么本身就是注入/绕过信号**。因此本模块的裁决基调是：
  - 检出任何 shell 结构 → 至少升级为 CONFIRM（需分解为结构化工具或显式确认）；
  - 检出危险结构（管道接 shell、重定向写块设备/关键配置、子命令命中红线规则）→ 升级为 DENY。

保守合并：本模块只产出「结构发现」，由 engine.check_command 把发现并入规则裁决并**取更严**，
AST 只能把判定变严，绝不能把规则已判的 CRITICAL/DENY 放松（见 engine._merge / 安全不变量）。

故障安全：bashlex 对某些构造会抛异常——**捕获并保守处理**（视为「无法解析的可疑命令」→ 至少
CONFIRM），绝不因解析失败而崩溃或放行。
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

import bashlex

from .rules import Action, RiskLevel, Rule, match_rules

# 真 shell 名单：管道下游是它们（`curl … | sh`）即经典「下载/解码即执行」，极高危 → CRITICAL。
_PIPE_SHELL_TARGETS = {"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "ash"}
# 通用解释器（python/perl/…）：piped 时**只有**把 stdin 当代码执行（裸调用 / 无 -e/-c 程序、无脚本
# 文件）才算 download-exec；带 `-e/-c '程序'` 的是把上游当**数据**处理（`ls | perl -pe 's/a/b/'`、
# `df | awk '{...}'`），绝非 download-exec——把它们也判 CRITICAL 是实测误杀的主因（benign held-out）。
_GENERAL_INTERPRETERS = {"perl", "ruby", "node", "nodejs", "php", "lua"}  # python* 另按前缀判

# P0-A：解释器 + 内联代码的「结构性高危」识别。
# 真实绕过的根源：executor 用 shlex.split + shell=False，`bash -c "rm -rf /"` 会被拆成
# argv ['bash','-c','rm -rf /'] 真的执行——而整串正则因 `/"` 收尾失配、bashlex 也不会去解析
# `-c` 后那段引号字符串（内层可为 python/perl，语言不定、内容无界，无法静态可信审查）。
# 因此把「解释器携带内联代码」这个**结构事实本身**当高危信号，不去解析内层（见模块文档/security-design）。
_SHELL_NAMES = {"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "ash"}
# 命令首词若匹配它即视为解释器（python3/python2.7 等带版本号一并覆盖）。
# eval 纳入：`eval STRING` 把其参数拼成命令在当前 shell 执行——是「就地执行任意代码」的典型构造，
# 与 `bash -c` 同类（评审「一.1」实测盲区：此前 eval 不在名单 → `eval "rm -rf /"` 被清白放行）。
_INTERPRETER_RE = re.compile(
    r"^(sh|bash|zsh|dash|ksh|csh|tcsh|ash|python[0-9.]*|perl|ruby|node|nodejs|php|lua|awk|eval)$")

# 重定向写入这些目标即灾难：块设备（覆写磁盘）/ 系统关键路径（越权改配置）。
_BLOCK_DEV_RE = re.compile(r"^/dev/(sd|nvme|vd|hd|mmcblk|loop|dm-|md)")
_CRITICAL_WRITE_RE = re.compile(r"^/(etc|boot|sys|proc|usr|bin|sbin|lib|lib64|root)(/|$)")

# 对这些命令使用作用于关键路径的通配符，影响面不可控（rm/chmod/chown/chgrp + 关键路径 glob）。
_GLOB_CMDS = {"rm", "chmod", "chown", "chgrp"}
# 调用某命令时应跳过的前缀词（取「真正被执行的命令」）。
_SKIP_WORDS = {"sudo", "env", "command", "nice", "nohup", "time", "exec"}


@dataclass(frozen=True)
class AstFinding:
    """一条 AST 结构发现。risk/action 与 rules.RiskLevel/Action 对齐，便于并入规则裁决。"""

    structure: str       # 结构类型代码，如 pipe_to_shell / command_substitution
    risk: RiskLevel      # 该结构的风险等级
    action: Action       # 命中后动作（deny / confirm）
    reason: str          # 人类可读原因

    def to_dict(self) -> dict:
        """序列化为 dict，供 engine 合并与前端「AST 结构分析」栏展示。"""
        return {
            "structure": self.structure,
            "risk": self.risk.value,
            "action": self.action.value,
            "reason": self.reason,
        }


@dataclass
class AstFindings:
    """一次 AST 结构分析的完整结论，供 engine 合并裁决、供前端思维链「AST 结构分析」栏展示。"""

    parse_ok: bool
    findings: list[AstFinding]
    parse_error: str = ""

    @property
    def has_shell_structure(self) -> bool:
        """是否检出任何 shell 解释结构（含解析失败的保守判定）。"""
        return bool(self.findings)

    @property
    def max_risk(self) -> RiskLevel:
        """所有 AST 发现中的最高风险等级（无发现时为 LOW）。"""
        if not self.findings:
            return RiskLevel.LOW
        return max((f.risk for f in self.findings), key=lambda r: r.order)

    def to_dict(self) -> dict:
        """序列化整次 AST 分析为 dict（含 has_shell_structure / max_risk 派生字段）。"""
        return {
            "parse_ok": self.parse_ok,
            "parse_error": self.parse_error,
            "has_shell_structure": self.has_shell_structure,
            "max_risk": self.max_risk.value if self.findings else None,
            "findings": [f.to_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------- #
# 语法树遍历                                                                     #
# --------------------------------------------------------------------------- #

def _node_text(node, src: str) -> str:
    """用节点在原串中的 pos 切回原文（最忠实的子命令重建，供对子命令复跑规则）。"""
    try:
        return src[node.pos[0]:node.pos[1]]
    except (AttributeError, TypeError, IndexError):
        return ""


def _words(node) -> list[str]:
    return [p.word for p in getattr(node, "parts", []) if getattr(p, "kind", "") == "word"]


def _cmd_and_args(node) -> tuple[str, list[str]]:
    """拆出命令的「真正可执行名」basename 与其后参数（跳过 sudo/env/赋值前缀）。"""
    cmd = ""
    args: list[str] = []
    for w in _words(node):
        if not cmd:
            if "=" in w.split("/")[-1] and not w.startswith("/"):  # FOO=bar 前置赋值
                continue
            base = os.path.basename(w)
            if base in _SKIP_WORDS:
                continue
            cmd = base
        else:
            args.append(w)
    return cmd, args


def _effective_cmd(node) -> str:
    """命令的「真正可执行名」basename：跳过 sudo/env/赋值前缀，取第一个实命令词。"""
    return _cmd_and_args(node)[0]


def _has_inline_code(cmd: str, args: list[str]) -> bool:
    """判断「解释器 + 内联代码」：按解释器家族识别其「就地执行代码」的旗标或位置程序串。

    不解析内层代码（语言不定、内容无界，静态无法可信审查）——结构事实本身即信号。
    """
    aset = set(args)

    def short_has(ch: str) -> bool:  # 组合短旗标里含某字母，如 -lc / -xec
        return any(re.fullmatch(rf"-[a-z]*{ch}[a-z]*", a) for a in args)

    if cmd in _SHELL_NAMES:                       # sh/bash… -c CMD、-s/读 stdin
        return short_has("c") or "--command" in aset or "-s" in aset or "-" in aset
    if cmd.startswith("python"):                  # python -c CODE、python - (stdin)
        return "-c" in aset or "--command" in aset or "-" in aset
    if cmd == "perl":                             # perl -e/-E CODE
        return short_has("e") or "-E" in aset
    if cmd == "ruby":                             # ruby -e CODE
        return short_has("e")
    if cmd in ("node", "nodejs"):                 # node -e/--eval/-p/--print CODE
        return bool(aset & {"-e", "--eval", "-p", "--print"})
    if cmd == "php":                              # php -r CODE
        return "-r" in aset
    if cmd == "lua":                              # lua -e CODE
        return "-e" in aset
    if cmd == "awk":                              # awk '程序串'（除非 -f 指定脚本文件）
        return "-f" not in aset and any(not a.startswith("-") for a in args)
    if cmd == "eval":                             # eval STRING…：任意非旗标参数都是待执行代码
        return any(not a.startswith("-") for a in args)
    return False


def _is_shell_interp(cmd: str) -> bool:
    """真 shell 解释器 / eval —— 内联即「就地执行任意 shell 命令」，CRITICAL 不可降。"""
    return cmd in _PIPE_SHELL_TARGETS or cmd == "eval"


def _is_general_interp(cmd: str) -> bool:
    """通用编程解释器（python*/perl/ruby/node/php/lua）：内联能力强，但海量良性一行流亦如此。"""
    return cmd.startswith("python") or cmd in _GENERAL_INTERPRETERS


# awk「就地 shell-out」信号：调用 system()/getline，或把 print 管道给外部命令（`| "cmd"`）。
# 纯字段处理（`{print $2}`、`{s+=$0}`）无这些信号——故 awk 默认不判危，消除实测误杀。
_AWK_SHELLOUT_RE = re.compile(r"system\s*\(|\bgetline\b|\|\s*\"")


def _check_interpreter_inline(node, out: list[AstFinding]) -> None:
    """命令首词是解释器且携带内联代码 → 结构性高危，按解释器能力分级裁决。

    （评审整改：精准化，消除「把 awk/perl 文本一行流一律判 CRITICAL」的实测误杀，benign held-out 实证。）

    - 真 shell（sh/bash/…）/ eval 内联：就地执行任意 shell 命令 → CRITICAL/DENY（不可降，硬拦）。
    - 通用解释器（python/perl/ruby/…）-e/-c 内联：能力强但海量良性一行流亦如此 → HIGH/DENY
      （仍拦截，但属"需显式授权"而非"灾难级硬拒"：合法操作者授权后可执行；红队最坏模型下仍被遏制）。
    - awk：文本处理器，**默认不判危**；仅当程序串 system()/getline/管道外部命令（真 shell-out）才 HIGH/DENY。
    （注：awk 写关键配置 `awk 'print > "/etc/passwd"'` 仍由正则 CFG-001 经规范化兜住，不依赖本层。）
    """
    cmd, args = _cmd_and_args(node)
    if not cmd or not _INTERPRETER_RE.fullmatch(cmd):
        return

    if cmd == "awk":
        prog = " ".join(a for a in args if not a.startswith("-"))
        if _AWK_SHELLOUT_RE.search(prog):
            out.append(AstFinding(
                "interpreter_shellout", RiskLevel.HIGH, Action.DENY,
                "awk 程序调用 system()/getline/管道外部命令（就地 shell-out），按最小权限需显式授权"))
        return

    if not _has_inline_code(cmd, args):
        return

    if _is_shell_interp(cmd):
        out.append(AstFinding(
            "interpreter_inline_code", RiskLevel.CRITICAL, Action.DENY,
            f"shell 解释器 {cmd} 携带内联代码（-c/eval/读 stdin）：就地执行任意 shell 命令，"
            "内层内容无界、静态不可信审查，按结构性灾难级拒绝。请改用结构化工具或受审计脚本文件。"))
    else:
        out.append(AstFinding(
            "interpreter_inline_code", RiskLevel.HIGH, Action.DENY,
            f"通用解释器 {cmd} 携带内联代码（-e/-c/程序串）：可就地执行任意代码（含 system 调用），"
            "按最小权限需显式授权后方可执行；勿向 Agent 下发自由形态解释器命令。"))


def _children(node) -> list:
    """兜底：列出节点下所有子 AST 节点，供未显式处理的 kind 继续下探（绝不漏掉藏在里面的命令）。"""
    out = []
    for attr in ("parts", "list", "command", "output", "heredoc"):
        v = getattr(node, attr, None)
        if isinstance(v, list):
            out.extend(x for x in v if hasattr(x, "kind"))
        elif hasattr(v, "kind"):
            out.append(v)
    return out


def _glob_on_critical(arg: str) -> bool:
    """判断带通配符的参数是否作用于关键路径（根级 `/​*` 或 /etc /usr… 下的批量匹配）。"""
    if not arg.startswith("/"):
        return False
    head = re.split(r"[*?\[]", arg, maxsplit=1)[0]          # 通配符前的固定前缀
    head_dir = head if head.endswith("/") else os.path.dirname(head)
    norm = os.path.normpath(head_dir or "/")
    if norm == "/":                                          # 根级通配：/* 、/*.bak
        return True
    return bool(_CRITICAL_WRITE_RE.match(norm + ("" if norm.endswith("/") else "/")))


def _handle_redirect(part, out: list[AstFinding]) -> None:
    rtype = getattr(part, "type", "") or ""
    if rtype in ("<<", "<<<") or getattr(part, "heredoc", None) is not None:
        out.append(AstFinding("heredoc", RiskLevel.MEDIUM, Action.CONFIRM,
                              "here-doc / here-string 注入多行内容（常用于写文件），依赖 shell，需确认"))
        return
    if not rtype.startswith(">"):       # 仅关注输出重定向；输入 `<` 读文件风险低
        return
    out_node = getattr(part, "output", None)
    target = getattr(out_node, "word", "") if out_node is not None else ""
    if not target:
        return
    norm = os.path.normpath(target)
    if _BLOCK_DEV_RE.match(norm):
        out.append(AstFinding("redirect_to_device", RiskLevel.CRITICAL, Action.DENY,
                              f"重定向覆写块设备 {target}，将损坏磁盘/分区数据"))
    elif _CRITICAL_WRITE_RE.match(norm):
        out.append(AstFinding("redirect_to_critical", RiskLevel.HIGH, Action.DENY,
                              f"重定向写入系统关键路径 {target}，可致系统损坏或越权改配置"))
    else:
        out.append(AstFinding("redirect_write", RiskLevel.MEDIUM, Action.CONFIRM,
                              f"重定向写文件 {target}，依赖 shell 解释，需确认"))


def _check_dangerous_glob(node, out: list[AstFinding]) -> None:
    words = _words(node)
    if not words or _effective_cmd(node) not in _GLOB_CMDS:
        return
    for w in words[1:]:
        if ("*" in w or "?" in w) and _glob_on_critical(w):
            out.append(AstFinding("dangerous_glob", RiskLevel.HIGH, Action.DENY,
                                  f"对关键路径使用通配符（{w}）批量删除/改权限，影响面不可控"))


def _handle_command(node, src: str, nested: bool, out: list[AstFinding]) -> None:
    # 1) 重定向
    for part in getattr(node, "parts", []):
        kind = getattr(part, "kind", "")
        if kind == "redirect":
            _handle_redirect(part, out)
        elif kind == "word":
            for sub in getattr(part, "parts", []) or []:   # 词内可能藏命令替换/进程替换
                _walk(sub, src, True, out)
    # 2) 危险 glob
    _check_dangerous_glob(node, out)
    # 2.5) 解释器 + 内联代码（P0-A 主修绕过：bash -c "rm -rf /" / python3 -c "…"）
    _check_interpreter_inline(node, out)
    # 3) 对被 shell 结构包裹的子命令复跑正则规则——这正是「正则漏网、AST 抓到」的来源：
    #    形如 echo $(rm -rf /) 的整串正则会因相邻标点错位而漏判，但隔离出的子命令必命中红线。
    if nested:
        text = _node_text(node, src).strip()
        hits = match_rules(text)
        if hits:
            top = max(hits, key=lambda r: r.risk.order)
            out.append(AstFinding("nested_dangerous_command", top.risk, top.action,
                                  f"被 shell 结构包裹的子命令命中规则 [{top.id}]：{top.description}"
                                  f"（子命令原文：{text}）"))


# 解释器「携带内联程序串」的旗标：带程序串 = 把 stdin 当**数据**处理，不是把 stdin 当**代码**执行。
_PROGRAM_FLAGS_LONG = {"--command", "--eval", "--print"}


def _interp_has_program(args: list[str]) -> bool:
    """解释器参数里是否带内联程序（-c/-e/-r/--eval/… 或组合短旗标含 c/e/r，含 perl -l40pe0 粘连写法）。"""
    for a in args:
        if a in _PROGRAM_FLAGS_LONG:
            return True
        if a.startswith("-") and not a.startswith("--") and any(ch in a[1:] for ch in "cer"):
            return True
    return False


def _pipe_reads_stdin_as_code(cmd: str, args: list[str]) -> bool:
    """管道下游命令是否构成「上游输出即被执行」(curl|sh / curl|python 范式)。

    - 真 shell（sh/bash/…）：永远是 download-exec。
    - 通用解释器（python/perl/…）：**仅当**把 stdin 当代码执行——无内联程序(-e/-c)、无脚本文件操作数
      （裸调用 / `python -` 读 stdin）——才算。带 `-e/-c '程序'`（`ls | perl -pe 's/a/b/'`、
      `df | awk` 走另路）是把上游当**数据**处理，不是 download-exec。这条精准区分是消除实测误杀的关键。
    """
    if cmd in _PIPE_SHELL_TARGETS:
        return True
    if not _is_general_interp(cmd):
        return False
    if _interp_has_program(args):
        return False
    has_script_file = any(not a.startswith("-") for a in args)
    return not has_script_file


def _handle_pipeline(node, src: str, nested: bool, out: list[AstFinding]) -> None:
    cmds = [p for p in node.parts if getattr(p, "kind", "") == "command"]
    out.append(AstFinding("pipeline", RiskLevel.MEDIUM, Action.CONFIRM,
                          "管道 | 串联多条命令、依赖 shell 解释（executor 为 shell=False，不会按预期执行），需分解或确认"))
    for i, c in enumerate(cmds):
        if i > 0:
            ccmd, cargs = _cmd_and_args(c)
            if _pipe_reads_stdin_as_code(ccmd, cargs):
                out.append(AstFinding("pipe_to_shell", RiskLevel.CRITICAL, Action.DENY,
                                      f"管道把上游输出直接喂给 {ccmd} 执行（下载/解码即执行范式），极高风险"))
        _walk(c, src, nested or i > 0, out)


def _handle_list(node, src: str, nested: bool, out: list[AstFinding]) -> None:
    ops = sorted({p.op for p in node.parts if getattr(p, "kind", "") == "operator"})
    out.append(AstFinding("command_chain", RiskLevel.MEDIUM, Action.CONFIRM,
                          f"命令链（{'、'.join(ops) or ';'}）串联多条命令，需对每条分别裁决/确认"))
    for i, p in enumerate(node.parts):
        if getattr(p, "kind", "") in ("command", "pipeline", "compound"):
            _walk(p, src, nested or i > 0, out)   # 链上第 2 条起视为「拼接其后」的子命令


def _walk(node, src: str, nested: bool, out: list[AstFinding]) -> None:
    kind = getattr(node, "kind", "")
    if kind == "pipeline":
        _handle_pipeline(node, src, nested, out)
    elif kind == "list":
        _handle_list(node, src, nested, out)
    elif kind == "compound":
        out.append(AstFinding("subshell", RiskLevel.MEDIUM, Action.CONFIRM,
                              "子 shell / 命令组 (...) 改变执行上下文，可隐藏副作用，需确认"))
        for child in getattr(node, "list", []):
            _walk(child, src, True, out)
    elif kind == "command":
        _handle_command(node, src, nested, out)
    elif kind == "commandsubstitution":
        out.append(AstFinding("command_substitution", RiskLevel.HIGH, Action.CONFIRM,
                              "命令替换 $(...) / 反引号 可隐藏二次执行，需确认其内部命令"))
        _walk(node.command, src, True, out)
    elif kind == "processsubstitution":
        out.append(AstFinding("process_substitution", RiskLevel.HIGH, Action.CONFIRM,
                              "进程替换 <(...) >(...) 引入额外命令执行，需确认"))
        _walk(node.command, src, True, out)
    else:
        for child in _children(node):          # 未显式处理的 kind：兜底下探，绝不漏掉藏着的命令
            _walk(child, src, nested, out)


def _dedup(findings: list[AstFinding]) -> list[AstFinding]:
    seen: set[tuple[str, str]] = set()
    out: list[AstFinding] = []
    for f in findings:
        key = (f.structure, f.reason)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def analyze_command_ast(cmd: str) -> AstFindings:
    """把命令解析成 Bash 语法树并识别高危结构。

    解析失败 → 返回 parse_ok=False、并带一条 CONFIRM 级「无法解析」发现（保守，绝不放行）。
    解析成功但遍历中出现意外 → 同样兜底为 CONFIRM，绝不崩溃。
    """
    text = (cmd or "").strip()
    if not text:
        return AstFindings(parse_ok=True, findings=[])
    try:
        trees = bashlex.parse(text)
    except Exception as e:  # noqa: BLE001 bashlex 的多种解析异常 + 任何意外都保守兜底
        return AstFindings(
            parse_ok=False,
            findings=[AstFinding("unparseable", RiskLevel.MEDIUM, Action.CONFIRM,
                                 f"命令含无法解析的 shell 构造（{type(e).__name__}），"
                                 "保守按『需确认』处理，绝不放行")],
            parse_error=str(e),
        )
    out: list[AstFinding] = []
    try:
        for t in trees:
            _walk(t, text, False, out)
    except Exception as e:  # noqa: BLE001 遍历意外也兜底为需确认，绝不崩溃/放行
        out.append(AstFinding("analysis_error", RiskLevel.MEDIUM, Action.CONFIRM,
                              f"AST 结构分析异常（{type(e).__name__}），保守按『需确认』处理"))
    return AstFindings(parse_ok=True, findings=_dedup(out))


def ast_synthetic_rules(findings: AstFindings) -> list[Rule]:
    """把 AST 发现转成合成规则，供 engine 并入 hits 走统一裁决（id 前缀 AST-，category=ast）。

    这样 AST 发现与正则规则共用同一套「取最高风险 + 授权/确认」裁决逻辑，天然保证：
    AST 只能把判定抬高，永远不会把规则已判的 CRITICAL/DENY 调低。
    """
    return [
        Rule(f"AST-{f.structure.upper()}", "", f.risk, f.action, f.reason, "ast")
        for f in findings.findings
    ]
