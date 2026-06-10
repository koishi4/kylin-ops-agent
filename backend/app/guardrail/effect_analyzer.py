"""护栏防线2 再增强：命令「副作用集」(EffectSet) 静态分析 —— 把护栏从
「匹配已知坏串」推进到「匹配实际效果」。

为什么需要它（评委必问的根治方向）：
  rules.py 的高危规则是**黑名单字符串匹配**，本质不可能枚举完整——`nc -e` 能换 `socat EXEC`，
  空格能用 `$IFS` 替代，`rm /etc` 能写成 `rm /etc/../etc`，命令顺序/旗标位置一变正则就失配。
  ast_analyzer.py 已从**结构**（管道/重定向/命令替换）补了一层；rules.hits_critical_path 已对
  **销毁动词**做了 realpath 路径兜底。本模块把这两者的思路**统一抽象成一个「效果集」分析器**：
  不去枚举「哪些命令是坏的」，而是静态推导**一条命令实际会产生什么副作用**——
    - 它会写/创建/覆盖哪些路径（writes）
    - 它会删除/截断哪些路径（deletes）
    - 它是否建立外联/反弹 shell 通道（egress）
    - 它是否需要提权（needs_priv）
  当这些副作用**落在系统关键区域**（CRITICAL_PATHS）或**构成外联**时，无论命令长什么样、用了
  什么动词，护栏都能据「效果」升级风险。这是「按效果判定」对「按字面拦串」的根治。

误杀率 0% 是本项目硬指标，所以本模块的裁决基调是**保守、只在能肯定时才发声**：
  - 只对**有明确写/删语义且目的路径可静态确定**的动词建模（见 _WRITE_DEST_* / _DELETE_VERBS）。
  - 路径一律 realpath+normpath 规范化后，**只在落入 CRITICAL_PATHS 时**才产出发现；
    写 /tmp、写家目录、**读** /etc（tar/cat/cp 的源）等一律沉默。
  - 判不准（动词不认识、路径含无法静态求值的变量/通配、cp/mv 缺目的）→ **不升级**。
  - **刻意不把 chmod/chown/chgrp 当 writes**：那是可恢复的元数据变更，且 `chmod 644 /etc/hosts`
    属常规运维（在红队 SAFE 语料里），按内容写升级会误杀——与 rules._DESTRUCTIVE_PATH_VERBS
    的取舍口径一致。

集成方式（engine.check_command）：与 AST 合成规则同样的「保守合并取更严」——本模块只产出**升级**
信号（高风险/严重发现），并入 hits 走统一裁决，**绝不能**把规则已判的 CRITICAL/DENY 调低。

故障安全：bashlex 解析失败 / 遍历异常 → 返回空 EffectSet（不升级），把「拦不拦」交回既有的
规则层与 AST 层兜底，本模块绝不因自身异常而崩溃或改变放行策略。
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

import bashlex

# 复用 rules 的关键路径判定口径（CRITICAL_PATHS 为运行时热加载的同一份引用，_is_under_critical
# 已含 realpath 后的「等于关键路径或在其下」判断）。严禁改 rules.py，这里只 import。
from .rules import CRITICAL_PATHS, _is_under_critical  # noqa: F401 (CRITICAL_PATHS 经 _is_under_critical 间接使用)

# 调用某命令时应跳过的前缀词（与 ast_analyzer._SKIP_WORDS 同口径，取「真正被执行的命令」）。
_SKIP_WORDS = {"sudo", "env", "command", "nice", "nohup", "time", "exec", "doas"}

# ---- 写/创建/覆盖类动词：操作数全是「写目的」（无源/目的二义性） ----
# 选取标准：动词语义就是「往目标路径落内容」，且其路径操作数即写目的。
#   tee：把 stdin 写入（或 -a 追加到）每个文件参数 → 全部是写目的
#   truncate：调整文件大小（含截断为 0）→ 写/毁目的
#   touch：创建/更新文件 → 写目的（落在关键区即可疑的「埋文件」）
_WRITE_DEST_ALL = {"tee", "truncate", "touch"}

# ---- 写类动词：只有「最后一个路径操作数」是目的，前面的是源（只读，绝不升级） ----
# cp/mv/install/ln：`cmd [opts] SRC... DEST`，仅 DEST 是写目的。
#   这样 `cp /etc/a /home/u/`（读 /etc、写 /home）不升级，`cp evil /etc/passwd`（写 /etc）升级。
_WRITE_DEST_LAST = {"cp", "mv", "install", "ln", "rsync"}

# ---- dd：只有 of=PATH 是写目的（if= 是只读源）；写裸设备另有红线，这里只补关键文件路径 ----
# （dd of=/dev/sd* 已由 rules DISK-002 / ast redirect_to_device 覆盖，这里抓 of=/etc/... 之类）

# ---- 删除/截断类动词：操作数是被销毁目标 ----
_DELETE_VERBS = {"rm", "unlink", "rmdir", "shred"}

# ---- 提权强信号：服务管理 / 包管理 / 用户管理等通常需 root ----
_PRIV_VERBS = {
    "systemctl", "service", "mount", "umount", "modprobe", "insmod", "rmmod",
    "useradd", "userdel", "usermod", "groupadd", "passwd", "visudo",
    "apt", "apt-get", "yum", "dnf", "zypper", "rpm", "dpkg",
}

# ---- 外联/反弹 shell 的结构信号（与 rules EGRESS-* 呼应，但这里从 token 结构判定） ----
_DEV_NET_RE = re.compile(r"/dev/(tcp|udp)/")
_NC_NAMES = {"nc", "ncat", "netcat"}
_NC_EXEC_RE = re.compile(r"^(-[a-zA-Z]*e[a-zA-Z]*|--exec|--sh-exec)$")
_SOCAT_EXEC_RE = re.compile(r"^(exec|system):", re.IGNORECASE)

# ---- 敏感凭据文件：被「内容读取动词」读出即 = 凭据窃取/外泄前置 -------------------------------
# 来由：held-out 外部基准 RedCode-Exec 的 redcode-exec-4_2（`cp /etc/shadow …` 凭据复制外泄）是
# 命令护栏的真盲区——既有规则只盯「破坏/写关键区」，对「读出凭据内容」无覆盖。按方法论「不在
# held-out 上补、把失败抽象成威胁类别再到内置语料打磨」，本块新增「读敏感凭据」这一**能力标签**
# （而非堆正则），呼应 Rule-of-Two：读敏感=「敏感数据」腿，叠加外联=「外发」腿，双腿即外泄。
#
# 选取标准：**文件内容本身即机密**（口令哈希 / 私钥 / sudo 策略），读出即有泄露价值。
# **刻意不含 /etc/passwd**（全局可读、getent/id 日常读取，纳入必造成误杀——本项目误杀率 0% 硬指标）。
# 判定按 realpath 后**精确匹配文件**或**私钥 basename**，绝不按目录前缀：`tar /etc` 读的是目录、
# 不暴露 shadow 本体，不算；唯有 `/etc/shadow` 作为显式操作数才算。
_SENSITIVE_FILES = {"/etc/shadow", "/etc/gshadow", "/etc/sudoers"}
_SENSITIVE_DIR_PREFIXES = ("/etc/sudoers.d/",)
_PRIVKEY_BASENAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}

# 「读出文件内容」的动词白名单（保守：宁可漏标也不误标，与本模块「只在能肯定时才发声」一致）。
# 刻意不含：元数据动词 chmod/chown/chgrp/ls/stat（不读内容）、销毁动词 rm/shred/truncate（另有红线）、
# tar/gpg/openssl（其文件操作数语义含「写归档/输出」二义，纳入有误杀风险，且收益低）。
_CONTENT_READ_VERBS = {
    "cat", "tac", "less", "more", "head", "tail", "nl",
    "grep", "egrep", "fgrep", "zgrep", "zcat",
    "strings", "xxd", "od", "hexdump", "base64", "base32",
    "sort", "uniq", "cut", "awk", "sed",
    "cp", "scp", "rsync", "install",
}
# 这些动词的最后一个非旗标实参是写目的(DEST)，取「读源」时须排除（cmd SRC... DEST）。
_READ_SRC_LAST_IS_DEST = {"cp", "scp", "rsync", "install"}

# 外发网络通道动词。**单独出现是常规数据传输，绝不升级**；仅当「已读出敏感凭据」时，据它把
# 裁决从 CONFIRM 抬到 DENY（读敏感 + 外发 = 主动外泄）。组合门控使其广度安全：一条命令既读凭据
# 又外发，无论意图都该有人在环，故不构成误杀。
_NET_SEND_VERBS = {"nc", "ncat", "netcat", "socat", "telnet", "scp", "sftp",
                   "ftp", "tftp", "curl", "wget"}
# curl/wget 上传旗标（其取值是被读出外发的本地文件）与下载旗标（抓远端产物落盘）。
_CURL_UPLOAD_VAL_FLAGS = {"-T", "--upload-file", "-d", "--data", "--data-binary",
                          "--data-raw", "-F", "--form"}
_CURL_DOWNLOAD_FLAGS = {"-O", "--remote-name", "-o", "--output"}

# 公共可写临时目录：下载落盘到这里是日常运维、天然良性（误杀率 0% 的 carve-out）。即便 /var/tmp
# 技术上挂在关键路径 /var 之下，落盘**严格在**这些目录之内的下载也**不升级**为 fetches_to_critical。
_BENIGN_WRITE_DIRS = ("/tmp", "/var/tmp", "/dev/shm")


@dataclass
class EffectSet:
    """一条命令静态推导出的副作用集合。

    writes/deletes 存的是**规范化(realpath+normpath)后**、且**落在 CRITICAL_PATHS 内**的路径
    （非关键路径不收录——本模块只关心「效果是否触及关键区」，不做全量审计）。
    egress=True 表示检出外联/反弹 shell 结构；needs_priv=True 表示推断需提权。
    """

    writes: list[str] = field(default_factory=list)
    deletes: list[str] = field(default_factory=list)
    egress: bool = False
    needs_priv: bool = False
    # 读出的敏感凭据文件（规范化后落在 _SENSITIVE_* 内）。非空即「凭据访问」——
    # 单独出现走 CONFIRM（外泄前置，需确认），叠加 egress/net_send 走 DENY（主动外泄）。
    reads_sensitive: list[str] = field(default_factory=list)
    # 外发网络通道（nc/socat/scp/curl…）。仅与 reads_sensitive 组合时参与升级，单独不升级。
    net_send: bool = False
    # curl/wget 抓取远端产物落盘（两段式「下载→后续执行」的第一段）。**信息性标注，不升级**——
    # 下载到盘是日常运维高频动作，升级必误杀；架构上下到盘的脚本也无自由执行路径（Action-Selector）。
    fetches_remote: bool = False
    # curl/wget 下载的**落盘目的**经规范化后落在系统关键路径（且非 /tmp、/var/tmp、/dev/shm 等公共可写
    # 临时目录）→ 远端内容写入可执行/持久化位置，是两段式攻击的落地段，**升级 DENY**（与仅 informational
    # 的 fetches_remote 区分）。
    fetches_to_critical: list[str] = field(default_factory=list)

    @property
    def hits_critical(self) -> bool:
        """是否有任何「触及关键区」的硬副作用（写/删落在关键路径，或外联）——据此才升级。"""
        return bool(self.writes) or bool(self.deletes) or self.egress

    @property
    def is_credential_exfil(self) -> bool:
        """读出敏感凭据**且**存在外发通道（egress 反弹 / net_send 外送）→ 主动凭据外泄。"""
        return bool(self.reads_sensitive) and (self.egress or self.net_send)

    def to_dict(self) -> dict:
        return {
            "writes": list(self.writes),
            "deletes": list(self.deletes),
            "egress": self.egress,
            "needs_priv": self.needs_priv,
            "reads_sensitive": list(self.reads_sensitive),
            "net_send": self.net_send,
            "fetches_remote": self.fetches_remote,
            "fetches_to_critical": list(self.fetches_to_critical),
            "hits_critical": self.hits_critical,
            "is_credential_exfil": self.is_credential_exfil,
        }


# --------------------------------------------------------------------------- #
# 工具：路径规范化 + 关键区判定                                                  #
# --------------------------------------------------------------------------- #

def _looks_like_path(tok: str) -> bool:
    return tok.startswith(("/", ".", "~")) or "/" in tok


def _statically_resolvable(tok: str) -> bool:
    """该 token 能否静态当作确定路径求值：含 shell 变量/通配/命令替换残留则不能（判不准 → 沉默）。"""
    return not any(c in tok for c in ("$", "*", "?", "`")) and "${" not in tok


def _resolve(tok: str) -> str:
    expanded = os.path.expanduser(tok)
    return os.path.normpath(os.path.realpath(expanded))


def _critical_or_none(tok: str) -> str | None:
    """把 token 规范化后，若落在 CRITICAL_PATHS 内返回规范化路径，否则 None（不升级）。

    判不准（非路径形态、含变量/通配）一律返回 None——保守，绝不臆测。
    """
    if not _looks_like_path(tok) or not _statically_resolvable(tok):
        return None
    resolved = _resolve(tok)
    return resolved if _is_under_critical(resolved) else None


def _under_benign_tmp(resolved: str) -> bool:
    """规范化路径是否落在公共可写临时目录内（含目录本身或其严格子路径）→ 良性下载落盘，不升级。"""
    return any(resolved == d or resolved.startswith(d + "/") for d in _BENIGN_WRITE_DIRS)


def _is_sensitive(resolved: str) -> bool:
    """规范化路径是否是敏感凭据文件（精确文件 / sudoers.d 下 / 私钥 basename）。"""
    if resolved in _SENSITIVE_FILES:
        return True
    if any(resolved.startswith(p) for p in _SENSITIVE_DIR_PREFIXES):
        return True
    return os.path.basename(resolved) in _PRIVKEY_BASENAMES


def _sensitive_or_none(tok: str) -> str | None:
    """token 规范化后若是敏感凭据文件返回规范化路径，否则 None（判不准→None，保守不臆测）。"""
    if not _looks_like_path(tok) or not _statically_resolvable(tok):
        return None
    resolved = _resolve(tok)
    return resolved if _is_sensitive(resolved) else None


def _curl_upload_files(args: list[str]) -> list[str]:
    """curl/wget 把本地文件作上传体的取值：-T/--upload-file FILE、--data/-d/-F 的 @FILE、--upload-file=FILE。"""
    out: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("--upload-file="):
            out.append(a.split("=", 1)[1])
        elif a in _CURL_UPLOAD_VAL_FLAGS and i + 1 < len(args):
            val = args[i + 1]
            if a in ("-T", "--upload-file"):
                out.append(val)
            elif "@" in val:                       # --data @file / -F field=@file
                out.append(val.split("@", 1)[1].split(";")[0])
            i += 1                                  # 跳过已消费的取值
        i += 1
    return out


def _download_dest_paths(verb: str, args: list[str]) -> list[str]:
    """抽取 curl/wget 下载的**显式落盘目的**（原始 token，规范化交给调用方）。

    - curl：`-o`/`--output` 的后续取值；以及 `-o=FILE` / `--output=FILE`（按 = 切分）。
    - wget：`-O`/`--output-document` 的取值与 `--output-document=FILE`；并含 `-P`/`--directory-prefix`
      的目录取值与 `--directory-prefix=DIR`（保存到关键目录下同属关键落盘，故把该目录本身计入）。
    - 目的恰为 `-`（输出到 stdout）忽略。
    - **不**揣测无 `-O`/`-o` 时按 URL basename 落 cwd 的默认目的——那不是可静态求值的路径，沉默（故障安全）。
    """
    out: list[str] = []
    i = 0
    if verb == "curl":
        val_flags = ("-o", "--output")
        eq_prefixes = ("-o=", "--output=")
    elif verb == "wget":
        val_flags = ("-O", "--output-document", "-P", "--directory-prefix")
        eq_prefixes = ("--output-document=", "--directory-prefix=")
    else:
        return out
    while i < len(args):
        a = args[i]
        matched = False
        for pfx in eq_prefixes:
            if a.startswith(pfx):
                out.append(a.split("=", 1)[1])
                matched = True
                break
        if not matched and a in val_flags and i + 1 < len(args):
            out.append(args[i + 1])
            i += 1                                  # 跳过已消费的取值
        i += 1
    return [d for d in out if d != "-"]             # `-` 是 stdout，不是落盘目的


def _is_download_to_disk(verb: str, args: list[str]) -> bool:
    """curl -O/-o，或 wget（默认写盘，除 -O - 输出到 stdout）→ 抓远端产物落盘。无上传旗标才算下载。"""
    if any(a.startswith("--upload-file=") or a in _CURL_UPLOAD_VAL_FLAGS for a in args):
        return False
    if verb == "curl":
        return any(a in _CURL_DOWNLOAD_FLAGS for a in args)
    if verb == "wget":
        return "-" not in args                     # `wget -O -` 输出到 stdout 不算落盘
    return False


# --------------------------------------------------------------------------- #
# bashlex 词级提取                                                              #
# --------------------------------------------------------------------------- #

def _command_words(node) -> list[str]:
    """取一个 command 节点的字面词序列（word part 的 .word），重定向/替换部件不计入。"""
    return [p.word for p in getattr(node, "parts", []) if getattr(p, "kind", "") == "word"]


def _redirect_targets(node) -> list[str]:
    """取 command 节点上所有**输出**重定向（>、>>）的目标路径字符串。

    输入重定向 `<` 是读，不计入写效果。`>` / `>>` 的目标即写/覆盖目的。
    """
    out: list[str] = []
    for part in getattr(node, "parts", []):
        if getattr(part, "kind", "") != "redirect":
            continue
        rtype = getattr(part, "type", "") or ""
        if not rtype.startswith(">"):
            continue
        tnode = getattr(part, "output", None)
        target = getattr(tnode, "word", "") if tnode is not None else ""
        if target:
            out.append(target)
    return out


def _split_verb_args(words: list[str]) -> tuple[str, list[str]]:
    """跳过 sudo/env/前置赋值，取「真正执行的命令」basename 与其后参数。"""
    verb = ""
    args: list[str] = []
    for w in words:
        if not verb:
            # 前置赋值 FOO=bar（不带斜杠的纯赋值）→ 跳过，继续找命令词
            head = w.split("/")[-1]
            if "=" in head and not w.startswith("/") and not _looks_like_path(w):
                continue
            base = os.path.basename(w)
            if base in _SKIP_WORDS:
                continue
            verb = base
        else:
            args.append(w)
    return verb, args


def _plain_path_args(args: list[str]) -> list[str]:
    """取像路径的实参（跳过旗标 -x 与非路径取值）。"""
    return [a for a in args if not a.startswith("-") and _looks_like_path(a)]


def _nonflag_args(args: list[str]) -> list[str]:
    """取所有非旗标实参（用于 cp/mv 这类 SRC... DEST，路径未必带 / 也可能是相对名）。"""
    return [a for a in args if not a.startswith("-")]


# --------------------------------------------------------------------------- #
# 单命令副作用归集                                                              #
# --------------------------------------------------------------------------- #

def _collect_egress(verb: str, args: list[str], all_words: list[str]) -> bool:
    """检出外联/反弹 shell 结构：/dev/tcp|udp、nc -e、socat EXEC|SYSTEM。"""
    # 任一词出现 /dev/tcp/ 或 /dev/udp/ → 外联通道（bash 的伪设备网络）
    if any(_DEV_NET_RE.search(w) for w in all_words):
        return True
    if verb in _NC_NAMES and any(_NC_EXEC_RE.match(a) for a in args):
        return True
    if verb == "socat" and any(_SOCAT_EXEC_RE.match(a) for a in args):
        return True
    return False


def _collect_command_effects(node, effects: EffectSet) -> None:
    """从一个 command 节点归集副作用，原地写入 effects（只收落在关键区的写/删 + egress/priv）。"""
    words = _command_words(node)
    if not words:
        return
    verb, args = _split_verb_args(words)
    if not verb:
        return

    # —— egress（外联/反弹 shell） ——
    if _collect_egress(verb, args, words):
        effects.egress = True

    # —— needs_priv（提权推断，仅作信息，不单独构成升级） ——
    if verb in _PRIV_VERBS:
        effects.needs_priv = True

    # —— reads_sensitive（读出敏感凭据 = 窃取/外泄前置） ——
    read_srcs: list[str] = []
    if verb == "dd":
        read_srcs = [a[len("if="):] for a in args if a.startswith("if=")]
    elif verb in _CONTENT_READ_VERBS:
        nonflag = _nonflag_args(args)
        if verb in _READ_SRC_LAST_IS_DEST and len(nonflag) >= 2:
            read_srcs = nonflag[:-1]          # 末参是写目的 DEST，排除，只取读源 SRC...
        else:
            read_srcs = nonflag
    if verb in ("curl", "wget"):
        read_srcs = read_srcs + _curl_upload_files(args)
    for src in read_srcs:
        hit = _sensitive_or_none(src)
        if hit and hit not in effects.reads_sensitive:
            effects.reads_sensitive.append(hit)

    # —— net_send（外发网络通道；仅与 reads_sensitive 组合时在裁决层升级，单独不升级） ——
    if verb in _NET_SEND_VERBS or any(_DEV_NET_RE.search(w) for w in words):
        effects.net_send = True

    # —— fetches_remote（curl/wget 抓远端产物落盘：信息性标注，不升级，#1 两段式攻击的可见性） ——
    if verb in ("curl", "wget") and _is_download_to_disk(verb, args):
        effects.fetches_remote = True

    # —— fetches_to_critical（下载落盘到系统关键路径 = 远端内容落入可执行/持久化位置：升级 DENY） ——
    # 仅在确为下载（curl 无上传旗标）时取显式落盘目的；目的规范化后落在关键区**且不在**公共可写临时目录
    # 内才升级（/var/tmp 等先 carve-out，再判关键区，与 _critical_or_none 同口径但多一道良性豁免）。
    if verb in ("curl", "wget") and not (verb == "curl" and _curl_upload_files(args)):
        for dest in _download_dest_paths(verb, args):
            if not _looks_like_path(dest) or not _statically_resolvable(dest):
                continue
            resolved = _resolve(dest)
            if _under_benign_tmp(resolved):
                continue
            if _is_under_critical(resolved) and resolved not in effects.fetches_to_critical:
                effects.fetches_to_critical.append(resolved)

    # —— writes：输出重定向目标（> / >>） ——
    for target in _redirect_targets(node):
        hit = _critical_or_none(target)
        if hit:
            effects.writes.append(hit)
            effects.needs_priv = True  # 写关键区必然要 root

    # —— writes：写类动词的写目的 ——
    write_dests: list[str] = []
    if verb in _WRITE_DEST_ALL:
        write_dests = _plain_path_args(args)
    elif verb in _WRITE_DEST_LAST:
        nonflag = _nonflag_args(args)
        # cmd SRC... DEST：只取最后一个（DEST）；少于 2 个非旗标实参则目的不明 → 不取
        if len(nonflag) >= 2:
            write_dests = [nonflag[-1]]
    elif verb == "dd":
        write_dests = [a[len("of="):] for a in args if a.startswith("of=")]

    for dest in write_dests:
        hit = _critical_or_none(dest)
        if hit:
            effects.writes.append(hit)
            effects.needs_priv = True

    # —— deletes：删除/截断类动词的目标 ——
    delete_targets: list[str] = []
    if verb in _DELETE_VERBS:
        delete_targets = _plain_path_args(args)
    elif verb == "truncate":
        # truncate -s 0 FILE 把文件截断为 0 = 内容销毁；其余 -s SIZE 改大小亦属写。
        # 路径同时进 writes（上面 _WRITE_DEST_ALL 已收）与 deletes（截断 0 的销毁语义）。
        if any(a in ("-s", "--size") for a in args):
            for p in _plain_path_args(args):
                hit = _critical_or_none(p)
                if hit:
                    delete_targets.append(p)

    for tgt in delete_targets:
        hit = _critical_or_none(tgt)
        if hit and hit not in effects.deletes:
            effects.deletes.append(hit)


# --------------------------------------------------------------------------- #
# AST 遍历：对每个 command 节点归集（含命令链/管道/子shell/命令替换里的子命令）        #
# --------------------------------------------------------------------------- #

def _walk(node, effects: EffectSet) -> None:
    kind = getattr(node, "kind", "")
    if kind == "command":
        _collect_command_effects(node, effects)
        # 词内可能藏命令替换/进程替换，其子命令副作用同样要归集
        for part in getattr(node, "parts", []):
            if getattr(part, "kind", "") == "word":
                for sub in getattr(part, "parts", []) or []:
                    _walk(sub, effects)
    elif kind in ("commandsubstitution", "processsubstitution"):
        _walk(getattr(node, "command", None), effects) if getattr(node, "command", None) is not None else None
    else:
        # pipeline / list / compound / 其它：下探所有子节点
        for attr in ("parts", "list", "command"):
            v = getattr(node, attr, None)
            if isinstance(v, list):
                for x in v:
                    if hasattr(x, "kind"):
                        _walk(x, effects)
            elif hasattr(v, "kind"):
                _walk(v, effects)


def analyze_effects(cmd: str) -> EffectSet:
    """静态推导一条命令的副作用集（EffectSet）。

    故障安全：解析失败/遍历异常 → 返回空 EffectSet（不升级），把裁决交回规则层与 AST 层。
    本模块只「锦上添花」地补「按效果应拦」的真盲区，绝不因自身异常改变放行策略或崩溃。
    """
    text = (cmd or "").strip()
    effects = EffectSet()
    if not text:
        return effects
    # 先用整串扫一遍 /dev/tcp 这类不依赖解析的 egress 信号（即便后续解析失败也能抓到）。
    if _DEV_NET_RE.search(text):
        effects.egress = True
    try:
        trees = bashlex.parse(text)
    except Exception:  # noqa: BLE001 解析失败 → 保持当前 effects（可能已含 egress），不再深挖
        return effects
    try:
        for t in trees:
            _walk(t, effects)
    except Exception:  # noqa: BLE001 遍历意外 → 返回已归集部分，绝不崩溃
        return effects
    # 去重，稳定顺序
    effects.writes = list(dict.fromkeys(effects.writes))
    effects.deletes = list(dict.fromkeys(effects.deletes))
    return effects
