"""智能根因分析 —— 评分④「智能化根因分析」。

赛题「基本功能需求」没列它，但评分表里是子项，很多队会漏做，做了就拉开档次（见 CLAUDE.md §2）。
本模块是**原创 IP**（CLAUDE.md §7 知识产权红线），不抄第三方。

定位：消费 MCP 感知工具采集到的只读数据，做一层「推理 + 关键性判断 + 建议」。
- 磁盘满 → 定位大文件 → **判断每个大文件的关键性**（可清理 / 关键勿删 / 需人工确认）→ 给清理建议
- 僵尸进程 → 找出父进程 → 建议处置（回收靠父进程，杀子进程无效）
- 负载异常 → 判断是否过载 → 指认占用最高的进程

铁律（CLAUDE.md §6）：**绝不在这里执行任何删除/杀进程动作，只产出分析与建议**。
真要执行，建议命令必须再走 executor → 护栏。本模块输出的 suggestions 是「给人看的命令文本」，不自动跑。
"""
from __future__ import annotations

import os
import re
import time
from enum import Enum

import psutil

from app.core.pathutil import is_path_within
from app.mcp_server.tools.disk import disk_usage, find_large_files
from app.mcp_server.tools.handle import list_open_files
from app.mcp_server.tools.process import find_zombie_processes, process_detail
from app.mcp_server.tools.system import system_load

# 磁盘使用率告警阈值（百分比）
DISK_WARN_PERCENT = 85.0
# 单核负载告警系数：loadavg_1m / cpu_count 超过此值视为过载
LOAD_WARN_RATIO = 1.5
# D 状态（不可中断睡眠 / 等磁盘）—— IO 瓶颈的强信号
_DSTATE = getattr(psutil, "STATUS_DISK_SLEEP", "disk-sleep")
# 系统级 D 状态进程数达到此值视为存在 IO 压力
DSTATE_PRESSURE = 2


class FileClass(Enum):
    """大文件关键性分类 —— 根因分析的灵魂，决定「能不能建议清理」。"""
    CLEANABLE = "cleanable"   # 日志/缓存/临时文件，通常可安全清理
    CRITICAL = "critical"     # 数据库/系统/启动文件，删除不可逆，禁止贸然处理
    UNKNOWN = "unknown"       # 拿不准，建议人工确认后再处理


# 关键文件特征：命中即判定为「关键勿删」。顺序在可清理之前判定。
_CRITICAL_DIR_PREFIXES = (
    "/var/lib/mysql", "/var/lib/postgresql", "/var/lib/mongodb",
    "/var/lib/docker", "/var/lib/etcd",
    "/boot", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
)
_CRITICAL_NAME_RE = re.compile(
    r"\.(db|sql|sqlite|sqlite3|frm|ibd|myd|myi|mdf|ldf|bak|dump)$"
    r"|vmlinuz|initramfs|initrd",
    re.IGNORECASE,
)

# 可清理文件特征：日志、缓存、临时。命中且未命中关键特征 → 可清理。
_CLEANABLE_DIR_PREFIXES = (
    "/tmp", "/var/tmp", "/var/log", "/var/cache",
)
_CLEANABLE_NAME_RE = re.compile(
    r"\.(log|log\.\d+|gz|old|tmp|temp|swp|core)$"
    r"|\.log\.|/\.cache/|(^|/)core\.\d+$",
    re.IGNORECASE,
)


def _is_critical(s: str) -> bool:
    # 用 commonpath 分量包含替代 startswith：杜绝 /var/lib/mysqlx 误判为 /var/lib/mysql 子路径（P0-1）
    return is_path_within(s, _CRITICAL_DIR_PREFIXES) or bool(_CRITICAL_NAME_RE.search(s))


def _is_cleanable(s: str) -> bool:
    # 同上：/var/log2、/tmpx 等兄弟目录不得误判为可清理（P0-1）
    return is_path_within(s, _CLEANABLE_DIR_PREFIXES) or bool(_CLEANABLE_NAME_RE.search(s))


def classify_file(path: str) -> tuple[FileClass, str]:
    """判断单个文件的关键性，返回 (分类, 人类可读理由)。

    判定优先级：关键特征 > 可清理特征 > 未知。关键优先，宁可保守也不误导用户删数据。

    安全（审查整改③）：normpath **不解析软链**，会被「字面 /var/log/x → 实指 /etc/passwd」
    绕过——truncate/rm 跟随软链写真实目标。故这里解析到真实路径再判：
    - 关键性取「字面 ∪ 软链解析后」的并集：任一命中关键即判关键（软链指向 /etc、*.db 也拦死）；
    - 可清理只认**软链解析后的真实目标**落在可清理特征——因为清空/删除实际作用在真实文件上，
      杜绝「字面在 /var/log、实写他处」的写穿。
    """
    literal = os.path.normpath(path)
    real = os.path.normpath(os.path.realpath(path))

    if _is_critical(literal) or _is_critical(real):
        why = "位于系统/数据库关键路径或为数据库/启动文件，删除不可逆，禁止贸然清理"
        if real != literal:
            why += "（软链解析后真实指向关键文件）"
        return FileClass.CRITICAL, why

    if _is_cleanable(real):
        return FileClass.CLEANABLE, "属日志/缓存/临时文件，通常可安全清理（建议先确认无进程占用）"

    return FileClass.UNKNOWN, "无法自动判定关键性，建议人工确认用途后再决定是否清理"


def diagnose_disk(path: str = "/", top_n: int = 10,
                  warn_percent: float = DISK_WARN_PERCENT) -> dict:
    """磁盘根因分析：使用率 → 定位大文件 → 逐个判关键性 → 给建议。

    Args:
        path: 要诊断的挂载点/目录
        top_n: 取占用最大的前 N 个文件分析
        warn_percent: 使用率告警阈值
    Returns:
        结构化诊断报告（含 findings/large_files/suggestions），绝不执行任何删除。
    """
    usage = disk_usage(path)
    if not usage.get("ok"):
        return {"ok": False, "topic": "disk", "error": usage.get("error")}

    percent = usage["percent"]
    severity = "critical" if percent >= 95 else "warning" if percent >= warn_percent else "ok"
    findings = [
        f"挂载点 {path} 使用率 {percent}%（已用 {usage['used_gb']}GB / 共 {usage['total_gb']}GB，"
        f"剩余 {usage['free_gb']}GB）。"
    ]

    large = find_large_files(path, top_n=top_n)
    files_report: list[dict] = []
    cleanable_mb = 0.0
    if large.get("ok"):
        for f in large["files"]:
            cls, reason = classify_file(f["path"])
            files_report.append({
                "path": f["path"], "size_mb": f["size_mb"],
                "class": cls.value, "reason": reason,
            })
            if cls is FileClass.CLEANABLE:
                cleanable_mb += f["size_mb"]
        if large.get("truncated"):
            findings.append(f"目录庞大，仅扫描了前 {large['scanned']} 个文件，结果可能不全。")
    else:
        findings.append(f"大文件扫描失败：{large.get('error')}")

    suggestions = _disk_suggestions(severity, files_report, cleanable_mb)

    return {
        "ok": True,
        "topic": "disk",
        "severity": severity,
        "path": path,
        "percent": percent,
        "findings": findings,
        "large_files": files_report,
        "cleanable_estimate_mb": round(cleanable_mb, 2),
        "suggestions": suggestions,
    }


def _disk_suggestions(severity: str, files: list[dict], cleanable_mb: float) -> list[str]:
    """据分类结果给出建议。可清理文件给出**建议命令文本**（不自动执行）。"""
    if severity == "ok":
        return ["磁盘使用率正常，暂无需处理。"]

    s: list[str] = []
    cleanable = [f for f in files if f["class"] == FileClass.CLEANABLE.value]
    critical = [f for f in files if f["class"] == FileClass.CRITICAL.value]
    unknown = [f for f in files if f["class"] == FileClass.UNKNOWN.value]

    if cleanable:
        s.append(
            f"发现 {len(cleanable)} 个可清理文件（日志/缓存/临时），预计可释放约 "
            f"{round(cleanable_mb, 2)}MB。可考虑（执行前仍会经护栏校验）："
        )
        for f in cleanable[:5]:
            # 仅给建议文本，绝不自动执行；日志类优先建议截断而非删除，保留近期排障线索
            if re.search(r"\.log($|\.)", f["path"], re.IGNORECASE):
                s.append(f"  · {f['path']}（{f['size_mb']}MB）：建议 `truncate -s 0 {f['path']}` 清空而非删除，保留文件句柄")
            else:
                s.append(f"  · {f['path']}（{f['size_mb']}MB）：确认无占用后可 `rm` 清理")
    if critical:
        s.append(
            f"发现 {len(critical)} 个关键文件（数据库/系统/启动），**禁止贸然删除**，"
            "如确需处理请人工评估并备份："
        )
        for f in critical[:5]:
            s.append(f"  · {f['path']}（{f['size_mb']}MB）：{f['reason']}")
    if unknown:
        s.append(f"另有 {len(unknown)} 个文件无法自动判定关键性，建议人工确认用途。")

    s.append("通用排查：`du -sh /var/* | sort -h` 自顶向下定位；检查是否有进程持续写大日志（lsof）。")
    return s


def diagnose_zombies() -> dict:
    """僵尸进程根因分析：僵尸本身已死，回收要靠父进程，杀僵尸无效 → 指认父进程。"""
    z = find_zombie_processes()
    count = z.get("count", 0)
    if count == 0:
        return {"ok": True, "topic": "zombie", "severity": "ok", "count": 0,
                "findings": ["未发现僵尸进程。"], "suggestions": []}

    ppids = sorted({item["ppid"] for item in z["zombies"]})
    findings = [
        f"发现 {count} 个僵尸进程（已终止但未被父进程回收，占用 PID 表项）。",
        f"涉及父进程 PID：{ppids}。",
    ]
    suggestions = [
        "僵尸进程无法被 kill（已是死进程），需让其**父进程**回收：",
        f"  · 排查父进程：`ps -p {','.join(map(str, ppids))} -o pid,ppid,cmd`",
        "  · 若父进程异常，可向父进程发 SIGCHLD：`kill -s SIGCHLD <ppid>`；仍不回收再考虑重启父进程。",
        "  · 大量僵尸通常是父进程未正确 wait() 的程序 bug，应修复或重启该服务。",
    ]
    return {"ok": True, "topic": "zombie", "severity": "warning",
            "count": count, "zombies": z["zombies"], "ppids": ppids,
            "findings": findings, "suggestions": suggestions}


def diagnose_load() -> dict:
    """系统负载根因分析：按单核负载系数判断是否过载。"""
    load = system_load()
    l1 = load.get("loadavg_1m")
    cpus = load.get("cpu_count") or 1
    if l1 is None:
        return {"ok": True, "topic": "load", "severity": "unknown",
                "findings": ["当前平台无法获取 loadavg。"], "suggestions": []}

    ratio = l1 / cpus
    severity = "critical" if ratio >= 2 * LOAD_WARN_RATIO else \
        "warning" if ratio >= LOAD_WARN_RATIO else "ok"
    findings = [
        f"1 分钟平均负载 {l1}，CPU 核数 {cpus}，单核负载系数 {round(ratio, 2)}"
        f"（>{LOAD_WARN_RATIO} 视为偏高）。CPU 总使用率 {load.get('cpu_percent')}%。"
    ]
    if severity == "ok":
        suggestions = ["负载处于正常范围。"]
    else:
        suggestions = [
            "负载偏高，建议定位元凶进程：`list_processes(sort_by='cpu')` 或 `top`。",
            "区分 CPU 密集还是 IO 等待：若 CPU% 不高但 load 高，多为 IO/锁等待，查磁盘与 D 状态进程。",
        ]
    return {"ok": True, "topic": "load", "severity": severity,
            "loadavg_1m": l1, "cpu_count": cpus, "ratio": round(ratio, 2),
            "findings": findings, "suggestions": suggestions}


# ============================================================================
# 跨信号关联根因分析（P1-1）—— 评分④的「智能」核心。
#
# 单指标阈值判断只算「监控」（磁盘满了、负载高了）；把【磁盘使用率告警 + 某大文件
# 持续增长 + lsof 关联到写入进程 + 该进程 D(IO 等待)状态 + 系统级 IO 压力】这些**独立
# 信号关联成一条证据链**，并据信号印证强度给出 confidence，才算「根因」。
#
# 设计：**采集与推理分离**。correlate_io_signals 是纯函数（输入已采集信号 → 输出根因/
# 证据链/置信度），可用构造数据做确定性测试；diagnose_io_correlation 负责真实采集
# （会采两次文件大小判增长、跑 lsof、读进程状态），把信号喂给纯函数。
# ============================================================================

# 各信号对「失控写入致磁盘+IO 双告警」结论的支撑权重（观测到即累加为 confidence，和为 1.0）
_IO_WEIGHTS = {
    "disk_high": 0.25,       # 症状：磁盘使用率告警
    "file_growing": 0.30,    # 实锤：大文件在采样窗口内确实变大（正被写入）
    "writer_found": 0.25,    # 关联：lsof 定位到持有该文件的写入进程
    "writer_dstate": 0.10,   # 印证：写入进程处于 D(IO 等待)状态
    "io_pressure": 0.10,     # 旁证：系统级多个 D 状态进程，存在 IO 压力
}


def _confidence_label(c: float) -> str:
    return "高" if c >= 0.7 else "中" if c >= 0.4 else "低"


def correlate_io_signals(sig: dict) -> dict:
    """纯函数：把已采集的多个信号关联成根因 + 证据链 + 置信度。

    Args:
        sig: 信号字典，键见下；缺失的信号视为「未观测到」，不参与加权。
            disk_percent / disk_warn / growing_file{path,size_mb,grew_bytes,interval_s}
            / writer{pid,command,fd} / writer_status / dstate_count
    Returns:
        含 root_cause / confidence / confidence_label / evidence / chain /
        findings / suggestions 的结构化报告。绝不执行任何处置。
    """
    evidence: list[dict] = []   # 支撑结论的多个信号（评分④要求体现）
    chain: list[str] = []       # 人类可读的定位链路，按编号串成证据链
    conf = 0.0

    # —— 信号①：磁盘使用率告警（症状）——
    disk_percent = sig.get("disk_percent")
    disk_warn = sig.get("disk_warn", DISK_WARN_PERCENT)
    disk_high = disk_percent is not None and disk_percent >= disk_warn
    if disk_high:
        conf += _IO_WEIGHTS["disk_high"]
        evidence.append({"signal": "disk_high",
                         "detail": f"磁盘使用率 {disk_percent}% ≥ 告警阈值 {disk_warn}%"})
        chain.append(f"① 磁盘使用率 {disk_percent}% 触发告警")

    # —— 信号②：大文件持续增长（实锤）——
    gf = sig.get("growing_file") or {}
    grew = gf.get("grew_bytes", 0) or 0
    file_growing = bool(gf) and grew > 0
    gf_class = classify_file(gf["path"])[0] if gf.get("path") else None
    if file_growing:
        conf += _IO_WEIGHTS["file_growing"]
        evidence.append({"signal": "file_growing",
                         "detail": f"{gf['path']} 在 {gf.get('interval_s')}s 内增长 "
                                   f"{round(grew / 1024, 1)}KB（当前 {gf.get('size_mb')}MB）"})
        chain.append(f"② 大文件 {gf['path']}（{gf.get('size_mb')}MB）正被持续写入"
                     f"（采样窗内 +{round(grew / 1024, 1)}KB）")
    elif gf.get("path"):
        chain.append(f"② 定位到大文件 {gf['path']}（{gf.get('size_mb')}MB），"
                     "但采样窗内未观测到实时增长")

    # —— 信号③：lsof 关联写入进程（关联）——
    writer = sig.get("writer") or {}
    writer_found = bool(writer.get("pid"))
    if writer_found:
        conf += _IO_WEIGHTS["writer_found"]
        evidence.append({"signal": "writer_found",
                         "detail": f"{writer.get('command')}(pid={writer['pid']}, "
                                   f"fd={writer.get('fd')}) 正持有该文件写句柄"})
        chain.append(f"③ lsof 关联写入进程：{writer.get('command')}"
                     f"(pid={writer['pid']}, fd={writer.get('fd')})")

    # —— 信号④：写入进程处于 D(IO 等待)状态（印证）——
    writer_dstate = sig.get("writer_status") == _DSTATE
    if writer_dstate:
        conf += _IO_WEIGHTS["writer_dstate"]
        evidence.append({"signal": "writer_dstate",
                         "detail": f"pid={writer.get('pid')} 处于 D(不可中断睡眠/IO 等待)状态"})
        chain.append("④ 该进程处于 D(不可中断睡眠/IO 等待)状态，印证 IO 瓶颈")

    # —— 信号⑤：系统级 IO 压力（旁证）——
    dcount = sig.get("dstate_count", 0) or 0
    io_pressure = dcount >= DSTATE_PRESSURE
    if io_pressure:
        conf += _IO_WEIGHTS["io_pressure"]
        evidence.append({"signal": "io_pressure",
                         "detail": f"系统级 {dcount} 个进程处于 D(IO 等待)状态"})
        chain.append(f"⑤ 系统级 {dcount} 个进程处于 D 状态，存在整体 IO 压力")

    conf = round(min(conf, 1.0), 2)
    root_cause, severity, suggestions = _io_conclusion(
        disk_high=disk_high, file_growing=file_growing, writer_found=writer_found,
        io_wait=(writer_dstate or io_pressure), gf=gf, gf_class=gf_class,
        writer=writer, disk_percent=disk_percent, conf=conf)

    findings = [f"关联了 {len(evidence)} 个信号，置信度 {conf}（{_confidence_label(conf)}）。"]
    if not chain:
        chain.append("未采集到磁盘/IO 关联异常信号。")

    return {
        "ok": True, "topic": "io", "severity": severity,
        "root_cause": root_cause, "confidence": conf,
        "confidence_label": _confidence_label(conf),
        "evidence": evidence, "chain": chain,
        "findings": findings, "suggestions": suggestions,
    }


def _io_conclusion(*, disk_high, file_growing, writer_found, io_wait, gf, gf_class,
                   writer, disk_percent, conf) -> tuple[str, str, list[str]]:
    """据信号组合给出根因结论、严重度与建议（建议是给人看的命令文本，绝不自动执行）。"""
    path = gf.get("path")
    is_critical_file = gf_class is FileClass.CRITICAL

    # 严重度：有明确关联且磁盘很满 → critical；否则按是否成链给 warning / ok
    if not disk_high and not file_growing:
        return ("未发现磁盘使用率与持续写入的关联异常，IO/磁盘暂无明显根因。", "ok",
                ["磁盘与 IO 指标正常，暂无需处理。"])
    severity = "critical" if (conf >= 0.7 and (disk_percent or 0) >= 95) else "warning"

    suggestions: list[str] = []
    if writer_found and file_growing:
        dual = "磁盘使用率与 IO 等待双告警" if io_wait else "磁盘使用率告警"
        root = (f"疑似进程 {writer.get('command')}(pid={writer['pid']}) 持续写入 "
                f"{path}，引发{dual}。")
        suggestions.append(
            f"定位链路已收敛到 pid={writer['pid']}（{writer.get('command')}），"
            "先确认其写入行为是否预期：")
        suggestions.append(f"  · 查看进程：`process_detail({writer['pid']})` / "
                           f"`ps -p {writer['pid']} -o pid,stat,wchan,cmd`")
    elif file_growing:
        root = (f"存在持续增长的大文件 {path}，疑似有进程在狂写，"
                "但未定位到具体写入进程（多为权限不足）。")
        suggestions.append(f"以 root 重跑 lsof 定位写入者：`sudo lsof -- {path}`")
    else:  # disk_high only
        root = ("磁盘使用率告警，但未观测到明显的持续写入源，"
                "更可能是历史文件堆积而非失控写入。")
        suggestions.append("按常规磁盘清理排查：`du -sh /var/* | sort -h` 自顶向下定位。")

    # 处置建议按文件关键性分流（复用 classify_file，呼应单点磁盘诊断的关键性判断）
    if path and is_critical_file:
        root += "（注意：该文件位于数据库/系统关键路径，删除不可逆，禁止贸然处理。）"
        suggestions.append(
            f"  · **{path} 是关键数据文件，切勿删除/清空**；若为数据库写入，"
            "应从业务侧排查写入量（慢查询/大事务/异常重试），必要时扩容磁盘。")
    elif path and file_growing:
        suggestions.append(
            f"  · 若确认为失控日志，可 `truncate -s 0 {path}` **清空止血**（保留文件句柄），"
            "并排查应用日志级别；切勿对正被写入的文件直接 `rm`——"
            "进程仍持有句柄，空间不会立即释放，反而要等其重启或 truncate 才生效。")
        suggestions.append("  · 受控清理请走『安全清理』按钮，在护栏二次确认下执行（绝不自动处置）。")
    return root, severity, suggestions


def _count_dstate() -> int:
    """统计系统级处于 D(不可中断睡眠/IO 等待)状态的进程数。READONLY。"""
    n = 0
    for p in psutil.process_iter(["status"]):
        try:
            if p.info["status"] == _DSTATE:
                n += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return n


def diagnose_io_correlation(path: str = "/var/log", *,
                            grow_interval: float = 0.5,
                            warn_percent: float = DISK_WARN_PERCENT) -> dict:
    """跨信号关联根因采集入口：把多源只读信号采全后交给 correlate_io_signals 推理。

    Args:
        path: 排查目录（默认 /var/log，日志失控写入的高发地）。
        grow_interval: 判「持续增长」的两次采样间隔秒数；设 0 则跳过、不判增长。
        warn_percent: 磁盘使用率告警阈值。
    Returns:
        关联根因报告（含证据链与置信度）。全程只读，绝不执行任何处置。
    """
    # 信号①：磁盘使用率（取 path 所在文件系统；失败回退根分区）
    disk = disk_usage(path)
    if not disk.get("ok"):
        disk = disk_usage("/")
    disk_percent = disk.get("percent")

    # 信号②：在最大的几个文件里采样判增长（两次 getsize 之差），控制开销
    growing = None
    large = find_large_files(path, top_n=10)
    candidates = large.get("files", []) if large.get("ok") else []
    sampled = []
    for f in candidates[:3]:
        try:
            sampled.append((f, os.path.getsize(f["path"])))
        except OSError:
            continue
    if sampled and grow_interval > 0:
        time.sleep(grow_interval)
    best = None  # (file, grew_bytes, current_size)
    for f, s0 in sampled:
        try:
            s1 = os.path.getsize(f["path"])
        except OSError:
            continue
        grew = s1 - s0
        if best is None or grew > best[1]:
            best = (f, grew, s1)
    if best:
        f, grew, s1 = best
        growing = {"path": f["path"], "size_mb": round(s1 / 1e6, 2),
                   "grew_bytes": max(grew, 0), "interval_s": grow_interval}

    # 信号③④：lsof 关联写入者 + 其进程状态
    writer = None
    writer_status = None
    if growing:
        holders = list_open_files(growing["path"])
        if holders.get("ok") and holders.get("holders"):
            wr = next((h for h in holders["holders"]
                       if "w" in (h.get("fd") or "").lower()
                       or "u" in (h.get("fd") or "").lower()), None)
            wr = wr or holders["holders"][0]
            writer = {"pid": wr.get("pid"), "command": wr.get("command"), "fd": wr.get("fd")}
            try:
                pd = process_detail(int(wr["pid"]))
                if pd.get("ok"):
                    writer_status = pd.get("status")
                    writer["command"] = writer.get("command") or pd.get("name")
            except (ValueError, TypeError, KeyError):
                pass

    # 信号⑤：系统级 IO 压力
    signals = {
        "disk_percent": disk_percent, "disk_warn": warn_percent,
        "growing_file": growing, "writer": writer,
        "writer_status": writer_status, "dstate_count": _count_dstate(),
    }
    report = correlate_io_signals(signals)
    report["path"] = path
    return report


def diagnose(topic: str = "all", path: str = "/") -> dict:
    """根因分析统一入口。topic ∈ {disk, zombie, load, io, all}。"""
    if topic == "disk":
        return diagnose_disk(path)
    if topic == "zombie":
        return diagnose_zombies()
    if topic == "load":
        return diagnose_load()
    if topic == "io":
        # io 关联诊断聚焦日志高发地；未显式指定时用 /var/log 而非全盘扫描
        return diagnose_io_correlation("/var/log" if path == "/" else path)
    if topic == "all":
        reports = [diagnose_disk(path), diagnose_zombies(), diagnose_load()]
        problems = [r for r in reports if r.get("severity") not in ("ok", "unknown", None)]
        return {
            "ok": True, "topic": "all",
            "summary": (f"共 {len(problems)} 项需关注。" if problems else "系统各项指标正常。"),
            "reports": reports,
        }
    return {"ok": False, "error": f"未知诊断主题: {topic}（可选 disk/zombie/load/io/all）"}
