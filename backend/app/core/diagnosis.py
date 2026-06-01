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
from enum import Enum

from app.mcp_server.tools.disk import disk_usage, find_large_files
from app.mcp_server.tools.process import find_zombie_processes
from app.mcp_server.tools.system import system_load

# 磁盘使用率告警阈值（百分比）
DISK_WARN_PERCENT = 85.0
# 单核负载告警系数：loadavg_1m / cpu_count 超过此值视为过载
LOAD_WARN_RATIO = 1.5


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


def classify_file(path: str) -> tuple[FileClass, str]:
    """判断单个文件的关键性，返回 (分类, 人类可读理由)。

    判定优先级：关键特征 > 可清理特征 > 未知。关键优先，宁可保守也不误导用户删数据。
    """
    p = os.path.normpath(path)

    if p.startswith(_CRITICAL_DIR_PREFIXES) or _CRITICAL_NAME_RE.search(p):
        return FileClass.CRITICAL, "位于系统/数据库关键路径或为数据库/启动文件，删除不可逆，禁止贸然清理"

    if p.startswith(_CLEANABLE_DIR_PREFIXES) or _CLEANABLE_NAME_RE.search(p):
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


def diagnose(topic: str = "all", path: str = "/") -> dict:
    """根因分析统一入口。topic ∈ {disk, zombie, load, all}。"""
    if topic == "disk":
        return diagnose_disk(path)
    if topic == "zombie":
        return diagnose_zombies()
    if topic == "load":
        return diagnose_load()
    if topic == "all":
        reports = [diagnose_disk(path), diagnose_zombies(), diagnose_load()]
        problems = [r for r in reports if r.get("severity") not in ("ok", "unknown", None)]
        return {
            "ok": True, "topic": "all",
            "summary": (f"共 {len(problems)} 项需关注。" if problems else "系统各项指标正常。"),
            "reports": reports,
        }
    return {"ok": False, "error": f"未知诊断主题: {topic}（可选 disk/zombie/load/all）"}
