"""运维简报生成（日报/周报）—— 把既有只读数据源聚合成一份可下载的结构化报告。

对应「自动化办公与效率工具」中『周报自动生成器 / 每日待办简报』的能力形态：
用户一键（或定时）生成，Agent 聚合四个既有 READONLY 数据源并渲染 Markdown：

1. 系统快照 —— psutil：主机 / 内核 / 运行时长 / 负载 / CPU / 内存 / 磁盘；
2. 健康诊断摘要 —— core/diagnosis.diagnose("all")（磁盘/僵尸/负载/内存四类根因分析）；
3. 安全态势摘要 —— core/posture.check_posture(live=False)（离线情报比对，绝不联网）；
4. 运维活动统计 —— audit/store.activity_stats（窗口内会话/拦截/污点/受控动作）。

设计要点（与项目安全架构同一风格）：
- **全只读、无副作用**：只聚合与渲染，绝不执行任何处置（建议仅供人工决策）；
- **确定性优先**：不依赖 LLM 也能产出完整报告（mock/离线/CI 均可跑）；
- **LLM 只做锦上添花**：可选的「AI 导语」是无工具的单次调用，只允许改写既有数据为
  流畅中文，失败/异常自动降级为确定性导语，绝不因模型抖动而丢报告。
"""
from __future__ import annotations

import os
import time

import psutil

from app.audit import store
from app.core import diagnosis, posture
from app.llm.provider import LLMProvider

# 周期 → (窗口秒数, 中文标题)。简报只有这两个受控档位，未知取值在路由层即 400。
PERIODS: dict[str, tuple[int, str]] = {
    "daily": (24 * 3600, "运维日报"),
    "weekly": (7 * 24 * 3600, "运维周报"),
}

# AI 导语的角色约束：只许基于给定数据改写，禁止编造——导语失实比没有导语更糟。
_OVERVIEW_SYSTEM = (
    "你是运维简报撰写助手。根据给定的结构化简报数据，用 3~5 句简洁中文写一段导语，"
    "概括系统健康状况、安全态势与本窗口运维活动的重点。"
    "只允许转述给定数据，禁止编造任何数字或事件；不用列表，不用标题，直接输出正文。"
)


def _system_snapshot() -> dict:
    """采集系统快照（全 psutil/os 本地读取，READONLY）。"""
    uname = os.uname()
    try:
        load1, load5, load15 = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = None
    vm = psutil.virtual_memory()
    du = psutil.disk_usage("/")
    boot = psutil.boot_time()
    up = int(time.time() - boot)
    days, rem = divmod(up, 86400)
    hours, minutes = rem // 3600, rem % 3600 // 60
    return {
        "hostname": uname.nodename,
        "kernel": uname.release,
        "arch": uname.machine,
        "uptime_human": f"{days}天{hours}小时{minutes}分",
        "loadavg": [load1, load5, load15],
        "cpu_count": psutil.cpu_count(logical=True),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "mem_percent": vm.percent,
        "mem_used_gb": round(vm.used / 1e9, 2),
        "mem_total_gb": round(vm.total / 1e9, 2),
        "disk_percent": du.percent,
        "disk_used_gb": round(du.used / 1e9, 2),
        "disk_total_gb": round(du.total / 1e9, 2),
    }


def _diagnosis_summary(report: dict) -> dict:
    """把 diagnose("all") 的多主题报告压成简报所需的摘要（问题清单 + 建议汇总）。"""
    reports = report.get("reports", [])
    issues: list[dict] = []
    suggestions: list[str] = []
    counts = {"critical": 0, "warning": 0, "ok": 0, "unknown": 0}
    for r in reports:
        sev = r.get("severity") or "unknown"
        counts[sev if sev in counts else "unknown"] += 1
        if sev not in ("ok", "unknown"):
            issues.append({
                "topic": r.get("topic"),
                "severity": sev,
                # 各主题报告首条 finding 即结论句，取它作为问题一句话描述
                "finding": (r.get("findings") or ["（无明细）"])[0],
            })
        suggestions.extend(r.get("suggestions") or [])
    return {
        "summary": report.get("summary", ""),
        "severity_counts": counts,
        "issues": issues,
        "suggestions": suggestions,
    }


def _posture_summary(report: dict) -> dict:
    """把姿态检查报告压成摘要：内核版本、总体档位、命中的情报条目。"""
    matches = report.get("matches") or []
    hits = [
        {"cve": m.get("cve"), "status": m.get("status"),
         "mitigations": m.get("mitigations") or []}
        for m in matches
        if m.get("status") not in ("not_affected", None)
    ]
    return {
        "kernel": report.get("kernel"),
        "severity": report.get("severity", "unknown"),
        "intel_source": report.get("intel_source"),
        "hits": hits,
    }


def _fallback_overview(briefing: dict) -> str:
    """确定性导语：LLM 不可用/未启用/失败时的兜底，只陈述已聚合的数字。"""
    diag = briefing["diagnosis"]
    act = briefing["activity"]
    pos = briefing["posture"]
    health = diag["summary"] or "健康诊断未产出结论。"
    sec = ("安全态势正常。" if pos["severity"] in ("ok", "info")
           else f"安全态势档位为 {pos['severity']}，命中情报 {len(pos['hits'])} 条，建议关注。")
    return (f"{health}窗口内共处理 {act['total']} 次会话，"
            f"其中 {act['blocked']} 次被安全护栏拦截，"
            f"执行受控动作 {act['actions']} 次。{sec}")


def _ai_overview(briefing: dict, llm: LLMProvider, model: str | None) -> str | None:
    """可选 AI 导语：单次无工具调用，把聚合数据改写成流畅导语；任何异常返回 None 降级。"""
    import json
    compact = {
        "period": briefing["period_label"],
        "snapshot": briefing["snapshot"],
        "diagnosis": briefing["diagnosis"],
        "posture": {k: briefing["posture"][k] for k in ("severity", "hits")},
        "activity": briefing["activity"],
    }
    messages = [
        {"role": "system", "content": _OVERVIEW_SYSTEM},
        {"role": "user", "content": json.dumps(compact, ensure_ascii=False, default=str)},
    ]
    try:
        # 关键：不传 tools——导语撰写是纯文本改写，结构上不给任何工具调用面。
        msg = llm.chat(messages, None, model=model)
        text = (msg.get("content") or "").strip()
        return text or None
    except Exception:  # noqa: BLE001 导语是锦上添花，任何失败都降级为确定性导语
        return None


def render_markdown(b: dict) -> str:
    """把结构化简报渲染为 Markdown 文本（前端预览 / 一键下载归档用）。"""
    s, diag, pos, act = b["snapshot"], b["diagnosis"], b["posture"], b["activity"]
    load = " / ".join("-" if v is None else f"{v:.2f}" for v in s["loadavg"])
    lines = [
        f"# {b['period_label']} · {b['date']}",
        "",
        f"> 主机 {s['hostname']}（{s['arch']}，内核 {s['kernel']}）"
        f" · 统计窗口 {b['window_start']} ~ {b['generated_at']}"
        f" · 导语来源：{'AI 撰写（数据约束）' if b['ai_overview_used'] else '确定性模板'}",
        "",
        "## 一、导语",
        "",
        b["overview"],
        "",
        "## 二、系统概况",
        "",
        f"- 运行时长：{s['uptime_human']}；负载(1/5/15m)：{load}（{s['cpu_count']} 核）",
        f"- CPU 使用率：{s['cpu_percent']}%",
        f"- 内存：{s['mem_used_gb']} / {s['mem_total_gb']} GB（{s['mem_percent']}%）",
        f"- 根分区：{s['disk_used_gb']} / {s['disk_total_gb']} GB（{s['disk_percent']}%）",
        "",
        "## 三、健康诊断",
        "",
        diag["summary"] or "（无结论）",
        "",
    ]
    if diag["issues"]:
        for i in diag["issues"]:
            lines.append(f"- **[{i['severity']}] {i['topic']}**：{i['finding']}")
    else:
        lines.append("- 未发现需要关注的问题。")
    lines += ["", "## 四、安全态势", ""]
    if pos["hits"]:
        lines.append(f"- 态势档位 **{pos['severity']}**，命中情报 {len(pos['hits'])} 条"
                     f"（情报源：{pos['intel_source'] or '本地种子库'}）：")
        for h in pos["hits"]:
            lines.append(f"  - {h['cve']}（{h['status']}）"
                         + (f"；缓解：{h['mitigations'][0]}" if h["mitigations"] else ""))
    else:
        lines.append(f"- 内核 {pos['kernel']}，与情报库比对未命中已知风险。")
    lines += [
        "",
        "## 五、运维活动",
        "",
        f"- 会话 {act['total']} 次；护栏拦截 {act['blocked']} 次；"
        f"污点路径 {act['tainted']} 条；受控动作 {act['actions']} 次。",
    ]
    if act["by_intent"]:
        dist = "、".join(f"{k}×{v}" for k, v in act["by_intent"].items())
        lines.append(f"- 意图分布：{dist}。")
    if act["blocked_samples"]:
        lines.append("- 拦截事件样例（详情可按 trace_id 回放）：")
        for e in act["blocked_samples"]:
            ts = time.strftime("%m-%d %H:%M", time.localtime(e["created_at"]))
            lines.append(f"  - {ts} 「{e['user_input']}」（trace `{e['trace_id'][:12]}…`）")
    lines += ["", "## 六、待办与建议", ""]
    todos = diag["suggestions"][:8]
    for h in pos["hits"]:
        todos.extend(h["mitigations"][:1])
    if todos:
        lines.extend(f"- [ ] {t}" for t in dict.fromkeys(todos))  # 去重保序
    else:
        lines.append("- 暂无待办。")
    lines += ["", "---", "",
              "本简报由系统只读聚合自动生成；所有建议仅供人工决策，"
              "任何变更须经受控动作（二次确认 + 护栏 + 审计）执行。", ""]
    return "\n".join(lines)


def generate_briefing(period: str = "daily", *, path: str = "/",
                      llm: LLMProvider | None = None,
                      model: str | None = None) -> dict:
    """生成一份运维简报（结构化数据 + Markdown 渲染）。

    Args:
        period: "daily"（近 24 小时）或 "weekly"（近 7 天）。
        path: 健康诊断的磁盘扫描根路径（同 /diagnose 口径）。
        llm: 可选 LLM provider，仅用于撰写导语；None / 失败 → 确定性导语。
        model: 传给 LLM 的模型覆盖（同编排层「深度思考」口径）。
    Returns:
        结构化简报 dict，含 markdown 字段（完整渲染文本）。
    """
    if period not in PERIODS:
        return {"ok": False,
                "error": f"未知简报周期: {period}（可选 {', '.join(PERIODS)}）"}
    window_s, label = PERIODS[period]
    now = time.time()
    fmt = "%Y-%m-%d %H:%M"

    briefing: dict = {
        "ok": True,
        "period": period,
        "period_label": label,
        "date": time.strftime("%Y-%m-%d", time.localtime(now)),
        "generated_at": time.strftime(fmt, time.localtime(now)),
        "window_start": time.strftime(fmt, time.localtime(now - window_s)),
        "snapshot": _system_snapshot(),
        "diagnosis": _diagnosis_summary(diagnosis.diagnose("all", path)),
        "posture": _posture_summary(posture.check_posture(live=False)),
        "activity": store.activity_stats(now - window_s),
    }

    overview = _ai_overview(briefing, llm, model) if llm is not None else None
    briefing["ai_overview_used"] = overview is not None
    briefing["overview"] = overview or _fallback_overview(briefing)
    briefing["markdown"] = render_markdown(briefing)
    return briefing
