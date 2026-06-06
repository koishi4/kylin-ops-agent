"""内核 / 主机安全姿态检查（P1-2）—— 把活情报落到「本机此刻是否暴露」的判断上。

链路：读本机内核版本 + 已加载内核模块（lsmod / /proc/modules）→ 与漏洞情报 feed（vuln_intel）
比对 → 命中则产出告警与**缓解建议**（如 `modprobe -r esp4 esp6 rxrpc` 或写 blacklist 配置）。

铁律：**只研判、只建议，绝不自动执行任何缓解**。缓解命令是给人看的候选文本，真要执行须走
受控动作层 /action/execute 的护栏 + 二次确认（human-in-the-loop）。

诚实的覆盖边界（写进结果与文档，不吹）：
- 覆盖：feed 里**已披露的 N-day**（如 Dirty Frag / CVE-2026-43284）——「本机内核命中且相关模块已加载」。
- 不覆盖：**未披露的 0-day**——没有情报就无从比对。这类由 P1-3 沙箱遏制兜底（不认识漏洞也能削其前提）。

设计：**采集与推理分离**。assess_posture 是纯函数（输入内核版本/已加载模块/情报 → 输出告警），
可用构造数据做确定性测试；check_posture 负责真实采集再喂给它。
"""
from __future__ import annotations

import os
import re

from app.mcp_server.tools.vuln_intel import query_vuln_intel

_VER_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def _kernel_release() -> str:
    """本机内核版本串，如 '6.6.114.1-microsoft-standard-WSL2'。失败返回空串。"""
    try:
        return os.uname().release
    except (AttributeError, OSError):
        return ""


def _loaded_modules() -> set[str]:
    """已加载内核模块名集合（读 /proc/modules，首列即模块名）。读不到返回空集。"""
    mods: set[str] = set()
    try:
        with open("/proc/modules", encoding="utf-8") as f:
            for line in f:
                name = line.split(" ", 1)[0].strip()
                if name:
                    mods.add(name)
    except OSError:
        pass
    return mods


def _ver_tuple(v: str) -> tuple[int, int, int] | None:
    """把版本串解析成 (major, minor, patch)，patch 缺省 0。解析不出返回 None。"""
    if not v:
        return None
    m = _VER_RE.search(v)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def _in_kernel_range(release: str, kmin: str | None, kmax: str | None) -> bool | None:
    """本机内核是否落在 [kmin, kmax]（含端点）。任一端解析不出则返回 None（无法判定）。"""
    cur = _ver_tuple(release)
    if cur is None:
        return None
    lo = _ver_tuple(kmin) if kmin else None
    hi = _ver_tuple(kmax) if kmax else None
    if lo is None and hi is None:
        return None
    if lo is not None and cur < lo:
        return False
    if hi is not None and cur > hi:
        return False
    return True


def assess_posture(kernel_release: str, loaded_modules: set[str],
                   advisories: list[dict]) -> dict:
    """纯函数：据本机内核版本 + 已加载模块 + 情报条目，逐条研判暴露面。

    每条 advisory 给出 status：
      - "exposed"      内核命中范围 **且** 相关模块已加载（或情报无关联模块但内核命中）→ 最高危
      - "module_only"  相关模块已加载，但内核版本无法判定（保守告警，宁可多提醒）
      - "kernel_only"  内核命中范围，但相关模块未加载（暴露面小，建议打补丁）
      - "clear"        既不命中内核范围、相关模块也未加载
    返回含 severity / findings / matches（逐条）/ mitigations / scope_note 的结构化报告。
    """
    matches: list[dict] = []
    for adv in advisories:
        adv_mods = {str(m).lower() for m in adv.get("modules", [])}
        loaded_hit = sorted(m for m in loaded_modules if m.lower() in adv_mods)
        kernel_hit = _in_kernel_range(kernel_release,
                                      adv.get("kernel_min"), adv.get("kernel_max"))

        if adv_mods:
            if loaded_hit and kernel_hit is not False:
                status = "exposed" if kernel_hit else "module_only"
            elif kernel_hit:
                status = "kernel_only"
            else:
                status = "clear"
        else:
            # 无关联可卸载模块（如 Copy Fail）：只能按内核范围判
            status = "exposed" if kernel_hit else ("clear" if kernel_hit is False else "kernel_only")

        if status == "clear":
            continue
        matches.append({
            "cve": adv.get("cve"),
            "aliases": adv.get("aliases", []),
            "title": adv.get("title"),
            "severity": adv.get("severity", "unknown"),
            "status": status,
            "loaded_modules_hit": loaded_hit,
            "kernel_in_range": kernel_hit,
            "summary": adv.get("summary", ""),
            # 缓解是给人看的候选命令文本；执行须走护栏 + 二次确认（不自动执行）
            "mitigations": adv.get("mitigations", []),
            "references": adv.get("references", []),
        })

    exposed = [m for m in matches if m["status"] in ("exposed", "module_only")]
    crit = [m for m in matches if m["severity"] == "critical" and m["status"] in ("exposed", "module_only")]
    severity = "critical" if crit else ("warning" if matches else "ok")

    findings: list[str] = [
        f"本机内核 {kernel_release or '未知'}，已加载模块 {len(loaded_modules)} 个。"
    ]
    if exposed:
        for m in exposed:
            mod_txt = ("，且相关模块已加载：" + ", ".join(m["loaded_modules_hit"])) \
                if m["loaded_modules_hit"] else ""
            alias = f"（{m['aliases'][0]}）" if m.get("aliases") else ""
            findings.append(f"⛔ 命中 {m['cve']}{alias}{mod_txt}")
    elif matches:
        findings.append("内核版本落在部分已披露漏洞范围，但相关模块未加载，暴露面有限。")
    else:
        findings.append("未命中情报库中任何已披露内核漏洞（仅就 N-day feed 而言）。")

    return {
        "ok": True,
        "topic": "posture",
        "severity": severity,
        "kernel": kernel_release,
        "loaded_module_count": len(loaded_modules),
        "matches": matches,
        "findings": findings,
        "remediation_policy": "缓解命令均为候选文本，须经 /action/execute 护栏 + 二次确认执行，绝不自动落地。",
        "scope_note": ("本检查覆盖情报库中**已披露的 N-day**（命中内核范围/已加载模块即告警）；"
                       "**不覆盖未披露的 0-day**——后者由执行沙箱（最小权限 + 能力削减）在『不认识漏洞』"
                       "的前提下遏制其利用前提。"),
    }


def check_posture(live: bool = False) -> dict:
    """姿态检查采集入口：采全真实信号后交给 assess_posture 研判。READONLY，绝不执行缓解。

    Args:
        live: 是否让情报源联网增强（默认 False，离线用本地种子库）。
    """
    intel = query_vuln_intel(live=live)
    report = assess_posture(_kernel_release(), _loaded_modules(), intel.get("advisories", []))
    report["feed_version"] = intel.get("feed_version")
    report["intel_source"] = intel.get("source")
    return report
