"""漏洞情报感知 MCP 工具（P1-1）——把「内核新漏洞的时效」从训练问题变成检索问题。

核心命题：对「看似无害的新内核漏洞利用」（如 Dirty Frag / CVE-2026-43284），内容特征检测
无效（命令本身无害），而模型也不可能知道训练截止之后才公开的 CVE。正确做法不是让模型「记住」
漏洞，而是给 Agent 一个**可检索的活情报源**：本地 advisory feed 兜底（离线也能演），必要时
联网（OSV.dev，无需 key）刷新。

设计：**本地优先、联网增强、失败回退**。
- 默认只读本地种子库 data/advisories.json（确定、离线、演示安全）。
- live=True 时尝试 OSV.dev 查询单个 CVE，带超时；任何网络异常都回退本地，绝不让工具失败。

READONLY：只检索情报、绝不改系统。外部 feed 内容视为不可信（A 腿），不直接驱动任何指令流。
"""
from __future__ import annotations

import json
import os
from functools import lru_cache

_FEED_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "advisories.json")


@lru_cache(maxsize=1)
def _load_local_feed() -> dict:
    """读取本地种子库；文件缺失/损坏时返回空结构（绝不抛异常，离线兜底永不空窗）。"""
    try:
        with open(_FEED_PATH, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("advisories"), list):
            return data
    except (OSError, ValueError):
        pass
    return {"feed_version": "unknown", "source": "empty", "advisories": []}


def _matches(adv: dict, *, component: str | None, cve: str | None) -> bool:
    """某条 advisory 是否匹配查询条件（大小写不敏感；component 匹配组件名/模块名/别名）。"""
    if cve and adv.get("cve", "").lower() != cve.lower():
        return False
    if component:
        c = component.lower()
        hay = [adv.get("cve", ""), adv.get("title", ""), *adv.get("aliases", []),
               *adv.get("components", []), *adv.get("modules", [])]
        if not any(c in str(h).lower() for h in hay):
            return False
    return True


def _fetch_osv_cve(cve: str, timeout: float) -> dict | None:
    """联网查询单个 CVE（OSV.dev，无需 key）。任何异常返回 None（交由上层回退本地）。"""
    try:
        import httpx
        r = httpx.get(f"https://api.osv.dev/v1/vulns/{cve}", timeout=timeout)
        if r.status_code == 200:
            j = r.json()
            return {
                "cve": cve,
                "aliases": j.get("aliases", []),
                "title": j.get("summary", "")[:200],
                "summary": (j.get("details", "") or "")[:500],
                "severity": "unknown",
                "components": [],
                "modules": [],
                "mitigations": [],
                "references": [ref.get("url") for ref in j.get("references", []) if ref.get("url")][:5],
                "source": "osv.dev",
            }
    except Exception:  # noqa: BLE001 网络/解析任何异常都回退本地，绝不让工具失败
        return None
    return None


def query_vuln_intel(component: str | None = None, cve: str | None = None,
                     live: bool = False, timeout: float = 3.0) -> dict:
    """检索漏洞情报。READONLY。

    Args:
        component: 按组件/内核模块/别名过滤，如 "esp4"、"rxrpc"、"Dirty Frag"。
        cve: 按 CVE 编号精确查询，如 "CVE-2026-43284"。
        live: 是否联网（OSV.dev）增强；默认 False（离线、确定、演示安全）。
        timeout: 联网超时秒数。
    Returns:
        含 advisories 列表的字典；live 失败会回退本地并在 live_error 标注。
    """
    feed = _load_local_feed()
    advisories = [a for a in feed["advisories"]
                  if _matches(a, component=component, cve=cve)]

    live_used = False
    live_error = None
    if live and cve:
        fetched = _fetch_osv_cve(cve, timeout)
        if fetched is not None:
            live_used = True
            # 联网结果优先合并到结果头部（不污染本地缓存）
            if not any(a.get("cve", "").lower() == cve.lower() for a in advisories):
                advisories = [fetched, *advisories]
        else:
            live_error = "联网查询失败或超时，已回退本地种子库"

    return {
        "ok": True,
        "level": "READONLY",
        "feed_version": feed.get("feed_version"),
        "source": "osv.dev+local" if live_used else "local",
        "live": live_used,
        "live_error": live_error,
        "count": len(advisories),
        "advisories": advisories,
    }
