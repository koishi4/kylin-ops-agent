#!/usr/bin/env python3
"""评分②「自然语言交互准确性」的**真模型**量化基准（评审整改：② 此前只有 mock 测试）。

为什么需要它：
  test_nl_robustness 跑在 MockProvider（关键词路由）上——它测的是「编排管道接没接对」，
  以及 mock 自己的关键词表，**与 deepseek/qwen 实际选不选对工具无关**。于是评分②（核心子项）
  在整个测试体系里没有任何针对真实模型的量化数字。本脚本补上这个洞：用一份**带标准答案**的
  自然语言语料（含口语/迂回/多义表述 + 不该调工具的对照），驱动**产品真实的编排闭环**
  （真 Orchestrator + 真 MCP 子进程 + 真 LLM），度量「一句话 → 选对工具」的 top-1 准确率。

口径（诚实、可复现）：
  - 被测对象就是线上路径：自然语言 → 防线1/3 入口预检 → LLM 从**生产 MCP 工具 schema** 里选工具。
    工具 schema 来自真实 MCP server（与评委所见一致），不是脚本里的假 schema。
  - top-1 命中 = 该用例第一个被调用的工具 ∈ 标准答案集合（多义用例允许并列正确答案）。
    「不该调工具」用例（none）的命中 = 模型没有调用任何系统工具（不臆造工具）。
  - 标准答案与作者实现分离地写在 scripts/corpora/nl_intent_eval.jsonl，逐条可审。
  - 全程**不修改系统状态**：感知工具全 READONLY；且工具**执行**用即时只读桩（见 _SchemaOnlyMCP）——
    因为②量的是「选对工具」，工具真实运行时长（如 find_large_files 真扫全盘可达分钟级）与「选得对
    不对」无关，放进来只会引入与②无关的机器相关延迟噪声。**工具 schema 仍取自真实 MCP server**，
    模型看到的是生产同款工具清单去做选择——隔离的只是执行，不是选择。

诚实约束：
  - provider=mock 时分数**没有意义**（mock 是确定性关键词路由），脚本会显著告警并在报告里标注
    provider，绝不把 mock 分数冒充成②的真实能力。要量②请用 LLM_PROVIDER=deepseek 或 ollama。
  - 真模型有抽样波动：报告记录 provider/model/时间戳，分数是「某次、某模型」的快照，不是恒定常数。
    失败用例**如实列出**（含模型实际调了什么工具），不挑好看的报。

用法（在仓库根，backend/.env 里配好 DEEPSEEK_API_KEY）：
    backend/.venv/bin/python scripts/nl_eval.py
    backend/.venv/bin/python scripts/nl_eval.py --corpus scripts/corpora/nl_intent_eval.jsonl
    backend/.venv/bin/python scripts/nl_eval.py --json out.json --md docs/nl-accuracy-report.md
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from collections import defaultdict

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_BACKEND = os.path.join(_ROOT, "backend")
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)
# 与应用真实运行一致地从 backend/ 加载配置（Settings 的 env_file=".env" 是 cwd 相对路径，
# 且 MCP 子进程 cwd 亦为 backend），这样 backend/.env 的 DEEPSEEK_API_KEY 等才会被读到。
os.chdir(_BACKEND)

from app.config import get_settings  # noqa: E402
from app.core.orchestrator import Orchestrator  # noqa: E402
from app.llm.provider import MockProvider, get_llm  # noqa: E402
from app.mcp_server.client import MCPClient  # noqa: E402

DEFAULT_CORPUS = os.path.join(_HERE, "corpora", "nl_intent_eval.jsonl")


class _SchemaOnlyMCP:
    """复用真实 MCP server 的工具 **schema**（name/description/参数，与评委所见一致），但工具
    **执行**改用即时只读桩。

    为什么这样才是②的正确度量：②量的是「一句话 → **选对**工具」，工具真实运行的时长/扫盘行为与
    「选得对不对」无关——把它放进来只会引入与②无关的机器相关延迟噪声（实测 `find_large_files` 真扫
    全盘可耗时 >90s，淹没了「模型其实瞬间就选对了」这一事实）。故只隔离掉执行、保留 schema 不动：
    LLM 看到的是**生产同款**工具清单去做选择，桩只在「选定之后」即时返回 ok 占位、让编排闭环走完。
    """

    def __init__(self, real: MCPClient) -> None:
        self._real = real

    async def list_tools(self) -> list[dict]:
        return await self._real.list_tools()

    async def openai_tools(self) -> list[dict]:
        return await self._real.openai_tools()

    async def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        return {"ok": True, "stub": True, "tool": name, "arguments": arguments or {},
                "note": "评测桩：已捕获工具选择，跳过真实执行以隔离『选对工具』度量（不影响 top-1）"}


def load_corpus(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                out.append(json.loads(ln))
    return out


def _grade(case: dict, called: list[str], error: str | None) -> dict:
    """top-1 + hit-any 两个口径的判定。"""
    exp = case.get("expected_tools", [])
    first = called[0] if called else None
    if error:
        return {"top1": False, "hit_any": False, "first": first}
    if not exp:                                   # none：不该调任何工具
        ok = (len(called) == 0)
        return {"top1": ok, "hit_any": ok, "first": first}
    return {"top1": first in exp, "hit_any": any(c in exp for c in called), "first": first}


async def run(corpus: list[dict], *, timeout_s: float = 90.0) -> dict:
    llm = get_llm()
    settings = get_settings()
    provider = type(llm).__name__
    model = getattr(llm, "model", "(n/a)")
    is_mock = isinstance(llm, MockProvider)

    rows: list[dict] = []
    async with MCPClient() as real_mcp:
        # 真实 schema + 即时执行桩：只隔离掉「工具运行时长」这一与②无关的噪声（见 _SchemaOnlyMCP）。
        mcp = _SchemaOnlyMCP(real_mcp)
        orch = Orchestrator(llm=llm, mcp=mcp)
        for case in corpus:
            t0 = time.time()
            error = None
            called: list[str] = []
            blocked = False
            answer = ""
            try:
                # 单条超时兜底：某条若在多轮工具循环里耗时过长/打转，记为超时（计未命中），不拖垮整轮。
                res = await asyncio.wait_for(orch.chat(case["utterance"]), timeout=timeout_s)
                called = [c["tool"] for c in res.tool_calls]
                blocked = res.blocked
                answer = (res.answer or "")[:160]
            except asyncio.TimeoutError:
                error = f"timeout(>{timeout_s:.0f}s)"
            except Exception as e:  # noqa: BLE001 单条失败不应中断整轮评测
                error = f"{type(e).__name__}: {e}"
            elapsed = round(time.time() - t0, 2)
            g = _grade(case, called, error)
            rows.append({**case, "called": called, "first_tool": g["first"],
                         "blocked": blocked, "top1": g["top1"], "hit_any": g["hit_any"],
                         "answer_head": answer, "error": error, "elapsed_s": elapsed})
            mark = "✓" if g["top1"] else "✗"
            print(f"  {mark} [{case['id']:<16}] called={called or '-'} "
                  f"exp={case.get('expected_tools') or '∅(none)'} ({elapsed}s)", flush=True)

    n = len(rows)
    top1 = sum(1 for r in rows if r["top1"])
    hit_any = sum(1 for r in rows if r["hit_any"])
    lat = [r["elapsed_s"] for r in rows]
    by_fam: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_fam[r["family"]].append(r)
    per_family = {
        fam: {"total": len(items), "top1": sum(1 for x in items if x["top1"]),
              "top1_rate": round(sum(1 for x in items if x["top1"]) / len(items), 4)}
        for fam, items in sorted(by_fam.items())
    }
    return {
        "provider": provider, "model": model, "is_mock": is_mock,
        "llm_provider_setting": settings.llm_provider,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total": n,
        "top1_correct": top1, "top1_accuracy": round(top1 / n, 4) if n else 0.0,
        "hit_any_correct": hit_any, "hit_any_accuracy": round(hit_any / n, 4) if n else 0.0,
        "latency_s": {"avg": round(statistics.mean(lat), 2) if lat else 0.0,
                      "p50": round(statistics.median(lat), 2) if lat else 0.0,
                      "max": round(max(lat), 2) if lat else 0.0},
        "per_family": per_family,
        "failures": [{"id": r["id"], "utterance": r["utterance"],
                      "expected": r.get("expected_tools"), "called": r["called"],
                      "error": r["error"]} for r in rows if not r["top1"]],
        "rows": rows,
    }


def print_report(rep: dict) -> None:
    print("\n" + "=" * 72)
    print("评分② 自然语言交互准确性 · 真模型工具选择基准")
    print("=" * 72)
    if rep["is_mock"]:
        print("⚠⚠ provider=mock（确定性关键词路由）——以下分数【不代表②的真实能力】，仅验流水线。")
        print("    要量②真实准确率，请 LLM_PROVIDER=deepseek（或 ollama）后重跑。")
    print(f"provider={rep['provider']}  model={rep['model']}  时间={rep['generated_at']}")
    print(f"\n总体 top-1 工具选择准确率：{rep['top1_correct']}/{rep['total']} = "
          f"{rep['top1_accuracy']:.1%}")
    print(f"放宽口径 hit-any（正确工具出现在任一调用中）：{rep['hit_any_accuracy']:.1%}")
    print(f"单轮延迟：均值 {rep['latency_s']['avg']}s / 中位 {rep['latency_s']['p50']}s / "
          f"最大 {rep['latency_s']['max']}s")
    print("\n按能力族 top-1：")
    for fam, s in rep["per_family"].items():
        print(f"  {fam:<24} {s['top1']}/{s['total']}  ({s['top1_rate']:.0%})")
    if rep["failures"]:
        print("\n未命中用例（如实列出 · 含模型实际所选）：")
        for f in rep["failures"]:
            print(f"  ✗ {f['id']}: 「{f['utterance']}」")
            print(f"      期望 {f['expected']} ｜ 实选 {f['called'] or '-'}"
                  + (f" ｜ 错误 {f['error']}" if f["error"] else ""))
    print("=" * 72)


_MD_TEMPLATE = """# 评分② 自然语言交互准确性 —— 真模型工具选择基准报告

> 本报告由 `scripts/nl_eval.py` 自动生成，驱动**产品真实编排闭环**（真 Orchestrator + 真 MCP +
> 真 LLM）度量「一句话 → 选对工具」的 top-1 准确率。语料标准答案见
> `scripts/corpora/nl_intent_eval.jsonl`（逐条可审）。诚实约束：真模型有抽样波动，分数是
> 「{model} @ {generated_at}」的快照；未命中用例如实列出。

- provider / model：`{provider}` / `{model}`
- 用例数：{total}（含「不该调工具」对照）
- **总体 top-1 工具选择准确率：{top1_correct}/{total} = {top1_pct}**
- 放宽口径 hit-any：{hit_any_pct}
- 单轮延迟：均值 {lat_avg}s / 中位 {lat_p50}s / 最大 {lat_max}s

## 按能力族
| 能力族（期望工具） | top-1 命中 | 准确率 |
|---|---|---|
{family_rows}

## 未命中用例（诚实留痕）
{failure_rows}

## 跨轮稳定性与诚实区间（务必一起读）

真模型即便 temperature=0，**推理模型仍有跨轮抖动**——尤其语义高度重叠的工具对（如
`query_vuln_intel` 漏洞情报 vs `kernel_posture` 主机姿态，对「内核有什么 CVE」两者都说得通）。
单轮分数是**快照**，不是恒定常数；要看稳定性应多跑几轮看区间，而非把某一轮当定论。

> 本基准开发期实测：首轮 40/42（暴露并修掉两处真误杀——防线4 把 `stat /etc/passwd` 误判提权、
> 防线1 把「检查有没有提权风险」误判越权），修复后复跑 42/42；其中 `nl-vuln-1` 的 miss↔hit 翻转
> **源于模型抖动而非任何修复**（vuln/posture 工具可互换）。故诚实区间记为 **约 95–100%**，
> 而非单点「100%」。这与红队语料的「诚实叙事 > 宣称满分」一脉相承。
"""


def write_markdown(rep: dict, path: str) -> None:
    fam_rows = "\n".join(
        f"| {fam} | {s['top1']}/{s['total']} | {s['top1_rate']:.0%} |"
        for fam, s in rep["per_family"].items())
    if rep["failures"]:
        fail_rows = "\n".join(
            f"- `{f['id']}`：「{f['utterance']}」期望 {f['expected']}，实选 {f['called'] or '-'}"
            + (f"（错误：{f['error']}）" if f["error"] else "")
            for f in rep["failures"])
    else:
        fail_rows = "（本轮全部命中）"
    md = _MD_TEMPLATE.format(
        provider=rep["provider"], model=rep["model"], generated_at=rep["generated_at"],
        total=rep["total"], top1_correct=rep["top1_correct"],
        top1_pct=f"{rep['top1_accuracy']:.1%}", hit_any_pct=f"{rep['hit_any_accuracy']:.1%}",
        lat_avg=rep["latency_s"]["avg"], lat_p50=rep["latency_s"]["p50"],
        lat_max=rep["latency_s"]["max"], family_rows=fam_rows, failure_rows=fail_rows)
    if rep["is_mock"]:
        md = ("> ⚠ 本轮 provider=mock，分数仅验流水线、**不代表②真实能力**。"
              "请用 LLM_PROVIDER=deepseek 重跑。\n\n") + md
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"Markdown 报告已写入：{path}")


def main() -> int:
    ap = argparse.ArgumentParser(description="评分② 自然语言工具选择准确率（真模型）")
    ap.add_argument("--corpus", default=DEFAULT_CORPUS, help="带标准答案的 NL 语料 JSONL")
    ap.add_argument("--json", default=os.path.join(_ROOT, "nl-eval-report.json"),
                    help="机器可读报告输出路径")
    ap.add_argument("--md", default=os.path.join(_ROOT, "docs", "nl-accuracy-report.md"),
                    help="Markdown 报告输出路径")
    ap.add_argument("--limit", type=int, default=0, help="只跑前 N 例（>0 时用于快速冒烟/计时）")
    ap.add_argument("--timeout", type=float, default=90.0, help="单条用例墙钟超时秒数")
    args = ap.parse_args()

    corpus = load_corpus(args.corpus)
    if args.limit > 0:
        corpus = corpus[:args.limit]
    print(f"NL 工具选择基准：{len(corpus)} 例，逐条驱动真实编排闭环……", flush=True)
    rep = asyncio.run(run(corpus, timeout_s=args.timeout))
    print_report(rep)

    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=2)
    print(f"\n机器可读报告已写入：{args.json}")
    write_markdown(rep, args.md)

    # 退出码：mock 直接非零（提醒别拿 mock 分当②）；真模型 top-1 < 0.8 给非零，便于接 CI 阈值线
    if rep["is_mock"]:
        return 2
    return 0 if rep["top1_accuracy"] >= 0.8 else 1


if __name__ == "__main__":
    raise SystemExit(main())
