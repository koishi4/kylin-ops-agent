#!/usr/bin/env python3
"""评分②/④ 的**多步推理（Agentic Loop）**量化基准（第三方评审「三.1」整改）。

为什么需要它（评审指出的真盲区）：
  `nl_eval.py` 用 `_SchemaOnlyMCP` 把工具执行换成 `{"ok":True,"stub":True}` 占位——模型拿不到
  **真实的中间状态**（比如 df 返回的具体占用率），所以它只能度量「一句话 → 第一步（top-1）选对工具」。
  但真实运维是**多轮**的：`disk_usage` 看到 96% 满 → 自主决定 `find_large_files` 定位 → 给出结论。
  这种「据上一步结果决定下一步」的推理链，nl_eval 测不到，是客观盲区。本脚本补上它。

口径（诚实、可复现，与 nl_eval 同源风格）：
  - **不修改系统状态**：感知工具全 READONLY；这里更进一步——工具执行换成**剧本化的真实态桩**
    （`_ScenarioMCP`），让每条用例处在一个**确定、可控**的"系统世界"里（如磁盘 96% 满、某进程吃
    38% 内存、nginx 端口冲突）。这样既不依赖被测机当时是否真处于故障态（否则不可复现），又让模型
    拿到**有意义的中间结果**去做下一步决策——正是 nl_eval 的 stub 给不了的。
  - 工具 **schema 仍取自真实 MCP server**（与评委所见、与 nl_eval 一致）；桩只替换"执行返回什么"，
    不替换"有哪些工具可选"。模型在生产同款工具清单上自主规划多步。
  - 评的是**链**而非单步：
      · chain_ok：期望链（每个位置可给若干可接受工具的"任一即可"集合）是实际调用序列的**有序子列**
        （允许中间穿插其它合理调用）——即"该先看占用、再定位大文件"的因果顺序对不对。
      · multi_step：实际调用的**不同**工具数 ≥ 该场景的 `min_distinct_tools`——证明模型**没有停在第一步**。
      · pass = chain_ok ∧ multi_step ∧ 无错误。另记 first_ok（首工具对不对）便于与 nl_eval 对照。
  - 期望链与剧本世界**逐条写在** scripts/corpora/agentic_chain_eval.jsonl，标准答案与实现分离、可审。

诚实约束（与 nl_eval 一致）：
  - provider=mock 时分数**没有意义**：MockProvider 是关键词路由、拿到工具结果即收尾，结构上不会多步
    链式。脚本会显著告警并在报告里标注 provider，绝不把 mock 分冒充成多步推理能力。要量请用
    LLM_PROVIDER=deepseek。
  - 真模型有抽样波动：报告记录 provider/model/时间戳，分数是"某次、某模型"的快照。失败用例如实
    列出（含模型实际调用序列），不挑好看的报。

用法（在仓库根，backend/.env 配好 DEEPSEEK_API_KEY）：
    backend/.venv/bin/python scripts/agentic_eval.py
    backend/.venv/bin/python scripts/agentic_eval.py --json out.json --md docs/agentic-chain-report.md
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
# 与 nl_eval 同：从 backend/ 加载配置（Settings env_file=".env" 为 cwd 相对；MCP 子进程 cwd 亦此）。
os.chdir(_BACKEND)

from app.config import get_settings  # noqa: E402
from app.core.orchestrator import Orchestrator  # noqa: E402
from app.llm.provider import MockProvider, get_llm  # noqa: E402
from app.mcp_server.client import MCPClient  # noqa: E402

DEFAULT_CORPUS = os.path.join(_HERE, "corpora", "agentic_chain_eval.jsonl")


class _ScenarioMCP:
    """复用真实 MCP server 的工具 **schema**，但工具**执行**换成**剧本化的真实态桩**。

    与 nl_eval._SchemaOnlyMCP 的关键差异：那个桩对任何工具都返回无信息的 `{"ok":True,"stub":True}`，
    模型据此无法做"看结果再决定下一步"的多步推理；这里按当前用例的剧本 `world` 返回**有意义的、
    确定的**系统状态（磁盘占用率、进程列表、服务状态、日志行……），让模型能真正基于中间结果链式规划。

    `world` 是 {tool_name: 返回 dict}。未在剧本里声明的工具被调用时，返回一个温和的 ok 占位
    （标 `unscripted`），既不让闭环崩、也不向模型注入额外故障信号。每条用例前由 run() 经 set_world 切换。
    """

    def __init__(self, real: MCPClient) -> None:
        self._real = real
        self._world: dict[str, dict] = {}

    def set_world(self, world: dict[str, dict]) -> None:
        self._world = world or {}

    async def list_tools(self) -> list[dict]:
        return await self._real.list_tools()

    async def openai_tools(self) -> list[dict]:
        return await self._real.openai_tools()

    async def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        scripted = self._world.get(name)
        if scripted is not None:
            # 复制一份并回填本次调用参数，避免跨用例共享可变对象。
            return {**scripted, "tool": name, "arguments": arguments or {}}
        # 剧本未覆盖的工具：温和占位（不注入故障信号、不影响链判定）。
        return {"ok": True, "level": "READONLY", "unscripted": True, "tool": name,
                "arguments": arguments or {},
                "note": "剧本未脚本化该工具，返回无信息占位（多步链判定只看是否按因果顺序选对工具）"}


def load_corpus(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                out.append(json.loads(ln))
    return out


def _chain_ok(called: list[str], expected_chain: list[list[str]]) -> bool:
    """期望链是否为实际调用序列的**有序子列**。

    expected_chain 的每个元素是一个"任一即可"的工具集合（处理同一步多个合理工具的歧义，
    如第二步 find_large_files 或 dir_size 都算定位大文件）。逐个位置按顺序在 called 里向后匹配，
    允许中间穿插其它调用；所有位置都按序匹配到 → True。
    """
    if not expected_chain:
        return True
    i = 0
    for tool in called:
        if tool in expected_chain[i]:
            i += 1
            if i == len(expected_chain):
                return True
    return False


def _grade(case: dict, called: list[str], error: str | None) -> dict:
    expected_chain = case.get("expected_chain", [])
    min_distinct = int(case.get("min_distinct_tools", len(expected_chain)))
    first = called[0] if called else None
    if error:
        return {"pass": False, "chain_ok": False, "multi_step": False, "first_ok": False,
                "first": first, "distinct": 0}
    distinct = len(dict.fromkeys(called))
    chain_ok = _chain_ok(called, expected_chain)
    multi_step = distinct >= min_distinct
    first_ok = (not expected_chain) or (first in expected_chain[0])
    return {"pass": chain_ok and multi_step, "chain_ok": chain_ok, "multi_step": multi_step,
            "first_ok": first_ok, "first": first, "distinct": distinct}


async def run(corpus: list[dict], *, timeout_s: float = 180.0) -> dict:
    llm = get_llm()
    settings = get_settings()
    provider = type(llm).__name__
    model = getattr(llm, "model", "(n/a)")
    is_mock = isinstance(llm, MockProvider)

    rows: list[dict] = []
    async with MCPClient() as real_mcp:
        mcp = _ScenarioMCP(real_mcp)
        orch = Orchestrator(llm=llm, mcp=mcp)
        for case in corpus:
            mcp.set_world(case.get("world", {}))
            t0 = time.time()
            error = None
            called: list[str] = []
            blocked = False
            answer = ""
            try:
                res = await asyncio.wait_for(orch.chat(case["utterance"]), timeout=timeout_s)
                called = [c["tool"] for c in res.tool_calls]
                blocked = res.blocked
                answer = (res.answer or "")[:200]
            except asyncio.TimeoutError:
                error = f"timeout(>{timeout_s:.0f}s)"
            except Exception as e:  # noqa: BLE001 单条失败不中断整轮
                error = f"{type(e).__name__}: {e}"
            elapsed = round(time.time() - t0, 2)
            g = _grade(case, called, error)
            rows.append({**{k: v for k, v in case.items() if k != "world"},
                         "called": called, "first_tool": g["first"], "distinct": g["distinct"],
                         "blocked": blocked, "pass": g["pass"], "chain_ok": g["chain_ok"],
                         "multi_step": g["multi_step"], "first_ok": g["first_ok"],
                         "answer_head": answer, "error": error, "elapsed_s": elapsed})
            mark = "✓" if g["pass"] else "✗"
            exp = " → ".join("|".join(s) for s in case.get("expected_chain", [])) or "∅"
            print(f"  {mark} [{case['id']:<18}] called={called or '-'}  期望链={exp}  "
                  f"(chain={'✓' if g['chain_ok'] else '✗'} multi={'✓' if g['multi_step'] else '✗'}, "
                  f"{elapsed}s)", flush=True)

    n = len(rows)
    passed = sum(1 for r in rows if r["pass"])
    chain = sum(1 for r in rows if r["chain_ok"])
    multi = sum(1 for r in rows if r["multi_step"])
    lat = [r["elapsed_s"] for r in rows]
    by_fam: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_fam[r.get("family", "?")].append(r)
    per_family = {
        fam: {"total": len(items), "pass": sum(1 for x in items if x["pass"]),
              "pass_rate": round(sum(1 for x in items if x["pass"]) / len(items), 4)}
        for fam, items in sorted(by_fam.items())
    }
    return {
        "provider": provider, "model": model, "is_mock": is_mock,
        "llm_provider_setting": settings.llm_provider,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total": n,
        "pass_correct": passed, "pass_accuracy": round(passed / n, 4) if n else 0.0,
        "chain_ok_rate": round(chain / n, 4) if n else 0.0,
        "multi_step_rate": round(multi / n, 4) if n else 0.0,
        "latency_s": {"avg": round(statistics.mean(lat), 2) if lat else 0.0,
                      "p50": round(statistics.median(lat), 2) if lat else 0.0,
                      "max": round(max(lat), 2) if lat else 0.0},
        "per_family": per_family,
        "failures": [{"id": r["id"], "utterance": r["utterance"],
                      "expected_chain": r.get("expected_chain"), "called": r["called"],
                      "chain_ok": r["chain_ok"], "multi_step": r["multi_step"],
                      "error": r["error"]} for r in rows if not r["pass"]],
        "rows": rows,
    }


def print_report(rep: dict) -> None:
    print("\n" + "=" * 72)
    print("评分②/④ 多步推理（Agentic Loop）· 真模型工具链基准")
    print("=" * 72)
    if rep["is_mock"]:
        print("⚠⚠ provider=mock（关键词路由，拿到结果即收尾）——结构上不会多步链式，以下分数")
        print("    【不代表多步推理能力】，仅验流水线。要量请 LLM_PROVIDER=deepseek 后重跑。")
    print(f"provider={rep['provider']}  model={rep['model']}  时间={rep['generated_at']}")
    print(f"\n多步链通过率 pass：{rep['pass_correct']}/{rep['total']} = {rep['pass_accuracy']:.1%}")
    print(f"  ├ chain_ok（按因果顺序选对工具）：{rep['chain_ok_rate']:.1%}")
    print(f"  └ multi_step（没停在第一步）：     {rep['multi_step_rate']:.1%}")
    lat = rep["latency_s"]
    print(f"单条延迟：均值 {lat['avg']}s / 中位 {lat['p50']}s / 最大 {lat['max']}s")
    print("\n分场景：")
    for fam, s in rep["per_family"].items():
        print(f"  {fam:<24} {s['pass']}/{s['total']}  ({s['pass_rate']:.0%})")
    if rep["failures"]:
        print("\n未通过用例（如实列出，含模型实际调用序列）：")
        for f in rep["failures"]:
            why = f.get("error") or (
                f"chain_ok={f['chain_ok']} multi_step={f['multi_step']}")
            print(f"  ✗ [{f['id']}] called={f['called'] or '-'}  ({why})")
    print("\n说明：剧本化真实态桩让模型拿到确定的中间状态去做多步决策——补 nl_eval（单步）测不到的"
          "「据上一步结果决定下一步」的推理链。分数是某次某模型的快照，非恒定常数。")


def write_markdown(rep: dict, path: str) -> None:
    fam_rows = "\n".join(
        f"| {fam} | {s['pass']}/{s['total']} | {s['pass_rate']:.0%} |"
        for fam, s in rep["per_family"].items())
    fail_rows = "\n".join(
        f"| {f['id']} | `{f['called']}` | chain={f['chain_ok']} multi={f['multi_step']} |"
        for f in rep["failures"]) or "| （无） | — | — |"
    md = f"""# 评分②/④ 多步推理（Agentic Loop）真模型工具链基准

> 自动生成于 {rep['generated_at']}；provider=`{rep['provider']}` model=`{rep['model']}`。
> {'**⚠ mock provider，分数不代表多步推理能力，仅验流水线。**' if rep['is_mock'] else '真模型快照，存在抽样波动。'}

补 `nl_eval`（单步 top-1）测不到的盲区：用**剧本化真实态桩**给模型确定的中间状态（磁盘 96% 满、
某进程吃内存、服务挂了……），度量它能否**据上一步结果自主决定下一步**、按因果顺序把工具链走完。

- **多步链通过率 pass：{rep['pass_correct']}/{rep['total']} = {rep['pass_accuracy']:.1%}**
  - chain_ok（按因果顺序选对工具，期望链为调用序列的有序子列）：{rep['chain_ok_rate']:.1%}
  - multi_step（不同工具数达场景下限，证明没停在第一步）：{rep['multi_step_rate']:.1%}
- 单条延迟：均值 {rep['latency_s']['avg']}s / 中位 {rep['latency_s']['p50']}s / 最大 {rep['latency_s']['max']}s

## 分场景

| 场景族 | 通过 | 通过率 |
|---|---|---|
{fam_rows}

## 未通过用例（诚实列出）

| id | 实际调用序列 | 失分点 |
|---|---|---|
{fail_rows}

> 口径：工具 schema 取自真实 MCP server；执行换剧本化真实态桩（确定、可复现、零系统副作用）。
> 标准答案（期望链 + 剧本世界）逐条写在 `scripts/corpora/agentic_chain_eval.jsonl`，与实现分离、可审。
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"Markdown 报告已写入：{path}")


def main() -> int:
    ap = argparse.ArgumentParser(description="评分②/④ 多步推理（Agentic Loop）真模型基准")
    ap.add_argument("--corpus", default=DEFAULT_CORPUS, help="带期望链+剧本世界的语料 JSONL")
    ap.add_argument("--json", default=os.path.join(_ROOT, "agentic-eval-report.json"),
                    help="机器可读报告输出路径")
    ap.add_argument("--md", default=os.path.join(_ROOT, "docs", "agentic-chain-report.md"),
                    help="Markdown 报告输出路径")
    ap.add_argument("--limit", type=int, default=0, help="只跑前 N 例（快速冒烟）")
    ap.add_argument("--timeout", type=float, default=180.0, help="单条用例墙钟超时秒数")
    args = ap.parse_args()

    corpus = load_corpus(args.corpus)
    if args.limit > 0:
        corpus = corpus[:args.limit]
    print(f"多步推理基准：{len(corpus)} 个场景，逐条驱动真实编排闭环（剧本化真实态桩）……", flush=True)
    rep = asyncio.run(run(corpus, timeout_s=args.timeout))
    print_report(rep)

    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=2)
    print(f"\n机器可读报告已写入：{args.json}")
    write_markdown(rep, args.md)

    # 退出码：mock 直接非零（提醒别拿 mock 分当多步能力）；真模型 pass<0.6 给非零，便于接 CI 阈值线。
    if rep["is_mock"]:
        return 2
    return 0 if rep["pass_accuracy"] >= 0.6 else 1


if __name__ == "__main__":
    raise SystemExit(main())
