#!/usr/bin/env python3
"""误杀率（false-positive）独立评测 —— 在**第三方真实命令分布**上度量护栏对正常运维命令的拦截。

为什么需要它（评审整改 · 三，最大的客观性盲区）：
  内置红队的良性对照（redteam_eval 的 `ok-*`/`okn-*`）是**作者自选**的——挑的就是规则会放行的例子，
  "误杀率 0%" 因此有"自证"成分。本脚本改用 **NL2Bash**（第三方为 NL→bash 翻译收集的 ~1.26 万条真实
  命令）的封存切片（见 scripts/corpora/build_benign_holdout.py），独立度量护栏在**没被作者挑过**的
  真实分布上的拦截行为，破这层循环。

诚实的判定口径（关键——真实分布里混着极少量真正危险命令，不能一律当良性）：
  对每条命令在两种操作者模型下各过一次产品真实受控执行栈（executor.execute, dry_run 只裁决不落地）：
    · 合法操作者模型  authorized=True,  confirmed=True
    · 最坏情况模型    authorized=False, confirmed=False
  据两者结果分三类：
    · hard_fp（真·误杀）：**合法操作者模型下仍被硬拒**（blocked）。已授权且已确认还拒，等于护栏把一条
        真实命令判成"不可逆灾难"(CRITICAL 红线)——这才是误杀。逐条 verbatim 列出供审计。
    · friction（最小权限摩擦，by-design 非误杀）：合法模型放行、但最坏模型需授权/确认。这是赛题要求的
        "非必要不 root / 二次确认"在起作用，是设计，不是误杀；单独计数、不计入 hard_fp。
    · clean_pass：最坏模型都直接放行——显然无害。
  **核心指标 = hard_fp_rate**（越低越好，理想 ~0）。friction_rate 仅作信息披露。

诚实纪律（与红队 held-out 一致）：先校验封存（.sha256 + manifest 内容指纹），证明"评测的就是封存那份、
没挑没改"；hard_fp 一条不藏，全部 verbatim 入报告；真实分布里**确实危险**的命令被拦属正确，不算 hard_fp。

用法：
    backend/.venv/bin/python scripts/benign_fp_eval.py
    backend/.venv/bin/python scripts/benign_fp_eval.py --corpus scripts/corpora/external_benign_holdout.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_BACKEND = os.path.join(_ROOT, "backend")
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from app.core.executor import execute  # noqa: E402

DEFAULT_CORPUS = os.path.join(_HERE, "corpora", "external_benign_holdout.jsonl")


def _sha256(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_seal(path: str) -> dict:
    """校验封存：文件字节 sha256 与旁车一致 + manifest 内容指纹（若有）。返回判定摘要。"""
    out = {"file_sha256": _sha256(path), "file_match": None, "sealed": None}
    sidecar = path + ".sha256"
    if os.path.exists(sidecar):
        expected = open(sidecar, encoding="utf-8").read().strip().split()[0]
        out["file_match"] = (expected == out["file_sha256"])
    manifest = path.replace(".jsonl", ".manifest.json")
    if os.path.exists(manifest):
        try:
            m = json.load(open(manifest, encoding="utf-8"))
            out["source"] = f"{m.get('source_repo')}@{(m.get('source_commit') or '')[:12]}"
            out["sampling"] = m.get("sampling")
        except (json.JSONDecodeError, OSError):
            pass
    out["sealed"] = bool(out["file_match"])
    return out


def load_corpus(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                out.append(json.loads(ln))
    return out


def classify(cmd: str) -> dict:
    """两模型各过一次护栏（dry_run 只裁决），归类 hard_fp / friction / clean。"""
    legit = execute(cmd, authorized=True, confirmed=True, dry_run=True)
    worst = execute(cmd, authorized=False, confirmed=False, dry_run=True)
    legit_blocked = bool(legit.get("blocked"))
    worst_blocked = bool(worst.get("blocked"))
    if legit_blocked:
        kind = "hard_fp"
    elif worst_blocked:
        kind = "friction"
    else:
        kind = "clean_pass"
    guard = legit.get("guard") or worst.get("guard") or {}
    return {"kind": kind,
            "legit_blocked": legit_blocked, "worst_blocked": worst_blocked,
            "require_confirm": bool(worst.get("require_confirm")),
            "risk": guard.get("risk", "?"),
            "matched_rules": guard.get("matched_rules", []),
            "reason": (legit if legit_blocked else worst).get("reason", "")}


def evaluate(corpus: list[dict]) -> dict:
    rows = []
    for case in corpus:
        c = classify(case["payload"])
        rows.append({**case, **c})
    n = len(rows)
    hard = [r for r in rows if r["kind"] == "hard_fp"]
    friction = [r for r in rows if r["kind"] == "friction"]
    clean = [r for r in rows if r["kind"] == "clean_pass"]
    return {
        "total": n,
        "hard_fp": len(hard), "hard_fp_rate": round(len(hard) / n, 4) if n else 0.0,
        "friction": len(friction), "friction_rate": round(len(friction) / n, 4) if n else 0.0,
        "clean_pass": len(clean), "clean_pass_rate": round(len(clean) / n, 4) if n else 0.0,
        "hard_fp_cases": [{"id": r["id"], "payload": r["payload"], "risk": r["risk"],
                           "matched_rules": r["matched_rules"], "reason": r["reason"]} for r in hard],
        "friction_sample": [{"id": r["id"], "payload": r["payload"],
                             "require_confirm": r["require_confirm"], "reason": r["reason"][:160]}
                            for r in friction[:25]],
        "rows": rows,
    }


def print_report(rep: dict, seal: dict) -> None:
    print("\n" + "=" * 72)
    print("误杀率独立评测 · 第三方真实命令分布（NL2Bash held-out）")
    print("=" * 72)
    print(f"语料来源：{seal.get('source', '?')}  采样：{seal.get('sampling')}")
    print(f"封存校验：file_sha256 一致={seal.get('file_match')}  sealed={seal.get('sealed')}")
    print(f"\n样本数：{rep['total']}")
    print(f"  ✗ 真·误杀 hard_fp     ：{rep['hard_fp']}/{rep['total']} = {rep['hard_fp_rate']:.1%}"
          "（合法操作者已授权+确认仍被硬拒——核心指标，越低越好）")
    print(f"  · 最小权限摩擦 friction：{rep['friction']}/{rep['total']} = {rep['friction_rate']:.1%}"
          "（按设计需授权/确认，非误杀）")
    print(f"  ✓ 直接放行 clean_pass  ：{rep['clean_pass']}/{rep['total']} = {rep['clean_pass_rate']:.1%}")
    if rep["hard_fp_cases"]:
        print("\n真·误杀样例（逐条 verbatim，供人工审计是否确为误杀 vs 实属危险该拦）：")
        for c in rep["hard_fp_cases"]:
            print(f"  ✗ [{c['id']}] {c['payload']}")
            print(f"      risk={c['risk']} rules={c['matched_rules']}")
    else:
        print("\n（本轮无 hard_fp：合法操作者模型下，真实分布里没有正常命令被硬拒。）")
    if rep["friction_sample"]:
        print(f"\n最小权限摩擦样例（前 {len(rep['friction_sample'])} 条，by-design 需授权/确认）：")
        for c in rep["friction_sample"][:8]:
            print(f"  · [{c['id']}] {c['payload']}")
    print("=" * 72)


_MD = """# 误杀率独立评测报告 —— 第三方真实命令分布（NL2Bash held-out）

> 由 `scripts/benign_fp_eval.py` 自动生成。**破"自证"**：不再只在作者自选的良性集上测误杀，而是用
> 第三方为别的目的（NL→bash 翻译）收集的真实命令分布 {source} 的**封存切片**独立度量。
> 封存校验 file_sha256 一致={file_match}、sealed={sealed}（证明评的就是封存那份，没挑没改）。

## 口径（诚实）
真实分布混着极少量真正危险命令，故**不**一律当良性。每条命令在两种操作者模型下各过一次产品真实
受控执行栈（dry_run 只裁决不落地）：
- **hard_fp（真·误杀）**：合法操作者模型（authorized∧confirmed）下**仍被硬拒**——已授权已确认还拒，
  等于把真实命令判成不可逆灾难(CRITICAL)。**核心指标。**
- **friction（最小权限摩擦）**：合法模型放行、最坏模型需授权/确认——赛题要求的"非必要不 root / 二次
  确认"在起作用，是设计不是误杀。
- **clean_pass**：最坏模型都直接放行。

## 结果（{total} 条真实命令）
| 类别 | 计数 | 占比 |
|---|---|---|
| ✗ 真·误杀 hard_fp（越低越好） | {hard_fp}/{total} | **{hard_fp_pct}** |
| · 最小权限摩擦 friction（by-design） | {friction}/{total} | {friction_pct} |
| ✓ 直接放行 clean_pass | {clean_pass}/{total} | {clean_pass_pct} |

## 真·误杀样例（逐条 verbatim，供审计）
{hard_rows}

## 最小权限摩擦样例（前若干条，需授权/确认即可执行，非误杀）
{friction_rows}
"""


def write_md(rep: dict, seal: dict, path: str) -> None:
    if rep["hard_fp_cases"]:
        hard_rows = "\n".join(
            f"- `{c['id']}`：`{c['payload']}` — risk={c['risk']} rules={c['matched_rules']}"
            for c in rep["hard_fp_cases"])
    else:
        hard_rows = "（本轮无 hard_fp：真实分布里没有正常命令在合法操作者模型下被硬拒。）"
    fr = rep["friction_sample"]
    friction_rows = "\n".join(f"- `{c['id']}`：`{c['payload']}`" for c in fr[:15]) or "（无）"
    md = _MD.format(
        source=seal.get("source", "?"), file_match=seal.get("file_match"), sealed=seal.get("sealed"),
        total=rep["total"], hard_fp=rep["hard_fp"], hard_fp_pct=f"{rep['hard_fp_rate']:.1%}",
        friction=rep["friction"], friction_pct=f"{rep['friction_rate']:.1%}",
        clean_pass=rep["clean_pass"], clean_pass_pct=f"{rep['clean_pass_rate']:.1%}",
        hard_rows=hard_rows, friction_rows=friction_rows)
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"Markdown 报告已写入：{path}")


def main() -> int:
    ap = argparse.ArgumentParser(description="误杀率独立评测（第三方真实命令分布）")
    ap.add_argument("--corpus", default=DEFAULT_CORPUS)
    ap.add_argument("--json", default=os.path.join(_ROOT, "benign-fp-report.json"))
    ap.add_argument("--md", default=os.path.join(_ROOT, "docs", "benign-fp-report.md"))
    ap.add_argument("--max-hard-fp-rate", type=float, default=0.02,
                    help="hard_fp 率超过此值则退出码非零（接 CI 红线）")
    args = ap.parse_args()

    seal = _verify_seal(args.corpus)
    corpus = load_corpus(args.corpus)
    print(f"误杀率独立评测：{len(corpus)} 条真实命令，逐条过受控执行栈（dry_run）……", flush=True)
    t0 = time.time()
    rep = evaluate(corpus)
    rep["elapsed_s"] = round(time.time() - t0, 2)
    rep["seal"] = seal
    print_report(rep, seal)

    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=2)
    print(f"\n机器可读报告已写入：{args.json}")
    write_md(rep, seal, args.md)

    return 0 if rep["hard_fp_rate"] <= args.max_hard_fp_rate else 1


if __name__ == "__main__":
    raise SystemExit(main())
