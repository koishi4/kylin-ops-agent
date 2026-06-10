#!/usr/bin/env python3
"""held-out **轮换切片 v4**：同源 RedCode-Exec 的第三份新鲜样本，与 v1/v2/v3 四方互不相交。

为什么需要它（held-out 反哺第三次轮换）：
  v2 残漏的 `7_4`（`content=$(cat "$file")` 读敏感却漏）暴露盲区——**命令替换 `$()` 作为「赋值的值」时
  AST 遍历不下探**。据此**威胁类**给护栏补遍历（`_walk` 纳入 assignment 部件的 $()）后，v2/v3 里该类题被
  **消耗**（seen）。方法论要求**再换一支切片**复测：本脚本取每个 index 的 `entries[6:8]`
  （v1=[0:2]、v2=[2:4]、v3=[4:6]），得与三者**逐题不相交**的新鲜样本。护栏遍历补强是**通用**实现
  （以内置语料 `c=$(cat /etc/shadow)` 等自撰例打磨，绝不针对 v2 的 `7_4` 具体串），故 v4 上的分数量的是
  **类级改进能否泛化到未见实例**。

纪律同 v1/v2/v3：固定 commit + 硬编码文件序 + 取每文件 entries[OFFSET:OFFSET+K] + payload 逐字透传 + 双重封存。
复用 v1 builder 的已封存助手，**绝不改动 v1/v2/v3 的任何产物**。

用法：
    backend/.venv/bin/python scripts/corpora/build_external_holdout_v4.py
    backend/.venv/bin/python scripts/redteam_eval.py --holdout scripts/corpora/external_holdout_v4.jsonl
"""
from __future__ import annotations

import json
import os
import sys

from build_external_holdout import (  # type: ignore
    REDCODE_BASH_DIR,
    REDCODE_BASH_INDICES,
    REDCODE_REPO,
    REDCODE_SHA,
    _fetch,
    _raw_url,
    content_fingerprint,
    file_sha256,
)

_HERE = os.path.dirname(os.path.abspath(__file__))

# 取样窗口：跳过 v1/v2/v3 用过的前 6 条，取 entries[6:8]，四方逐题不相交。
OFFSET = 6
K_PER_INDEX = 2

OUT_JSONL = os.path.join(_HERE, "external_holdout_v4.jsonl")
OUT_SHA = OUT_JSONL + ".sha256"
OUT_MANIFEST = os.path.join(_HERE, "external_holdout_v4.manifest.json")


def build_redcode_exec_v4() -> list[dict]:
    """RedCode-Exec bash 子集的**第三份新鲜切片**：每个 risk-index 取 entries[OFFSET:OFFSET+K]。"""
    cases: list[dict] = []
    for idx in REDCODE_BASH_INDICES:
        path = f"{REDCODE_BASH_DIR}/index{idx}_30_codes_full_upd.json"
        data = json.loads(_fetch(_raw_url(REDCODE_REPO, REDCODE_SHA, path)).decode("utf-8"))
        for entry in data[OFFSET:OFFSET + K_PER_INDEX]:
            code = entry.get("Code", "").strip()
            if not code:
                continue
            cases.append({
                "id": f"redcode-exec-{entry.get('Index', idx)}",
                "family": "exec",
                "payload": code,
                "source": "RedCode-Exec",
            })
    return cases


def main() -> int:
    print("构建 held-out 轮换切片 v4（同源、与 v1/v2/v3 四方不相交的新鲜样本）……", file=sys.stderr)
    print(f"  RedCode-Exec @ {REDCODE_SHA[:12]}  ({len(REDCODE_BASH_INDICES)} risk-index × "
          f"entries[{OFFSET}:{OFFSET + K_PER_INDEX}])", file=sys.stderr)
    items_raw = build_redcode_exec_v4()

    items = sorted(items_raw, key=lambda x: (x["family"], x["id"], x["payload"]))

    with open(OUT_JSONL, "w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps({"id": it["id"], "family": it["family"], "payload": it["payload"]},
                               ensure_ascii=False) + "\n")

    raw_sha = file_sha256(OUT_JSONL)
    with open(OUT_SHA, "w", encoding="utf-8") as f:
        f.write(f"{raw_sha}  {os.path.basename(OUT_JSONL)}\n")
    fp = content_fingerprint(items)

    manifest = {
        "description": "held-out 轮换切片 v4：同源真实基准的新鲜样本，与 v1/v2/v3 四方逐题不相交，用于「值内 $() 遍历」类级改进的无偏泛化复测",
        "rotation": {
            "rationale": "据『命令替换作为赋值的值』遍历盲区改护栏后，v2/v3 中该类题已被消耗(seen)；轮换到未见实例复测泛化",
            "disjoint_from": ["external_holdout.jsonl (v1)", "external_holdout_v2.jsonl (v2)", "external_holdout_v3.jsonl (v3)"],
            "window": f"entries[{OFFSET}:{OFFSET + K_PER_INDEX}]（v1=[0:2]，v2=[2:4]，v3=[4:6]）",
            "families_rotated": ["exec"],
        },
        "sources": [
            {"name": "RedCode-Exec", "repo": REDCODE_REPO, "commit": REDCODE_SHA,
             "license": "MIT", "path": REDCODE_BASH_DIR,
             "selection": f"index{{{','.join(map(str, REDCODE_BASH_INDICES))}}} 各取 entries[{OFFSET}:{OFFSET + K_PER_INDEX}] 的 Code",
             "family": "exec", "count": len(items)},
        ],
        "total": len(items),
        "by_family": {"exec": len(items)},
        "file_sha256": raw_sha,
        "content_fingerprint_sha256": fp,
        "note": "确定性转换：固定 commit + 硬编码文件序 + 取每文件 entries[OFFSET:OFFSET+K] + payload 逐字透传。重跑字节一致。",
    }
    with open(OUT_MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print(f"\n✓ 写出 {len(items)} 例 → {os.path.relpath(OUT_JSONL)}", file=sys.stderr)
    print(f"  文件 sha256 = {raw_sha}  内容指纹 = {fp}", file=sys.stderr)
    print(f"  封存 → {os.path.relpath(OUT_SHA)} ; provenance → {os.path.relpath(OUT_MANIFEST)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
