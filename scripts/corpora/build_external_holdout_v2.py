#!/usr/bin/env python3
"""held-out **轮换切片 v2**：从同一真实第三方基准取一份**互不相交的新鲜样本**，用于
「按方法论改护栏后」对**未见实例**做无偏复测（thermometer-not-stove 的「换一支温度计」）。

为什么需要它（held-out 反哺纪律的闭环兑现）：
  v1（external_holdout.jsonl）取 RedCode-Exec 每个 risk-index 的**前 2 条**（entries[0:2]）。当我们据
  「下载写关键区」这一**威胁类**改进护栏后，v1 里 `2_1/2_2`（`wget -O /usr/…`）这类**已被它探到**的题
  会从「漏过」变「拦住」——v1 对该类已**被消耗**（seen），它的新分数不再是该类的「无偏泛化」度量。
  方法论要求此时**轮换到新鲜切片**复测：本脚本取每个 index 的**第 3–4 条**（entries[2:4]），与 v1
  **逐题不相交**（id/payload 皆不同），且**护栏逻辑从未针对这些具体串编写**（改进是通用「按效果」控制，
  以内置语料 `/usr/bin/payload`、`/etc/cron.d/job` 等自撰例打磨）。因此在 v2 上的分数，量的是
  **类级改进能否泛化到未见实例**，而非对卷面变体的过拟合。

纪律同 v1（缺一不可）：
1. **确定性**：固定 commit + 硬编码文件序 + 取每文件 entries[OFFSET:OFFSET+K]，无随机。重跑字节一致。
2. **逐字透传**：payload 原样取自外部源，绝不改写/挑拣。
3. **与 v1 不相交**：OFFSET=2 跳过 v1 用过的前 2 条；id（如 `2_3`）与 v1（`2_1`）天然不同。
4. **只轮换本轮改动的家族**：本轮只改 exec（下载/写关键区）类，故 v2 **只取 exec**；inject 防御未变，
   其 held-out（v1 的 11/14）仍是当前 inject 度量，inject 轮换留待 inject 防御变更时再做。

本脚本**复用 v1 builder 的已封存助手**（`_fetch`/`_raw_url`/`content_fingerprint`/`file_sha256` 等），
**绝不改动 v1 的任何产物**——v1 的字节哈希与封存保持恒等，历史可复核。

用法：
    backend/.venv/bin/python scripts/corpora/build_external_holdout_v2.py
    backend/.venv/bin/python scripts/redteam_eval.py --holdout scripts/corpora/external_holdout_v2.jsonl
"""
from __future__ import annotations

import json
import os
import sys

# 复用 v1 builder 的助手与来源 pin（同一 commit/目录/index 序），只改取样窗口 → 保证 v2 与 v1 同源、互斥。
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

# 取样窗口：跳过 v1 用过的前 2 条（OFFSET=2），再取 2 条 → entries[2:4]，与 v1 逐题不相交。
OFFSET = 2
K_PER_INDEX = 2

OUT_JSONL = os.path.join(_HERE, "external_holdout_v2.jsonl")
OUT_SHA = OUT_JSONL + ".sha256"
OUT_MANIFEST = os.path.join(_HERE, "external_holdout_v2.manifest.json")


def build_redcode_exec_v2() -> list[dict]:
    """RedCode-Exec bash 子集的**新鲜切片**：每个 risk-index 取 entries[OFFSET:OFFSET+K]。"""
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
    print("构建 held-out 轮换切片 v2（同源、与 v1 不相交的新鲜样本）……", file=sys.stderr)
    print(f"  RedCode-Exec @ {REDCODE_SHA[:12]}  ({len(REDCODE_BASH_INDICES)} risk-index × "
          f"entries[{OFFSET}:{OFFSET + K_PER_INDEX}])", file=sys.stderr)
    items_raw = build_redcode_exec_v2()

    # 确定性排序：family, id, payload —— 与指纹口径一致，重跑稳定
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
        "description": "held-out 轮换切片 v2：同源真实基准的新鲜样本，与 v1 逐题不相交，用于类级改进的无偏泛化复测",
        "rotation": {
            "rationale": "据『下载写关键区』威胁类改进护栏后，v1 中该类题已被消耗(seen)；轮换到未见实例复测泛化",
            "disjoint_from": "external_holdout.jsonl (v1)",
            "window": f"entries[{OFFSET}:{OFFSET + K_PER_INDEX}]（v1 用 entries[0:2]）",
            "families_rotated": ["exec"],
            "note_inject": "inject 防御本轮未变，v1 的 inject 切片(11/14)仍为当前度量；inject 轮换留待其防御变更时",
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
