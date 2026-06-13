#!/usr/bin/env python3
"""把**真实第三方命令语料**下载成 benign held-out JSONL —— 独立测「误杀率」（评审整改 · 三）。

动机（reviewer 指出的最大客观性盲区）：误杀率(false-block)此前只在作者**自选**的良性集上测，
本质是"自证"——挑的就是规则会放行的例子。本脚本接入一份**与本项目无关、第三方为别的目的
(NL→bash 翻译)收集**的真实命令分布 NL2Bash，独立度量护栏对正常运维命令的拦截率，破这层循环。

来源（pin 到固定 commit，可复现 → 指纹可封存）：
- **NL2Bash**（TellinaTool/nl2bash, BSD-3-Clause）：data/bash/all.cm，约 1.26 万条来自
  StackOverflow / 运维问答的真实 bash 命令。family=`benign-exec`，payload 逐字取自该文件
  第 `OFFSET::STRIDE` 行（确定性**跨步**采样，覆盖整张表而非头部聚簇）。

诚实说明（关键）：NL2Bash 是**真实分布**而非"保证全良性"——绝大多数是正常运维命令，但也混入
极少量真正危险的（rm -rf 等）。故配套 `scripts/benign_fp_eval.py` **不**把它们一律当良性：
在合法操作者模型（authorized ∧ confirmed）下**仍被硬拒**的才算"误杀"，并逐条 verbatim 列出供审计；
按设计需授权/确认的只算"最小权限摩擦"（by-design，非误杀）。

纪律同 RedCode held-out：固定 commit + 硬编码采样参数 + 逐字透传 + 双重封存（.sha256 + manifest 指纹）。
复跑此脚本可重现同一份 JSONL 与指纹。

用法：
    backend/.venv/bin/python scripts/corpora/build_benign_holdout.py
    backend/.venv/bin/python scripts/benign_fp_eval.py
"""
from __future__ import annotations

import json
import os
import sys

# 复用已封存的 RedCode held-out builder 的下载/封存助手（与攻击侧 held-out 同一套口径）。
from build_external_holdout import (  # type: ignore
    _fetch,
    _raw_url,
    content_fingerprint,
    file_sha256,
)

_HERE = os.path.dirname(os.path.abspath(__file__))

# --- 来源 pin（固定 commit，勿改为分支名；分支会动，指纹会漂） ------------------------------
NL2BASH_REPO = "TellinaTool/nl2bash"
# data/bash/all.cm 的末次改动 commit（2017-11-01），其后内容稳定——按 commit 取字节恒定。
NL2BASH_SHA = "10963c9f418e9726944ec0b67ab4bf2926c5180d"
NL2BASH_PATH = "data/bash/all.cm"

# 确定性跨步采样：~12.6k 行每 STRIDE 取一条，覆盖整表分布（头部聚簇于 top/awk，故不取前 N）。
OFFSET = 0
STRIDE = 25
MAX_LEN = 400  # 跳过异常长行（>400 字符多为多句拼接噪声，解析意义不大）

OUT_JSONL = os.path.join(_HERE, "external_benign_holdout.jsonl")
OUT_SHA = OUT_JSONL + ".sha256"
OUT_MANIFEST = os.path.join(_HERE, "external_benign_holdout.manifest.json")


def build() -> list[dict]:
    raw = _fetch(_raw_url(NL2BASH_REPO, NL2BASH_SHA, NL2BASH_PATH)).decode("utf-8")
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    picked = lines[OFFSET::STRIDE]
    cases: list[dict] = []
    for i, cmd in enumerate(picked):
        if len(cmd) > MAX_LEN:
            continue
        # id 用原始行号（OFFSET + i*STRIDE），逐条可回溯到 all.cm 的具体行。
        cases.append({"id": f"nl2bash-{OFFSET + i * STRIDE}", "family": "benign-exec",
                      "payload": cmd, "source": "NL2Bash"})
    return cases


def main() -> int:
    print(f"构建 benign held-out（NL2Bash @ {NL2BASH_SHA[:12]}，第 {OFFSET}::{STRIDE} 行）……",
          file=sys.stderr)
    items_raw = build()
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
        "description": ("benign held-out：第三方真实命令分布 NL2Bash 的确定性跨步采样，"
                        "独立度量护栏误杀率（防自证）"),
        "source_repo": NL2BASH_REPO,
        "source_commit": NL2BASH_SHA,
        "source_path": NL2BASH_PATH,
        "sampling": {"offset": OFFSET, "stride": STRIDE, "max_len": MAX_LEN},
        "count": len(items),
        "file_sha256": raw_sha,
        "content_fingerprint_sha256": fp,
        "license": "BSD-3-Clause (TellinaTool/nl2bash)",
        "honesty_note": ("真实分布含极少量真正危险命令；误杀判定见 benign_fp_eval.py——"
                         "合法操作者模型(authorized∧confirmed)下仍硬拒才算误杀，按设计需授权/确认只算最小权限摩擦"),
    }
    with open(OUT_MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print(f"写出 {OUT_JSONL}（{len(items)} 条）")
    print(f"  file_sha256       = {raw_sha}")
    print(f"  content_fingerprint = {fp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
