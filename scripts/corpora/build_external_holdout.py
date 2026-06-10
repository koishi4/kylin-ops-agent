#!/usr/bin/env python3
"""把**真实第三方安全基准**下载并转成本目录 held-out JSONL（去自评 / 防过拟合）。

README 里点名的「真正去自评应接入真实外部基准」就是这一步的落地。来源（均 **pin 到固定 commit**，
保证可复现 → 指纹可封存）：

- **RedCode-Exec**（AI-secure/RedCode，MIT）：危险代码执行基准的 bash 子集 → family=`exec`，
  payload 取每条的 `Code`（真实危险 bash），喂给产品真实受控执行栈（dry_run，只裁决不落地）。
- **garak**（NVIDIA/garak，Apache-2.0）的 DAN 越狱模板 → family=`inject`，payload 取每个模板的首条，
  喂给 `scan_injection`。

设计纪律（与 corpora/README.md 一致，缺一不可，否则封存指纹失去意义）：
1. **确定性**：固定 commit + 硬编码文件序 + 取每文件前 K 条，**无随机**。重跑 → 字节一致 → sha256
   稳定，「自封存以来未改动」才可核验。
2. **逐字透传**：payload 原样取自外部源，绝不改写/挑拣——honest：我们没给这份「卷子」放水。
3. **脚本入库即 provenance**：任何人复跑此脚本都能重现同一份 JSONL 与指纹。

用法：
    backend/.venv/bin/python scripts/corpora/build_external_holdout.py
    # 写出 external_holdout.jsonl + external_holdout.jsonl.sha256 + external_holdout.manifest.json
    # 随后独立评测：
    backend/.venv/bin/python scripts/redteam_eval.py --holdout scripts/corpora/external_holdout.jsonl
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))

# --- 来源 pin（固定 commit，勿改为分支名；分支会动，指纹会漂） ------------------------------
REDCODE_REPO = "AI-secure/RedCode"
REDCODE_SHA = "dbbf08281c56669d88502feb38b2dd901a69333c"
REDCODE_BASH_DIR = "dataset/RedCode-Exec/bash2text_dataset_json"
# 该 commit 下 bash2text 实际存在的 risk-index（硬编码以求确定性，不依赖 API 列目录的返回序）
REDCODE_BASH_INDICES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15, 16, 18, 20, 21, 22, 23, 25]
REDCODE_K_PER_INDEX = 2  # 每个 risk-index 取前 K 条（跨 20 类风险求多样，而非堆同一模式）

GARAK_REPO = "NVIDIA/garak"
GARAK_SHA = "35b7d27f8f3b8a12eb94780488ae8689975c70a7"
GARAK_DAN_DIR = "garak/data/dan"
GARAK_DAN_FILES = [
    "AntiDAN.json", "ChatGPT_Developer_Mode_RANTI.json", "ChatGPT_Developer_Mode_v2.json",
    "ChatGPT_Image_Markdown.json", "DAN_Jailbreak.json", "DUDE.json",
    "Dan_10_0.json", "Dan_11_0.json", "Dan_6_0.json", "Dan_6_2.json",
    "Dan_7_0.json", "Dan_8_0.json", "Dan_9_0.json", "STAN.json",
]

OUT_JSONL = os.path.join(_HERE, "external_holdout.jsonl")
OUT_SHA = OUT_JSONL + ".sha256"
OUT_MANIFEST = os.path.join(_HERE, "external_holdout.manifest.json")


def _raw_url(repo: str, sha: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "kylin-ops-agent-holdout-builder"})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (固定 https 源)
        return r.read()


def build_redcode_exec() -> list[dict]:
    """RedCode-Exec bash 子集 → family=exec。payload = 每条的真实危险 Code。"""
    cases: list[dict] = []
    for idx in REDCODE_BASH_INDICES:
        path = f"{REDCODE_BASH_DIR}/index{idx}_30_codes_full_upd.json"
        data = json.loads(_fetch(_raw_url(REDCODE_REPO, REDCODE_SHA, path)).decode("utf-8"))
        for entry in data[:REDCODE_K_PER_INDEX]:
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


def build_garak_dan() -> list[dict]:
    """garak DAN 越狱模板 → family=inject。payload = 每个模板的首条话术。"""
    cases: list[dict] = []
    for fname in GARAK_DAN_FILES:
        path = f"{GARAK_DAN_DIR}/{fname}"
        prompts = json.loads(_fetch(_raw_url(GARAK_REPO, GARAK_SHA, path)).decode("utf-8"))
        if not isinstance(prompts, list) or not prompts:
            continue
        text = prompts[0]
        if not isinstance(text, str) or not text.strip():
            continue
        cases.append({
            "id": f"garak-dan-{os.path.splitext(fname)[0]}",
            "family": "inject",
            "payload": text.strip(),
            "source": "garak/dan",
        })
    return cases


def content_fingerprint(items: list[dict]) -> str:
    """与 redteam_eval.corpus_fingerprint 同口径：sha256 over 排序后 family|id|payload。顺序无关。

    这是**内容指纹**（抓「题目集合是否被偷换」的语义校验），写进 manifest——**不**写进 .sha256。
    .sha256 留给真正的文件字节校验和（标准 sha256sum 口径），好让第三方零信任 `sha256sum -c` 核验。
    """
    h = hashlib.sha256()
    for it in sorted(items, key=lambda x: (x.get("family", ""), x.get("id", ""), x.get("payload", ""))):
        h.update(f"{it.get('family','')}\x1f{it.get('id','')}\x1f{it['payload']}\x1e".encode("utf-8"))
    return h.hexdigest()


def file_sha256(path: str) -> str:
    """原始文件字节 sha256——标准 sha256sum 口径，写进 .sha256 旁车文件。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    print("下载真实第三方基准（pin 到固定 commit）……", file=sys.stderr)
    print(f"  RedCode-Exec @ {REDCODE_SHA[:12]}  ({len(REDCODE_BASH_INDICES)} risk-index × K={REDCODE_K_PER_INDEX})",
          file=sys.stderr)
    redcode = build_redcode_exec()
    print(f"  garak/dan    @ {GARAK_SHA[:12]}   ({len(GARAK_DAN_FILES)} 模板)", file=sys.stderr)
    garak = build_garak_dan()

    # 确定性排序：family, id, payload —— 与指纹口径一致，重跑稳定
    items = sorted(redcode + garak, key=lambda x: (x["family"], x["id"], x["payload"]))

    with open(OUT_JSONL, "w", encoding="utf-8") as f:
        for it in items:
            # 只落 redteam_eval 需要的三字段（source 留 manifest），保证与指纹口径完全对齐
            f.write(json.dumps({"id": it["id"], "family": it["family"], "payload": it["payload"]},
                               ensure_ascii=False) + "\n")

    # .sha256 = 真正的文件字节校验和（标准格式 "<hash>  <文件名>"），第三方 sha256sum -c 即可核验。
    raw_sha = file_sha256(OUT_JSONL)
    with open(OUT_SHA, "w", encoding="utf-8") as f:
        f.write(f"{raw_sha}  {os.path.basename(OUT_JSONL)}\n")
    # 内容指纹（语义校验）只入 manifest，不伪装成 .sha256 校验和。
    fp = content_fingerprint(items)

    manifest = {
        "description": "真实第三方安全基准转成的 held-out 评测集（去自评/防过拟合）",
        "sources": [
            {"name": "RedCode-Exec", "repo": REDCODE_REPO, "commit": REDCODE_SHA,
             "license": "MIT", "path": REDCODE_BASH_DIR,
             "selection": f"index{{{','.join(map(str, REDCODE_BASH_INDICES))}}} 各取前 {REDCODE_K_PER_INDEX} 条 Code",
             "family": "exec", "count": len(redcode)},
            {"name": "garak/dan", "repo": GARAK_REPO, "commit": GARAK_SHA,
             "license": "Apache-2.0", "path": GARAK_DAN_DIR,
             "selection": f"{len(GARAK_DAN_FILES)} 个 DAN 模板各取首条", "family": "inject", "count": len(garak)},
        ],
        "total": len(items),
        "by_family": {"exec": len(redcode), "inject": len(garak)},
        "file_sha256": raw_sha,                   # 文件字节校验和（与 .sha256 一致）
        "content_fingerprint_sha256": fp,          # 内容指纹（语义校验：题目集合是否被偷换）
        "note": "确定性转换：固定 commit + 硬编码文件序 + 取每文件前 K 条 + payload 逐字透传。重跑字节一致。",
    }
    with open(OUT_MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print(f"\n✓ 写出 {len(items)} 例 → {os.path.relpath(OUT_JSONL)}", file=sys.stderr)
    print(f"  exec(RedCode-Exec)={len(redcode)}  inject(garak)={len(garak)}", file=sys.stderr)
    print(f"  文件 sha256 = {raw_sha}  内容指纹 = {fp}", file=sys.stderr)
    print(f"  封存 → {os.path.relpath(OUT_SHA)} ; provenance → {os.path.relpath(OUT_MANIFEST)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
