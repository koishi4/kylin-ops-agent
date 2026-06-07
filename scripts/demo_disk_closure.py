#!/usr/bin/env python3
"""完整磁盘处置闭环演示（IMPROVEMENTS-v3 P2）——一条命令跑通评分④的「感知→根因→安全处置→验证→留痕」。

闭环：disk_usage（看总体）→ find_large_files（定位大文件）→ classify（判关键性）→ dry-run（护栏预览，
不执行）→ confirm（二次确认后 fd-safe 清空）→ 再 find_large_files / 看大小（验证已回收）→ trace 闭环
（落审计 + 哈希链 verify，证明全过程可追溯且防篡改）。

铁律（CLAUDE.md §6）：**绝不在真实系统上跑破坏性命令**。本演示只在自建的临时目录（/tmp 下）操作
自己写入的无害日志文件，结束即清理；危险路径只演示「被拒/被拦」，不演示「破坏成功」。

运行（任意目录均可）：
    python3 scripts/demo_disk_closure.py
评测/演示脚本不纳入 pytest（roadmap 纪律）。
"""
from __future__ import annotations

import os
import sys
import tempfile

# 自定位 backend 到 sys.path，使脚本可从任意目录运行
_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.join(os.path.dirname(_HERE), "backend")
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from app.audit import store                                  # noqa: E402
from app.core import actions                                 # noqa: E402
from app.core.diagnosis import classify_file                 # noqa: E402
from app.mcp_server.tools.disk import disk_usage, find_large_files  # noqa: E402


def _hr(title: str) -> None:
    print(f"\n{'─' * 68}\n▶ {title}\n{'─' * 68}")


def _size_mb(path: str) -> float:
    return round(os.path.getsize(path) / 1e6, 2) if os.path.isfile(path) else 0.0


def main() -> int:
    # 把审计库指向临时文件，演示不污染真实 audit.sqlite
    tmp_root = tempfile.mkdtemp(prefix="kylin-disk-demo-")
    store._db_path = lambda: os.path.join(tmp_root, "demo-audit.sqlite")  # type: ignore[assignment]
    store.init_db()

    # 准备：在 /tmp 下临时目录写几个不同大小的「日志」文件（无害，结束即删）
    target = os.path.join(tmp_root, "app.log")
    with open(target, "wb") as f:
        f.write(b"INFO demo log line\n" * 200_000)          # ~3.8MB，模拟暴涨日志
    for name, n in (("small.log", 2_000), ("mid.log", 40_000)):
        with open(os.path.join(tmp_root, name), "wb") as f:
            f.write(b"x" * n)

    print(f"演示沙盒目录：{tmp_root}")
    print(f"待处置目标：{target}（{_size_mb(target)} MB，无害自建日志）")

    # ① 感知：总体磁盘
    _hr("① 感知环境 · disk_usage('/')")
    du = disk_usage("/")
    print(f"  根分区：used {du['used_gb']}GB / total {du['total_gb']}GB（{du['percent']}%），"
          f"free {du['free_gb']}GB")

    # ② 根因：定位大文件
    _hr("② 根因分析 · find_large_files(沙盒目录, top_n=5)")
    lf = find_large_files(tmp_root, top_n=5)
    for i, item in enumerate(lf["files"], 1):
        print(f"  {i}. {item['size_mb']:>7} MB  {item['path']}")
    biggest = lf["files"][0]["path"]
    print(f"  → 最大文件：{biggest}")

    # ③ 关键性判定
    _hr("③ 关键性判定 · classify_file(最大文件)")
    cls, why = classify_file(biggest)
    print(f"  分类：{cls.value}｜理由：{why}")
    if cls.value != "cleanable":
        print("  非可清理类——按设计应拒绝处置，演示到此（不破坏）。")
        return 0

    # ④ dry-run：护栏预览，绝不执行
    _hr("④ 安全预览 · truncate_log（confirmed=False → 只校验不执行）")
    preview = actions.run_action("truncate_log", {"path": biggest},
                                 confirmed=False, dry_run=True)
    print(f"  executed={preview['executed']}  require_confirm={preview['require_confirm']}")
    print(f"  护栏/语义裁决：{preview['reason']}")
    print(f"  清空前大小：{_size_mb(biggest)} MB（未变——dry-run 不改状态）")

    # ⑤ confirm：二次确认后 fd-safe 清空
    _hr("⑤ 确认执行 · truncate_log（confirmed=True, dry_run=False → fd-safe os.ftruncate）")
    done = actions.run_action("truncate_log", {"path": biggest},
                              confirmed=True, dry_run=False)
    print(f"  executed={done['executed']}  ok={done['ok']}")
    print(f"  结果：{done['reason']}")

    # ⑥ 验证：再看大小 / 再定位大文件
    _hr("⑥ 验证回收 · 复查大小 + 重新 find_large_files")
    print(f"  清空后大小：{_size_mb(biggest)} MB（应为 0.0——空间已回收，inode/句柄保留）")
    lf2 = find_large_files(tmp_root, top_n=5)
    after = next((x for x in lf2["files"] if x["path"] == biggest), None)
    print(f"  复查中该文件大小：{after['size_mb'] if after else 0.0} MB")

    # ⑦ trace 闭环：落审计 + 哈希链 verify（可追溯 + 防篡改）
    _hr("⑦ trace 闭环 · 落审计 + 哈希链 verify")
    trace_id = "demo-disk-closure"
    store.save_trace(trace_id, f"清理大文件 {biggest}", done["reason"],
                     done["trace"], intent="action", blocked=False, llm_provider="demo")
    print("  五段执行链：")
    for s in done["trace"]:
        print(f"    · {s['stage']}")
    v = store.verify_chain(trace_id)
    print(f"  哈希链校验：valid={v['valid']}（{v['reason']}）")
    pack = store.export_evidence(trace_id, components={"note": "disk-closure demo"})
    ev = store.verify_evidence(pack)
    print(f"  证据包封口：seal_matches={ev['seal_matches']} chain_valid={ev['chain_valid']}")

    _hr("闭环完成")
    print("  感知 → 根因 → 关键性 → 预览(不执行) → 确认执行 → 验证回收 → 审计可追溯+防篡改 ✓")

    # 清理沙盒
    for fn in os.listdir(tmp_root):
        try:
            os.remove(os.path.join(tmp_root, fn))
        except OSError:
            pass
    try:
        os.rmdir(tmp_root)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
