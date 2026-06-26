"""资源/负载基准 —— 补充 bench.py 的延迟指标之外的「硬性情况」：
内存常驻、CPU 占用、并发吞吐、长稳无泄漏、审计存储成本、冷启动。

跑法（在 backend/ 下）：
    python scripts/bench_resource.py
    python scripts/bench_resource.py --backend-pid 25694   # 指定在跑的 uvicorn 进程量其常驻内存

设计：全部走只读/离线纯函数路径，不依赖网络；并发用线程池打 check_command（护栏裁决，
CPU 密集纯 Python），度量在 GIL 约束下单进程的真实处理能力；审计存储成本直接量已有
audit.sqlite（行数与字节）。所有数字现采现报，便于写进性能测试报告。
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import psutil  # noqa: E402
from app.guardrail.engine import check_command  # noqa: E402
from tests.test_guardrail_redteam import DANGEROUS, SAFE  # noqa: E402

CMDS = DANGEROUS + SAFE
PROC = psutil.Process(os.getpid())


def _rss_mb(proc: psutil.Process) -> float:
    return proc.memory_info().rss / (1024 * 1024)


def bench_footprint(backend_pid: int | None) -> dict:
    """① 进程常驻内存：本基准进程导入全栈后的 RSS；若给了在跑的后端 pid，量其 RSS。"""
    out = {"bench_rss_mb": round(_rss_mb(PROC), 1)}
    if backend_pid:
        try:
            out["backend_rss_mb"] = round(_rss_mb(psutil.Process(backend_pid)), 1)
        except psutil.Error as e:  # noqa: PERF203
            out["backend_rss_mb"] = f"取不到({e.__class__.__name__})"
    return out


def bench_cpu(duration_s: float = 3.0) -> dict:
    """② CPU 占用：持续打护栏裁决 duration_s 秒，量本进程 CPU% 与期间完成的裁决数。"""
    PROC.cpu_percent(None)  # 复位基线
    n = 0
    t_end = time.perf_counter() + duration_s
    i = 0
    while time.perf_counter() < t_end:
        check_command(CMDS[i % len(CMDS)])
        i += 1
        n += 1
    cpu = PROC.cpu_percent(None)
    return {"duration_s": duration_s, "decisions": n,
            "cpu_percent": round(cpu, 1),
            "per_sec": round(n / duration_s)}


def _worker(rounds: int) -> int:
    for i in range(rounds):
        check_command(CMDS[i % len(CMDS)])
    return rounds


def bench_concurrency(total: int = 40000, levels=(1, 4, 16, 64)) -> list[dict]:
    """③ 并发吞吐：固定总裁决量，用不同线程数分摊，量墙钟吞吐（GIL 下单进程真实能力）。"""
    rows = []
    for workers in levels:
        per = total // workers
        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(_worker, [per] * workers))
        dt = time.perf_counter() - t0
        done = per * workers
        rows.append({"workers": workers, "decisions": done,
                     "seconds": round(dt, 3),
                     "per_sec": round(done / dt)})
    return rows


def bench_stability(n: int = 200000) -> dict:
    """④ 长稳/泄漏：连续 n 次裁决，量前后 RSS 增量（判内存是否泄漏）。"""
    import gc
    gc.collect()
    rss0 = _rss_mb(PROC)
    t0 = time.perf_counter()
    for i in range(n):
        check_command(CMDS[i % len(CMDS)])
    dt = time.perf_counter() - t0
    gc.collect()
    rss1 = _rss_mb(PROC)
    return {"decisions": n, "seconds": round(dt, 2),
            "rss_before_mb": round(rss0, 1), "rss_after_mb": round(rss1, 1),
            "rss_delta_mb": round(rss1 - rss0, 2)}


def bench_audit_storage(db_candidates: list[Path]) -> dict:
    """⑤ 审计存储成本：量已有 audit.sqlite 的会话/思维段行数与字节，折算每会话开销。"""
    for db in db_candidates:
        if db.exists() and db.stat().st_size > 0:
            try:
                con = sqlite3.connect(str(db))
                cur = con.cursor()
                tables = {r[0] for r in cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
                sess = next((t for t in ("sessions", "session", "traces") if t in tables), None)
                step = next((t for t in ("steps", "step") if t in tables), None)
                n_sess = cur.execute(f"SELECT COUNT(*) FROM {sess}").fetchone()[0] if sess else 0
                n_step = cur.execute(f"SELECT COUNT(*) FROM {step}").fetchone()[0] if step else 0
                con.close()
                size = db.stat().st_size
                return {"db": db.name, "size_kb": round(size / 1024, 1),
                        "sessions": n_sess, "steps": n_step,
                        "kb_per_session": round(size / 1024 / n_sess, 2) if n_sess else None,
                        "steps_per_session": round(n_step / n_sess, 1) if n_sess else None}
            except sqlite3.Error as e:
                return {"db": db.name, "error": str(e)}
    return {"error": "未找到可读的 audit.sqlite"}


def bench_coldstart() -> dict:
    """⑥ 冷启动：子进程从零导入护栏并完成首条裁决的时间。"""
    import subprocess
    code = ("import time;t=time.perf_counter();"
            "from app.guardrail.engine import check_command;"
            "check_command('rm -rf /');"
            "print(round((time.perf_counter()-t)*1000,1))")
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent.parent))
    t0 = time.perf_counter()
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    wall = (time.perf_counter() - t0) * 1000
    inner = r.stdout.strip()
    return {"import_to_first_decision_ms": float(inner) if inner else None,
            "process_wall_ms": round(wall, 1)}


def main() -> None:
    ap = argparse.ArgumentParser(description="资源/负载基准（硬性指标）")
    ap.add_argument("--backend-pid", type=int, default=None)
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    print("# 资源/负载基准（硬性指标）\n")
    print(f"采样时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"平台：{psutil.cpu_count()} 核 / "
          f"{round(psutil.virtual_memory().total/1e9,1)} GB / "
          f"Python {sys.version.split()[0]}\n")

    print("## ① 进程常驻内存")
    print(bench_footprint(args.backend_pid), "\n")
    print("## ② CPU 占用（持续裁决）")
    print(bench_cpu(), "\n")
    print("## ③ 并发吞吐")
    for r in bench_concurrency():
        print(r)
    print()
    print("## ④ 长稳 / 泄漏")
    print(bench_stability(), "\n")
    print("## ⑤ 审计存储成本")
    print(bench_audit_storage([root / "audit.sqlite", root.parent / "audit.sqlite"]), "\n")
    print("## ⑥ 冷启动")
    print(bench_coldstart())


if __name__ == "__main__":
    main()
