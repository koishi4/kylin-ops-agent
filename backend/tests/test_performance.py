"""性能基准测试（P1-2）：为「性能(核心指标)测试报告」提供可回归的下限保证。

复用 scripts/bench.py 的纯函数测量逻辑。阈值取得**宽松**（按慢机器留足余量），
目的是「护栏开销在可接受量级」的回归红线，而非追求精确数值——精确数值由报告脚本产出。
"""
from __future__ import annotations

from scripts.bench import (
    accuracy_metrics,
    bench_correlation,
    bench_guardrail,
    bench_throughput,
    build_markdown,
    measure,
    percentile,
)


class TestStatsHelpers:
    def test_percentile_interpolation(self):
        s = [1.0, 2.0, 3.0, 4.0, 5.0]
        assert percentile(s, 0) == 1.0
        assert percentile(s, 100) == 5.0
        assert percentile(s, 50) == 3.0
        assert percentile([], 50) == 0.0

    def test_measure_shape(self):
        r = measure(lambda: sum(range(10)), iters=200, warmup=10)
        assert r["iters"] == 200
        assert r["mean_us"] > 0
        assert r["p50_us"] <= r["p95_us"] <= r["p99_us"]


class TestLatencyBudget:
    def test_guardrail_decision_is_cheap(self):
        """护栏单命令裁决均值应在毫秒以内（宽松上限 5ms，实际为百微秒级）。"""
        r = bench_guardrail(iters=300)
        assert r["mean_us"] < 5000, f"护栏裁决过慢: {r['mean_us']:.1f}μs"

    def test_correlation_reasoning_is_cheap(self):
        r = bench_correlation(iters=300)
        assert r["mean_us"] < 5000, f"关联推理过慢: {r['mean_us']:.1f}μs"

    def test_throughput_floor(self):
        """批量裁决吞吐应远高于实际命令流速率（宽松下限 500 decisions/s）。"""
        r = bench_throughput(rounds=10)
        assert r["per_sec"] > 500, f"吞吐过低: {r['per_sec']:.0f}/s"


class TestAccuracyAndReport:
    def test_accuracy_metrics(self):
        a = accuracy_metrics()
        assert a["block_rate"] == 1.0
        assert a["fp_rate"] == 0.0
        assert a["inj_rate"] == 1.0

    def test_build_markdown_has_sections(self):
        md = build_markdown(
            latency={"guardrail": bench_guardrail(iters=100)},
            throughput=bench_throughput(rounds=5),
            accuracy=accuracy_metrics(),
            e2e={"ok": False, "reason": "unit-test"},
            env={"Python": "3.11"},
        )
        assert "性能（核心指标）测试报告" in md
        assert "护栏命令裁决" in md
        assert "拦截率" in md and "100.0%" in md
        assert "跳过本地段" in md       # e2e ok=False 分支（mock 本地段未测）
        assert "串行 LLM 往返" in md     # 主导项：按意图分类的 LLM 往返次数表
        assert "双层安全研判" in md      # 诚实说明灰意图多付一次往返的取舍
