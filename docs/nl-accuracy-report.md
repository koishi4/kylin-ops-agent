# 评分② 自然语言交互准确性 —— 真模型工具选择基准报告

> 本报告由 `scripts/nl_eval.py` 自动生成，驱动**产品真实编排闭环**（真 Orchestrator + 真 MCP +
> 真 LLM）度量「一句话 → 选对工具」的 top-1 准确率。语料标准答案见
> `scripts/corpora/nl_intent_eval.jsonl`（逐条可审）。诚实约束：真模型有抽样波动，分数是
> 「deepseek-v4-pro @ 2026-06-11 10:13:03」的快照；未命中用例如实列出。

- provider / model：`DeepSeekProvider` / `deepseek-v4-pro`
- 用例数：42（含「不该调工具」对照）
- **总体 top-1 工具选择准确率：42/42 = 100.0%**
- 放宽口径 hit-any：100.0%
- 单轮延迟：均值 20.44s / 中位 18.07s / 最大 43.9s

## 按能力族
| 能力族（期望工具） | top-1 命中 | 准确率 |
|---|---|---|
| check_port | 2/2 | 100% |
| dir_size | 2/2 | 100% |
| disk_usage | 3/3 | 100% |
| find_large_files | 3/3 | 100% |
| find_zombie_processes | 2/2 | 100% |
| kernel_posture | 2/2 | 100% |
| list_listening_ports | 2/2 | 100% |
| list_open_files | 2/2 | 100% |
| list_processes | 3/3 | 100% |
| memory_info | 3/3 | 100% |
| none | 3/3 | 100% |
| process_detail | 2/2 | 100% |
| query_journal | 2/2 | 100% |
| query_vuln_intel | 2/2 | 100% |
| service_status | 2/2 | 100% |
| system_load | 3/3 | 100% |
| tail_log | 2/2 | 100% |
| uptime_info | 2/2 | 100% |

## 未命中用例（诚实留痕）
（本轮全部命中）

## 跨轮稳定性与诚实区间（务必一起读）

真模型即便 temperature=0，**推理模型仍有跨轮抖动**——尤其语义高度重叠的工具对（如
`query_vuln_intel` 漏洞情报 vs `kernel_posture` 主机姿态，对「内核有什么 CVE」两者都说得通）。
单轮分数是**快照**，不是恒定常数；要看稳定性应多跑几轮看区间，而非把某一轮当定论。

> 本基准开发期实测：首轮 40/42（暴露并修掉两处真误杀——防线4 把 `stat /etc/passwd` 误判提权、
> 防线1 把「检查有没有提权风险」误判越权），修复后复跑 42/42；其中 `nl-vuln-1` 的 miss↔hit 翻转
> **源于模型抖动而非任何修复**（vuln/posture 工具可互换）。故诚实区间记为 **约 95–100%**，
> 而非单点「100%」。这与红队语料的「诚实叙事 > 宣称满分」一脉相承。
