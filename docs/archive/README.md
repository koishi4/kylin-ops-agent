# docs/archive — 历史规划文档归档

本目录存放**已执行完毕**的规划/施工文档。它们记录了「为什么这么做」的决策轨迹，但**不再反映当前实现状态**，请勿据此施工或对外引用为产品现状。

为何保留而非删除：仓库内约 14 处代码与测试注释按「P 编号」援引这些文档作为设计依据（如 `guardrail/trifecta.py` → 「改进v2 P3-2」、`api/routes.py` → 「IMPROVEMENTS-v3 P0-4」）。这些引用按名不按路径，移入本目录不影响其有效性，删除则会让依据悬空。

| 文件 | 原位置 | 内容 |
|---|---|---|
| `IMPROVEMENTS.md` | docs/ | v1 改进方案（P0–P4 施工单） |
| `IMPROVEMENTS-v3.md` | docs/ | 整合 GPT Pro 审查 + 内核漏洞防御 |
| `IMPROVEMENTS-v4.md` | docs/ | 护栏绕过修复 + 第二轮审查整合 |
| `改进v2.md` | docs/ | 前沿调研与改进建议（P3 系列来源） |

当前权威文档：`docs/dev-log.md`（开发日志）、`docs/security-design.md`（安全总纲）、`docs/roadmap.md`（路线图）、`docs/课程报告.md` 与 `docs/软件杯-*`（提交物）。
