# 前沿对标与理论拔高：本项目护栏的第一性原理

> 对应 docs/改进v2.md 推荐2/3（理论拔高 + 答辩金句），是课程报告「对标前沿/相关工作」章与软件杯答辩
> 「创新性」陈述的素材底稿。把本项目的工程实现对齐到 2025 年学术/工业最新框架，让「一个不错的运维工具」
> 升级为「一个把可信执行框架落到国产 Linux 的研究型作品」。
>
> 引用均标注来源与版本（数字见 docs/改进v2.md「Key Findings」，已核实）；凡本项目未完整实现者一律诚实标注
> 「借鉴思想/轻量版」，不夸大。

---

## 1. 问题陈述（引言锚点 / 答辩金句）

**一句话立论**：提示词注入是 LLM **架构级、尚未解决**的根本缺陷——模型无法可靠区分「指令」与「数据」；
**纯检测式防御必被自适应攻击绕过，唯有架构级约束可靠**。这正是本项目护栏「确定性规则掌握最终放行权、
AI 只能升级风险不能翻案放行」设计哲学的理论依据。

三个权威锚点：
- **「The Attacker Moves Second」**（arXiv:2510，OpenAI/Anthropic/Google DeepMind 等 14 位作者）：对 12 种
  已发布防御施加自适应攻击，再次确认**任何纯检测式防御都会被绕过**。→ 故本项目不把最终放行权交给任何概率式
  模型，而是交给确定性规则 + realpath 兜底（防线2）。
- **Simon Willison「Lethal Trifecta / 致命三要素」**（2025-06）：Agent 同时具备①接触不可信内容 ②访问敏感/私有
  数据 ③改状态或对外通信时，必然可被注入利用。→ 本项目把它做成可视的能力面板（P3-2）。
- **Meta「Agents Rule of Two」**（2025-10-31）：一个会话内三要素至多满足两项，三者皆需则**必须人在回路**。
  → 本项目 15 工具全 READONLY（结构上 ≤2 腿）、第三腿仅存于强制二次确认的动作层（P0-3 + P3-2）。

---

## 2. 六大安全设计模式映射（arXiv:2506.08837，IBM/Invariant Labs/ETH/Google/Microsoft）

该论文的核心原则可直接引用：**"Once an [AI] agent has ingested untrusted input, it must be constrained so that
it is impossible for that input to trigger any consequential actions."**（一旦 Agent 摄入不可信输入，就必须
约束它，使该输入不可能触发任何有后果的动作。）论文专门有一个 **OS Assistant 案例研究，用 Dual LLM 模式安全
处理文件内容**——与本赛题几乎同场景。

| 设计模式 | 论文要义 | 本项目对应实现 | 落点文件 |
|---|---|---|---|
| **Plan-Then-Execute** | 先定不可变计划，注入无法改变动作序列 | 入口先做意图分类（白/灰/黑）+ 注入体检，**判黑/命中注入直接拒绝、绝不进 LLM**；灰意图先研判再执行 | `guardrail/classifier.py`、`core/orchestrator.py` |
| **Dual LLM**（特权/隔离分离） | 特权 LLM 看可信指令并能调工具，隔离 LLM 只处理不可信数据、无工具权 | **双层意图研判**：执行用 LLM 与**独立低温安全评审 LLM**分离，评审 prompt 只评风险、不执行、不被诱导；规则与 AI **保守合并取更严** | `guardrail/risk_assessor.py` |
| **Context-Minimization** | 处理后剔除不可信内容，使其无法驱动后续动作 | 工具输出**沙盒化隔离 + datamarking 打标**，结构上隔离「数据 vs 指令」；命中注入降权 | `guardrail/context_sanitizer.py`（P0-2 + P3-1） |
| **Action-Selector** | Agent 只能从受限动作集里选，不能拼任意操作 | MCP 工具全 READONLY；变更动作做成**白名单参数化动作**（truncate_log/kill_process/clean_path），非自由 shell | `mcp_server/tools/`、`core/actions.py` |
| **LLM Map-Reduce** | 拆分处理不可信数据降低单点影响 | （部分）逐工具结果独立沙盒化后再喂回，单条注入不污染全局 | `core/orchestrator.py` |
| **Code-Then-Execute** | 先生成受约束代码再执行 | （未实现，诚实标注）本项目走「工具调用 + 白名单动作」路线，未引入代码生成执行，规避其新增攻击面 | — |

> 叙事：本项目并非「想到哪做到哪」，而是工程实现**恰好命中六大设计模式中的五个**，与顶会论文的第一性原理对齐。

---

## 3. 信息流控制 / 能力安全（CaMeL，arXiv:2503.18813，Google DeepMind/ETH）

CaMeL 把传统软件安全的**控制流完整性、访问控制、信息流控制**搬到 LLM：用特制解释器追踪每个变量的来源
(provenance) 与能力 (capability)，区分 Privileged LLM（看可信指令、能调工具）与 Quarantined LLM（只处理
不可信数据、无工具权）。论文 v2 在 AgentDojo 上「77% 任务且可证明安全」（无防御基线 84%），已开源
(github.com/google-research/camel-prompt-injection)。

本项目的**轻量版落地**（P3-3，诚实标注：取其思想，非完整移植）：
- 审计链加 `tainted` 污点位，标记执行路径是否**摄入过外部不可信数据**（data provenance 的最小形态）。
- **可证明的信息流分离**：能力库里「摄入不可信」(untrusted) 腿与「改状态」(state_change) 腿**互斥**
  （`tests/test_taint.py` 固化），且编排路径工具全 READONLY → **「污点 ∧ 改状态」恒不成立**：会摄入不可信
  数据的路径绝不改状态，会改状态的路径绝不污点。这是 CaMeL「控制流/数据流分离」思想的架构级体现。

落点：`audit/store.py`（tainted 列 + HMAC 哈希链）、`core/orchestrator.py`、`guardrail/trifecta.py`。

---

## 4. 能力约束：致命三要素 / Rule of Two 面板（P3-2）

把 §1 的 Willison/Meta 框架变成项目里**可度量、可演示**的一等公民：
- 给 15 工具 + 3 动作打三条能力腿布尔标签（`guardrail/trifecta.py` 的 `TOOL_CAPS`）。
- `evaluate_path()` 对执行路径做能力并集 + Rule of Two 裁决；前端「⚖️ 能力面板」可视化。
- **结构性不变量**：感知层能力上限恒 ≤2 腿（无『改状态/外联』腿）；第三腿仅存于强制二次确认的动作层——
  任何可能集齐致命三要素的路径都必经人工闸门，**Rule of Two 由架构强制，而非靠提醒**。

对标 OWASP **LLM06 Excessive Agency**（2025 扩为 excessive functionality / permissions / autonomy 三根因）：
本项目「最小权限执行 + 高危需确认 + 工具能力打标」正是对这三点的直接缓解。

---

## 5. LLM 监督 LLM：保守合并的正确性与脆弱性

- 本项目「双层意图研判」即 LLM-as-a-judge 的安全用法：在有后果动作前插入第二个低温模型做实时 gate
  （范式同 Anthropic Constitutional AI、OpenAI Evals）。
- **关键设计正确性**：规则与 AI **保守合并取更严**——规则说危险即危险（AI 不能翻案放行），AI 可把规则未覆盖项
  **升级**为需确认/拒绝。即「规则保可靠性、LLM 补泛化性」。
- **深度警示（体现思考深度）**：Trend Micro 研究发现**评审模型自身也会被未净化的目标响应注入**（如 Base64
  角色扮演让 judge 泄露自身模型家族）。这恰好佐证本项目「**不把最终放行权交给概率式模型**」的保守合并是对的——
  AI 研判只能升级风险，确定性规则掌握最终放行权。

落点：`guardrail/risk_assessor.py`、`guardrail/engine.py`（保守合并裁决）。

---

## 6. MCP 生态与供应链安全（P3-4）

- **运维向 MCP 已有先例**：Red Hat `linux-mcp-server`（只读诊断）、SUSE Multi-Linux Manager MCP（OAuth +
  elicitation 人在回路）——但**大多只读或仅人工确认；本项目的确定性写操作护栏是真正差异化**。
- **MCP 自身新攻击面**（Invariant Labs 2025-04）：工具投毒（恶意指令藏工具描述里，不被调用也生效，约 **5.5%
  公开 server 含投毒元数据**）、工具影子（跨工具篡改）、rug pull。开源 `mcp-scan`（本地分析，不上传）。
- **本项目实现**：`guardrail/tool_scan.py` 是 mcp-scan 思路的本地化原创实现——静态扫工具 name/description/schema
  里的投毒/影子/隐形载荷，复用 `scan_injection` + 七类专项启发式；连接 MCP 后启动即扫并记日志。补上第三个
  「不信任」（工具元数据/供应链），与「不信任 LLM 输出」「不信任外部数据」三位一体。

---

## 7. 量化对标（评测基准，P3-5 + 文献数字）

| 基准 | 规模 | 关键数字（来源核实见 改进v2.md） |
|---|---|---|
| AgentDojo（NeurIPS 2024，ETH） | 97 任务 + 629 安全用例 | 最佳 Agent 被攻击成功率 <25%；自带 tool-filter 把 ASR 降到 **7.5%** |
| InjecAgent（ACL 2024，UIUC） | 1,054 用例 | ReAct GPT-4 ASR **24%**，加 hacking prompt 升 **47%**，微调降 **7.1%** |
| RedCode-Exec（NeurIPS 2024） | 4,050 高危用例（Py+Bash） | **Bash/自然语言比 Python 更易绕过拒绝**——印证本项目用正则+realpath 兜底 Bash 的必要性 |
| ToolEmu（ICLR 2024 Spotlight） | 144 用例 | 最安全 Agent 仍 **23.9%** 失败率；terminal 工具 7 个严重失败 6 个真机可复现（含 `rm -rf /`） |
| Spotlighting（Microsoft 2024-03） | — | datamarking 把 ASR 从 **>50% 降到 <2%**（GPT-3.5 降至 3.10%，Text-003 降至 0.00%） |

**本项目自测（docs/guardrail-ab.md，与上文献同方法论、适配运维语料）**：加护栏把 ASR 从 **100%→0%**，正常
任务完成率维持 **100%**（误杀 0）。诚实标注：借鉴范式而非跑原版满分；且本项目**确定性规则掌握最终放行权**，
不会被自适应攻击翻案。

---

## 8. 模块 → 前沿方法 总览对标表

| 本项目模块 | 对标前沿方法/产品 | 落点文件 |
|---|---|---|
| 意图风险分类（防线1） | Llama Guard 风险分类法、NeMo input rails、Plan-Then-Execute | `guardrail/classifier.py` |
| 高危命令规则库（防线2，正则+realpath） | 可编程确定性护栏、ToolEmu terminal 案例、RedCode-Exec Bash 场景 | `guardrail/rules.py`+`rules.yaml`、`guardrail/engine.py` |
| 提示词注入沙盒 + datamarking（防线3） | Spotlighting、Microsoft Prompt Shields、Context-Minimization | `guardrail/context_sanitizer.py` |
| 最小权限 + 能力打标（防线4） | OWASP LLM06、Meta Rule of Two、致命三要素 | `guardrail/privilege.py`、`guardrail/trifecta.py` |
| 双层意图研判（保守合并） | LLM-as-a-judge、Constitutional AI、Dual LLM | `guardrail/risk_assessor.py` |
| 污点追踪审计 | CaMeL 信息流控制、设计模式论文「数据/动作归因」 | `audit/store.py`、`core/orchestrator.py` |
| HMAC 哈希链审计 | OWASP Agentic 2026 transparency & explainability | `audit/store.py` |
| MCP 工具供应链扫描 | mcp-scan、Invariant Labs 工具投毒研究 | `guardrail/tool_scan.py` |
| 智能根因分析 | 微软 RCA（ICSE 2023）、ReAct RCA Agent、华为知识图谱 RCA | `core/diagnosis.py` |
| 量化 A/B 实验 | InjecAgent/AgentDojo/RedCode「有防御 vs 无防御」 | `scripts/redteam_ab.py` |

> AI Investigation Capability Ladder：L0 手动 → L3 单次诊断 → L4 多步 Agent 调查 → **L5 闭环调查+修复（带人工
> 审批）**。本项目处于 L3–L4，且**安全护栏正是迈向 L5（敢做修复）的前提**——这是本作品相对「只读/只建议」竞品
> 的核心定位。

---

## 9. 诚实边界（Caveats，写进报告反而更显专业）

- **护栏不是银弹**：Meta 自己强调 Rule of Two「不应被视为终点线」，满足它的设计仍可能因用户盲目点确认失效。
  本项目表述为「**纵深防御 + 显著降低最高危后果**」，而非「彻底杜绝注入」。
- **确定性 vs 概率要把握分寸**：核心卖点是确定性规则兜底，但 LLM 安全研判仍是概率式的。叙事重点是
  「**概率式只能升级风险等级、确定性规则掌握最终放行权**」这一保守合并逻辑。
- **CaMeL/六模式为借鉴非移植**：完整移植到 LoongArch+麒麟 一个月内不现实，本项目取其思想做轻量落地，
  并在代码与本文档如实标注。
- **基准为适配非原版**：借鉴 InjecAgent/AgentDojo/RedCode 的注入样本与评测方法论，移植到自有运维工具集做对比，
  不追求跑原版满分（其场景为邮件/银行/Docker）。
