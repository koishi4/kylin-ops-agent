# 安全能力 → 框架映射（security-mapping.md）

> 把本项目已实现的安全能力，逐条映射到两套权威框架：
> **OWASP Top 10 for LLM/Agentic Applications（含 2026 Agentic 视角）** 与 **OWASP MCP Security Cheat Sheet**。
> 每条都指向**具体代码模块**与**可演示项**，便于评委/评审按图索骥。总纲与威胁模型见
> [security-design.md](./security-design.md)。

---

## 1. OWASP Top 10 for LLM / Agentic Applications

| 风险项 | 本项目对应能力 | 代码模块 | 可演示 |
|---|---|---|---|
| **LLM01 Prompt Injection** | 注入检测 + 数据/指令分离（外部内容打污点、spotlighting 边界标注、不喂进决策流） | `guardrail/context_sanitizer.py`、taint / spotlighting 测试 | 日志里夹带「忽略规则」被识别并拒绝 |
| **LLM02 Insecure Output Handling** | LLM 输出**不被信任**：所有候选命令过护栏二次过滤，绝不直接执行 | `guardrail/engine.py`、`core/executor.py` | 模型生成 `rm -rf /` 被拦 |
| **LLM06 Excessive Agency（过度代理）** | 受控动作白名单 + 强制二次确认 + 执行沙箱（资源/能力保险丝） | `core/actions.py`、`core/sandbox.py` | 失控进程被沙箱秒杀；危险动作需确认 |
| **LLM08 Excessive Permissions / Least Privilege** | 非 root 启动闸门 + 沙箱内 setuid 降权 + capability 削减 | `guardrail/privilege.py`、`core/sandbox.py` | 非 root 启动；raw 套接字被拒 |
| **LLM04 Model DoS / 资源滥用** | 只读工具资源硬上限（max_scan 夹断、伪文件系统拒扫）+ 沙箱 rlimit（CPU/AS/NPROC/FSIZE）+ 墙钟超时 | `mcp_server/tools/_validate.py`、`core/sandbox.py` | 超大扫描被夹断 truncated；CPU 自旋被掐死 |
| **LLM05 Supply Chain** | MCP 工具元数据静态扫描（投毒/影子/隐形 Unicode 载荷）+ 依赖锁定 | `guardrail/tool_scan.py`、`requirements.lock` | 工具供应链扫描面板 |
| **LLM07 Insecure Plugin/Tool Design** | 工具读写分级（READONLY/MUTATING/PRIVILEGED）+ 入参白名单校验 | `mcp_server/tools/__init__.py`、`_validate.py` | 非法 unit/priority/since 结构化报错 |
| **LLM09 Overreliance** | 双通道：LLM 工具调用 + 确定性 NL 安全路由；关键安全判断不完全依赖模型 | `core/orchestrator.py`、确定性路由 | 模型不稳时确定性路由仍可走通 |
| **LLM10 Auditability / 可追溯** | 五段思维链 + HMAC 哈希链防篡改审计，可按 trace_id 回放与校验 | `audit/store.py`、`/traces/{id}/verify` | 思维链回放 + 篡改即断链 |

> Agentic 2026 视角补充：把上述能力组织成 **Lethal Trifecta（致命三要素）/ Meta「Agents Rule of Two」**
> 的结构性论证——见 `guardrail/trifecta.py` 与下表「Rule of Two」行。

---

## 2. Agentic 安全设计模式（致命三要素 / Rule of Two / 人在回路）

| 模式 | 本项目落地 | 代码 |
|---|---|---|
| **Lethal Trifecta**（不可信内容 + 敏感数据 + 改状态/外联 三者齐 = 必可被注入利用） | 给每个工具/动作打三条能力腿，路径做能力并集判定 | `guardrail/trifecta.py:TOOL_CAPS / evaluate_path` |
| **Rule of Two**（一会话至多满足两腿，三腿必须人在回路） | 感知层全 READONLY、能力 ≤2 腿；第三腿只在强制二次确认的动作层 | `trifecta.py` 结构性不变量 + `actions.py` 二次确认 |
| **Human-in-the-loop** | 高危动作 / 内核缓解命令均须显式 `confirmed`，绝不自动执行 | `core/actions.py`、`core/posture.py` 缓解仅候选文本 |
| **Confused Deputy 防护** | 外部不可信内容打污点、不驱动指令流；受控动作恒非污点（信息流分离） | `taint` / `api/routes.py` 动作落审计 `tainted=False` |
| **Least Agency / 攻击面削减** | 沙箱削减 capability（NET_RAW/SYS_MODULE/…）+ no_new_privs + 断网 | `core/sandbox.py` |

---

## 3. OWASP MCP Security Cheat Sheet

| Cheat Sheet 关注点 | 本项目对应 | 代码 |
|---|---|---|
| **Tool Poisoning（工具投毒：描述里藏指令）** | 静态扫描工具 name/description/schema 的可疑指令模式 | `guardrail/tool_scan.py` |
| **Tool Shadowing / Rug-pull（工具影子/事后掉包）** | 启动即扫描工具元数据并告警；schema hash + 变更告警列为 P2 | `main.py` 启动扫描、`tool_scan.py` |
| **Invisible / Unicode 隐形载荷** | 检测描述中的隐形 Unicode / 控制字符 | `tool_scan.py` |
| **不上传文件/凭据（本地分析）** | 扫描全程本地、绝不外传（致敬 mcp-scan 思路但自实现） | `tool_scan.py` |
| **最小工具权限 / 只读优先** | 17 个感知工具全 READONLY；变更仅经受控动作层 | `mcp_server/tools/__init__.py` |
| **输入校验** | unit/priority/since 白名单、路径 commonpath 包含判断、扫描上限 | `_validate.py`、`core/pathutil.py` |
| **传输与隔离** | MCP Server 独立进程经 stdio 与后端通信；后端默认只监听 127.0.0.1 | `mcp_server/server.py`、`config.api_bind_host` |
| **鉴权（受控动作）** | `/action/execute` 最小 token 鉴权（Bearer + 常量时间比较） | `api/routes.py:require_operator` |

---

## 4. 一图速览：威胁 → 防线 → 框架

```
自然语言指令
  │
  ├─[防线1 意图分类]            ── LLM01/LLM02
  ├─[防线2 规则库+realpath+AST] ── LLM02/LLM07
  ├─[防线3 注入检测/数据-指令分离]── LLM01 / Confused Deputy
  ├─[防线4 最小权限+受控动作+沙箱]── LLM06/LLM08 / Rule of Two / Human-in-loop
  │        └─[攻击面削减 cap-drop/no_new_privs] ── 威胁模型B：内核 LPE 遏制
  └─[五段思维链 + HMAC 审计]    ── LLM10 可追溯

旁路：MCP 工具供应链扫描（LLM05 / MCP Cheat Sheet）
      漏洞情报 + 姿态检查（威胁模型B：时效化情报，N-day 覆盖）
```

> 说明：威胁模型 A（运维操作安全）由防线 1~4 正面覆盖；威胁模型 B（内核 0-day 经无害命令利用）
> 由「最小权限 + 沙箱遏制（对 0-day 有效）+ 活情报（N-day 覆盖）」应对，详见 security-design.md 第 3 节。
