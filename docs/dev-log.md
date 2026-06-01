# 开发日志 dev-log.md
> 每完成一块就在这里记：做了什么、为什么这么设计、踩了什么坑、怎么解决的。
> 这是课程报告"第6章 总结"和软件杯文档的素材库，顺手记，不补写。

## 模板
### [日期] 模块名
- 做了什么：
- 设计决策与理由：
- 踩坑：
- 解决方法：

---

### 2026-06-01 第1周：骨架 + 最小闭环
- 做了什么：
  - 搭好本地后端环境（Python 3.11 venv，requirements 全装通过）。
  - `config.py`：pydantic-settings 统一读 .env，集中管理 LLM 切换 / 审计库 / 执行账户。
  - MCP 工具层：3 个只读工具 `disk_usage` / `memory_info` / `list_processes`（基于 psutil），
    纯函数 + 注册表（`tools/REGISTRY` 标注读写级别），`server.py` 用官方 FastMCP 注册并以 stdio 暴露。
  - `client.py`：后端作为 MCP client 以子进程连 server，提供「列工具 / 转 OpenAI schema / 调工具」。
  - LLM 抽象层扩成三模式 deepseek/ollama/**mock**：mock 用关键词规则模拟选工具，保证无 key 无网也能跑通闭环和 CI。
  - `orchestrator.py`：自然语言 → LLM 选工具 → 执行 → 作答，并产出五段 trace（接收指令/感知环境/推理决策/安全校验/执行结果），为第3周思维链溯源打底。
  - FastAPI：`/health` `/tools` `/chat` 三接口，lifespan 启动时连 MCP、装配编排器。
  - 测试：11 条 pytest 全绿（工具单测 6 + MCP协议/编排闭环集成 5）。
  - 前端：Vite + Vue3 + Element Plus 对话界面，消息流 + 可折叠「思维链回放」时间线，npm build 通过。
- 设计决策与理由：
  - **后端不直接 import 工具，而是走 MCP 协议连 server**：让工具层成为真正独立的 MCP 插件，契合赛题「实现 MCP 协议」硬要求，也方便演示「列工具/调工具」（评分①）。
  - **加 MockProvider**：CLAUDE.md 要求「永远保持可演示」，mock 让演示/测试不依赖云端 key 或本地大模型，CI 可离线跑。
  - **trace 里预留「安全校验」段**：本周工具全是 READONLY 自动放行，但把护栏接入点先留在编排器里，第2/3周直接挂规则库，不返工。
- 踩坑：
  - pytest 集成测试报 `Attempted to exit cancel scope in a different task`：MCP stdio client 内部用 anyio task group，AsyncExitStack 的 connect 与 aclose 被 pytest-asyncio 放到不同 task 里执行就会炸。
  - 本机 curl 访问 127.0.0.1 被环境 HTTP 代理拦截返回 502。
- 解决方法：
  - 给 MCPClient 加 `__aenter__/__aexit__`，测试里用 `async with MCPClient()` 把 connect/use/close 收进同一个 task（FastAPI lifespan 本就是单 task，生产侧无此问题）。
  - 验证接口时 curl 加 `--noproxy '*'` 绕过代理。
- 下一步（第2周）：补全 MCP 工具（网络/日志/句柄/服务），落地护栏防线2高危命令规则库，执行器统一出口，rm -rf / 拦截 demo。

---

### 2026-06-01 第2周：MCP 工具补全 + 护栏防线2 + 执行器
- 做了什么：
  - MCP 工具从 3 个补到 **15 个**，覆盖六大类：磁盘(disk_usage/find_large_files/dir_size)、内存系统(memory_info/system_load/uptime_info/service_status)、进程(list_processes/find_zombie_processes/process_detail)、网络(list_listening_ports/check_port)、日志(tail_log/query_journal)、句柄(list_open_files)。全部 READONLY，纯函数 + pytest。
  - 护栏防线2 高危命令规则库扩到 **25 条**：删除/权限/磁盘/提权/配置五类各 ≥3 条 + 注入类 5 条。正则覆盖变形（-rf/-fr/--recursive、多空格、引号、命令拼接）。
  - `rules.py` 加 `hits_critical_path`：对 rm 命令的路径参数做 `realpath` 规范化，捕获 `rm -rf /etc/../etc`、相对路径、软链接绕过等正则难覆盖的变形（合成虚拟规则 PATH-001）。
  - `engine.py` 护栏引擎：`check_command` 按风险等级裁决，返回统一 `GuardResult`（allowed/action/matched_rules/risk/reason/require_confirm）；`scan_injection` 单独扫注入（防线3 接入点）。
  - `executor.py` 统一执行出口：所有可变命令唯一入口，执行前强制过护栏，不放行绝不执行；shell=False + shlex 杜绝元字符二次解释。
  - 后端加 `/guardrail/rules`（规则可视化）和 `/guardrail/check`（拦截 demo，只校验不执行）两个接口。
  - 红队测试集：危险样本 32 条 + 正常样本 15 条 + 注入 4 条，**拦截率 100%、误杀率 0%**；执行器拦截 demo 测试（rm -rf / 端到端被拦）。全套 87 条 pytest 全绿。
- 设计决策与理由：
  - **realpath 兜底只对 rm 生效，不对 chmod/chown**：删除不可逆，是路径绕过攻击的高价值目标；chmod/chown 可恢复且已被 PERM-* 规则覆盖，若一并升级 CRITICAL 会误杀「chmod 644 /etc/hosts」这类正常单文件运维 → 加进 SAFE 样本回归锁定。这是「拦得狠又不误杀」的平衡点，测试用例可直接进报告。
  - **风险四级 × 三动作矩阵**：CRITICAL 不可覆盖；HIGH+DENY 需显式授权（authorized，防线4 接入点）；HIGH/MEDIUM+CONFIRM 需用户二次确认（confirmed）；LOW/未命中放行。
  - **MCP 工具全 READONLY**：本阶段只做「感知」，不做「改」；真正的 MUTATING 动作（kill/clean）走 executor 并必经护栏，职责清晰。
  - **/guardrail/check 只校验不执行**：Web 入口绝不暴露真实执行，避免任何从前端触发破坏性命令的可能，符合 CLAUDE.md「只演示被拦、不演示执行成功」。
- 踩坑：
  - 初版 `hits_critical_path` 把 chmod/chown 也纳入 realpath 升级，导致 `chmod -R 777 /etc` 被升级成 CRITICAL 无法被授权覆盖，且会误杀单文件 chmod —— 测试一次性暴露。
- 解决方法：把 realpath 升级范围收敛到 rm；chmod/chown 交回 PERM-* 正则规则（保持 HIGH，可授权覆盖）。
- 指标（可直接进报告/答辩）：MCP 工具 15、护栏规则 25（命令五类各≥3 + 注入5）、红队拦截率 100%、误杀率 0%、pytest 87 全绿。
- 下一步（第3周）：护栏防线1意图分类、防线3注入接入编排器、防线4最小权限；红队集扩到 30+ 并出指标表；根因分析模块（评分④）；trace 落 SQLite + 前端思维链回放界面。
