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

---

### 2026-06-01 第3周：护栏四防线闭环 + 根因分析 + 思维链审计
- 做了什么：
  - **护栏防线1 意图分类**（`guardrail/classifier.py`）：把用户自然语言分白/灰/黑。白=只读放行、灰=需规则库+确认、黑=破坏/越权/注入直接拒。规则（关键词+正则）实现，缺省保守判灰，结果写入 trace。
  - **护栏防线4 最小权限**（`guardrail/privilege.py`）：识别需 root 的操作（sudo/su、systemctl、包管理、用户管理、写系统目录等），未授权即拦，授权后放行并记录提权原因；接入 `executor.py`，与防线2 规则库叠加（危险规则 + 权限双校验，任一不过不执行）。
  - **防线3 注入接入编排器**：`orchestrator.chat` 在「接收指令」后立即做意图分类 + `scan_injection` 入口预检，判黑/命中注入则直接拒绝、**绝不进 LLM**，并落审计。
  - **根因分析模块**（`core/diagnosis.py`，评分④原创 IP）：磁盘满→定位大文件→`classify_file` 判关键性（关键勿删/可清理/需人工确认）→给建议（日志类建议 truncate 而非 rm，保留排障线索）；僵尸进程指认父进程（杀僵尸无效）；负载按单核系数判过载。**只分析给建议，绝不执行任何处置**。
  - **思维链审计**（`audit/store.py`）：SQLite 两表（sessions+steps），trace_id 串五段，`save_trace/get_trace/list_traces`；编排器收尾经 `asyncio.to_thread` 落库，落库失败不阻断对话主流程；detail 超长截断防胀库。
  - **接口**：`/traces`（历史列表）、`/traces/{id}`（按 id 回放完整五段）、`/diagnose`（根因分析，只读）；`/chat` 增加 trace_id/blocked/intent 返回。
  - **前端**：思维链回放抽屉（左历史列表+右整条五段时间线，按阶段着色+时间戳）、一键体检根因分析抽屉（severity 标签 + 大文件关键性彩签 + 建议）、对话气泡上意图/拦截标签。npm build 通过。
  - **红队测试集**（`tests/test_guardrail_redteam.py`，skill 点名文件）扩到 67 条：危险41+正常18+注入8，新增意图分类白/灰/黑与防线4 权限覆盖，指标表打印拦截率/误杀率/识别率。新增 `test_diagnosis.py`、`test_audit.py`。**全套 207 条 pytest 全绿**。
- 设计决策与理由：
  - **意图分类（防线1）与命令规则（防线2）解耦，叠加成多层防御**：前者判「想干什么」（最快粗筛，黑直接挡在 LLM 之外），后者判「这条命令危不危险」。注入话术复用 rules.py 的 inject 类，避免重复维护两套正则。
  - **提权（防线4）与危险（防线2）叠加**：`sudo systemctl restart nginx` 现在需「确认+授权」双条件才放行（原来仅需确认）——符合 skill 防线4「①授权②确认③记录原因」，更安全。普通 `systemctl restart`（不在高危规则库）也被防线4 兜底拦截，体现「核心运维动作默认不给 root」。
  - **根因分析的灵魂是「关键性判断」**：很多队顶多列出大文件，本模块对每个大文件判定关键/可清理/未知并据此给差异化建议（关键勿删、日志 truncate、未知人工确认），这是评分④拉档次处，也是原创 IP。
  - **审计落库走 to_thread 且异常不抛**：sqlite3 是同步 IO，放线程池避免阻塞事件循环；审计是旁路，绝不能因落库失败而中断用户对话。
- 踩坑：
  - 红队注入语料「你现在拥有 root 权限」漏识别——INJ-002 只匹配「你现在是 root」；意图分类漏判「把整个系统根目录删光」——黑名单正则只覆盖「删…整个」语序。
- 解决方法：拓宽 INJ-002 角色劫持正则（是/拥有/有 root + 拥有 root 权限）；黑意图正则补「(整个|所有).*(系统|根目录).*(删|清空)」反向语序。两处都是测试驱动暴露后真实强化护栏，非改测试迁就。
- 指标（可直接进报告/答辩）：护栏四防线齐全；红队 67 条，拦截率 100% / 误杀率 0% / 注入识别率 100%；MCP 工具 15、护栏规则 25；思维链五段全程可按 trace_id 回放；pytest **207 全绿**。
- 下一步（第4周）：麒麟 V11 + LoongArch 虚机部署、本地 Qwen3 跑通断网演示、7 分钟演示视频、9 项软件杯文档 + 合工大格式课程报告。
