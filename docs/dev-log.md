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
