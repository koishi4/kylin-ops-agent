# 麒麟安全智能运维 Agent（软件杯 A2）

自然语言运维 Linux 的智能 Agent，核心是「安全护栏」。详见 docs/总方案.md。

## 快速开始
1. 读 CLAUDE.md（项目纲领）
2. 读 docs/总方案.md（环境配置 + 架构）
3. 按 docs/roadmap.md 推进

## 结构
- backend/   FastAPI 后端 + MCP Server + 护栏 + 审计
- frontend/  Vue3 B/S 界面
- docs/      方案、路线图、开发日志、UML 图
- .claude/skills/  三个开发技能（MCP工具/护栏/报告）

## 运行（第1周最小闭环已跑通）

### 后端
```bash
cd backend
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # 填 DEEPSEEK_API_KEY；或在 .env 设 LLM_PROVIDER=mock 离线跑
uvicorn app.main:app --reload --port 8000
```
- `GET /health`：存活 + 当前 LLM provider
- `GET /tools`：列出 MCP 工具（评分①「列工具」）
- `POST /chat` `{"message": "磁盘还剩多少"}`：返回 answer + 五段思维链 trace

LLM 三模式（环境变量 `LLM_PROVIDER`）：`deepseek`（云端，开发默认）/ `ollama`（本地 Qwen3，答辩离线）/ `mock`（无 key 无网，演示与 CI）。

### 前端
```bash
cd frontend
npm install
npm run dev                   # http://localhost:5173 ，/api 已代理到后端 8000
```

### 测试
```bash
cd backend && source .venv/bin/activate
LLM_PROVIDER=mock python -m pytest -v   # 11 条全绿（工具单测 + MCP/编排闭环）
```

### 单独运行 MCP Server（可接 MCP Inspector 调试）
```bash
cd backend && python -m app.mcp_server.server
```
