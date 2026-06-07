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
pip install -r requirements.lock   # 锁定版本，可复现；开发升级依赖时才用 requirements.txt
cp .env.example .env          # 填 DEEPSEEK_API_KEY；或在 .env 设 LLM_PROVIDER=mock 离线跑
uvicorn app.main:app --reload --port 8000
```
- `GET /health`：存活 + 当前 LLM provider
- `GET /tools`：列出 MCP 工具（评分①「列工具」）
- `POST /chat` `{"message": "磁盘还剩多少"}`：返回 answer + 五段执行链 trace

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
LLM_PROVIDER=mock python -m pytest -q   # Python 3.11 + 非 root 下全绿（默认离线 mock，无需 key/联网）
```
> 测试默认 `LLM_PROVIDER=mock`：不依赖云端模型，结果确定。root/容器环境有两处已知环境差异（kill 授权、
> 沙箱内存限额归因），已用兼容性断言覆盖。

### 一键可复现（装依赖 → 跑后端测试 → 构建前端）
```bash
bash scripts/ci_check.sh
```

### 受控动作鉴权（P0-4）
`/action/execute` 是唯一会改系统状态的端点。本机演示默认不强制鉴权（后端只监听 127.0.0.1）；
生产/联网演示请在 `backend/.env` 设 `OPERATOR_TOKEN`，并在 `frontend/.env` 设同值的 `VITE_OPERATOR_TOKEN`。

### 单独运行 MCP Server（可接 MCP Inspector 调试）
```bash
cd backend && python -m app.mcp_server.server
```

### 打包 / 解压（避免中文文件名 mojibake）
```bash
python -m zipfile -c submission.zip backend frontend docs scripts README.md CLAUDE.md   # 打包
python -m zipfile -e submission.zip ./out                                                # 解压
```
