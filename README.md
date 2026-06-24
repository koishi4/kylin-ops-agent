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

LLM 双模式（环境变量 `LLM_PROVIDER`）：`deepseek`（云端，国产开源，开发/演示默认）/ `mock`（无 key 无网，演示与 CI）。`LLMProvider` 抽象不与厂商耦合，任一 OpenAI 兼容端点（含私有化自托管的国产大模型）改 `DEEPSEEK_BASE_URL` 即可接入。

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

### 麒麟虚机一键部署（LoongArch + 麒麟 V11）
从 GitHub 拉代码 → 配环境 → 起服务 → 冒烟，一条命令搞定（幂等，可反复跑）。脚本是
`docs/deploy-loongarch.md` 预案的可执行落地版：系统包优先免编译、`uvicorn` 去 `[standard]`、
前端不在 LoongArch 构建（用仓库已带的 `frontend/dist`）。
```bash
# 推荐生产姿态：opsagent 非 root + systemd 自启 + nginx 托管前端并反代 /api + 联网 DeepSeek
bash scripts/deploy_kylin.sh --systemd --nginx --provider deepseek --api-key sk-xxx
#   --systemd          建受限账户 opsagent + 以其身份开机自启（坐实需求④最小权限）
#   --nginx            把 frontend/dist 托管到 80 端口，/api 反代到后端 8000；浏览器开 http://<VM-IP>/
#   --provider mock    默认；断网/无 key 也能演示（省略 --provider 即用 mock）
bash scripts/deploy_kylin.sh --help    # 全部参数
```
> 前端 `dist/` 已随 git 下发（LoongArch 无 Node 工具链不在本机构建）。**重建前端**：在 x86 开发机
> `cd frontend && npm run build`，再 `git add frontend/dist && git commit`（产物带内容哈希、会如实进 diff）。
> 不加 `--nginx` 时后端仍可单跑，前端另行托管（或开发期 `npm run dev` 用 vite 代理）。

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
