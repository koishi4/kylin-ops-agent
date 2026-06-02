# LoongArch + 麒麟 V11 部署适配预案

> 对应 IMPROVEMENTS P2-5。目标环境：**麒麟高级服务器操作系统 V11 + LoongArch（loongarch64）**，官方发放虚机。
> 本文档不依赖虚机即可先写好，虚机到手后照此逐项验证并回填实测结果。
> 核心判断（见 docs/总方案.md）：项目纯逻辑在 x86 WSL 开发完成；麒麟是标准 Linux 发行版，`psutil`/`lsof`/`journalctl`/`ss`/`df` 等都在，
> **迁移成本几乎全部集中在「LoongArch 上没有预编译 wheel 的 Python 扩展如何装上」**。本预案就是把这件事拆细、给好退路。

## 0. 一句话策略

> **能用麒麟官方源的系统包就用系统包；装不上 wheel 的扩展走源码编译；编译也难的非核心扩展直接降级/替代。前端在 x86 上 `vite build`，只把 `dist/` 拷过去托管，不在 LoongArch 上碰 Node 工具链。**

## 1. 依赖盘点与适配难度分级

| 依赖 | 类型 | LoongArch 风险 | 适配策略 |
|---|---|---|---|
| `fastapi` / `starlette` | 纯 Python | 无 | 直接 `pip install` |
| `httpx` / `openai` / `python-dotenv` / `aiosqlite` | 纯 Python | 无 | 直接装；SQLite 引擎用系统 `libsqlite3` |
| `mcp`（官方 SDK） | 纯 Python | 低 | 直接装；如依赖 `pydantic` 见下 |
| `pyyaml` | 纯 Python + 可选 C 加速（libyaml） | 低 | 纯 Python 解析即可工作；想要 `CSafeLoader` 加速再装 `libyaml-devel` |
| **`psutil`** | **C 扩展** | **中**（loongarch64 多半无预编译 wheel） | 优先系统包 `python3-psutil`；否则源码编译（需 `gcc`+`python3-devel`） |
| **`pydantic`（pydantic-core）** | **Rust 扩展** | **中高**（pydantic v2 核心是 Rust，需 Rust 工具链编译） | 优先系统包；否则装 `rust`/`cargo` 后源码编译；极端预案见 §5 |
| `uvicorn[standard]` | 含 `uvloop`(C)/`httptools`(C)/`watchfiles`(Rust) 等 extras | 中（extras 可能编不过） | **去掉 `[standard]`**，用纯 Python 的 `asyncio` 事件循环：`pip install uvicorn`，启动加 `--loop asyncio --http h11` |
| 前端 `vue`/`vite`/`element-plus` | Node 构建产物 | 不在 LoongArch 跑构建 | 在 x86 开发机 `npm run build`，把 `frontend/dist/` 拷到麒麟，由后端或 nginx 托管静态文件 |
| LLM 运行时 `ollama` | Go 二进制 | 中（看是否有 loongarch 构建） | 见 §4：优先 ollama 官方/麒麟源；否则 `llama.cpp` 源码编译跑 GGUF；再不行用 deepseek 云端 / mock 离线兜底 |

> 备注：本项目命令执行只封装系统自带的 `lsof`/`netstat`/`journalctl`/`df`/`ss` 等，这些是 OS 原生工具，LoongArch 上无适配问题，只需确认已安装（`which lsof ss journalctl`）。

## 2. 三套安装策略（按优先级）

### 策略 A：优先用麒麟官方源的系统包（最省事，最稳）
麒麟 V11 基于 RPM，包管理用 `dnf`/`yum`。C/Rust 扩展优先走系统已编译好的包：
```bash
sudo dnf install -y python3 python3-pip python3-devel gcc make \
                    python3-psutil python3-pydantic python3-yaml \
                    sqlite lsof iproute procps-ng
```
> 注：系统包版本可能低于 requirements.txt 的下限。装完用 `python3 -c "import psutil, pydantic; print(psutil.__version__, pydantic.VERSION)"` 核对，
> 若版本过低再考虑策略 B 升级，或放宽本项目对应的版本下限（功能上 psutil>=5.9、pydantic>=2.6 是为了 API 稳定，可按实测调整）。

建议让系统包提供的扩展直接对 venv 可见：创建虚拟环境时加 `--system-site-packages`，纯 Python 依赖仍装进 venv：
```bash
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install fastapi "uvicorn" httpx openai python-dotenv aiosqlite mcp pyyaml
# 注意：上面未装 psutil/pydantic（用系统包）、未用 uvicorn[standard]
```

### 策略 B：源码编译缺失的扩展（系统源没有或版本太低时）
LoongArch 上 `pip install psutil`/`pydantic` 若无 wheel 会自动拉源码编译，前置工具链：
```bash
sudo dnf install -y gcc gcc-c++ make python3-devel
# pydantic-core 是 Rust，需要 Rust 工具链：
sudo dnf install -y rust cargo        # 或用 rustup 装最新版
pip install psutil pydantic           # 触发源码编译，耐心等
```
> 留足时间：Rust 首次编译 pydantic-core 在虚机上可能数分钟到十几分钟。编译失败常见原因是缺 `python3-devel` 头文件或 Rust 版本过旧——按报错补齐。

### 策略 C：降级 / 替代（编译实在过不去的非核心项）
- **uvicorn**：不要装 `[standard]`（其 `uvloop`/`watchfiles` 是编译大头且非必需）。用纯 Python：
  ```bash
  pip install uvicorn        # 不带 [standard]
  uvicorn app.main:app --host 0.0.0.0 --port 8000 --loop asyncio --http h11
  ```
- **pyyaml 的 C 加速**：装不上 `libyaml` 没关系，PyYAML 自带纯 Python `SafeLoader`，本项目 `yaml.safe_load` 照常工作（只是稍慢，规则文件就 25 条，无感）。
- **pydantic 极端预案**：见 §5。

## 3. 部署步骤（虚机到手后照做）

```bash
# 1) 取代码（git 或拷贝 tar 包）
cd /opt && git clone <repo> kylin-ops-agent && cd kylin-ops-agent/backend

# 2) 按 §2 策略 A/B 准备依赖
python3 -m venv --system-site-packages .venv && source .venv/bin/activate
pip install fastapi uvicorn httpx openai python-dotenv aiosqlite mcp pyyaml
python -c "import psutil, pydantic, yaml; print('deps ok', psutil.__version__, pydantic.VERSION)"

# 3) 前端（在 x86 开发机构建后拷过来，不在 LoongArch 构建）
#   x86:  cd frontend && npm ci && npm run build      → 产出 frontend/dist/
#   拷贝: scp -r frontend/dist  kylin:/opt/kylin-ops-agent/frontend/dist
#   托管: 用 nginx 指向 dist/，或让 FastAPI 用 StaticFiles 挂载（生产再加）

# 4) 配置 LLM provider（断网答辩可先用 mock 验证主流程）
echo "LLM_PROVIDER=mock" > .env          # 或 ollama / deepseek
# deepseek 需联网 + 在 .env 填 DEEPSEEK_API_KEY（切勿提交进 git）

# 5) 起服务
uvicorn app.main:app --host 0.0.0.0 --port 8000 --loop asyncio --http h11

# 6) 冒烟
curl --noproxy '*' http://127.0.0.1:8000/health
curl --noproxy '*' http://127.0.0.1:8000/tools
python scripts/demo.py --provider mock --auto                 # 一键剧本离线自检（已在 backend/ 下）
pytest -q                                                     # 全套回归（最能证明适配成功）
```

> `pytest -q` 全绿是「LoongArch 适配成功」最硬的证据：它会真实拉起 MCP 子进程、跑护栏/根因/审计全链路。把这条实测结果回填到课程报告「第5章 部署」。

## 4. 国产化 LLM 运行时（ollama / 替代）

答辩现场要「断网可演 + 国产化加分」，本地 LLM 是亮点，但 LoongArch 上 ollama 可用性需到手实测：
1. **首选**：查麒麟官方源 / ollama 官方是否有 loongarch64 构建（`dnf search ollama` / 官网 release 页）。有则直接装，`ollama pull qwen3:8b && ollama serve`，`.env` 设 `LLM_PROVIDER=ollama`。
2. **次选**：源码编译 `llama.cpp`（C++，对 LoongArch 友好度高于 Go 生态），下载 Qwen3-8B 的 GGUF 量化权重，用其 OpenAI 兼容 server 暴露端点；把 `OLLAMA_BASE_URL` 指过去即可（本项目走 OpenAI 兼容接口，端点可换）。
3. **兜底**：`LLM_PROVIDER=deepseek`（需联网）或 `LLM_PROVIDER=mock`（完全离线，跑关键词选工具 + 全部护栏/根因/审计真实逻辑）。**即便本地大模型一时跑不起来，mock 模式保证项目在 LoongArch 上「永远可演示」**——这正是当初设计三档 provider 的目的。

## 5. 风险与回退一览

| 风险点 | 触发现象 | 回退方案 |
|---|---|---|
| psutil 无 wheel | `pip install psutil` 编译报错 | 系统包 `python3-psutil`（策略 A）；再不行按报错补 `python3-devel` 后源码编译 |
| pydantic-core 编不过 | 缺 Rust / Rust 过旧 | 装 `rust cargo`；系统包 `python3-pydantic`；极端情况评估降级 pydantic v1（需改少量 `BaseModel` 用法，最后手段） |
| uvicorn[standard] 编不过 | uvloop/watchfiles 报错 | 去掉 `[standard]`，`--loop asyncio --http h11`（策略 C），功能不受影响 |
| ollama 无 loongarch 构建 | 装不上 / 跑不起 | llama.cpp 源码编译，或 deepseek 云端，或 mock 离线兜底（§4） |
| 在 LoongArch 上构建前端失败 | node/vite 工具链问题 | 不在设备上构建，x86 出 `dist/` 拷过去托管（§1/§3） |
| 系统 Python 版本偏低 | `python3 --version` < 3.11 | 优先用麒麟提供的较高版本；或放宽个别语法（项目用到 3.10+ 的 `X | Y` 类型标注，需 3.10+）；必要时源码装 Python 3.11 |
| 离线/内网无法 pip | 无外网 | x86 上 `pip download` 仅得 x86 wheel **不通用**；改为：①尽量用系统包；②在另一台同架构 LoongArch 机器上 build 出 wheelhouse 带过去 |

## 6. 验证清单（虚机到手逐项打勾回填）

- [ ] `uname -m` 输出 `loongarch64`，`cat /etc/kylin-release` 确认 V11
- [ ] `which lsof ss journalctl df free ps` 全部存在
- [ ] `python -c "import psutil, pydantic, yaml, mcp, fastapi"` 无报错
- [ ] `uvicorn ... --loop asyncio --http h11` 起服务，`/health` 返回 ok
- [ ] `/tools` 列出 15 个 MCP 工具
- [ ] `python scripts/demo.py --provider mock --auto` 七幕全过、exit 0
- [ ] `pytest -q` 全套通过（回填通过数与耗时）
- [ ] 本地 LLM（ollama / llama.cpp）可用性结论：______
- [ ] 前端 `dist/` 托管后页面可访问、对话/规则库/回放三抽屉正常

> 以上每项的实测结果即课程报告「第5章 系统部署」与软件杯「部署文档」的一手素材。
