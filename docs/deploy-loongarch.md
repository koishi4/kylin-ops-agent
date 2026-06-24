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
| LLM 运行时 | 无需在设备上跑模型 | 低 | 见 §4：用 DeepSeek 云端 API（国产开源）；无网/无 key 用 `LLM_PROVIDER=mock` 离线确定性桩兜底。**不在 LoongArch 上部署本地大模型**（已移除 8B 双模式，见 dev-log 2026-06-11） |

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

## 3.0 一键部署脚本（推荐，已在真机跑通）

本预案的全部步骤已固化进 **`scripts/deploy_kylin.sh`**（幂等，可反复跑）。**优先用它**，下面 §3 的
手工步骤作为原理参考/排障兜底保留。

```bash
# 从 GitHub 拉代码 → 配环境 → 起服务 → 冒烟，一条命令搞定。推荐生产姿态：
bash scripts/deploy_kylin.sh --systemd --nginx --provider deepseek --api-key sk-xxx
#   --systemd          建受限账户 opsagent + 以其身份开机自启（坐实需求④，等价 §3.5 ①②）
#   --nginx            把 frontend/dist 托管到 80 端口、/api 反代到后端 8000 → 浏览器开 http://<VM-IP>/
#   --provider mock    默认；断网/无 key 也能演示（省略 --provider 即 mock）
#   --skip-rust        已自备 cargo>=1.85 时跳过 rustup；--pip-index/--rust-mirror 换镜像
bash scripts/deploy_kylin.sh --help    # 全部参数
```

脚本相对手工步骤多做了几件「真机踩坑后」的自愈，避免照文档逐条敲时漏项：
- **Rust 工具链自愈**：LoongArch 上 `pydantic-core`/`jiter` 等 Rust 扩展无预编译 wheel，需源码编译；
  麒麟自带 cargo 1.82 < 1.85（maturin 的 edition2024 解析失败）→ 脚本探测到即用 rustup 升级（默认走镜像）。
- **uvicorn 去 `[standard]`**：由 `requirements.txt` 动态生成清单时 `sed` 改写，免编 uvloop/watchfiles。
- **前端 `dist/` 随 git 下发**：仓库已带 `frontend/dist`（`.gitignore` 已只跟踪它），脚本 step5 直接托管，
  不在 LoongArch 上碰 Node。**重建**：x86 上 `npm run build` 后 `git add frontend/dist && git commit`。

**前端访问（`--nginx`）**：nginx `location /api/ → http://127.0.0.1:8000/`（末尾斜杠剥掉 `/api` 前缀），
与前端 `baseURL='/api'`、开发期 vite 代理行为一致——故 build 产物无需改任何 URL。不加 `--nginx` 则后端
单跑、前端另行托管。

> **真机实测一处缺陷已修（务必拉最新代码）**：执行沙箱原先仅用 `shutil.which` 判断「装没装」bwrap，
> bwrap *装了却不可用*——本 VM 上 bwrap 单跑能建命名空间，但 `--unshare-pid` 需 `fork()`，撞上 executor
> 落地时 `preexec` 施加的 `RLIMIT_NPROC`（默认 64，运行账户进程数已超 64）→ fork `EAGAIN`、内层命令没跑
> （真实 stderr：`bwrap: Creating new namespace failed: Resource temporarily unavailable`），导致每条走
> 沙箱的命令空 stdout，受控动作（clean/kill）演示当场失效、14 个用例红。已改为**生产同款功能性自检**：用
> 与真实执行一致的包裹参数 **+ 同款 `preexec`（含 RLIMIT_NPROC）** 跑一条 `echo` 验证，不可用即自动降级到
> 纯 rlimit（限额仍在、root 下 setuid 降权仍在）。详见 dev-log「2026-06-24 沙箱缺陷二诊」。
> 教训：**自检要在「生产同款条件」下做——只验"裸后端能跑"会漏掉"叠加 preexec 后才暴露"的不可用。**

## 3. 部署步骤（手工原理参考 / 排障兜底；常规部署用 §3.0 的脚本）

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
echo "LLM_PROVIDER=mock" > .env          # 或 deepseek
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

## 3.5 最小权限部署（赛题基本需求④：核心运维动作在受限 Account 下运行）

赛题硬性要求「核心运维动作需在受限的 Account 下运行，非必要不使用 root」。本项目对此有**三层**落地，
部署时务必按下面坐实——否则变更动作会以 root 落地，丢这一分。

**① 创建受限运维账户（推荐做法，一步到位满足需求④）**
```bash
sudo useradd -r -s /usr/sbin/nologin opsagent      # 无登录权的服务账户，名字与 exec_user 默认值一致
sudo chown -R opsagent:opsagent /opt/kylin-ops-agent
```

**② 让后端以非 root 身份运行**——推荐用 systemd，`User=opsagent` 直接坐实「非必要不 root」：
```ini
# /etc/systemd/system/kylin-ops-agent.service
[Unit]
Description=Kylin Ops Agent
After=network.target
[Service]
User=opsagent
Group=opsagent
WorkingDirectory=/opt/kylin-ops-agent/backend
ExecStart=/opt/kylin-ops-agent/backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --loop asyncio --http h11
# 生产/联网再按需开下面两项（见 §安全启动守卫）
# Environment=OPERATOR_TOKEN=<强随机>
# Environment=AUDIT_HMAC_KEY=<独立密钥>
# Environment=REQUIRE_PRIVILEGE_DROP=true
NoNewPrivileges=yes
[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now kylin-ops-agent
```

**③ 落地身份是可演示、可审计的（评分证据，不是口头保证）**：每个变更动作（truncate/kill/clean）的
思维链「安全校验」段都带 `privilege_posture`，明确写出它**以什么身份落地**：
- 后端以 `opsagent` 跑 → `running_as_root=false`，落地命令天然受限于该账户（最小权限已满足）；
- 若以 root 跑且配了 `EXEC_USER=opsagent`（默认）→ kill/clean 经沙箱 **setuid 降权**到 opsagent 落地；
- 若以 root 跑且 `opsagent` 账户**不存在** → 如实标注「将以 root 落地」并在启动日志告警（曾经的静默缺口）。

**④ 生产强制（可选，fail-closed）**：设 `REQUIRE_PRIVILEGE_DROP=true`，动作层会**拒绝任何会以 root
落地的变更动作**（与 `REFUSE_ROOT` 互补：后者管「能否以 root 启动」，前者管「变更能否以 root 落地」）。
演示默认不开，保顺滑；隔离/生产建议开。

> 验证：起服务后看启动日志应有「最小权限落地身份：后端以非 root 运行……」；在前端跑一次「安全清理」，
> 回放 trace 的安全校验段能看到 `privilege_posture.running_as_root=false`——这就是需求④的一手演示证据。

## 4. 国产化 LLM 运行时

「国产化」由 **DeepSeek 本身满足**（深度求索，权重开源）——无需在 LoongArch 设备上跑本地大模型。
本项目**已移除本地 Qwen3-8B 双模式**（8B 在多轮编排+JSON 自愈+CaMeL 隔离阅读协议下指令遵循/JSON
合法性不足，为对齐它而妥协架构得不偿失；见 dev-log「2026-06-11 移除本地 8B 双模式」）。设备上只需：
1. **联网演示**：`LLM_PROVIDER=deepseek` + `.env` 填 `DEEPSEEK_API_KEY`（DeepSeek 云端，国产开源）。
2. **断网演示**：`LLM_PROVIDER=mock`（完全离线，跑关键词选工具 + 全部护栏/根因/审计真实逻辑）。
   **mock 模式保证项目在 LoongArch 上「永远可演示」**，断网亮点由它承载，不依赖任何本地模型运行时。
3. **私有化自托管（可选，非答辩必需）**：`LLMProvider` 走 OpenAI 兼容接口、不与厂商耦合——把
   `DEEPSEEK_BASE_URL` 指向自托管的 OpenAI 兼容网关（如更大参数的国产模型推理服务）即可数行接入，
   不再绑定某个特定的本地小模型与某种运行时（ollama/llama.cpp）。

## 5. 风险与回退一览

| 风险点 | 触发现象 | 回退方案 |
|---|---|---|
| psutil 无 wheel | `pip install psutil` 编译报错 | 系统包 `python3-psutil`（策略 A）；再不行按报错补 `python3-devel` 后源码编译 |
| pydantic-core 编不过 | 缺 Rust / Rust 过旧 | 装 `rust cargo`；系统包 `python3-pydantic`；极端情况评估降级 pydantic v1（需改少量 `BaseModel` 用法，最后手段） |
| uvicorn[standard] 编不过 | uvloop/watchfiles 报错 | 去掉 `[standard]`，`--loop asyncio --http h11`（策略 C），功能不受影响 |
| 设备无外网（无法用 deepseek 云端） | 答辩现场断网 | `LLM_PROVIDER=mock` 完全离线兜底，全部护栏/根因/审计真实逻辑照跑（§4）；无需任何本地模型运行时 |
| 在 LoongArch 上构建前端失败 | node/vite 工具链问题 | 不在设备上构建，x86 出 `dist/` 拷过去托管（§1/§3） |
| 系统 Python 版本偏低 | `python3 --version` < 3.11 | 优先用麒麟提供的较高版本；或放宽个别语法（项目用到 3.10+ 的 `X | Y` 类型标注，需 3.10+）；必要时源码装 Python 3.11 |
| 离线/内网无法 pip | 无外网 | x86 上 `pip download` 仅得 x86 wheel **不通用**；改为：①尽量用系统包；②在另一台同架构 LoongArch 机器上 build 出 wheelhouse 带过去 |

## 6. 验证清单（虚机到手逐项打勾回填）

- [ ] `uname -m` 输出 `loongarch64`，`cat /etc/kylin-release` 确认 V11
- [ ] `which lsof ss journalctl df free ps` 全部存在
- [ ] `python -c "import psutil, pydantic, yaml, mcp, fastapi"` 无报错
- [ ] `uvicorn ... --loop asyncio --http h11` 起服务，`/health` 返回 ok
- [x] `/tools` 列出 **22** 个 MCP 工具（真机首跑已确认，原文档「15」为旧值）
- [ ] `python scripts/demo.py --provider mock --auto` 七幕全过、exit 0
- [ ] `pytest -q` 全套通过（回填通过数与耗时）
      ⚠️ 真机首跑曾 14 红——bwrap 的 fork（--unshare-pid）撞 preexec 的 RLIMIT_NPROC→EAGAIN，已修为「生产同款自检→自动降级 rlimit」；
      **务必拉最新代码**后重跑，预期全绿。启动日志会有一行「执行沙箱隔离后端：rlimit……」表明降级生效。
- [ ] 执行沙箱后端选择：启动日志 `执行沙箱隔离后端：<bwrap|nsjail|rlimit>`——LoongArch 麒麟上预期为 `rlimit`
      （命名空间隔离不可用时的兜底，限额/降权仍在）。回填实际值：______
- [ ] **最小权限（需求④）**：以 `opsagent` 非 root 起服务，启动日志含「最小权限落地身份：……非 root……」；
      跑一次「安全清理」回放 trace，安全校验段 `privilege_posture.running_as_root=false`（落地身份可演示证据）
- [x] `LLM_PROVIDER=deepseek` 联网可用性：真机首跑 `/health` 返回 `llm_provider=deepseek`、连通成功
- [ ] 前端：`frontend/dist` 随 git 下发（无需手工拷），`--nginx` 托管后 `http://<VM-IP>/` 页面可访问、
      对话/规则库/回放三抽屉正常（前端 `baseURL=/api` 经 nginx 反代到后端 8000）

> 以上每项的实测结果即课程报告「第5章 系统部署」与软件杯「部署文档」的一手素材。
