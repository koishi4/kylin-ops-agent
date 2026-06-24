# 安装与部署文档（LoongArch + 麒麟高级服务器操作系统 V11）

本文档说明本系统在采用 LoongArch 架构的麒麟高级服务器操作系统 V11 上的安装与部署方法。麒麟是标准的 Linux 发行版，系统所依赖的 `psutil`、`lsof`、`journalctl`、`ss`、`df` 等工具均可正常使用，因此部署的主要工作集中在「为 LoongArch 架构准备好缺少预编译包的 Python 扩展」这一件事上。本文档将这件事拆解清楚，并给出对应的退路。

## 0 总体策略

部署遵循一条简明的总体策略：能使用麒麟官方源中系统包的，优先使用系统包；系统包装不上的扩展，走源码编译；编译也难以通过的非核心扩展，则降级或替代。前端在 x86 开发机上完成构建，只把构建产物拷贝到目标机托管，不在 LoongArch 上引入 Node 工具链。

## 1 依赖盘点与适配难度

系统的主要依赖及其在 LoongArch 上的适配难度与策略如表 1 所示。纯 Python 依赖可直接安装，无适配风险；`psutil` 为 C 扩展、`pydantic` 的核心为 Rust 扩展，在 LoongArch 上多半没有预编译包，需优先使用系统包或源码编译；`uvicorn` 的增强版含若干编译型扩展，可去除增强版改用纯 Python 事件循环；前端构建产物在 x86 机器上生成后拷贝过来托管；大模型采用云端接口或本地桩，无需在设备上运行模型。

| 依赖 | 类型 | LoongArch 风险 | 适配策略 |
|---|---|---|---|
| fastapi、starlette | 纯 Python | 无 | 直接安装 |
| httpx、openai、python-dotenv、aiosqlite | 纯 Python | 无 | 直接安装；SQLite 引擎用系统库 |
| mcp（官方 SDK） | 纯 Python | 低 | 直接安装 |
| pyyaml | 纯 Python 含可选 C 加速 | 低 | 纯 Python 解析即可工作 |
| psutil | C 扩展 | 中 | 优先系统包，否则源码编译 |
| pydantic | Rust 扩展 | 中高 | 优先系统包，否则装 Rust 工具链后源码编译 |
| uvicorn 增强版 | 含编译型扩展 | 中 | 去除增强版，启动时指定纯 Python 事件循环 |
| 前端 vue、vite、element-plus | Node 构建产物 | 不在设备构建 | x86 上构建，拷贝产物到目标机托管 |
| 大模型运行时 | 无需在设备运行 | 低 | 采用云端接口或本地桩，详见第 4 节 |

<p align="center">表 1　依赖盘点与适配策略</p>

系统所封装的命令均为操作系统自带的原生工具，在 LoongArch 上没有适配问题，仅需确认其已安装即可。

## 2 三套安装策略

**策略 A：优先使用系统包。** 麒麟 V11 基于 RPM，包管理使用 dnf。对 C 与 Rust 扩展优先采用系统已编译好的包：

```bash
sudo dnf install -y python3 python3-pip python3-devel gcc make \
                    python3-psutil python3-pydantic python3-yaml \
                    sqlite lsof iproute procps-ng
```

系统包版本可能略低于项目下限，安装后应核对版本，必要时再升级或按实测放宽版本下限。建议创建虚拟环境时启用对系统站点包的可见性，使系统包提供的扩展对虚拟环境可见，纯 Python 依赖仍安装进虚拟环境：

```bash
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install fastapi uvicorn httpx openai python-dotenv aiosqlite mcp pyyaml
```

**策略 B：源码编译缺失的扩展。** 当系统源中没有相应包或版本过低时，可在准备好工具链后由 pip 触发源码编译：

```bash
sudo dnf install -y gcc gcc-c++ make python3-devel
sudo dnf install -y rust cargo
pip install psutil pydantic
```

其中 Rust 首次编译 pydantic 核心在虚拟机上可能耗时数分钟到十几分钟。编译失败的常见原因是缺少开发头文件或 Rust 版本过旧，应按报错补齐。

**策略 C：降级或替代。** 对于编译确实难以通过的非核心项，可采取替代方案。uvicorn 不安装增强版，启动时指定纯 Python 事件循环即可，功能不受影响：

```bash
pip install uvicorn
uvicorn app.main:app --host 0.0.0.0 --port 8000 --loop asyncio --http h11
```

PyYAML 即使装不上 C 加速也无妨，其自带的纯 Python 解析器可正常工作，只是稍慢，而项目的规则文件规模很小，影响可忽略。

## 3 一键部署脚本

上述全部步骤已固化进部署脚本 `scripts/deploy_kylin.sh`，该脚本具有幂等性，可反复执行，推荐优先使用。脚本完成从拉取代码、配置环境、启动服务到冒烟测试的全过程：

```bash
bash scripts/deploy_kylin.sh --systemd --nginx --provider deepseek --api-key sk-xxx
#   --systemd        建立受限账户 opsagent，并以其身份开机自启
#   --nginx          将前端构建产物托管到 80 端口，并将 /api 反向代理到后端 8000
#   --provider mock  默认值；在断网或无密钥时也能演示
#   --skip-rust      已自备较新 cargo 时跳过 Rust 工具链安装
bash scripts/deploy_kylin.sh --help    # 查看全部参数
```

脚本相对手工步骤额外做了三项自动适配。其一是 Rust 工具链自适应：LoongArch 上 pydantic 等 Rust 扩展需源码编译，而麒麟自带的 cargo 版本可能偏低导致编译失败，脚本探测到后会自动升级。其二是去除 uvicorn 增强版：脚本在生成依赖清单时自动改写，免去编译型扩展。其三是前端产物随仓库下发：仓库已携带前端构建产物，脚本直接托管，不在 LoongArch 上引入 Node 工具链；如需重建前端，在 x86 机器上构建后将产物提交入库即可。

在启用 nginx 托管时，nginx 将以 /api 为前缀的请求反向代理到后端，并在转发时剥去该前缀，这与前端的接口基址以及开发期代理的行为一致，因此构建产物无需修改任何地址。若不启用 nginx，则后端可单独运行，前端另行托管。

需要说明的是，系统的执行沙箱在不同环境下会选择不同的隔离后端。在支持命名空间隔离的环境下采用相应后端，而在 LoongArch 麒麟环境下，命名空间隔离通常不可用，沙箱会自动降级为基于资源限额的后端；此时资源限额与在 root 下的降权落地仍然有效，安全性不受影响。系统在启动时会以与真实执行一致的条件做一次功能性自检，并据此选择可用的后端。

## 4 国产化大模型运行时

系统的国产化诉求由 DeepSeek 本身满足，无需在 LoongArch 设备上运行本地大模型。设备上的大模型运行时有三种配置方式。在联网演示时，将大模型提供者设为 deepseek 并在环境变量中填入接口密钥即可。在断网演示时，将大模型提供者设为本地桩，此时系统完全离线运行，关键词选工具与全部护栏、根因分析、审计逻辑均真实执行，由此保证系统在 LoongArch 上始终可演示。此外，由于大模型提供者抽象遵循通用的接口规范、不与具体厂商耦合，若需私有化自托管，只需将接口基址指向自托管的兼容网关即可数行接入，而不绑定某个特定的本地模型与运行时。

## 5 风险与回退

部署过程中可能遇到的风险点及其回退方案如表 2 所示。

| 风险点 | 触发现象 | 回退方案 |
|---|---|---|
| psutil 无预编译包 | 安装时编译报错 | 改用系统包，或补齐开发头文件后源码编译 |
| pydantic 核心编不过 | 缺 Rust 或 Rust 过旧 | 安装 Rust 工具链，或改用系统包 |
| uvicorn 增强版编不过 | 编译型扩展报错 | 去除增强版，指定纯 Python 事件循环，功能不受影响 |
| 设备无外网 | 无法调用云端接口 | 切换为本地桩完全离线运行，护栏、根因、审计逻辑照常 |
| 前端在设备上构建失败 | Node 工具链问题 | 不在设备构建，在 x86 上生成产物后拷贝托管 |
| 系统 Python 版本偏低 | 版本低于 3.11 | 优先使用麒麟提供的较高版本，必要时源码安装 |
| 内网无法访问软件源 | 无外网 | 尽量使用系统包，或在同架构机器上预先准备依赖后带入 |

<p align="center">表 2　风险与回退一览</p>

## 6 最小权限部署

系统要求核心运维动作在受限账户下运行、非必要不使用 root，对此系统提供了完整的落地方式，部署时应按下述步骤落实，否则变更动作可能以 root 身份落地。

首先，创建一个无登录权限的受限服务账户，并将程序目录的属主设为该账户：

```bash
sudo useradd -r -s /usr/sbin/nologin opsagent
sudo chown -R opsagent:opsagent /opt/kylin-ops-agent
```

随后，推荐使用 systemd 以该账户身份运行后端服务，从而在进程层面落实非 root 运行：

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
# 生产或联网环境可按需开启以下三项
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

系统的落地身份是可演示、可审计的。每个变更动作的思维链在安全校验段都会记录其落地身份。当后端以受限账户运行时，落地命令天然受限于该账户；当后端以 root 运行且配置了执行账户时，变更动作会经沙箱降权到该账户后落地；当后端以 root 运行而受限账户不存在时，系统会如实标注其将以 root 落地，并在启动日志中告警。若需在生产环境强制约束，可开启相应开关，使动作层拒绝任何会以 root 落地的变更动作。部署完成后，可在启动日志中确认落地身份，并通过执行一次清理动作、回放其思维链来验证安全校验段中记录的非 root 落地身份。

## 7 验证清单

完成部署后，可按下述清单逐项验证部署是否成功。

- 确认架构为 loongarch64，且系统版本为麒麟 V11。
- 确认 lsof、ss、journalctl、df、free、ps 等原生工具均已安装。
- 确认 psutil、pydantic、yaml、mcp、fastapi 等依赖均可正常导入。
- 以纯 Python 事件循环启动服务，健康检查接口返回正常。
- 工具列举接口返回 22 个 MCP 工具。
- 离线自检脚本完整通过。
- 自动化测试全套通过。自动化测试全部通过是 LoongArch 适配成功最有力的证据，因为它会真实拉起 MCP 子进程并跑通护栏、根因与审计全链路。
- 确认执行沙箱所选用的隔离后端（LoongArch 麒麟上预期为基于资源限额的后端）。
- 以受限账户非 root 启动服务，确认启动日志中的落地身份提示，并通过回放一次清理动作的思维链确认其安全校验段记录为非 root 落地。
- 确认大模型云端接口在联网时连通正常。
- 确认前端在托管后可正常访问，且对话、规则库、回放等功能正常。
