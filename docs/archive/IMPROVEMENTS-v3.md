# IMPROVEMENTS-v3.md — 整合 GPT Pro 代码审查 + 内核漏洞防御创新

> 🗄️ **已归档（历史规划文档）**：本文 P-任务均已执行落地。代码/测试按「P 编号」援引本文作设计依据故保留，请勿据此再施工。

> 给 Claude Code 的话：先读 CLAUDE.md、docs/dev-log.md、docs/theory-alignment.md 了解现状，再按本文件推进。
> 优先级：**P0 必修（提交可信度命门）→ P1 创新核心（内核漏洞遏制）+ P1 得分动作 → 实机证明 → P2**。
> 纪律：所有可变命令唯一经 core/executor.py；保守合并取更严；只演示「被拦」不演示「破坏」；mock/无依赖也要能跑；评测/演示脚本不纳入 pytest。每完成一项：`pytest -q` 全绿 → 更新 docs/dev-log.md（写设计取舍）→ 勾本文件。

## 〇、本方案的来历与取舍（必读）

本方案整合两个来源：(A) GPT Pro 的一轮代码审查——一份准确的「加固 + 参赛包装」审查；(B) 针对 Dirty Frag（CVE-2026-43284 / 43500，2026-05 公开的内核 LPE，靠 esp/rxrpc + splice 页缓存写、无害命令即可提权）这类「知识库不实时 + 漏洞利用看似无害」问题的防御创新——这是 GPT 审查的盲区。

GPT 审查指出的 P0 安全 bug **经核实在当前版本仍然存在**（详见各项标注）。对一个主打安全的作品，这些是可信度命门，必修。

**反 bloat 原则**：本方案末尾有「别做」清单。不要掉进「企业级平台」陷阱（RBAC/SSO/多租户/K8s/Vault/外部见证/重型 IDS）——竞赛虚机跑不动、评委不加分、还稀释核心叙事。

---

## P0 — 必修加固（来自 GPT 审查，已核实仍存在）

### P0-1　路径前缀判断 bug → 统一用 commonpath（最重要的一条）
**已核实仍在**：`core/diagnosis.py:69` `_is_critical`、`:73` `_is_cleanable` 用 `s.startswith(_CRITICAL/_CLEANABLE_DIR_PREFIXES)`；`mcp_server/tools/log.py:38` `tail_log` 用 `real.startswith(_ALLOWED_LOG_ROOTS)`。后果：`/var/log2` 误判为 `/var/log` 子路径、`/tmpx` 误判为 `/tmp`，安全判定可被绕过。
**做什么**：
- 在公共模块（如 `core/pathutil.py`）新增：
  ```python
  import os
  def path_under_any_root(path: str, roots: tuple[str, ...]) -> bool:
      real = os.path.realpath(path)
      for root in roots:
          root_real = os.path.realpath(root)
          try:
              if os.path.commonpath([real, root_real]) == root_real:
                  return True
          except ValueError:
              continue
      return False
  ```
- 用它替换 `diagnosis._is_critical`/`_is_cleanable`、`tail_log` 白名单，以及全仓所有 `startswith("/tmp")`、`startswith("/var/log")` 这类路径前缀判断。
**测试**：在 test_path_hardening.py 增反例：`/var/log2/x`、`/tmpx/y`、`/var/lib/mysqlx` 不得命中；真实子路径仍命中；符号链接逃逸仍被拦。
- [x] P0-1 完成（新增 `core/pathutil.py`：`is_path_within`/`path_under_any_root`；替换 diagnosis+tail_log；反例测试齐）

### P0-2　测试在 root / 容器环境下的稳定性
**来自 GPT，复验环境差异**：`test_kill_child_process_executes` 在 root 下因「root 进程需 authorized」而期望冲突；`test_memory_hog_is_limited` 在容器里被归因为 cpu 而非 memory，导致「全绿」声明被现场打脸。
**做什么**：
- kill 测试按运行身份取 `authorized = os.geteuid() == 0`，断言 executed 成立。
- 沙箱限额测试不要只断言单一归因字符串：断言「进程被限制/异常退出/未逃逸」，再宽松校验归因属于 {memory, cpu, killed} 之一。
- docs 里把测试结论改成可成立的表述：「Python 3.11 + 非 root opsagent 下后端测试全绿；root/容器环境存在两处已知环境差异，已用兼容性断言覆盖。」并把所有文档里的测试数量与当前仓库重新对齐。
- [x] P0-2 完成（kill 测试 authorized 按 euid 取；内存归因放宽 {memory,cpu,killed}；dev-log 结论已改为可成立表述）

### P0-3　只读工具资源硬上限 + 参数校验
**已核实**：`disk.py` 的 `top_n` 已封顶（第 45 行），但 `max_scan`（find_large_files=200000 / dir_size=500000）无显式硬上限；`service_status`/`query_journal` 参数未做格式校验。
**做什么**：
- 给 `max_scan` 加硬上限并回报截断：`max_scan = max(1, min(int(max_scan), 200000))`；返回结构含 `{"truncated": bool, "scanned": n, "reason": "max_scan limit reached"}`。
- 对 `/proc`、`/sys`、`/dev`、`/run`、网络挂载点默认拒绝或限制扫描。
- systemd unit 名校验：`^[A-Za-z0-9_.@:-]+(\.service)?$`，不合法直接结构化报错。
- journalctl：`priority` 限 0–7、`lines` ≤ 200、`since` 仅允许 `-1h`/`-30m`/`today` 等白名单格式、`unit` 复用上面的校验。
**测试**：超大 max_scan 被夹断且 truncated=true；非法 unit/priority 被拒；正常参数不受影响。
- [x] P0-3 完成（新增 `tools/_validate.py`；max_scan 夹断+reason；/proc /sys /dev /run 拒扫；unit/priority/since 白名单；test_tool_limits.py）

### P0-4　/action/execute 最小鉴权（最小版，别做 RBAC）
**已核实无鉴权**：routes.py 无 token/Depends。
**做什么**：
- `.env.example` 增 `OPERATOR_TOKEN=please-change-me`、`API_BIND_HOST=127.0.0.1`。
- 后端用一个依赖校验 `Authorization: Bearer <token>`；默认只监听 127.0.0.1；前端请求带该 header。
- README 说明：演示环境为本机可信控制台；生产须改 token。
- **就到此为止**——不要做账号系统 / session / OIDC / RBAC。
**测试**：无/错 token 的 /action/execute 返回 401/403；正确 token 放行。
- [x] P0-4 完成（require_operator 依赖+secrets.compare_digest；.env.example 增 OPERATOR_TOKEN/API_BIND_HOST；前端 VITE_OPERATOR_TOKEN 拦截器；test_auth.py）

### P0-5　一键可复现 + 杂项代码修正
**来自 GPT**：
- 新增 `scripts/ci_check.sh`：安装依赖 → `LLM_PROVIDER=mock` 跑 pytest → 前端 `npm ci && npm run build`。
- 固定 Python 3.11；生成 `requirements.lock`（或 uv.lock）；README 写明本地测试默认 mock。
- 修 routes.py 可变默认（**已核实** `:34 params: dict = {}`）→ `params: dict = Field(default_factory=dict)`。
- `/diagnose` 用 `await asyncio.to_thread(...)` 包同步扫描，避免阻塞事件循环。
- [x] P0-5 完成（scripts/ci_check.sh；backend/requirements.lock(Py3.11)；params→Field(default_factory=dict)；/diagnose 走 to_thread）

### P0-6　提交包健壮性
**来自 GPT**：ZIP 解压在异构环境出现中文文件名 mojibake（如 `#U603b#U65b9#U6848.md`），README 引用对不上。
**做什么**：docs 关键文件改英文名（solution.md / improvement-v2.md / demo-script.md / perf-report.md …）并同步 README 引用；提交前用干净方式打包（避免之前 unzip 兼容问题），README 注明「如需解压用 `python -m zipfile -e`」。
- [~] P0-6 部分完成：README 已加「打包/解压用 `python -m zipfile`」说明；新建文档一律英文名（security-design.md 等）。
  **暂缓**：批量重命名既有中文文档（churn 大、易断引用，且属课程报告中文交付物）——留待提交打包前统一处理。

---

## P1 — 创新核心：内核漏洞遏制三件套（答 Dirty Frag，GPT 未覆盖）

> 主线：对「看似无害的新内核漏洞利用」，检测无效（无内容特征 + 模型不知道新 CVE），正确答案是**遏制 + 时效化情报**。这深化你已有的「约束能力，而非检测内容」哲学——一套哲学，两类威胁。

### P1-1　漏洞情报感知 MCP 工具（把「时效」从训练问题变检索问题）
**做什么**：
- 新增 `mcp_server/tools/vuln_intel.py`：
  - 本地 advisory feed（`data/advisories.json`），种子录入当前真实内核 LPE：Dirty Frag（CVE-2026-43284 / 43500，受影响模块 esp4/esp6/rxrpc，缓解=模块 blacklist + 打补丁）、Copy Fail（CVE-2026-31431）。字段：cve、别名、受影响组件/模块、内核版本范围、严重度、缓解步骤、来源 URL。
  - 可选 live fetcher：从 OSV.dev REST（无需 key）或 NVD API 2.0 拉取，带超时 + 失败回退到本地 feed（**离线也要能演**）。
  - 工具标 READONLY。
- [x] P1-1 完成（MCP 工具 query_vuln_intel + app/data/advisories.json 种子；OSV.dev live 带超时回退本地；test_vuln_intel.py）

### P1-2　内核/主机姿态检查 + 缓解建议（可演示的高光）
**做什么**：
- 新增 `core/posture.py` + 一个工具/接口：读取内核版本、`lsmod` 已加载模块、关键包版本，与 vuln_intel feed 比对，命中则产出告警：「本机内核命中 CVE-2026-43284（Dirty Frag），且 esp/rxrpc 模块已加载」。
- 缓解必须走护栏 + 二次确认流程提出（如生成 `modprobe -r esp4 esp6 rxrpc` 或写 blacklist 配置），不自动执行。
- **诚实标注范围**：覆盖已披露 N-day（feed 里有的），不覆盖未披露 0-day——后者由 P1-3 沙箱遏制兜底。这句话写进结果与文档。
**测试**：构造「模块已加载 + 命中 CVE」场景断言告警与缓解建议；未命中不误报。
- [x] P1-2 完成（core/posture.py 采集/推理分离 + MCP 工具 kernel_posture + /posture；缓解仅候选文本走护栏确认；诚实标注 N-day/0-day 边界；test_posture.py）

### P1-3　沙箱即攻击面削减（强化现有沙箱，直接掐断 Dirty Frag 前提）
**做什么**：
- 强化 `core/sandbox.py` 的隔离 profile：drop `CAP_NET_ADMIN`/`CAP_NET_RAW`/`CAP_SYS_MODULE`/`CAP_SYS_PTRACE` 等；限制 socket 族（执行 runner 无需 raw/xfrm 套接字）；禁模块加载；禁 ptrace；评估限制 `splice`/`sendfile`（确认不误伤正常运维命令再启用）。
- **文档把它和 Dirty Frag 前提对应**：Dirty Frag 需要「访问 esp/rxrpc 接口 + splice 操纵页缓存」；一个 drop 掉相关能力/套接字族、禁模块加载的非 root 受限 runner，能在**不认识该漏洞**的前提下移除其前提条件——「遏制对未知漏洞有效，因为它不需要认识漏洞」。
**测试**：正常运维命令（df/ps/journalctl/cat 日志）在强化 profile 下仍正常；尝试加载模块/打开 raw 套接字被拒；机制不可用时优雅降级不崩。
- [x] P1-3 完成（bwrap --cap-drop ALL/--unshare-ipc/uts；rlimit 兜底 prctl no_new_privs + capbset drop NET_ADMIN/NET_RAW/SYS_MODULE/SYS_PTRACE；hardening 画像；实测非 root SOCK_RAW 被拒、no_new_privs=1；test_sandbox.py 攻击面削减组）

### P1-4　威胁模型 + OWASP 映射文档（免费且必写）
**做什么**：新增 `docs/security-design.md` 与 `docs/security-mapping.md`：
- 显式**威胁模型**：本护栏覆盖「运维操作安全」（AI 误操作 / 人为手滑 / 注入诱导的明显破坏）；「内核 0-day 经无害命令利用」属「系统沦陷」威胁模型，内容检测无法覆盖，靠最小权限 + 沙箱遏制 + 活情报 + 运行时检测应对。
- **主线论点**「约束能力，而非检测内容」，用 Dirty Frag 作工作示例串起 P1-1/2/3。
- 能力映射到 OWASP MCP Security Cheat Sheet 与 OWASP Top 10 for Agentic Applications 2026（tool poisoning / rug-pull / confused deputy / excessive agency / least privilege / auditability / sandbox / human-in-the-loop）。
- 末尾「已知边界与未来工作」：不执行任意 shell、变更走受控 action、默认只读、高危需确认、本地模型有确定性 fallback、运行时行为检测（eBPF/auditd/Falco）列为未来工作。
- [x] P1-4 完成（docs/security-design.md 威胁模型A/B + Dirty Frag 工作示例串三件套；docs/security-mapping.md OWASP Top10/Agentic/MCP Cheat Sheet 逐条映射到代码）

---

## P1 — 得分动作（来自 GPT，纳入）

### P1-5　前端「评委模式」首页
四张卡对应评分点（OS 感知+MCP / 自然语言运维 / 安全护栏 / 根因分析+处置闭环），每张一键 demo，展示输入→工具调用→安全判定→审计 trace→结果。把评分点喂到评委眼前。
- [x] P1-5 完成（frontend/src/JudgeMode.vue + 头部「🏆 评委模式」抽屉；四卡一键演示整条链路；③卡内嵌内核姿态体检；mock 后端端到端实测通过）

### P1-6　三通道可靠性叙事（写进文档，不新增大功能）
把现有「LLM 工具调用 / 确定性 NL 路由 / mock 演示」三层兜底明确写成：「LLM + 确定性安全路由双通道，关键安全判断不完全依赖模型输出」——正面呼应赛题「AI 推理不可控」。确认确定性 NL 路由在模型不稳时确实可走通即可。
- [x] P1-6 完成（security-design.md §4 双通道叙事；MockProvider 接入三件套关键词路由；test_mcp_loop/test_nl_robustness 确认 mock 确定性路由可走通）

---

## 实机证明（并行轨，虚机就绪后做；GPT 与既有结论都强调）
新增 `docs/kylin-deployment.md`：Kylin V11 版本、CPU 架构（是否 LoongArch）、Python/Node 版本、systemd unit、opsagent 低权限用户、MCP server 启动日志，以及截图：`/health`、`/tools`、一次完整 `/chat` trace、一次危险命令拦截、一次 HMAC trace verify、姿态检查命中 Dirty Frag 的告警。这是「麒麟作品」而非「通用 Linux demo」的关键证据。

## P2 — 有余力再做（全部完成）
- [x] MCP 工具 schema hash + 变更告警（对应 rug-pull / tool poisoning，增强现有 tool_scan）
  → `tool_fingerprint`/`scan_with_drift` + TOFU 基线 + `TP-RUGPULL`(high 自动隔离)/`TP-NEW`(medium)；
    `POST /guardrail/tool-scan/pin` 重锚（require_operator）；启动即锚定。test_tool_drift.py（18 例）。
- [x] 审计证据包导出（trace JSON + HMAC head + rules/schema 版本 + verify 结果）
  → `store.export_evidence`/`verify_evidence` + `GET /traces/{id}/evidence`：trace+verify+规则指纹+
    工具基线指纹+应用版本，HMAC 封口；与库内哈希链双层防篡改。test_evidence_pack.py（6 例）。
- [x] 完整磁盘处置闭环 demo：disk_usage → find_large_files → classify → dry-run → confirm → truncate → 再 disk_usage 验证 → trace 闭环
  → `scripts/demo_disk_closure.py`（/tmp 自建无害日志，结束即清理；落审计+verify+证据包封口）。非 pytest。
- [x] 前端代码分割 / 懒加载（主 chunk ~1MB，演示专业度）
  → `JudgeMode.vue` 改 `defineAsyncComponent` 动态 import，Vite 切出独立 async chunk（6.55kB），首屏主包瘦身。
- [x] 接入前面《第三方安全测试》方案的 DeepTeam / RedCode-Exec 独立评测
  → `scripts/redteam_eval.py`（护栏=被测目标，检出率/ASR/误拦率+JSON 报告，`--corpus` 接外部语料）+
    `docs/third-party-redteam.md`。**首跑诚实暴露防线3 漏过 7 条越狱→补强 INJ-006~010→42/42、ASR 0%**。

---

## 别做（反 bloat 清单，理由见上一轮对企业报告的评估）
- 完整 RBAC / SSO / OIDC 身份体系（P0-4 的本机 token 足够）
- 多租户 / 行级安全 / 命名空间隔离
- Kubernetes / Helm / ArgoCD / GitOps
- Vault / OpenBao 动态密钥、Rekor / immudb 外部见证审计
- 重型运行时 IDS（eBPF / Falco）——仅作未来工作写进文档
- 前端大规模架构重写
> 共同理由：竞赛虚机跑不动、评委不加分、稀释「安全护栏 + 内核遏制」核心叙事。

## 执行顺序
1. **P0 全部**（尤其 P0-1 路径 bug，安全作品命门）。
2. **P1 创新三件套 + P1-4 文档**（这是回答 Dirty Frag、最能拿创新分的部分）。
3. **P1-5/6 得分动作**。
4. 虚机就绪 → 实机证明。
5. P2 看时间。

每完成一项：`pytest -q` 全绿、更新 dev-log（设计取舍即报告素材）、勾选。
