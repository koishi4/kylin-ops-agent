# IMPROVEMENTS-v4.md — 护栏绕过修复 + GPT Pro 审查整合（交给 Claude Code）

> 先读 CLAUDE.md、docs/dev-log.md、docs/theory-alignment.md。优先级 **P0-A → P0-B → P0-C → P0-D → P1**。
> 纪律：所有可变命令唯一经 core/executor.py；保守合并取更严；只演示「被拦」不演示「破坏」；mock/无依赖也要能跑；评测/演示脚本不纳入 pytest。每完成一项：`pytest -q` 全绿 → 更新 docs/dev-log.md（设计取舍即报告素材）→ 勾本文件。
> 状态标注：✅已核实存在 / ◑已部分硬化仍有残留 / 来自 GPT Pro 第二轮 review。

## 〇、核心判断（必读）

GPT Pro 第二轮 review 抓到一个**之前方案漏掉、且最关键**的问题：**命令护栏存在真实可执行的绕过**。已用项目自己的 `check_command` 实测（最新版），8 条里 7 条以 LOW/ALLOW 通过：
```
bash -c "rm -rf /"  /  sh -c "cat /etc/shadow"  /  python3 -c "shutil.rmtree('/')"
find / -delete  /  find / -maxdepth 1 -delete  /  truncate -s 0 /etc/passwd  /  kill -9 1
```
（`chmod 777 /etc/passwd` 已被拦，是 GPT 这条例的出入。）
**且 executor 是 `shlex.split + shell=False`，`bash -c "rm -rf /"` → argv `['bash','-c','rm -rf /']` 执行时真的会跑——是真实绕过，不是语义错位。**

**修法原则（别掉进黑名单跑步机）**：不要靠"再加几十条危险正则"去堵——枚举式黑名单总能被新变形绕过（你 theory-alignment.md 已写明）。结构上正确的是三层：① 把「解释器 + 内联代码」这个**结构事实本身**当高危信号；② 把红线/关键路径兜底从「只管 rm」推广到**所有破坏性动词**；③ 把绕过样例固化成红队回归，永不退化。这与你「约束能力，而非检测内容」的哲学一致，并和沙箱遏制层闭环：**命令护栏总可能被新变形绕过，非 root 受限沙箱是兜底。**

---

## P0-A　命令护栏绕过修复（核心卖点，最高优先级）✅已核实

**文件**：`backend/app/guardrail/ast_analyzer.py`（`_handle_command` ~182、`_INTERPRETERS` ~35）、`backend/app/guardrail/rules.py`（`_REDLINE_RULES` 73–95、`hits_critical_path` 266–281）、`backend/app/core/executor.py`（74–85）。

**做什么**：

1. **解释器 + 内联代码 = 结构性高危（AST 层，主修）**
   在 `ast_analyzer._handle_command`：当命令首词是解释器（sh/bash/zsh/dash/ksh/csh/tcsh/ash、python[0-9.]*、perl、ruby、node/nodejs、php、lua、awk）**且**带内联代码标志（`-c`/`-lc`/`-e`/`--command`/`--eval`，awk 的程序串，或从 stdin 读脚本）→ 直接产出 CRITICAL/HIGH 的 AstFinding，裁决 **DENY（至少 CONFIRM）**。
   **关键**：不要去解析 `-c` 里的内层字符串再判断——内层可能是 python/perl，bash AST 解析不了，且内容无界。**结构事实「解释器带内联代码」本身就是信号**。文档写清这一点（回答评委「为什么不解析内层」）。

2. **破坏性动词扩展（红线 + 关键路径兜底）**
   - `_REDLINE_RULES` 增类：`find ... -delete` / `find ... -exec rm`、`truncate`/`shred`/`tee`/`dd`/`install` 写关键路径、单文件 `chmod`/`chown` 关键路径、`kill` 命中 PID 1 / 负 PID / 进程组（`-1`、`-<pgid>`）。
   - `hits_critical_path`：当前**只对 rm 做 realpath 兜底**——推广为：对一组破坏性动词（rm/unlink/shred/truncate/dd/mkfs/chmod/chown/mv/cp/tee/install/find-delete）凡操作数 realpath 落在关键路径下即 CRITICAL。这样变量化/变形路径也能兜住。

3. **红队回归（固化，永不退化）**
   新增 `backend/tests/test_guardrail_bypass.py`，把上面确认的绕过样例 + 变形全部纳入，断言一律 DENY 或至少 CONFIRM，绝不 LOW/ALLOW。同时跑一遍正常运维命令（df/ps/journalctl/cat 日志/systemctl status）断言**不误杀**（假阳性要低）。可把这批样例并进 `scripts/redteam_ab.py`，A/B 数字会更亮眼。

4. **（可后置）executor 收紧**
   GPT 建议 executor 改 argv 原生接口、不把"shell 命令字符串"当统一执行对象。这是较大重构，本轮可先不做；但在 dev-log 记为「已知架构改进项」。当前先靠 1–3 把绕过堵死。

- [x] P0-A 完成（实测那 7 条全部不再 LOW/ALLOW）—— 解释器内联代码=CRITICAL/DENY、破坏性动词 realpath 推广、
      KILL-001 红线、`tests/test_guardrail_bypass.py` 固化 7+27 变形；540→631 全绿，误杀率仍 0%。
      偏离：刻意不把 chmod/chown/mv/cp 升 CRITICAL（可恢复/操作数二义性，已由 PERM-* 覆盖），见 dev-log。

---

## P0-B　fd-safe 文件操作（消除 TOCTOU）◑部分硬化

**文件**：`backend/app/mcp_server/tools/log.py`（tail_log ~40–60，✅仍是"校验后开原始 path"）、`backend/app/core/actions.py`（truncate_log ~89–118，◑已拒软链+classify，但 classify→外部 truncate 仍有 check→exec 窗口）。

**做什么**：
1. `tail_log` 改 fd 级防护：`fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)` → `fstat` 确认是普通文件 → 经该 fd 读取（不要再 `open(原始path)`）；读后可再校验。保留已有的 `path_under_any_root` 白名单与敏感名单判定。
2. `truncate_log` 的真实落地不要再调外部 `truncate` 命令，改 Python 原子：`fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)` → `fstat` 确认普通文件、inode 未变/仍在允许范围 → `os.ftruncate(fd, 0)`。
   - 若为演示仍需经 executor 留审计：把「护栏裁决/审计」与「真实文件操作」拆开——护栏只做裁决与落审计，落地动作由 fd-safe Python 执行。
**测试**：构造软链在校验后被替换的场景断言被 O_NOFOLLOW 拒；正常日志读取/清空仍工作。
- [ ] P0-B 完成

---

## P0-C　MCP 工具投毒：命中后隔离，而非只告警 ✅已核实

**文件**：`backend/app/main.py`（~37–55，✅命中仅 `logger.warning`）、`backend/app/core/orchestrator.py`（~109–118 仍把工具 schema 传模型）、`backend/app/guardrail/tool_scan.py`。

**做什么**：扫描结果分三档处置——
- high → fail-closed：**不进入 `openai_tools()`**，不喂给 LLM；
- medium → 默认 quarantine，需 operator override 才启用；
- low → 告警但可用。
`suspicious=True` 的工具默认不进模型上下文（工具投毒的核心风险正是：恶意 description 不需被调用，只要进上下文就影响模型）。前端 `/guardrail/tool-scan` 面板展示「已隔离/已放行/需人工复核」状态，而非只展示报告。
**测试**：注入一个带可疑 description 的工具，断言它不出现在传给 LLM 的 tools 列表里。
- [ ] P0-C 完成

---

## P0-D　DEMO/PROD 模式 + 失败安全默认 + 审计先于执行 ✅已核实

**文件**：`backend/app/config.py`（✅`audit_hmac_key` 写死默认；`operator_token=""` 已是空值——合理；`api_bind_host="127.0.0.1"`）、`backend/app/api/routes.py`（/action/execute ✅先执行后审计、`except: pass` 吞掉失败）、`backend/app/audit/store.py`（◑注释提 WAL 但 `_connect` 未设 PRAGMA）。

**做什么**：
1. 启动守卫（DEMO/PROD 分界）：当 `api_bind_host != 127.0.0.1`（视为联网/生产）**且**（`operator_token` 为空 **或** `audit_hmac_key` 仍是默认值）→ 直接拒绝启动并报清晰错误。本机 demo（127.0.0.1 + 空 token）保持顺滑不变。
2. `/action/execute` 改"审计先于执行"：**先写 pending audit → 执行状态变更 → 写 result audit**；若 pending audit 写入失败，则**不执行**状态变更动作（普通 /chat 的 best-effort 审计可保持现状）。
3. `audit/store._connect` 补 `PRAGMA journal_mode=WAL` 与 `busy_timeout`，避免并发 `database is locked`。
- [ ] P0-D 完成

---

## P1　便宜的硬化（GPT 其余项，一并折叠）

- [ ] **请求模型约束**：`ChatRequest.message`、`GuardCheckRequest.command` 加 `Field(min_length, max_length)`；`ActionRequest.action` 用 `Literal["truncate_log","kill_process","clean_path"]`，各 action 定义独立 params schema。
- [ ] **rules/reload 鉴权 + 审计**：`POST /guardrail/rules/reload` 挂 `require_operator`，reload 结果写审计（who/when/prev_hash/new_hash/errors/applied），并暴露当前 rules.yaml 内容 hash（答辩证明"现在生效的是哪版规则"）。
- [ ] **只读高消耗端点**：`/diagnose`、`/posture?live=true`、`/vuln-intel?live=true`、`/guardrail/sandbox-demo` 在非 127.0.0.1 绑定时要求 operator token 或限流（demo 模式可豁免）。
- [ ] **审计脱敏**：`store.py` 单条 detail 已截断 8000 字符；再对 token/key/password/私钥路径/Authorization 等做脱敏。
- [ ] **工程化**：README 改 `pip install -r requirements.lock`（开发升级才用 requirements.txt）；`ci_check.sh` 缺 python3.11 直接失败而非 fallback；可加 ruff/pre-commit。
- [ ] **命名**：README/路由注释/前端把"思维链"统一改为"执行链/审计链/决策 trace"——当前并不要求模型输出原始 chain-of-thought，改名更准确、也避免误解。
- [ ] **（可选）前端代码分割**：评委模式/规则库/回放/检测台抽屉组件动态 import 或 Vite manualChunks 拆 Element Plus（主 chunk ~1.08MB）。

---

## 报告/答辩怎么用这次修复（免费且加分）

把这次绕过修复写成「我们对自己的护栏做了红队，发现并修补了 N 类基础绕过，并固化为回归测试」——**发现并修补 > 宣称 100% 通过**，这与第三方测试的诚实叙事一致，是公信力提升而非减分。再点明结构性论点：**解释器内联代码无法静态可信审查 → 把包装结构本身当信号；命令护栏总有新变形 → 非 root 受限沙箱兜底爆炸半径**。一套「约束能力而非检测内容」的哲学，贯穿命令绕过、内核漏洞、提示注入三类威胁。

## 别做（反 bloat）
不做完整 RBAC/SSO、多租户、K8s、Vault、外部见证、重型运行时 IDS（仅作未来工作写进文档）。理由同前：竞赛虚机跑不动、评委不加分、稀释核心叙事。executor 的 argv 原生重构可作"已知改进项"记录，本轮不强求。
