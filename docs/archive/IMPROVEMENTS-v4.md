# IMPROVEMENTS-v4.md — 护栏绕过修复 + GPT Pro 审查整合（交给 Claude Code）

> 🗄️ **已归档（历史规划文档）**：本文 P-任务均已执行落地。代码/测试按「P 编号」援引本文作设计依据故保留，请勿据此再施工。

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

4. **（可后置 → 已补做）executor 收紧**
   GPT 建议 executor 改 argv 原生接口、不把"shell 命令字符串"当统一执行对象。已落地：新增结构化入口
   `execute_argv(argv: list[str])`，护栏在 `shlex.join(argv)` 上裁决、放行后直接执行该 argv（不再二次
   `shlex.split`），因 `shlex.split(shlex.join(x))==x` 恒等故「所审即所执」可证；动作层（kill/clean）改
   argv 原生，executor 唯一生产调用方全量收口。原 `execute(str)` 保留为自由形态/兼容入口。见 dev-log「P0-A.4」。
   - [x] P0-A.4 完成 —— `tests/test_executor_argv.py` 12 例固化（危险 argv 等价被拦、元字符 token 不被再解析、
         join/split 恒等、入参防御）；644→656 全绿。

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
- [x] P0-B 完成 —— tail_log 改 O_RDONLY|O_NOFOLLOW+fstat 经 fd 读；truncate_log 改 fd-safe os.ftruncate
      （不再走 truncate 命令，与 P0-A 闭环）；新增末段软链 TOCTOU 拒读测试。631→633 全绿。
      诚实边界：O_NOFOLLOW 仅护末段，中间目录软链由 realpath 覆盖（per-component openat 列未来工作）。

---

## P0-C　MCP 工具投毒：命中后隔离，而非只告警 ✅已核实

**文件**：`backend/app/main.py`（~37–55，✅命中仅 `logger.warning`）、`backend/app/core/orchestrator.py`（~109–118 仍把工具 schema 传模型）、`backend/app/guardrail/tool_scan.py`。

**做什么**：扫描结果分三档处置——
- high → fail-closed：**不进入 `openai_tools()`**，不喂给 LLM；
- medium → 默认 quarantine，需 operator override 才启用；
- low → 告警但可用。
`suspicious=True` 的工具默认不进模型上下文（工具投毒的核心风险正是：恶意 description 不需被调用，只要进上下文就影响模型）。前端 `/guardrail/tool-scan` 面板展示「已隔离/已放行/需人工复核」状态，而非只展示报告。
**测试**：注入一个带可疑 description 的工具，断言它不出现在传给 LLM 的 tools 列表里。
- [x] P0-C 完成 —— apply_quarantine 三档处置（high 隔离/medium 默认隔离需 override/low 告警可用）；
      orchestrator 取 openai_tools 后过滤隔离工具再喂模型（trace 留隔离记录）；前端按档位展示。
      端到端断言被隔离工具不进 LLM tools 列表。633→637 全绿。

---

## P0-D　DEMO/PROD 模式 + 失败安全默认 + 审计先于执行 ✅已核实

**文件**：`backend/app/config.py`（✅`audit_hmac_key` 写死默认；`operator_token=""` 已是空值——合理；`api_bind_host="127.0.0.1"`）、`backend/app/api/routes.py`（/action/execute ✅先执行后审计、`except: pass` 吞掉失败）、`backend/app/audit/store.py`（◑注释提 WAL 但 `_connect` 未设 PRAGMA）。

**做什么**：
1. 启动守卫（DEMO/PROD 分界）：当 `api_bind_host != 127.0.0.1`（视为联网/生产）**且**（`operator_token` 为空 **或** `audit_hmac_key` 仍是默认值）→ 直接拒绝启动并报清晰错误。本机 demo（127.0.0.1 + 空 token）保持顺滑不变。
2. `/action/execute` 改"审计先于执行"：**先写 pending audit → 执行状态变更 → 写 result audit**；若 pending audit 写入失败，则**不执行**状态变更动作（普通 /chat 的 best-effort 审计可保持现状）。
3. `audit/store._connect` 补 `PRAGMA journal_mode=WAL` 与 `busy_timeout`，避免并发 `database is locked`。
- [x] P0-D 完成 —— 失败安全启动守卫（非回环+弱默认→拒启）；/action/execute 审计先于执行（改状态调用
      pending 审计写不下就拒执行）；审计库 WAL+busy_timeout。test_startup_guard.py 固化。637→643 全绿。

---

## P1　便宜的硬化（GPT 其余项，一并折叠）

- [x] **请求模型约束** —— ChatRequest.message / GuardCheckRequest.command 加 Field(min/max_length)；
      ActionRequest.action 用 Literal 白名单 + model_validator 按动作校验 params 形状（缺必填即 422）。
- [x] **rules/reload 鉴权 + 审计** —— reload 端点挂 require_operator；结果写审计（actor/prev→new 指纹/applied/errors）；
      新增 rules_fingerprint()，/guardrail/rules 与 reload 均回报生效规则集指纹（证明此刻在用哪版规则）。
- [x] **只读高消耗端点** —— /diagnose、/posture、/vuln-intel、/guardrail/sandbox-demo 挂 require_operator
      （demo 空 token 豁免、prod 非回环已由 P0-D 强制配 token → 自动生效）。
- [x] **审计脱敏** —— store 落库前 _redact：Bearer/Authorization、token/key/password/secret 键值、PEM 私钥块
      → ***REDACTED***（脱敏在计哈希之前，verify_chain 仍自洽）。新增 test_audit_redacts_credentials。
- [x] **工程化** —— README 改 `pip install -r requirements.lock`；ci_check.sh 缺 python3.11 直接失败不再 fallback。
      （ruff/pre-commit 属「可加」，本轮不引入以免 bloat。）
- [x] **命名** —— README/路由注释/前端用户可见标签「思维链」统一改「执行链（trace）」（测试仅 docstring 提及，不受影响）。
- [x] **（可选）前端代码分割** —— vite manualChunks 拆出 element-plus / vue vendor：主业务 chunk 1.08MB→76KB（缓存友好）。

---

## 报告/答辩怎么用这次修复（免费且加分）

把这次绕过修复写成「我们对自己的护栏做了红队，发现并修补了 N 类基础绕过，并固化为回归测试」——**发现并修补 > 宣称 100% 通过**，这与第三方测试的诚实叙事一致，是公信力提升而非减分。再点明结构性论点：**解释器内联代码无法静态可信审查 → 把包装结构本身当信号；命令护栏总有新变形 → 非 root 受限沙箱兜底爆炸半径**。一套「约束能力而非检测内容」的哲学，贯穿命令绕过、内核漏洞、提示注入三类威胁。

## 别做（反 bloat）
不做完整 RBAC/SSO、多租户、K8s、Vault、外部见证、重型运行时 IDS（仅作未来工作写进文档）。理由同前：竞赛虚机跑不动、评委不加分、稀释核心叙事。executor 的 argv 原生重构可作"已知改进项"记录，本轮不强求。
