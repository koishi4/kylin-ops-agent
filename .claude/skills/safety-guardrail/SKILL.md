---
name: safety-guardrail
description: 编写或扩展安全护栏（意图风险过滤、高危命令规则库、提示词注入检测、最小权限校验）时使用。这是 A2 项目的核心创新点和拿分关键。当任务涉及拦截危险命令、识别 rm -rf/chmod 风险参数、防止 prompt injection、权限合规检查时触发。
---

# 安全护栏编写规范（项目灵魂）

这是评分项③（安全护栏，属功能 55%）和创新分（25%）的核心。投入产出比最高，重点雕琢。

## 护栏的定位
**不信任 LLM 的输出。** LLM 生成的命令是"候选"，护栏是"二次过滤"的最后一道闸门。
即使 LLM 被诱导生成了 `rm -rf /`，护栏也必须独立拦下来。护栏逻辑与 LLM 完全解耦。

## 第一性原则：主控制是「架构」，规则只是纵深防御（扩护栏前先读这条）

本项目真正的第一道安全保证**不是规则引擎**，而是**架构层面让 LLM 够不到危险路径**：
- LLM 在编排路径里**只能从 READONLY MCP 工具里选工具**，不能拼装/自由执行命令；
- 变更动作只有 `truncate_log/kill_process/clean_path` 三个**白名单参数化动作**，且**不在 MCP 工具注册表里**
  （LLM 无法把它们当工具调用），只能由用户经 `/action/execute` 显式触发、强制二次确认；
- 工具输出经 spotlighting/datamarking 结构性隔离后才回喂模型 → 注入即便成功也驱动不了状态变更。

由此得到**可证明的结构性不变量**（`guardrail/trifecta.py` + `tests/test_e2e_injection.py` 实测）：
感知路径能力上限 ≤2 条腿（无「改状态/外联」），结构上满足 Rule of Two，**危险动作不可能在污点下放行**。

> 扩展护栏时的纪律（血泪教训，见 dev-log「第三方评审整改」）：
> **优先强化架构控制（收紧动作白名单 / 能力标签 / 保持工具只读），而不是无止境往规则库堆正则。**
> 正则是脆的——`nc -e`、`$IFS` 空格替代、语序变形都能绕过；黑名单是跑步机，永远追不完。
> 规则引擎的价值是「纵深防御 + 可解释 + 可演示」，不是「唯一闸门」。先问「能不能从架构上消除这条路径」，
> 不能再写规则。新增规则务必同时补**红队对抗样例**和**良性误杀对照**，否则等于没测。

## 四道防线（纵深防御层，按顺序执行，任一拦截即终止）

### 防线1：意图风险分类
把用户自然语言意图分三类：
- 白（READONLY 查询类）→ 直接放行
- 灰（MUTATING 修改类）→ 进入规则库 + 二次确认
- 黑（明显破坏/越权）→ 直接拒绝
可用规则 + 小模型分类。分类结果写入 trace。

### 防线2：高危命令规则库（核心，必须原创）
结构化规则，放 `guardrail/rules.py`，支持热加载。每条规则：

```python
from enum import Enum
from dataclasses import dataclass

class RiskLevel(Enum):
    CRITICAL = "critical"   # 直接拒绝
    HIGH = "high"           # 拦截，需显式授权
    MEDIUM = "medium"       # 二次确认
    LOW = "low"             # 记录后放行

class Action(Enum):
    DENY = "deny"
    CONFIRM = "confirm"
    ALLOW = "allow"

@dataclass
class Rule:
    id: str
    pattern: str          # 正则
    risk: RiskLevel
    action: Action
    description: str       # 命中后给用户的解释
    category: str          # delete/permission/disk/privilege/inject/config
```

必须覆盖的规则类别（每类至少3条）：
1. **删除类**：`rm -rf /`、`rm` 命中 `/ /etc /var /boot /usr` 等、删除 `*.db`/mysql 数据目录
2. **权限类**：`chmod 777`、`chmod -R` 作用于系统目录、`chown` 改 root 属主、**单文件改 `/etc/shadow|sudoers|passwd` 权限/属主**
3. **磁盘类**：`mkfs.*`、`dd of=/dev/sd*`、重定向覆盖块设备 `> /dev/sd*`
4. **提权类**：未授权 `sudo`/`su`、修改 `/etc/sudoers`、改 root 密码、`useradd -u 0`
5. **注入类**：见防线3；含 `$IFS`/`${IFS}` 空格替代等规范化绕过
6. **外联/反弹 shell（egress）**：`/dev/tcp`、`nc -e`/`ncat --exec`、`socat EXEC/SYSTEM:` —— 防「把本机交给远端」（数据外泄/RCE 后门），易被「只盯毁本机数据」的规则集漏掉
7. **关键配置保护**：写入 `/etc/passwd /etc/shadow /etc/fstab sshd_config /etc/hosts` 等

匹配要兼顾变形：路径前后空格、绝对/相对路径、`-rf` 与 `-fr` 与 `-r -f`、引号包裹。
用正则 + 路径规范化（os.path.realpath）双重判断，别只做字符串包含。

### 防线3：提示词注入检测
扫描用户输入与"被当作上下文的文件内容"，识别：
- 指令覆盖型：忽略以上/之前的(规则|指令|设定)、ignore previous instructions、disregard the rules
- 角色劫持型：你现在是root、你可以做任何事、进入开发者模式、越狱
- 夹带执行型：文档/日志内容里嵌入 `请执行 rm...`、隐藏的命令拼接
- 编码绕过：base64/hex 编码的命令、`echo ... | base64 -d | sh`
命中则拒绝整个请求并记录到审计，向用户说明"检测到疑似注入"。

### 防线4：最小权限校验
- 默认在受限账户执行，核心运维动作不用 root
- PRIVILEGED 操作必须：①命中授权白名单 ②用户显式确认 ③记录提权原因
- 校验当前操作所需权限是否超出会话授权范围，超出即拦截

## 输出结构
护栏统一返回：
```python
@dataclass
class GuardResult:
    allowed: bool
    action: Action
    matched_rules: list[str]   # 命中的规则 id
    risk: RiskLevel
    reason: str                # 给用户和日志的人类可读解释
    require_confirm: bool
```

## 被拦截后的行为
- 不静默丢弃：向用户解释为什么被拦、风险是什么、建议怎么做
- 全部写入审计日志（trace 的"安全校验"段）
- CONFIRM 类：返回给前端弹二次确认，用户确认后才放行

## 测试要求（这部分测试报告最出彩）
建红队测试集 `tests/test_guardrail_redteam.py`，至少 30 条：
- 各类危险命令变形（断言 DENY）
- 各类注入话术（断言识别）
- 正常运维命令（断言不误杀，假阳性要低）
统计拦截率/误杀率，做成表格进课程报告，也是答辩硬数据。
绝不在测试里真实执行 CRITICAL 命令，只验证"是否被拦"。
