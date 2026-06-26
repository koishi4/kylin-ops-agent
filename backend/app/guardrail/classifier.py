"""护栏防线1：意图分类——是**路由层**，不是安全边界（见 dev-log 2026-06-11「意图层去明文化」）。

把用户自然语言意图粗分两路，作为编排前最快、最省的一道分流：
- 白 WHITE（只读查询）→ 走只读快路，跳过 防线1.5 语义研判
- 灰 GRAY（修改/运维动作 + 意图不明的保守缺省）→ 叠加 防线1.5 LLM 语义研判，
  之后生成的命令再过 防线2 命令规则 + 二次确认

**设计立场（重要）：意图层不再做「破坏意图」的明文关键词判黑。**
明文匹配在输入侧本质可绕——base64 编码、小语种（低资源语言越狱）、GCG 对抗后缀都能
绕开任何明文过滤器；对真实攻击≈摆设，却对正常的安全运维词汇（「检查提权风险」「清理磁盘」）
高频误杀。本项目的安全边界**不在这一层**：
  1. 架构层——LLM 只能【选只读 MCP 工具】+【3 个强制二次确认的白名单动作】，根本没有
     「自然语言 → 任意命令执行」这条腿；破坏意图再「黑」也炸不了系统（见 tests/test_e2e_injection）；
  2. 防线1.5——对灰意图叠加 LLM 语义研判：委婉删库这种【无关键词可匹配】的表述才是真考验，
     靠语义而非话术（见 risk_assessor，真机实测「把没用的大家伙清理掉」→ critical/deny）；
  3. 防线2——对【已被模型解码成的具体命令产物】做 realpath + AST + 效果分析：混淆到产物侧
     早被「编译掉」（无论用户当初用英文/小语种/base64 问，落地的都是明文命令），明文匹配在这里才有牙。
因此本层只返回 WHITE/GRAY 做路由。唯一例外是**注入/操纵话术仍判 BLACK**——但那不是安全承重
（真正的抗注入是 防线3 scan_injection 的结构化隔离 + 上述架构），只是一道廉价、低误报的
「拒绝与操纵对话 + 留审计」首过滤，与 防线3 互为冗余（orchestrator 另有 scan_injection 独立兜底）。

分类结果写入 trace 的「安全校验」段。与 rules.py 的命令级规则解耦：这里判「意图路由」，那里判「具体命令」。
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .rules import match_rules, normalize


class IntentClass(Enum):
    """意图分类档位（路由层，非安全承重）：白=只读快路 / 灰=进研判+护栏 / 黑=注入话术留痕。"""

    WHITE = "white"   # 只读查询，走快路
    GRAY = "gray"     # 修改类 / 意图不明的保守缺省，叠加 防线1.5 研判 + 命令级护栏
    BLACK = "black"   # 仅注入/操纵话术：拒绝并留痕（非安全承重，见模块注释）


@dataclass
class IntentResult:
    """意图分类结论：档位、判定理由、命中的关键词/规则。"""

    intent: IntentClass
    reason: str
    matched: list[str]  # 命中的关键词/规则，便于审计与解释

    def to_dict(self) -> dict:
        """序列化为 dict，供审计与前端展示。"""
        return {"intent": self.intent.value, "reason": self.reason, "matched": self.matched}


# 注：此处**刻意不再保留**「破坏意图」的明文关键词判黑（旧 _BLACK_PATTERNS / _PRIVESC_BACKDOOR
# 已于 2026-06-11 移除）。理由见模块注释——明文匹配在输入侧可被 base64/小语种/GCG 对抗后缀绕开，
# 对真实攻击是摆设，却高频误杀「检查提权风险 / 格式化前确认 / 清理磁盘」这类正当运维表述。
# 「格式化/删库/关防火墙/提权」这些表述现在自然落到「灰」（含动词关键词或保守缺省），交由
# 防线1.5 LLM 语义研判 + 防线2 命令级护栏 + 架构（无任意执行腿）兜底——它们才是确定性的安全边界。

# 灰：修改/运维动作意图
_GRAY_KEYWORDS = [
    "删除", "清理", "清除", "重启", "重启动", "停止", "启动", "杀", "kill",
    "修改", "更改", "设置", "配置", "安装", "卸载", "更新", "升级",
    "释放", "扩容", "挂载", "卸载", "格式化", "权限", "chmod", "chown",
]

# 白：只读查询意图
_WHITE_KEYWORDS = [
    "查看", "查询", "看一下", "看看", "显示", "列出", "列举", "多少", "有没有",
    "是否", "状态", "情况", "怎么样", "为什么", "分析", "诊断", "排查", "检查",
    "占用", "使用率", "监控", "show", "list", "status", "check",
]


def classify_intent(text: str) -> IntentResult:
    """对用户输入做意图路由：注入→黑（拒绝+留痕），改动→灰，只读→白，缺省保守判灰。

    注意：本层不对「破坏/越权意图」判黑（见模块注释）——那靠架构 + 防线1.5 + 防线2，不靠话术匹配。
    """
    t = normalize(text)

    # 1) 注入/操纵话术 → 黑（拒绝并留痕）。这不是安全承重，只是廉价首过滤：真正的抗注入是
    #    防线3 scan_injection 的结构化隔离 + 架构（orchestrator 另有 scan_injection 独立兜底，
    #    故此处即便漏判也不放过注入）。复用规则库 inject 类，避免重复维护。
    inj = [r for r in match_rules(t) if r.category == "inject"]
    if inj:
        return IntentResult(IntentClass.BLACK,
                            f"检测到提示词注入/操纵话术：{inj[0].description}",
                            [r.id for r in inj])

    # 2) 修改类关键词 → 灰
    gray_hit = [k for k in _GRAY_KEYWORDS if k in t]
    if gray_hit:
        return IntentResult(IntentClass.GRAY,
                            f"含修改/运维动作意图（{', '.join(gray_hit[:3])}），"
                            "生成的命令需经规则库校验与二次确认", gray_hit)

    # 3) 只读查询关键词 → 白
    white_hit = [k for k in _WHITE_KEYWORDS if k.lower() in t.lower()]
    if white_hit:
        return IntentResult(IntentClass.WHITE,
                            "只读查询意图，放行进入正常编排", white_hit)

    # 4) 缺省保守：判灰，让 防线1.5 + 命令级护栏继续把关（宁可多确认，不可漏放行）
    return IntentResult(IntentClass.GRAY,
                        "意图不明确，按保守策略归为修改类，后续命令仍受规则库约束", [])
