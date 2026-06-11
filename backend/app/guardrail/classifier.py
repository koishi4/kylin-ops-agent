"""护栏防线1：意图风险分类（见 safety-guardrail skill）。

把用户自然语言意图分三类，作为护栏链路的第一道闸（最快、最省，先粗筛）：
- 白 WHITE（只读查询）→ 直接放行进入正常编排
- 灰 GRAY（修改/运维动作）→ 后续命令必须过规则库 + 二次确认
- 黑 BLACK（明显破坏/越权/注入）→ 直接拒绝，不进 LLM

实现用规则（关键词 + 正则）即可满足赛题与演示；分类结果写入 trace 的「安全校验」段。
与 rules.py 的命令级规则解耦：这里判「意图」，那里判「具体命令」，两层防御。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .rules import match_rules, normalize


class IntentClass(Enum):
    WHITE = "white"   # 只读查询，放行
    GRAY = "gray"     # 修改类，需规则库 + 确认
    BLACK = "black"   # 破坏/越权/注入，拒绝


@dataclass
class IntentResult:
    intent: IntentClass
    reason: str
    matched: list[str]  # 命中的关键词/规则，便于审计与解释

    def to_dict(self) -> dict:
        return {"intent": self.intent.value, "reason": self.reason, "matched": self.matched}


# 关停类动词 / 具体安全设施名——两者近距离同现即「意图关停安全设施」（顺序无关，见下）。
_DISABLE_VERBS = r"关闭|禁用|停掉|停用|卸载|清空"
_SECURITY_FACILITIES = r"防火墙|firewalld|iptables|selinux|审计|auditd|安全防护|入侵检测"

# 黑：明显破坏/越权意图（自然语言层面，命令层另有 rules.py 兜底）
_BLACK_PATTERNS = [
    (r"(格式化|清空).*(磁盘|分区|硬盘|/dev)", "意图格式化/清空磁盘设备"),
    (r"(删(除|光|掉).*(整个|所有|全部).*(系统|根目录|/)"
     r"|(整个|所有|全部).*(系统|根目录).*(删|清空|抹|干掉))", "意图删除整个系统/根目录"),
    (r"rm\s+-[a-z]*[rf]", "自然语言中直接夹带递归删除命令"),
    # 只把「关停具体安全/审计设施」判黑（不可覆盖），且**顺序无关**——中文「关闭防火墙」与
    # 「把 selinux 停掉」都要命中，故用「动词…设施」与「设施…动词」双向、近距离([^，。\n]{0,10})匹配。
    # 刻意不含裸「安全」「日志」：「安全」太泛会误杀「关闭这个不安全的端口」；停日志收集应落到
    # 需确认的灰（缺省保守判灰），不该是不可覆盖的硬黑。
    (rf"(({_DISABLE_VERBS})[^，。\n]{{0,10}}({_SECURITY_FACILITIES})"
     rf"|({_SECURITY_FACILITIES})[^，。\n]{{0,10}}({_DISABLE_VERBS}))",
     "意图关闭安全/审计设施"),
    # 注：越权提权/后门**不**放在这里无条件判黑——它有「动作」与「诊断」两种意图，需区分（见下）。
]

# 越权/后门特征。难点：「帮我提权 / 植入后门」是**动作**意图（黑），而「检查有没有提权风险 /
# 扫描后门 / 有没有提权漏洞」是正当的**防御诊断**意图（应放行给只读编排，让模型选 kernel_posture /
# query_vuln_intel 等只读工具）。实测误杀：「帮我检查下有没有 Dirty Pipe 那类提权风险」被判黑拦下。
_PRIVESC_BACKDOOR = re.compile(r"(提权|获取?\s*root|拿到?\s*root\s*权限|后门|backdoor)", re.IGNORECASE)
# 诊断/排查/防护类语境标记：与越权词同现时，意图是「查风险」而非「搞提权」，不判黑。
_DIAGNOSTIC_INTENT = re.compile(
    r"(检查|排查|检测|查一下|查查|查询|看看|有没有|是否|是不是|存在|风险|漏洞|隐患|"
    r"审计|加固|防范|防护|扫描|评估|核查|巡检|cve)", re.IGNORECASE)

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
    """对用户输入做意图分类。先查黑（含注入），再灰，再白，缺省保守判灰。"""
    t = normalize(text)

    # 1) 注入话术直接判黑（复用规则库 inject 类，避免重复维护）
    inj = [r for r in match_rules(t) if r.category == "inject"]
    if inj:
        return IntentResult(IntentClass.BLACK,
                            f"检测到提示词注入/破坏特征：{inj[0].description}",
                            [r.id for r in inj])

    # 2) 自然语言层面的破坏/越权意图
    for pat, why in _BLACK_PATTERNS:
        if re.search(pat, t, re.IGNORECASE):
            return IntentResult(IntentClass.BLACK, why, [pat])

    # 2.5) 越权提权/后门：仅「动作意图」判黑；带诊断/排查/防护语境的是正当防御查询，放行给只读编排。
    # 例：「帮我提权」「植入后门」→ 黑；「检查有没有提权风险」「扫描后门」「有没有提权漏洞」→ 不黑。
    if _PRIVESC_BACKDOOR.search(t) and not _DIAGNOSTIC_INTENT.search(t):
        return IntentResult(IntentClass.BLACK, "意图越权提权/植入后门",
                            [_PRIVESC_BACKDOOR.pattern])

    # 3) 修改类关键词 → 灰
    gray_hit = [k for k in _GRAY_KEYWORDS if k in t]
    if gray_hit:
        return IntentResult(IntentClass.GRAY,
                            f"含修改/运维动作意图（{', '.join(gray_hit[:3])}），"
                            "生成的命令需经规则库校验与二次确认", gray_hit)

    # 4) 只读查询关键词 → 白
    white_hit = [k for k in _WHITE_KEYWORDS if k.lower() in t.lower()]
    if white_hit:
        return IntentResult(IntentClass.WHITE,
                            "只读查询意图，放行进入正常编排", white_hit)

    # 5) 缺省保守：判灰，让命令级护栏继续把关（宁可多确认，不可漏放行）
    return IntentResult(IntentClass.GRAY,
                        "意图不明确，按保守策略归为修改类，后续命令仍受规则库约束", [])
