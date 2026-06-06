"""内核安全姿态检查的 MCP 工具薄封装（P1-2）。

真正逻辑在 core/posture.py。这里只做一层薄封装把它登记成 MCP 工具，且**延迟导入** core
——避免 tools 包在 import 期反向依赖 core（core.posture 又依赖 tools.vuln_intel）形成循环。

READONLY：只研判本机内核/模块的暴露面、给缓解建议，绝不执行任何缓解。
"""
from __future__ import annotations


def kernel_posture(live: bool = False) -> dict:
    """检查本机内核 / 已加载模块是否命中已披露内核漏洞（如 Dirty Frag），给缓解建议。READONLY。

    Args:
        live: 是否让漏洞情报源联网增强（默认 False，离线用本地种子库）。
    Returns:
        含 severity/matches/findings/mitigations/scope_note 的结构化姿态报告。
        缓解命令仅为候选文本，须经 /action/execute 护栏 + 二次确认执行，绝不自动落地。
    """
    from app.core.posture import check_posture
    return check_posture(live=live)
