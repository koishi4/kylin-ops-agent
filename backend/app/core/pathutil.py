"""路径包含判断公共模块（P0-1）—— 把全仓的「路径前缀判断」统一收口到这里。

**为什么不能用 startswith**：`"/var/log2".startswith("/var/log")` 为真，
`"/tmpx".startswith("/tmp")` 也为真——字符串前缀 ≠ 目录包含。安全判定（哪些目录可清理、
哪些日志可读）一旦用 startswith，攻击者用 `/var/log2`、`/tmpx`、`/var/lib/mysqlx`
这类「兄弟目录」即可绕过白/黑名单。正确做法是按**路径分量**判断包含关系，用 os.path.commonpath。

提供两种语义，调用方按需选择：
- is_path_within：**不解析软链**，对给定路径字面规范化后判分量包含。用于「字面 ∪ 软链解析后」
  并集判定里的「字面」一侧（见 diagnosis.classify_file）。
- path_under_any_root：**先 realpath 解析软链**再判包含。用于白名单这类「真实落点必须在允许根内」
  的场景（见 log.tail_log），同时堵死软链跳出允许根。
"""
from __future__ import annotations

import os


def _contains(parent: str, child: str) -> bool:
    """child 是否就是 parent 或落在 parent 之下（按路径分量，非字符串前缀）。

    commonpath(["/var/log2", "/var/log"]) == "/var" ≠ "/var/log" → 正确判否；
    commonpath(["/var/log/app", "/var/log"]) == "/var/log" → 正确判是。
    两者绝对/相对不一致或跨盘时 commonpath 抛 ValueError，按「不包含」保守处理。
    """
    try:
        return os.path.commonpath([child, parent]) == parent
    except ValueError:
        return False


def is_path_within(path: str, roots: tuple[str, ...]) -> bool:
    """字面规范化（normpath，**不解析软链**）后，path 是否落在任一 root 下。

    用于需要保留「字面路径」语义的判定——例如关键性判断要取「字面命中 ∪ 软链解析后命中」
    的并集，字面一侧不能被 realpath 解析掉，否则 `/etc/foo -> /tmp/x` 这类「名字在 /etc」
    的线索会丢失。
    """
    p = os.path.normpath(path)
    return any(_contains(os.path.normpath(root), p) for root in roots)


def path_under_any_root(path: str, roots: tuple[str, ...]) -> bool:
    """先 realpath 解析软链，再判 path 的真实落点是否在任一 root 之下。

    用于白名单（允许读取/操作的根目录集）：既修掉 `/var/log2` 误判为 `/var/log` 子路径，
    又堵死「字面在允许根、软链实指他处」的逃逸——真实目标不在允许根内即拒。
    """
    real = os.path.realpath(path)
    return any(_contains(os.path.realpath(root), real) for root in roots)
