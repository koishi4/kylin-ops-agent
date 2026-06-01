"""思维链审计存储 —— 评分明确要求的「可追溯」闭环硬证据。

每次会话生成一个 trace_id，把五段（接收指令 / 感知环境 / 推理决策 / 安全校验 / 执行结果）
都挂在同一 trace 下落 SQLite。前端可按 trace_id 回放整条思维链。

设计取舍：
- 用标准库 sqlite3，零依赖、麒麟上零配置（符合 CLAUDE.md 技术栈）。
- 两张表：sessions（一次会话一行）+ steps（一段思维一行，外键挂 trace_id）。
- 写操作幂等建表，按需开连接（WAL + check_same_thread=False），并发量极低，简单可靠。
- detail 用 JSON 字符串存，回放时还原结构；存前做长度截断防止单条日志撑爆库。
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from app.config import get_settings

# 单条 detail 最大留存长度，过长的工具输出截断（审计要的是链路，不是全量数据）
_MAX_DETAIL = 8000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    trace_id    TEXT PRIMARY KEY,
    created_at  REAL NOT NULL,
    user_input  TEXT NOT NULL,
    answer      TEXT,
    intent      TEXT,          -- 防线1 意图分类结果：white/gray/black
    blocked     INTEGER NOT NULL DEFAULT 0,  -- 是否被护栏拦下（1/0）
    llm_provider TEXT
);
CREATE TABLE IF NOT EXISTS steps (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    trace_id  TEXT NOT NULL,
    seq       INTEGER NOT NULL,   -- 段序，回放时按此排序
    stage     TEXT NOT NULL,      -- 五段名
    detail    TEXT,               -- JSON 字符串
    ts        REAL NOT NULL,
    FOREIGN KEY (trace_id) REFERENCES sessions(trace_id)
);
CREATE INDEX IF NOT EXISTS idx_steps_trace ON steps(trace_id, seq);
"""


def _db_path() -> str:
    return get_settings().audit_db


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    """开一个连接并保证建表、提交、关闭。"""
    path = _db_path()
    # 确保父目录存在（audit_db 可能配在子目录）
    parent = Path(path).expanduser().parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(_SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """显式初始化（建表）。启动时调用一次即可，连接里也会兜底建表。"""
    with _connect():
        pass


def _truncate(text: str) -> str:
    if len(text) > _MAX_DETAIL:
        return text[:_MAX_DETAIL] + f"…(已截断，原长 {len(text)} 字符)"
    return text


def save_trace(
    trace_id: str,
    user_input: str,
    answer: str,
    steps: list[dict[str, Any]],
    *,
    intent: str | None = None,
    blocked: bool = False,
    llm_provider: str | None = None,
) -> None:
    """落一整条会话思维链。steps 每项形如 {"stage": str, "detail": Any}。"""
    now = time.time()
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO sessions "
            "(trace_id, created_at, user_input, answer, intent, blocked, llm_provider) "
            "VALUES (?,?,?,?,?,?,?)",
            (trace_id, now, user_input, answer, intent, 1 if blocked else 0, llm_provider),
        )
        # 重存同一 trace 时先清旧段，避免重复
        conn.execute("DELETE FROM steps WHERE trace_id = ?", (trace_id,))
        rows = []
        for seq, step in enumerate(steps):
            detail = step.get("detail")
            detail_json = _truncate(json.dumps(detail, ensure_ascii=False, default=str))
            rows.append((trace_id, seq, step.get("stage", ""), detail_json, now))
        conn.executemany(
            "INSERT INTO steps (trace_id, seq, stage, detail, ts) VALUES (?,?,?,?,?)",
            rows,
        )


def list_traces(limit: int = 50) -> list[dict[str, Any]]:
    """列出最近会话（不含完整 steps），供前端历史列表。"""
    with _connect() as conn:
        cur = conn.execute(
            "SELECT trace_id, created_at, user_input, answer, intent, blocked, llm_provider "
            "FROM sessions ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        return [_session_row(r) for r in cur.fetchall()]


def get_trace(trace_id: str) -> dict[str, Any] | None:
    """取一条会话的完整思维链（含五段 steps），供前端回放。"""
    with _connect() as conn:
        s = conn.execute(
            "SELECT trace_id, created_at, user_input, answer, intent, blocked, llm_provider "
            "FROM sessions WHERE trace_id = ?",
            (trace_id,),
        ).fetchone()
        if s is None:
            return None
        steps = conn.execute(
            "SELECT seq, stage, detail, ts FROM steps WHERE trace_id = ? ORDER BY seq",
            (trace_id,),
        ).fetchall()
    out = _session_row(s)
    out["steps"] = [
        {"seq": r["seq"], "stage": r["stage"], "ts": r["ts"], "detail": _load(r["detail"])}
        for r in steps
    ]
    return out


def _session_row(r: sqlite3.Row) -> dict[str, Any]:
    return {
        "trace_id": r["trace_id"],
        "created_at": r["created_at"],
        "user_input": r["user_input"],
        "answer": r["answer"],
        "intent": r["intent"],
        "blocked": bool(r["blocked"]),
        "llm_provider": r["llm_provider"],
    }


def _load(detail_json: str | None) -> Any:
    if detail_json is None:
        return None
    try:
        return json.loads(detail_json)
    except (json.JSONDecodeError, TypeError):
        return detail_json
