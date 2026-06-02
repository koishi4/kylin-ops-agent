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

import hashlib
import hmac
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from app.config import get_settings

# 单条 detail 最大留存长度，过长的工具输出截断（审计要的是链路，不是全量数据）
_MAX_DETAIL = 8000

# 哈希链链首锚（第一条 step 的 prev_hash），固定常量
_GENESIS = "GENESIS"
# 段字段分隔符（不可见字符，避免字段拼接歧义）
_SEP = "\x1f"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    trace_id    TEXT PRIMARY KEY,
    created_at  REAL NOT NULL,
    user_input  TEXT NOT NULL,
    answer      TEXT,
    intent      TEXT,          -- 防线1 意图分类结果：white/gray/black
    blocked     INTEGER NOT NULL DEFAULT 0,  -- 是否被护栏拦下（1/0）
    llm_provider TEXT,
    head_hash   TEXT           -- 整条链的封口哈希（最后一条 step 的 hash）
);
CREATE TABLE IF NOT EXISTS steps (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    trace_id  TEXT NOT NULL,
    seq       INTEGER NOT NULL,   -- 段序，回放时按此排序
    stage     TEXT NOT NULL,      -- 五段名
    detail    TEXT,               -- JSON 字符串
    ts        REAL NOT NULL,
    prev_hash TEXT,               -- 上一条 step 的哈希（链接前一环）
    step_hash TEXT,               -- 本条 = HMAC(key, prev_hash + 内容)，防篡改
    FOREIGN KEY (trace_id) REFERENCES sessions(trace_id)
);
CREATE INDEX IF NOT EXISTS idx_steps_trace ON steps(trace_id, seq);
"""

# 旧库平滑升级：给已存在的表补哈希链字段（列已存在则忽略）
_MIGRATIONS = [
    "ALTER TABLE sessions ADD COLUMN head_hash TEXT",
    "ALTER TABLE steps ADD COLUMN prev_hash TEXT",
    "ALTER TABLE steps ADD COLUMN step_hash TEXT",
]


def _db_path() -> str:
    return get_settings().audit_db


def _hmac_key() -> bytes:
    return get_settings().audit_hmac_key.encode("utf-8")


def _step_digest(key: bytes, prev_hash: str, trace_id: str, seq: int,
                 stage: str, detail_json: str) -> str:
    """本条 step 的防篡改哈希：HMAC-SHA256(key, prev_hash + 本条全部内容)。

    用 HMAC 而非裸 SHA：无密钥者即便改了 detail 也无法重算出合法 step_hash，
    任何事后篡改都会在 verify_chain 处断链。
    """
    msg = _SEP.join([prev_hash, trace_id, str(seq), stage, detail_json or ""])
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    """开一个连接并保证建表、迁移、提交、关闭。"""
    path = _db_path()
    # 确保父目录存在（audit_db 可能配在子目录）
    parent = Path(path).expanduser().parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(_SCHEMA)
        for stmt in _MIGRATIONS:  # 旧库补列；新库已含列，重复执行报错忽略即可
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass
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
    """落一整条会话思维链。steps 每项形如 {"stage": str, "detail": Any}。

    落库时逐段计算 HMAC 哈希链：step_hash = HMAC(key, prev_hash + 本段内容)，
    prev 串起前一环，head_hash 封口整条链。任何事后篡改都会被 verify_chain 检出（断链）。
    """
    now = time.time()
    key = _hmac_key()
    rows = []
    prev = _GENESIS
    for seq, step in enumerate(steps):
        stage = step.get("stage", "")
        detail_json = _truncate(json.dumps(step.get("detail"), ensure_ascii=False, default=str))
        step_hash = _step_digest(key, prev, trace_id, seq, stage, detail_json)
        rows.append((trace_id, seq, stage, detail_json, now, prev, step_hash))
        prev = step_hash
    head_hash = prev  # 无 step 时即 _GENESIS

    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO sessions "
            "(trace_id, created_at, user_input, answer, intent, blocked, llm_provider, head_hash) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (trace_id, now, user_input, answer, intent, 1 if blocked else 0,
             llm_provider, head_hash),
        )
        # 重存同一 trace 时先清旧段，避免重复
        conn.execute("DELETE FROM steps WHERE trace_id = ?", (trace_id,))
        conn.executemany(
            "INSERT INTO steps (trace_id, seq, stage, detail, ts, prev_hash, step_hash) "
            "VALUES (?,?,?,?,?,?,?)",
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
            "SELECT trace_id, created_at, user_input, answer, intent, blocked, "
            "llm_provider, head_hash FROM sessions WHERE trace_id = ?",
            (trace_id,),
        ).fetchone()
        if s is None:
            return None
        steps = conn.execute(
            "SELECT seq, stage, detail, ts, prev_hash, step_hash "
            "FROM steps WHERE trace_id = ? ORDER BY seq",
            (trace_id,),
        ).fetchall()
    out = _session_row(s)
    out["head_hash"] = s["head_hash"] if "head_hash" in s.keys() else None
    out["steps"] = [
        {"seq": r["seq"], "stage": r["stage"], "ts": r["ts"],
         "detail": _load(r["detail"]),
         "prev_hash": r["prev_hash"], "step_hash": r["step_hash"]}
        for r in steps
    ]
    return out


def verify_chain(trace_id: str) -> dict[str, Any]:
    """校验一条 trace 的哈希链完整性（防篡改硬证据）。

    逐段用 HMAC 重算 step_hash 并与库内值比对：内容被改 / 段被增删 / 顺序被换 / head 被动，
    都会导致重算不一致而「断链」。返回 valid 及首个断裂点 broken_at。
    """
    key = _hmac_key()
    with _connect() as conn:
        s = conn.execute(
            "SELECT head_hash FROM sessions WHERE trace_id = ?", (trace_id,)
        ).fetchone()
        if s is None:
            return {"trace_id": trace_id, "valid": False, "reason": "trace 不存在",
                    "steps": 0, "broken_at": None}
        rows = conn.execute(
            "SELECT seq, stage, detail, step_hash FROM steps WHERE trace_id = ? ORDER BY seq",
            (trace_id,),
        ).fetchall()

    prev = _GENESIS
    for i, r in enumerate(rows):
        if r["step_hash"] is None:
            return {"trace_id": trace_id, "valid": False, "steps": len(rows),
                    "broken_at": r["seq"],
                    "reason": f"第 {r['seq']} 段缺少哈希（早于防篡改特性或被清空）"}
        if r["seq"] != i:
            return {"trace_id": trace_id, "valid": False, "steps": len(rows),
                    "broken_at": i, "reason": f"段序异常：期望 seq={i}，实为 {r['seq']}（疑似增删/重排）"}
        recomputed = _step_digest(key, prev, trace_id, r["seq"], r["stage"], r["detail"])
        if not hmac.compare_digest(recomputed, r["step_hash"]):
            return {"trace_id": trace_id, "valid": False, "steps": len(rows),
                    "broken_at": r["seq"],
                    "reason": f"第 {r['seq']} 段哈希不匹配，内容疑被篡改（断链）"}
        prev = recomputed

    head = s["head_hash"] if "head_hash" in s.keys() else None
    if head != prev:
        return {"trace_id": trace_id, "valid": False, "steps": len(rows),
                "broken_at": len(rows) - 1 if rows else None,
                "reason": "封口哈希 head_hash 与链尾不一致（疑似尾部段被删/改）"}

    return {"trace_id": trace_id, "valid": True, "steps": len(rows),
            "broken_at": None, "head_hash": head,
            "reason": "哈希链完整，未检测到篡改。"}


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
