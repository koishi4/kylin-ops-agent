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
import re
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from app.config import get_settings

# 单条 detail 最大留存长度，过长的工具输出截断（审计要的是链路，不是全量数据）
_MAX_DETAIL = 8000

_REDACTED = "***REDACTED***"
# P1：审计脱敏——审计要可追溯但不该把凭据明文存进库（库被读=凭据泄露）。
# 在落库前对 detail JSON 文本做正则脱敏：Bearer/Authorization、token/key/password/secret 等键值、私钥块。
_REDACT_PATTERNS = [
    # JSON 键值对：含敏感词的键，其字符串值整体替换
    (re.compile(r'("(?:[^"]*(?:authorization|token|api[_-]?key|secret|password|passwd|pwd|'
                r'access[_-]?token|refresh[_-]?token|private[_-]?key)[^"]*)"\s*:\s*")'
                r'(?:\\.|[^"\\])*(")', re.IGNORECASE), rf'\1{_REDACTED}\2'),
    # 裸 Bearer 令牌
    (re.compile(r'(?i)(bearer\s+)[A-Za-z0-9._\-]{6,}'), rf'\1{_REDACTED}'),
    # PEM 私钥块
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
                re.DOTALL), f'-----BEGIN PRIVATE KEY-----{_REDACTED}-----END PRIVATE KEY-----'),
]


def _redact(text: str) -> str:
    """落库前脱敏：抹掉 detail 里可能夹带的凭据明文（token/key/password/Bearer/私钥）。"""
    for pat, repl in _REDACT_PATTERNS:
        text = pat.sub(repl, text)
    return text

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
    tainted     INTEGER NOT NULL DEFAULT 0,  -- 污点追踪：本路径是否摄入过不可信数据（CaMeL 轻量版）
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
    "ALTER TABLE sessions ADD COLUMN tainted INTEGER NOT NULL DEFAULT 0",
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
    # P0-D：WAL 提升读写并发、busy_timeout 避免「database is locked」即时报错（动作/对话/回放可能并发）。
    # 内存库（:memory:）不支持 WAL，try/except 兜底；失败退回默认 journal 模式不影响功能。
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
    except sqlite3.OperationalError:
        pass
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
    tainted: bool = False,
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
        # 先脱敏再截断，最后才计哈希——存进库与参与哈希链的是同一份脱敏文本，verify_chain 仍自洽。
        detail_json = _truncate(_redact(
            json.dumps(step.get("detail"), ensure_ascii=False, default=str)))
        step_hash = _step_digest(key, prev, trace_id, seq, stage, detail_json)
        rows.append((trace_id, seq, stage, detail_json, now, prev, step_hash))
        prev = step_hash
    head_hash = prev  # 无 step 时即 _GENESIS

    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO sessions "
            "(trace_id, created_at, user_input, answer, intent, blocked, tainted, "
            "llm_provider, head_hash) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (trace_id, now, user_input, answer, intent, 1 if blocked else 0,
             1 if tainted else 0, llm_provider, head_hash),
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
            "SELECT trace_id, created_at, user_input, answer, intent, blocked, tainted, "
            "llm_provider FROM sessions ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        return [_session_row(r) for r in cur.fetchall()]


def get_trace(trace_id: str) -> dict[str, Any] | None:
    """取一条会话的完整思维链（含五段 steps），供前端回放。"""
    with _connect() as conn:
        s = conn.execute(
            "SELECT trace_id, created_at, user_input, answer, intent, blocked, tainted, "
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


# ---------------------------------------------------------------------------
# P2：审计证据包导出 —— 把「一条 trace + 防篡改证明 + 当时的护栏/工具版本」打成一个**自封口**的
# 可携带证据包。用途：把可追溯性从「只能在本系统里回放」升级为「可离线核验的取证材料」。
# 内容：完整五段 trace + verify_chain 结果 + head_hash + 导出时的规则指纹/工具基线指纹 + 元数据，
# 再用同一 HMAC 密钥对整包封口（seal）。任何对证据包内容的事后改动都会令 seal 重算不一致而被 verify_evidence
# 检出——与库内哈希链「双重防篡改」：链证明库未被改，seal 证明导出后的这份材料未被改。
# ---------------------------------------------------------------------------
EVIDENCE_KIND = "kylin-ops-agent.evidence-pack"
EVIDENCE_VERSION = "1"


def _evidence_seal(body: dict[str, Any]) -> str:
    """对证据包正文（不含 seal 自身）计算 HMAC-SHA256 封口。"""
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, default=str)
    return hmac.new(_hmac_key(), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def export_evidence(trace_id: str, *, components: dict[str, Any] | None = None) -> dict[str, Any]:
    """导出一条 trace 的自封口证据包。components 由调用方填入导出时的护栏/工具版本快照。

    Returns: {ok, evidence:{kind,version,generated_at,trace_id,head_hash,hmac_alg,
              components, trace, verify, seal}} 或 {ok:False,error}。
    """
    trace = get_trace(trace_id)
    if trace is None:
        return {"ok": False, "error": f"trace 不存在: {trace_id}", "trace_id": trace_id}
    body = {
        "kind": EVIDENCE_KIND,
        "version": EVIDENCE_VERSION,
        "generated_at": time.time(),
        "trace_id": trace_id,
        "head_hash": trace.get("head_hash"),
        "hmac_alg": "HMAC-SHA256",
        "components": components or {},   # 规则指纹 / 工具 schema 基线指纹 / 应用版本
        "trace": trace,                   # 完整五段（detail 落库时已脱敏）
        "verify": verify_chain(trace_id),  # 导出时刻的链完整性裁决
    }
    return {"ok": True, "evidence": {**body, "seal": _evidence_seal(body)}}


def verify_evidence(pack: dict[str, Any]) -> dict[str, Any]:
    """核验证据包封口（持有同一 HMAC 密钥方可验证）：重算 seal 与包内 seal 比对。

    seal 不匹配 = 导出后这份材料被改过；seal 匹配再看包内 verify.valid（导出时链是否完整）。
    """
    ev = pack.get("evidence", pack)
    seal = ev.get("seal")
    if not seal:
        return {"valid": False, "seal_matches": False, "chain_valid": False,
                "reason": "证据包缺少 seal，无法核验。"}
    body = {k: v for k, v in ev.items() if k != "seal"}
    seal_ok = hmac.compare_digest(_evidence_seal(body), seal)
    chain_valid = bool(ev.get("verify", {}).get("valid"))
    if not seal_ok:
        reason = "证据包 seal 不匹配——导出后内容被篡改。"
    elif not chain_valid:
        reason = "证据包封口完好，但导出时记录的哈希链 verify 为无效（库内链曾被破坏）。"
    else:
        reason = "证据包封口完好且导出时哈希链完整——材料可信。"
    return {"valid": seal_ok and chain_valid, "seal_matches": seal_ok,
            "chain_valid": chain_valid, "reason": reason}


def _session_row(r: sqlite3.Row) -> dict[str, Any]:
    return {
        "trace_id": r["trace_id"],
        "created_at": r["created_at"],
        "user_input": r["user_input"],
        "answer": r["answer"],
        "intent": r["intent"],
        "blocked": bool(r["blocked"]),
        "tainted": bool(r["tainted"]) if "tainted" in r.keys() else False,
        "llm_provider": r["llm_provider"],
    }


def _load(detail_json: str | None) -> Any:
    if detail_json is None:
        return None
    try:
        return json.loads(detail_json)
    except (json.JSONDecodeError, TypeError):
        return detail_json
