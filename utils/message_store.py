"""The decoded-message database: one searchable store of what every decoder heard.

A separate SQLite file (instance/messages.db) so a million rows of traffic
never slow down the settings database. Rows are written by the event
pipeline's single worker thread; searches come from request handlers, each
on its own connection (WAL lets them read while the worker writes).

Repeated updates of a tracked object (an aircraft, a vessel, a BLE device)
are kept at most once per THROTTLE_SECONDS per object, so the store holds a
track rather than every position report.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import utils.database as database
from utils.message_normalize import NormalizedMessage

logger = logging.getLogger("intercept.message_store")

THROTTLE_SECONDS = 60
PAGE_SIZE_MAX = 500
DEFAULTS = {"enabled": True, "max_rows": 1_000_000, "max_mb": 512, "max_days": 0}

# Retention runs after this many inserts, or this long since it last ran
_RETENTION_EVERY_ROWS = 2000
_RETENTION_EVERY_SECONDS = 300

try:
    from gevent.local import local as _LocalClass
except ImportError:
    _LocalClass = threading.local  # type: ignore[assignment]

_local = _LocalClass()
_schema_lock = threading.Lock()
_schema_ready_for: Path | None = None
_fts_available = True

_last_stored: dict[tuple[str, str, str], float] = {}
_inserts_since_retention = 0
_last_retention = time.monotonic()
_settings_cache: tuple[float, dict] | None = None


def db_path() -> Path:
    # Resolved on every call: tests point database.DB_DIR at a temp directory
    return database.DB_DIR / "messages.db"


def _connect() -> sqlite3.Connection:
    path = db_path()
    conn = getattr(_local, "conn", None)
    if conn is not None and getattr(_local, "path", None) == path:
        return conn
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    _local.conn, _local.path = conn, path
    _ensure_schema(conn, path)
    return conn


def _ensure_schema(conn: sqlite3.Connection, path: Path) -> None:
    global _schema_ready_for, _fts_available
    with _schema_lock:
        if _schema_ready_for == path:
            return
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                mode TEXT NOT NULL,
                event_type TEXT,
                ident TEXT,
                aliases TEXT,
                freq_hz REAL,
                lat REAL,
                lon REAL,
                summary TEXT,
                text TEXT,
                payload TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_mode_ts ON messages(mode, ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_ident ON messages(ident)")
        try:
            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                    ident, aliases, summary, text,
                    content='messages', content_rowid='id'
                )
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
                    INSERT INTO messages_fts(rowid, ident, aliases, summary, text)
                    VALUES (new.id, new.ident, new.aliases, new.summary, new.text);
                END
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
                    INSERT INTO messages_fts(messages_fts, rowid, ident, aliases, summary, text)
                    VALUES ('delete', old.id, old.ident, old.aliases, old.summary, old.text);
                END
            """)
            _fts_available = True
        except sqlite3.OperationalError:
            # SQLite built without FTS5: search falls back to LIKE
            logger.warning("SQLite has no FTS5; message search will use slower substring matching")
            _fts_available = False
        conn.commit()
        _schema_ready_for = path


# =============================================================================
# Settings
# =============================================================================


def get_settings() -> dict:
    global _settings_cache
    now = time.monotonic()
    if _settings_cache and now - _settings_cache[0] < 10:
        return dict(_settings_cache[1])
    settings = {key: database.get_setting(f"messages.{key}", default) for key, default in DEFAULTS.items()}
    _settings_cache = (now, settings)
    return dict(settings)


def update_settings(changes: dict) -> dict:
    global _settings_cache
    for key, value in changes.items():
        if key not in DEFAULTS:
            raise ValueError(f"unknown setting: {key}")
        if key == "enabled":
            value = bool(value)
        else:
            value = int(value)
            if value < 0:
                raise ValueError(f"{key} must not be negative")
        database.set_setting(f"messages.{key}", value)
    _settings_cache = None
    return get_settings()


# =============================================================================
# Writing
# =============================================================================


def record(msg: NormalizedMessage | None) -> bool:
    """Store one normalized message. Returns whether a row was written."""
    global _inserts_since_retention
    if msg is None or not get_settings()["enabled"]:
        return False

    now = time.time()
    if msg.tracked and msg.ident:
        key = (msg.mode, msg.event_type or "", msg.ident)
        last = _last_stored.get(key)
        if last is not None and now - last < THROTTLE_SECONDS:
            return False
        _last_stored[key] = now
        if len(_last_stored) > 50_000:
            _prune_throttle(now)

    conn = _connect()
    conn.execute(
        """
        INSERT INTO messages (ts, mode, event_type, ident, aliases, freq_hz, lat, lon, summary, text, payload)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            now,
            msg.mode,
            msg.event_type,
            msg.ident,
            " ".join(msg.aliases),
            msg.freq_hz,
            msg.lat,
            msg.lon,
            msg.summary,
            msg.text,
            json.dumps(msg.payload, default=str),
        ),
    )
    conn.commit()

    _inserts_since_retention += 1
    if (
        _inserts_since_retention >= _RETENTION_EVERY_ROWS
        or time.monotonic() - _last_retention > _RETENTION_EVERY_SECONDS
    ):
        apply_retention()
    return True


def _prune_throttle(now: float) -> None:
    for key in [k for k, t in _last_stored.items() if now - t >= THROTTLE_SECONDS]:
        del _last_stored[key]


def apply_retention() -> int:
    """Delete the oldest rows until the row, size and age limits hold."""
    global _inserts_since_retention, _last_retention
    _inserts_since_retention = 0
    _last_retention = time.monotonic()
    settings = get_settings()
    conn = _connect()
    deleted = 0

    if settings["max_days"] > 0:
        cutoff = time.time() - settings["max_days"] * 86400
        deleted += conn.execute("DELETE FROM messages WHERE ts < ?", (cutoff,)).rowcount

    if settings["max_rows"] > 0:
        count = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        if count > settings["max_rows"]:
            deleted += _delete_oldest(conn, count - settings["max_rows"])

    if settings["max_mb"] > 0:
        cap = settings["max_mb"] * 1024 * 1024
        # Deleted pages are reused, not returned to the OS, so measure used pages
        for _ in range(20):
            if _used_bytes(conn) <= cap:
                break
            count = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
            if not count:
                break
            deleted += _delete_oldest(conn, max(1, count // 10))

    conn.commit()
    return deleted


def _delete_oldest(conn: sqlite3.Connection, n: int) -> int:
    return conn.execute(
        "DELETE FROM messages WHERE id IN (SELECT id FROM messages ORDER BY id ASC LIMIT ?)", (n,)
    ).rowcount


def _used_bytes(conn: sqlite3.Connection) -> int:
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    pages = conn.execute("PRAGMA page_count").fetchone()[0]
    free = conn.execute("PRAGMA freelist_count").fetchone()[0]
    return (pages - free) * page_size


def clear() -> int:
    conn = _connect()
    deleted = conn.execute("DELETE FROM messages").rowcount
    conn.commit()
    _last_stored.clear()
    return deleted


# =============================================================================
# Reading
# =============================================================================


def fts_query(text: str) -> str:
    """User words to an FTS5 query: every word must appear, word* is a prefix.

    Each word is quoted, so FTS5 operators and punctuation in what the user
    typed (AND, NEAR, a colon in a MAC address) are searched for, not parsed.
    """
    terms = []
    for word in text.split():
        prefix = word.endswith("*")
        word = word.rstrip("*").replace('"', "")
        if not word:
            continue
        terms.append(f'"{word}"*' if prefix else f'"{word}"')
    return " ".join(terms)


def _where(filters: dict) -> tuple[str, list]:
    clauses: list[str] = []
    params: list[Any] = []
    q = (filters.get("q") or "").strip()
    if q:
        if _fts_available:
            match = fts_query(q)
            if match:
                clauses.append("m.id IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)")
                params.append(match)
        else:
            for word in q.split():
                like = f"%{word.rstrip('*')}%"
                clauses.append("(m.ident LIKE ? OR m.aliases LIKE ? OR m.summary LIKE ? OR m.text LIKE ?)")
                params.extend([like] * 4)
    modes = filters.get("modes")
    if modes:
        clauses.append(f"m.mode IN ({','.join('?' * len(modes))})")
        params.extend(modes)
    if filters.get("ident"):
        clauses.append("(m.ident = ? COLLATE NOCASE)")
        params.append(filters["ident"])
    if filters.get("since") is not None:
        clauses.append("m.ts >= ?")
        params.append(float(filters["since"]))
    if filters.get("until") is not None:
        clauses.append("m.ts <= ?")
        params.append(float(filters["until"]))
    if filters.get("has_position"):
        clauses.append("m.lat IS NOT NULL")
    if filters.get("before_id"):
        clauses.append("m.id < ?")
        params.append(int(filters["before_id"]))
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def _row(row: sqlite3.Row, with_payload: bool) -> dict:
    out = {
        "id": row["id"],
        "ts": row["ts"],
        "mode": row["mode"],
        "event_type": row["event_type"],
        "ident": row["ident"],
        "aliases": row["aliases"].split() if row["aliases"] else [],
        "freq_hz": row["freq_hz"],
        "lat": row["lat"],
        "lon": row["lon"],
        "summary": row["summary"],
        "text": row["text"],
    }
    if with_payload:
        try:
            out["payload"] = json.loads(row["payload"]) if row["payload"] else {}
        except json.JSONDecodeError:
            out["payload"] = {}
    return out


def search(filters: dict, limit: int = 100) -> dict:
    """Newest first. Page on with before_id = the last row's id."""
    limit = max(1, min(int(limit), PAGE_SIZE_MAX))
    where, params = _where(filters)
    conn = _connect()
    rows = conn.execute(
        f"SELECT * FROM messages m{where} ORDER BY m.id DESC LIMIT ?",  # noqa: S608 - clauses are fixed strings
        [*params, limit + 1],
    ).fetchall()
    more = len(rows) > limit
    items = [_row(r, with_payload=False) for r in rows[:limit]]
    return {"messages": items, "next_before_id": items[-1]["id"] if more else None}


def get(message_id: int) -> dict | None:
    row = _connect().execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
    return _row(row, with_payload=True) if row else None


def iter_matching(filters: dict, batch: int = 1000) -> Iterator[dict]:
    """Every row the filters match, newest first, with payloads (for export)."""
    filters = dict(filters)
    while True:
        where, params = _where(filters)
        rows = (
            _connect()
            .execute(
                f"SELECT * FROM messages m{where} ORDER BY m.id DESC LIMIT ?",  # noqa: S608
                [*params, batch],
            )
            .fetchall()
        )
        if not rows:
            return
        for row in rows:
            yield _row(row, with_payload=True)
        filters["before_id"] = rows[-1]["id"]


def stats() -> dict:
    conn = _connect()
    by_mode = {r["mode"]: r["n"] for r in conn.execute("SELECT mode, COUNT(*) AS n FROM messages GROUP BY mode")}
    oldest = conn.execute("SELECT MIN(ts) FROM messages").fetchone()[0]
    return {
        "total": sum(by_mode.values()),
        "by_mode": by_mode,
        "oldest_ts": oldest,
        "used_bytes": _used_bytes(conn),
        "full_text_search": _fts_available,
        "settings": get_settings(),
    }
