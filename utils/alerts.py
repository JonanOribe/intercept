"""Alerting engine for cross-mode events."""

from __future__ import annotations

import json
import logging
import queue
import re
import threading
import time
from collections import deque
from collections.abc import Generator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from utils import alert_channels, watchlists
from utils.database import get_db, get_setting, set_setting
from utils.message_normalize import NormalizedMessage, normalize

logger = logging.getLogger("intercept.alerts")

# Limits on pushes. Cooldown: the same rule or watchlist entry on the same
# station fires again only after this many minutes. Quiet hours (server local
# time, may run over midnight): alerts are kept in the history but not pushed.
LIMIT_DEFAULTS = {"max_per_hour": 30, "cooldown_minutes": 5, "quiet_start": "", "quiet_end": ""}

_HHMM = re.compile(r"([01]\d|2[0-3]):[0-5]\d")


@dataclass
class AlertRule:
    id: int
    name: str
    mode: str | None
    event_type: str | None
    match: dict
    severity: str
    enabled: bool
    notify: dict
    created_at: str | None = None


class AlertManager:
    def __init__(self) -> None:
        self._queue: queue.Queue = queue.Queue(maxsize=1000)
        self._rules_cache: list[AlertRule] = []
        self._rules_loaded_at = 0.0
        self._cache_lock = threading.Lock()
        self._limits_cache: tuple[float, dict] | None = None
        self._last_fired: dict[tuple, float] = {}
        self._pushed: deque[float] = deque()
        # process_event runs on the pipeline worker and on some decoder threads
        self._limit_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def invalidate_cache(self) -> None:
        with self._cache_lock:
            self._rules_loaded_at = 0.0

    def _load_rules(self) -> None:
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT id, name, mode, event_type, match, severity, enabled, notify, created_at
                FROM alert_rules
                WHERE enabled = 1
                ORDER BY id ASC
            """)
            rules: list[AlertRule] = []
            for row in cursor:
                match = {}
                notify = {}
                try:
                    match = json.loads(row["match"]) if row["match"] else {}
                except json.JSONDecodeError:
                    match = {}
                try:
                    notify = json.loads(row["notify"]) if row["notify"] else {}
                except json.JSONDecodeError:
                    notify = {}
                rules.append(
                    AlertRule(
                        id=row["id"],
                        name=row["name"],
                        mode=row["mode"],
                        event_type=row["event_type"],
                        match=match,
                        severity=row["severity"] or "medium",
                        enabled=bool(row["enabled"]),
                        notify=notify,
                        created_at=row["created_at"],
                    )
                )
        with self._cache_lock:
            self._rules_cache = rules
            self._rules_loaded_at = time.time()

    def _get_rules(self) -> list[AlertRule]:
        with self._cache_lock:
            stale = (time.time() - self._rules_loaded_at) > 10
        if stale:
            self._load_rules()
        with self._cache_lock:
            return list(self._rules_cache)

    def list_rules(self, include_disabled: bool = False) -> list[dict]:
        with get_db() as conn:
            if include_disabled:
                cursor = conn.execute("""
                    SELECT id, name, mode, event_type, match, severity, enabled, notify, created_at
                    FROM alert_rules
                    ORDER BY id DESC
                """)
            else:
                cursor = conn.execute("""
                    SELECT id, name, mode, event_type, match, severity, enabled, notify, created_at
                    FROM alert_rules
                    WHERE enabled = 1
                    ORDER BY id DESC
                """)

            return [
                {
                    "id": row["id"],
                    "name": row["name"],
                    "mode": row["mode"],
                    "event_type": row["event_type"],
                    "match": json.loads(row["match"]) if row["match"] else {},
                    "severity": row["severity"],
                    "enabled": bool(row["enabled"]),
                    "notify": json.loads(row["notify"]) if row["notify"] else {},
                    "created_at": row["created_at"],
                }
                for row in cursor
            ]

    def add_rule(self, rule: dict) -> int:
        with get_db() as conn:
            cursor = conn.execute(
                """
                INSERT INTO alert_rules (name, mode, event_type, match, severity, enabled, notify)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    rule.get("name") or "Alert Rule",
                    rule.get("mode"),
                    rule.get("event_type"),
                    json.dumps(rule.get("match") or {}),
                    rule.get("severity") or "medium",
                    1 if rule.get("enabled", True) else 0,
                    json.dumps(rule.get("notify") or {}),
                ),
            )
            rule_id = cursor.lastrowid
        self.invalidate_cache()
        return int(rule_id)

    def update_rule(self, rule_id: int, updates: dict) -> bool:
        fields = []
        params = []
        for key in ("name", "mode", "event_type", "severity"):
            if key in updates:
                fields.append(f"{key} = ?")
                params.append(updates[key])
        if "enabled" in updates:
            fields.append("enabled = ?")
            params.append(1 if updates["enabled"] else 0)
        if "match" in updates:
            fields.append("match = ?")
            params.append(json.dumps(updates["match"] or {}))
        if "notify" in updates:
            fields.append("notify = ?")
            params.append(json.dumps(updates["notify"] or {}))

        if not fields:
            return False

        params.append(rule_id)
        with get_db() as conn:
            cursor = conn.execute(f"UPDATE alert_rules SET {', '.join(fields)} WHERE id = ?", params)
            updated = cursor.rowcount > 0

        if updated:
            self.invalidate_cache()
        return updated

    def delete_rule(self, rule_id: int) -> bool:
        with get_db() as conn:
            cursor = conn.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
            deleted = cursor.rowcount > 0
        if deleted:
            self.invalidate_cache()
        return deleted

    def list_events(self, limit: int = 100, mode: str | None = None, severity: str | None = None) -> list[dict]:
        query = (
            "SELECT id, rule_id, watchlist_id, mode, event_type, severity, title, message, ident, delivery,"
            " payload, created_at FROM alert_events"
        )
        clauses = []
        params: list[Any] = []
        if mode:
            clauses.append("mode = ?")
            params.append(mode)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with get_db() as conn:
            cursor = conn.execute(query, params)
            events = []
            for row in cursor:
                events.append(
                    {
                        "id": row["id"],
                        "rule_id": row["rule_id"],
                        "watchlist_id": row["watchlist_id"],
                        "mode": row["mode"],
                        "event_type": row["event_type"],
                        "severity": row["severity"],
                        "title": row["title"],
                        "message": row["message"],
                        "ident": row["ident"],
                        "delivery": row["delivery"],
                        "payload": json.loads(row["payload"]) if row["payload"] else {},
                        "created_at": row["created_at"],
                    }
                )
            return events

    # ------------------------------------------------------------------
    # Limits
    # ------------------------------------------------------------------

    def get_limits(self) -> dict:
        now = time.monotonic()
        if self._limits_cache and now - self._limits_cache[0] < 10:
            return dict(self._limits_cache[1])
        limits = {key: get_setting(f"alerts.{key}", default) for key, default in LIMIT_DEFAULTS.items()}
        self._limits_cache = (now, limits)
        return dict(limits)

    def update_limits(self, changes: dict) -> dict:
        for key, value in changes.items():
            if key not in LIMIT_DEFAULTS:
                raise ValueError(f"unknown setting: {key}")
            if key in ("quiet_start", "quiet_end"):
                value = str(value or "").strip()
                if value and not _HHMM.fullmatch(value):
                    raise ValueError(f"{key} must be HH:MM or empty")
            else:
                value = int(value)
                if value < 0:
                    raise ValueError(f"{key} must not be negative")
            set_setting(f"alerts.{key}", value)
        self._limits_cache = None
        return self.get_limits()

    def _cooling_down(self, key: tuple, minutes: int, now: float) -> bool:
        """True if this key fired within the cooldown; otherwise marks it fired."""
        if minutes <= 0:
            return False
        with self._limit_lock:
            return self._cooling_down_locked(key, minutes, now)

    def _cooling_down_locked(self, key: tuple, minutes: int, now: float) -> bool:
        last = self._last_fired.get(key)
        if last is not None and now - last < minutes * 60:
            return True
        self._last_fired[key] = now
        if len(self._last_fired) > 20_000:
            horizon = now - minutes * 60
            self._last_fired = {k: t for k, t in self._last_fired.items() if t >= horizon}
        return False

    def _delivery(self, push: bool, limits: dict, now: float) -> str:
        """What happens to the push for an alert that fired now."""
        if not push:
            return "off"
        if _in_quiet_hours(limits.get("quiet_start"), limits.get("quiet_end"), datetime.now()):
            return "quiet_hours"
        if not alert_channels.has_channels():
            return "no_channel"
        with self._limit_lock:
            return self._take_push_slot(limits, now)

    def _take_push_slot(self, limits: dict, now: float) -> str:
        while self._pushed and now - self._pushed[0] > 3600:
            self._pushed.popleft()
        cap = limits.get("max_per_hour") or 0
        if cap and len(self._pushed) >= cap:
            return "rate_limited"
        self._pushed.append(now)
        return "sent"

    # ------------------------------------------------------------------
    # Event processing
    # ------------------------------------------------------------------

    def process_event(
        self,
        mode: str,
        event: dict,
        event_type: str | None = None,
        msg: NormalizedMessage | None = None,
    ) -> None:
        if not isinstance(event, dict):
            return

        if event_type in ("keepalive", "ping", "status"):
            return

        if msg is None:
            msg = normalize(mode, event, event_type)
        ident = msg.ident if msg else None
        limits = self.get_limits()
        now = time.monotonic()

        for rule in self._get_rules():
            if rule.mode and rule.mode != mode:
                continue
            if rule.event_type and event_type and rule.event_type != event_type:
                continue
            if rule.event_type and not event_type:
                continue
            if not self._match_rule(rule.match, event):
                continue
            # The same rule on the same station again only after the cooldown;
            # without this a rule on a moving aircraft fires every second
            notify = rule.notify if isinstance(rule.notify, dict) else {}
            cooldown = int(notify.get("cooldown_minutes", limits["cooldown_minutes"]))
            if ident and self._cooling_down(("rule", rule.id, mode, ident), cooldown, now):
                continue

            push = notify.get("push", notify.get("webhook", True)) is not False
            self._fire(
                rule_id=rule.id,
                watchlist_id=None,
                title=rule.name or "Alert",
                message=self._build_message(rule, event, event_type),
                severity=rule.severity,
                mode=mode,
                event_type=event_type,
                ident=ident,
                payload={
                    "mode": mode,
                    "event_type": event_type,
                    "event": event,
                    "rule": {"id": rule.id, "name": rule.name},
                },
                push=push,
                limits=limits,
                now=now,
            )

        if msg is None:
            return
        for wl in watchlists.active_watchlists():
            entry = watchlists.match(wl, msg)
            if entry is None:
                continue
            if self._cooling_down(
                ("watchlist", wl.id, entry, mode, ident or msg.summary), limits["cooldown_minutes"], now
            ):
                continue
            self._fire(
                rule_id=None,
                watchlist_id=wl.id,
                title=f"{wl.name}: {entry}",
                message=f"{mode.upper()} {msg.summary}".strip(),
                severity=wl.severity,
                mode=mode,
                event_type=event_type,
                ident=ident,
                payload={
                    "mode": mode,
                    "event_type": event_type,
                    "event": event,
                    "watchlist": {"id": wl.id, "name": wl.name, "kind": wl.kind, "matched": entry},
                    "freq_hz": msg.freq_hz,
                },
                push=True,
                limits=limits,
                now=now,
            )

    def _fire(
        self,
        *,
        rule_id: int | None,
        watchlist_id: int | None,
        title: str,
        message: str,
        severity: str,
        mode: str,
        event_type: str | None,
        ident: str | None,
        payload: dict,
        push: bool,
        limits: dict,
        now: float,
    ) -> None:
        delivery = self._delivery(push, limits, now)
        event_id = self._store_event(
            rule_id, watchlist_id, mode, event_type, severity, title, message, ident, delivery, payload
        )
        alert_payload = {
            "id": event_id,
            "rule_id": rule_id,
            "watchlist_id": watchlist_id,
            "mode": mode,
            "event_type": event_type,
            "severity": severity,
            "title": title,
            "message": message,
            "ident": ident,
            "delivery": delivery,
            "payload": payload,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._queue_event(alert_payload)
        if delivery == "sent":
            alert_channels.enqueue(alert_payload)

    def _build_message(self, rule: AlertRule, event: dict, event_type: str | None) -> str:
        if isinstance(rule.notify, dict) and rule.notify.get("message"):
            return str(rule.notify.get("message"))
        summary_bits = []
        if event_type:
            summary_bits.append(event_type)
        if "name" in event:
            summary_bits.append(str(event.get("name")))
        if "ssid" in event:
            summary_bits.append(str(event.get("ssid")))
        if "bssid" in event:
            summary_bits.append(str(event.get("bssid")))
        if "address" in event:
            summary_bits.append(str(event.get("address")))
        if "mac" in event:
            summary_bits.append(str(event.get("mac")))
        summary = " | ".join(summary_bits) if summary_bits else "Alert triggered"
        return summary

    def _store_event(
        self,
        rule_id: int | None,
        watchlist_id: int | None,
        mode: str,
        event_type: str | None,
        severity: str,
        title: str,
        message: str,
        ident: str | None,
        delivery: str,
        payload: dict,
    ) -> int:
        with get_db() as conn:
            cursor = conn.execute(
                """
                INSERT INTO alert_events
                    (rule_id, watchlist_id, mode, event_type, severity, title, message, ident, delivery, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    rule_id,
                    watchlist_id,
                    mode,
                    event_type,
                    severity,
                    title,
                    message,
                    ident,
                    delivery,
                    json.dumps(payload, default=str),
                ),
            )
            return int(cursor.lastrowid)

    def _queue_event(self, alert_payload: dict) -> None:
        try:
            self._queue.put_nowait(alert_payload)
        except queue.Full:
            try:
                self._queue.get_nowait()
                self._queue.put_nowait(alert_payload)
            except queue.Empty:
                pass

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def _match_rule(self, rule_match: dict, event: dict) -> bool:
        if not rule_match:
            return True

        for key, expected in rule_match.items():
            actual = self._extract_value(event, key)
            if not self._match_value(actual, expected):
                return False
        return True

    def _extract_value(self, event: dict, key: str) -> Any:
        if "." not in key:
            return event.get(key)
        current: Any = event
        for part in key.split("."):
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current

    def _match_value(self, actual: Any, expected: Any) -> bool:
        if isinstance(expected, dict) and "op" in expected:
            op = expected.get("op")
            value = expected.get("value")
            return self._apply_op(op, actual, value)

        if isinstance(expected, list):
            return actual in expected

        if isinstance(expected, str):
            if actual is None:
                return False
            return str(actual).lower() == expected.lower()

        return actual == expected

    def _apply_op(self, op: str, actual: Any, value: Any) -> bool:
        if op == "exists":
            return actual is not None
        if op == "eq":
            return actual == value
        if op == "neq":
            return actual != value
        if op == "gt":
            return _safe_number(actual) is not None and _safe_number(actual) > _safe_number(value)
        if op == "gte":
            return _safe_number(actual) is not None and _safe_number(actual) >= _safe_number(value)
        if op == "lt":
            return _safe_number(actual) is not None and _safe_number(actual) < _safe_number(value)
        if op == "lte":
            return _safe_number(actual) is not None and _safe_number(actual) <= _safe_number(value)
        if op == "in":
            return actual in (value or [])
        if op == "contains":
            if actual is None:
                return False
            if isinstance(actual, list):
                return any(str(value).lower() in str(item).lower() for item in actual)
            return str(value).lower() in str(actual).lower()
        if op == "regex":
            if actual is None or value is None:
                return False
            try:
                return re.search(str(value), str(actual)) is not None
            except re.error:
                return False
        return False

    # ------------------------------------------------------------------
    # Streaming
    # ------------------------------------------------------------------

    def stream_events(self, timeout: float = 1.0) -> Generator[dict, None, None]:
        while True:
            try:
                event = self._queue.get(timeout=timeout)
                yield event
            except queue.Empty:
                yield {"type": "keepalive"}


_alert_manager: AlertManager | None = None
_alert_lock = threading.Lock()


def get_alert_manager() -> AlertManager:
    global _alert_manager
    with _alert_lock:
        if _alert_manager is None:
            _alert_manager = AlertManager()
        return _alert_manager


def _safe_number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _in_quiet_hours(start: str | None, end: str | None, now: datetime) -> bool:
    if not start or not end or start == end:
        return False
    current = now.strftime("%H:%M")
    if start < end:
        return start <= current < end
    return current >= start or current < end
