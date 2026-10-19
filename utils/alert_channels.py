"""Where alerts are pushed: ntfy, a Telegram bot, or a generic webhook.

Channels are stored in the alert_channels table. Tokens are kept there and
never returned by the API, written to a log, or put in an alert's history;
the API reports only whether one is set.

Delivery runs on its own thread with a bounded queue, so a slow or dead
endpoint never holds up the event pipeline.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import urllib.parse
import urllib.request

from config import ALERT_WEBHOOK_SECRET, ALERT_WEBHOOK_TIMEOUT, ALERT_WEBHOOK_URL
from utils.database import get_db

logger = logging.getLogger("intercept.alert_channels")

KINDS = ("ntfy", "telegram", "webhook")

# Per kind: required fields, optional fields, and which of them are secret
_FIELDS = {
    "ntfy": (("server", "topic"), ("token",), ("token",)),
    "telegram": (("bot_token", "chat_id"), (), ("bot_token",)),
    "webhook": (("url",), ("token",), ("token",)),
}

_NTFY_PRIORITY = {"low": "2", "medium": "3", "high": "4", "critical": "5"}

_outbox: queue.Queue = queue.Queue(maxsize=200)
_sender: threading.Thread | None = None
_sender_lock = threading.Lock()


# =============================================================================
# Storage
# =============================================================================


def _clean_config(kind: str, config: dict, existing: dict | None = None) -> dict:
    required, optional, secrets = _FIELDS[kind]
    out: dict = {}
    for key in (*required, *optional):
        value = str(config.get(key) or "").strip()
        if not value and existing and key in secrets:
            # A blank secret on update means "keep the one already stored"
            value = existing.get(key, "")
        if key in required and not value:
            raise ValueError(f"{key} is required for {kind}")
        if value:
            out[key] = value
    for key in ("server", "url"):
        if key in out and urllib.parse.urlparse(out[key]).scheme not in ("http", "https"):
            raise ValueError(f"{key} must be an http(s) address")
    return out


def _public(row) -> dict:
    config = json.loads(row["config"] or "{}")
    secrets = _FIELDS.get(row["kind"], ((), (), ()))[2]
    shown = {k: v for k, v in config.items() if k not in secrets}
    for key in secrets:
        shown[f"{key}_set"] = bool(config.get(key))
    return {
        "id": row["id"],
        "kind": row["kind"],
        "name": row["name"],
        "enabled": bool(row["enabled"]),
        "config": shown,
    }


def list_channels() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM alert_channels ORDER BY id ASC").fetchall()
    return [_public(r) for r in rows]


def create(data: dict) -> int:
    kind = data.get("kind")
    if kind not in KINDS:
        raise ValueError(f"kind must be one of: {', '.join(KINDS)}")
    config = _clean_config(kind, data.get("config") or {})
    name = str(data.get("name") or kind).strip()[:120]
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO alert_channels (kind, name, config, enabled) VALUES (?, ?, ?, ?)",
            (kind, name, json.dumps(config), 1 if data.get("enabled", True) else 0),
        )
        return int(cur.lastrowid)


def update(channel_id: int, data: dict) -> bool:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM alert_channels WHERE id = ?", (channel_id,)).fetchone()
        if not row:
            return False
        name = str(data.get("name") or row["name"]).strip()[:120]
        enabled = bool(data["enabled"]) if "enabled" in data else bool(row["enabled"])
        config = json.loads(row["config"] or "{}")
        if "config" in data:
            config = _clean_config(row["kind"], data["config"] or {}, existing=config)
        conn.execute(
            "UPDATE alert_channels SET name = ?, config = ?, enabled = ? WHERE id = ?",
            (name, json.dumps(config), 1 if enabled else 0, channel_id),
        )
    return True


def delete(channel_id: int) -> bool:
    with get_db() as conn:
        return bool(conn.execute("DELETE FROM alert_channels WHERE id = ?", (channel_id,)).rowcount)


def _enabled_channels(channel_id: int | None = None) -> list[tuple[str, str, dict]]:
    """(kind, name, config with secrets) of every enabled channel, plus the
    INTERCEPT_ALERT_WEBHOOK_URL webhook when that is set."""
    with get_db() as conn:
        if channel_id is None:
            rows = conn.execute("SELECT * FROM alert_channels WHERE enabled = 1").fetchall()
        else:
            rows = conn.execute("SELECT * FROM alert_channels WHERE id = ?", (channel_id,)).fetchall()
    channels = [(r["kind"], r["name"], json.loads(r["config"] or "{}")) for r in rows]
    if channel_id is None and ALERT_WEBHOOK_URL:
        channels.append(("webhook", "environment", {"url": ALERT_WEBHOOK_URL, "legacy_secret": ALERT_WEBHOOK_SECRET}))
    return channels


def has_channels() -> bool:
    return bool(_enabled_channels())


# =============================================================================
# Delivery
# =============================================================================


def _post(url: str, body: bytes, headers: dict) -> None:
    req = urllib.request.Request(url, data=body, headers={"User-Agent": "Intercept-Alert", **headers}, method="POST")
    with urllib.request.urlopen(req, timeout=ALERT_WEBHOOK_TIMEOUT) as resp:  # noqa: S310 - scheme checked on save
        resp.read(0)


def send_one(kind: str, config: dict, alert: dict) -> None:
    """Deliver one alert to one channel. Raises on failure."""
    title = str(alert.get("title") or "Alert")
    message = str(alert.get("message") or "")
    severity = str(alert.get("severity") or "medium")

    if kind == "ntfy":
        url = f"{config['server'].rstrip('/')}/{urllib.parse.quote(config['topic'])}"
        headers = {
            # HTTP headers must be latin-1; ntfy reads RFC 2047 for anything else
            "Title": title.encode("latin-1", "replace").decode("latin-1"),
            "Priority": _NTFY_PRIORITY.get(severity, "3"),
            "Tags": f"intercept,{alert.get('mode') or 'alert'}",
        }
        if config.get("token"):
            headers["Authorization"] = f"Bearer {config['token']}"
        _post(url, message.encode("utf-8"), headers)
    elif kind == "telegram":
        url = f"https://api.telegram.org/bot{config['bot_token']}/sendMessage"
        body = json.dumps({"chat_id": config["chat_id"], "text": f"{title}\n{message}".strip()}).encode("utf-8")
        _post(url, body, {"Content-Type": "application/json"})
    elif kind == "webhook":
        headers = {"Content-Type": "application/json"}
        if config.get("token"):
            headers["Authorization"] = f"Bearer {config['token']}"
        if "legacy_secret" in config:
            headers["X-Alert-Token"] = config["legacy_secret"] or ""
        _post(config["url"], json.dumps(alert, default=str).encode("utf-8"), headers)
    else:
        raise ValueError(f"unknown channel kind {kind}")


def enqueue(alert: dict) -> bool:
    """Queue an alert for every enabled channel. False if the outbox is full."""
    _ensure_sender()
    try:
        _outbox.put_nowait(alert)
        return True
    except queue.Full:
        logger.warning("Alert outbox full; dropping push for %s", alert.get("title"))
        return False


def send_test(channel_id: int | None = None) -> list[dict]:
    """Send a test alert now (not queued) and report each channel's result."""
    alert = {
        "title": "INTERCEPT test alert",
        "message": "If you can read this, alerts reach this channel.",
        "severity": "low",
        "mode": "test",
    }
    results = []
    for kind, name, config in _enabled_channels(channel_id):
        try:
            send_one(kind, config, alert)
            results.append({"channel": name, "kind": kind, "ok": True})
        except Exception as e:
            # The error text can carry the URL, and a Telegram URL holds the token
            results.append({"channel": name, "kind": kind, "ok": False, "error": type(e).__name__})
    return results


def _ensure_sender() -> None:
    global _sender
    if _sender is not None and _sender.is_alive():
        return
    with _sender_lock:
        if _sender is None or not _sender.is_alive():
            _sender = threading.Thread(target=_send_loop, name="alert-sender", daemon=True)
            _sender.start()


def _send_loop() -> None:
    while True:
        alert = _outbox.get()
        try:
            for kind, name, config in _enabled_channels():
                try:
                    send_one(kind, config, alert)
                except Exception as e:
                    logger.info("Alert push to %s (%s) failed: %s", name, kind, type(e).__name__)
        except Exception as e:
            logger.debug("Alert sender error: %s", e)
        finally:
            _outbox.task_done()
