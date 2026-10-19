"""Watchlists: plain lists of what to be told about.

Each list has a kind and entries typed one per line (commas and semicolons
also separate). They match the normalized message, so a list of aircraft
hears ADS-B, ACARS and VDL2 alike.

  aircraft   ICAO hex, registration or callsign       ADS-B, ACARS, VDL2
  vessel     MMSI, ship name or callsign               AIS, DSC
  callsign   LY1ABC (any SSID) or LY1ABC-9 (that one)  APRS, Meshtastic
  device     MAC address or BSSID                      WiFi, Bluetooth, TSCM
  frequency  162.025 (MHz), 162025 kHz, 144-146        any event with a frequency
  keyword    a word or phrase, not case sensitive      decoded message text

A trailing * matches the start of an identity. Identities are compared
without case, spaces, dashes and colons (except callsign SSIDs).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from utils.database import get_db
from utils.message_normalize import (
    KIND_AIRCRAFT,
    KIND_CALLSIGN,
    KIND_DEVICE,
    KIND_VESSEL,
    NormalizedMessage,
)

KINDS = ("aircraft", "vessel", "callsign", "device", "frequency", "keyword")
SEVERITIES = ("low", "medium", "high", "critical")
DEFAULT_TOLERANCE_KHZ = 5.0

_IDENT_KIND = {
    "aircraft": KIND_AIRCRAFT,
    "vessel": KIND_VESSEL,
    "callsign": KIND_CALLSIGN,
    "device": KIND_DEVICE,
}

_SPLIT = re.compile(r"[\n,;]+")
_STRIP = re.compile(r"[\s\-:._]")


@dataclass
class Watchlist:
    id: int
    name: str
    kind: str
    entries: list[str]
    severity: str = "medium"
    enabled: bool = True
    tolerance_khz: float = DEFAULT_TOLERANCE_KHZ
    _freq_ranges: list[tuple[str, float, float]] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "entries": self.entries,
            "severity": self.severity,
            "enabled": self.enabled,
            "tolerance_khz": self.tolerance_khz,
        }


def parse_entries(text: str | list) -> list[str]:
    parts = text if isinstance(text, list) else _SPLIT.split(text or "")
    out: list[str] = []
    for part in parts:
        entry = str(part).strip()
        if entry and entry not in out:
            out.append(entry)
    return out


def parse_frequency(entry: str) -> tuple[float, float] | None:
    """An entry as (low Hz, high Hz). Plain numbers are MHz; 'kHz', 'MHz' and
    'Hz' suffixes are honoured; 'a-b' is a range in the same unit."""
    m = re.fullmatch(r"\s*([\d.]+)\s*(?:-\s*([\d.]+))?\s*(hz|khz|mhz|ghz)?\s*", entry, re.IGNORECASE)
    if not m:
        return None
    scale = {"hz": 1, "khz": 1e3, "mhz": 1e6, "ghz": 1e9}[(m.group(3) or "mhz").lower()]
    try:
        low = float(m.group(1)) * scale
        high = float(m.group(2)) * scale if m.group(2) else low
    except ValueError:
        return None
    return (min(low, high), max(low, high))


def validate(data: dict, partial: bool = False) -> dict:
    """Clean a create/update body. Raises ValueError with a message for the user."""
    out: dict = {}
    if "name" in data or not partial:
        name = str(data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")
        out["name"] = name[:120]
    if "kind" in data or not partial:
        kind = data.get("kind")
        if kind not in KINDS:
            raise ValueError(f"kind must be one of: {', '.join(KINDS)}")
        out["kind"] = kind
    if "entries" in data or not partial:
        entries = parse_entries(data.get("entries") or "")
        kind = out.get("kind") or data.get("kind")
        if kind == "frequency":
            bad = [e for e in entries if parse_frequency(e) is None]
            if bad:
                raise ValueError(f"not a frequency: {', '.join(bad[:3])}")
        out["entries"] = entries
    if "severity" in data:
        if data["severity"] not in SEVERITIES:
            raise ValueError(f"severity must be one of: {', '.join(SEVERITIES)}")
        out["severity"] = data["severity"]
    if "enabled" in data:
        out["enabled"] = bool(data["enabled"])
    if "tolerance_khz" in data:
        try:
            tol = float(data["tolerance_khz"])
        except (TypeError, ValueError):
            raise ValueError("tolerance_khz must be a number") from None
        if tol < 0:
            raise ValueError("tolerance_khz must not be negative")
        out["tolerance_khz"] = tol
    return out


# =============================================================================
# Storage
# =============================================================================


_cache: tuple[float, list[Watchlist]] | None = None


def invalidate_cache() -> None:
    global _cache
    _cache = None


def _from_row(row) -> Watchlist:
    wl = Watchlist(
        id=row["id"],
        name=row["name"],
        kind=row["kind"],
        entries=parse_entries(row["entries"] or ""),
        severity=row["severity"] or "medium",
        enabled=bool(row["enabled"]),
        tolerance_khz=row["tolerance_khz"] if row["tolerance_khz"] is not None else DEFAULT_TOLERANCE_KHZ,
    )
    if wl.kind == "frequency":
        tol = wl.tolerance_khz * 1e3
        for entry in wl.entries:
            span = parse_frequency(entry)
            if span:
                wl._freq_ranges.append((entry, span[0] - tol, span[1] + tol))
    return wl


def list_watchlists() -> list[Watchlist]:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM watchlists ORDER BY id ASC").fetchall()
    return [_from_row(r) for r in rows]


def active_watchlists() -> list[Watchlist]:
    global _cache
    now = time.monotonic()
    if _cache is None or now - _cache[0] > 10:
        _cache = (now, [w for w in list_watchlists() if w.enabled])
    return _cache[1]


def create(data: dict) -> int:
    clean = validate(data)
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO watchlists (name, kind, entries, severity, enabled, tolerance_khz) VALUES (?, ?, ?, ?, ?, ?)",
            (
                clean["name"],
                clean["kind"],
                "\n".join(clean["entries"]),
                clean.get("severity", "medium"),
                1 if clean.get("enabled", True) else 0,
                clean.get("tolerance_khz", DEFAULT_TOLERANCE_KHZ),
            ),
        )
        new_id = int(cur.lastrowid)
    invalidate_cache()
    return new_id


def update(watchlist_id: int, data: dict) -> bool:
    with get_db() as conn:
        row = conn.execute("SELECT kind, entries FROM watchlists WHERE id = ?", (watchlist_id,)).fetchone()
        if not row:
            return False
        # Entries are checked against the kind the list will have, so a
        # change of kind re-checks the entries already there
        body = {**data, "kind": data.get("kind", row["kind"])}
        if "kind" in data and "entries" not in data:
            body["entries"] = row["entries"]
        clean = validate(body, partial=True)
        if "entries" in clean:
            clean["entries"] = "\n".join(clean["entries"])
        if "enabled" in clean:
            clean["enabled"] = 1 if clean["enabled"] else 0
        if not clean:
            return True
        sets = ", ".join(f"{k} = ?" for k in clean)
        conn.execute(f"UPDATE watchlists SET {sets} WHERE id = ?", [*clean.values(), watchlist_id])  # noqa: S608
    invalidate_cache()
    return True


def delete(watchlist_id: int) -> bool:
    with get_db() as conn:
        deleted = conn.execute("DELETE FROM watchlists WHERE id = ?", (watchlist_id,)).rowcount
    invalidate_cache()
    return bool(deleted)


# =============================================================================
# Matching
# =============================================================================


def _norm(value: str) -> str:
    return _STRIP.sub("", value).upper()


def _ident_matches(entry: str, identity: str) -> bool:
    if entry.endswith("*"):
        stem = _norm(entry[:-1])
        return bool(stem) and _norm(identity).startswith(stem)
    return _norm(entry) == _norm(identity)


def _callsign_matches(entry: str, identity: str) -> bool:
    entry_u, ident_u = entry.strip().upper(), identity.strip().upper()
    if entry_u.endswith("*"):
        return ident_u.startswith(entry_u[:-1])
    if "-" in entry_u:
        return entry_u == ident_u
    return ident_u.split("-", 1)[0] == entry_u


def match(wl: Watchlist, msg: NormalizedMessage) -> str | None:
    """The entry of the list that this message matches, or None."""
    if wl.kind in _IDENT_KIND:
        if msg.kind != _IDENT_KIND[wl.kind]:
            return None
        compare = _callsign_matches if wl.kind == "callsign" else _ident_matches
        identities = msg.identities()
        for entry in wl.entries:
            if any(compare(entry, identity) for identity in identities):
                return entry
        return None

    if wl.kind == "frequency":
        if not msg.freq_hz:
            return None
        for entry, low, high in wl._freq_ranges:
            if low <= msg.freq_hz <= high:
                return entry
        return None

    if wl.kind == "keyword":
        if not msg.text:
            return None
        haystack = msg.text.lower()
        for entry in wl.entries:
            if entry.lower() in haystack:
                return entry
    return None
