"""One shape for every decoded event: who sent it, on what frequency, where,
and what it said.

The message store indexes this shape and the watchlists match against it,
so a mode only has to be taught here once. normalize() returns None for
events that are not decoded traffic (status lines, spectra, progress).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Event types that never carry decoded traffic
SKIP_TYPES = frozenset(
    {
        "keepalive",
        "ping",
        "status",
        "error",
        "info",
        "raw",
        "log",
        "scope",
        "meter",
        "stats",
        "progress",
        "privileges",
        "internal",
        "managed",
        "controller",
        "hci",
        "macos",
        "baseline",
        "devices",
        "scan_started",
        "scan_stopped",
        "scan_error",
        "scan_update",
        "freq_change",
        "signal_lost",
        "signal_skipped",
        "sstv_progress",
        "waterfall_sweep",
        "waterfall_error",
        "morse_char",
        "morse_element",
        "morse_gap",
        "morse_space",
        "ook_raw",
        "deauth_detector_started",
        "deauth_detector_stopped",
        "deauth_error",
    }
)

# Prefixes of event types that are measurements rather than traffic
# (subghz rx_level, rx_spectrum, decode_waveform, ...)
SKIP_TYPE_PREFIXES = ("rx_", "decode_", "tx_")

SKIP_MODES = frozenset({"waterfall"})

# Modes whose events are repeated updates of the same object (a position,
# a signal level). The store keeps these at most once per interval per object.
TRACKED_MODES = frozenset(
    {"adsb", "ais", "radiosonde", "drone", "wifi", "bluetooth", "meshtastic", "gps", "sensor", "rtlamr"}
)

# Events of tracked modes that are news, not another position report
DISCRETE_TYPES = frozenset({"geofence", "probe_request", "hidden_revealed", "message"})

# Kinds of identity, used by watchlists to know which entries apply
KIND_AIRCRAFT = "aircraft"
KIND_VESSEL = "vessel"
KIND_CALLSIGN = "callsign"
KIND_DEVICE = "device"
KIND_OTHER = "other"

_MODE_KIND = {
    "adsb": KIND_AIRCRAFT,
    "acars": KIND_AIRCRAFT,
    "vdl2": KIND_AIRCRAFT,
    "ais": KIND_VESSEL,
    "dsc": KIND_VESSEL,
    "aprs": KIND_CALLSIGN,
    "meshtastic": KIND_CALLSIGN,
    "wifi": KIND_DEVICE,
    "bluetooth": KIND_DEVICE,
    "tscm": KIND_DEVICE,
}

# Fields that hold message text, in order of preference
_TEXT_FIELDS = ("message", "text", "msg_text", "comment", "status_text", "payload_text")


@dataclass
class NormalizedMessage:
    mode: str
    event_type: str | None
    kind: str
    ident: str | None
    aliases: list[str] = field(default_factory=list)
    freq_hz: float | None = None
    lat: float | None = None
    lon: float | None = None
    text: str = ""
    summary: str = ""
    tracked: bool = False
    payload: dict = field(default_factory=dict)

    def identities(self) -> list[str]:
        """The ident and every alias, without blanks or repeats."""
        seen: list[str] = []
        for value in [self.ident, *self.aliases]:
            if value and value not in seen:
                seen.append(value)
        return seen


def normalize(mode: str, event: Any, event_type: str | None = None) -> NormalizedMessage | None:
    if not isinstance(event, dict) or mode in SKIP_MODES:
        return None
    etype = event_type or event.get("type")
    if etype in SKIP_TYPES or (isinstance(etype, str) and etype.startswith(SKIP_TYPE_PREFIXES)):
        return None

    extractor = _EXTRACTORS.get(mode, _generic)
    ident, aliases, summary = extractor(event)

    text = _text(event)
    lat, lon = _position(event)
    msg = NormalizedMessage(
        mode=mode,
        event_type=etype,
        kind=_MODE_KIND.get(mode, KIND_OTHER),
        ident=_clean(ident),
        aliases=[a for a in (_clean(a) for a in aliases) if a],
        freq_hz=_freq_hz(event),
        lat=lat,
        lon=lon,
        text=text,
        tracked=mode in TRACKED_MODES and etype not in DISCRETE_TYPES,
        payload=event,
    )
    msg.summary = summary or _default_summary(msg)
    if not (msg.ident or msg.text or msg.freq_hz or msg.lat is not None):
        # Nothing to identify, search or place: not worth a row
        return None
    return msg


# =============================================================================
# Per-mode extractors: (ident, aliases, summary)
# =============================================================================


def _pager(e: dict) -> tuple[Any, list, str]:
    proto = e.get("protocol") or "Pager"
    return e.get("address"), [], f"{proto} {e.get('address', '')}: {e.get('message', '')}".strip()


def _acars(e: dict) -> tuple[Any, list, str]:
    flight = e.get("flight")
    tail = e.get("tail") or e.get("reg")
    label = e.get("label_description") or e.get("label") or ""
    ident = tail or flight or e.get("icao")
    aliases = [flight, tail, e.get("icao")]
    who = " / ".join(str(x) for x in (flight, tail) if x)
    return ident, aliases, f"{who} {label}".strip()


def _adsb(e: dict) -> tuple[Any, list, str]:
    icao = e.get("icao") or e.get("hex")
    callsign = e.get("callsign") or e.get("flight")
    reg = e.get("registration") or e.get("reg")
    bits = [str(x).strip() for x in (callsign, reg) if x and str(x).strip()]
    if e.get("squawk"):
        bits.append(f"squawk {e['squawk']}")
    if e.get("altitude") not in (None, ""):
        bits.append(f"{e['altitude']} ft")
    return icao, [callsign, reg], f"{icao or ''} {' '.join(bits)}".strip()


def _ais(e: dict) -> tuple[Any, list, str]:
    name = e.get("name") or e.get("shipname")
    return e.get("mmsi"), [name, e.get("callsign")], f"{e.get('mmsi', '')} {name or ''}".strip()


def _dsc(e: dict) -> tuple[Any, list, str]:
    mmsi = e.get("source_mmsi") or e.get("mmsi")
    what = e.get("nature_of_distress") or e.get("category") or e.get("format_text") or ""
    return mmsi, [e.get("dest_mmsi")], f"DSC {mmsi or ''} {what}".strip()


def _aprs(e: dict) -> tuple[Any, list, str]:
    call = e.get("callsign") or e.get("from")
    kind = e.get("packet_type") or ""
    return call, [e.get("addressee")], f"{call or ''} {kind}".strip()


def _sensor(e: dict) -> tuple[Any, list, str]:
    model = e.get("model")
    parts = [str(p) for p in (model, e.get("id"), e.get("channel")) if p not in (None, "")]
    readings = []
    for key, unit in (("temperature_C", "°C"), ("humidity", "%"), ("pressure_hPa", "hPa"), ("wind_avg_km_h", "km/h")):
        if e.get(key) is not None:
            readings.append(f"{e[key]}{unit}")
    return ":".join(parts) or None, [model], f"{model or 'Sensor'} {e.get('id', '')} {' '.join(readings)}".strip()


def _rtlamr(e: dict) -> tuple[Any, list, str]:
    inner = e.get("Message") if isinstance(e.get("Message"), dict) else e
    meter = inner.get("ID") or inner.get("EndpointID") or e.get("id")
    consumption = inner.get("Consumption") or inner.get("LastConsumptionCount")
    return meter, [], f"Meter {meter or ''} {consumption if consumption is not None else ''}".strip()


def _radiosonde(e: dict) -> tuple[Any, list, str]:
    serial = e.get("id") or e.get("serial")
    alt = e.get("alt") or e.get("altitude")
    return (
        serial,
        [e.get("type_name") or e.get("sonde_type")],
        f"Sonde {serial or ''} {f'{alt} m' if alt else ''}".strip(),
    )


def _drone(e: dict) -> tuple[Any, list, str]:
    d = e.get("data") if isinstance(e.get("data"), dict) else e
    ident = d.get("serial_number") or d.get("id")
    return ident, [d.get("id"), d.get("operator_id")], f"Drone {ident or ''} {d.get('risk_level') or ''}".strip()


def _wifi(e: dict) -> tuple[Any, list, str]:
    d = e.get("network") or e.get("client") or e
    mac = d.get("bssid") or d.get("mac") or d.get("client_mac") or e.get("bssid") or e.get("mac")
    essid = d.get("essid") or d.get("ssid") or e.get("ssid")
    return mac, [essid], f"{mac or ''} {essid or ''}".strip()


def _bluetooth(e: dict) -> tuple[Any, list, str]:
    d = e.get("device") if isinstance(e.get("device"), dict) else e
    addr = d.get("address") or d.get("mac") or d.get("device_id")
    name = d.get("name")
    extra = d.get("manufacturer_name") or ""
    return addr, [name], f"{addr or ''} {name or ''} {extra}".strip()


def _meshtastic(e: dict) -> tuple[Any, list, str]:
    node = e.get("from") or e.get("id") or e.get("node_id")
    name = e.get("from_name") or e.get("callsign") or e.get("long_name") or e.get("short_name")
    who = name or node or ""
    text = e.get("message")
    return node, [name], f"{who}: {text}" if isinstance(text, str) and text else who


def _generic(e: dict) -> tuple[Any, list, str]:
    for key in ("id", "device_id", "address", "callsign", "mac", "serial", "hex"):
        if e.get(key) not in (None, ""):
            return e.get(key), [e.get("name")], ""
    return None, [e.get("name")], ""


_EXTRACTORS = {
    "pager": _pager,
    "acars": _acars,
    "vdl2": _acars,
    "adsb": _adsb,
    "ais": _ais,
    "dsc": _dsc,
    "aprs": _aprs,
    "sensor": _sensor,
    "rtlamr": _rtlamr,
    "radiosonde": _radiosonde,
    "drone": _drone,
    "wifi": _wifi,
    "bluetooth": _bluetooth,
    "meshtastic": _meshtastic,
}


# =============================================================================
# Field helpers
# =============================================================================


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _text(e: dict) -> str:
    for key in _TEXT_FIELDS:
        value = e.get(key)
        if isinstance(value, str) and value.strip() and value not in ("[No Message]", "[Tone Only]"):
            return value.strip()
    return ""


def _number(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number == number else None  # NaN


def _position(e: dict) -> tuple[float | None, float | None]:
    sources = [e]
    for key in ("data", "device", "network", "position"):
        if isinstance(e.get(key), dict):
            sources.append(e[key])
    for src in sources:
        lat = _number(src.get("lat", src.get("latitude")))
        lon = _number(src.get("lon", src.get("lng", src.get("longitude"))))
        if lat is not None and lon is not None and -90 <= lat <= 90 and -180 <= lon <= 180:
            if lat == 0 and lon == 0:
                continue
            return lat, lon
        pos = src.get("position")
        if isinstance(pos, (list, tuple)) and len(pos) >= 2:
            lat, lon = _number(pos[0]), _number(pos[1])
            if lat is not None and lon is not None:
                return lat, lon
    return None, None


def _freq_hz(e: dict) -> float | None:
    """A frequency in Hz from whichever field the decoder used.

    Fields named *_hz are Hz, *_mhz MHz. Bare freq/frequency values are
    MHz when small (decoders report 131.725 or 162.025) and Hz otherwise.
    """
    for key in ("freq_hz", "frequency_hz"):
        value = _number(e.get(key))
        if value:
            return value
    for key in ("freq_mhz", "frequency_mhz"):
        value = _number(e.get(key))
        if value:
            return value * 1e6
    for key in ("freq", "frequency"):
        value = _number(e.get(key))
        if value:
            return value * 1e6 if value < 100_000 else value
    return None


def _default_summary(msg: NormalizedMessage) -> str:
    bits = [msg.ident or "", msg.text[:120]]
    if not any(bits) and msg.freq_hz:
        bits.append(f"{msg.freq_hz / 1e6:.4f} MHz")
    return " ".join(b for b in bits if b) or (msg.event_type or msg.mode)
