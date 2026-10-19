"""Watchlists, alert limits (cooldown, hourly cap, quiet hours) and push channels."""

from __future__ import annotations

import json
from datetime import datetime
from unittest.mock import patch

import pytest

from utils import alert_channels, watchlists
from utils.alerts import AlertManager, _in_quiet_hours
from utils.database import get_db
from utils.message_normalize import normalize


@pytest.fixture(autouse=True)
def clean_tables():
    def wipe():
        with get_db() as conn:
            conn.execute("DELETE FROM watchlists")
            conn.execute("DELETE FROM alert_channels")
            conn.execute("DELETE FROM alert_rules")
        watchlists.invalidate_cache()

    wipe()
    yield
    wipe()


@pytest.fixture
def manager():
    m = AlertManager()
    m.update_limits({"max_per_hour": 30, "cooldown_minutes": 5, "quiet_start": "", "quiet_end": ""})
    return m


@pytest.fixture
def sent():
    """Pushes handed to the channel outbox, without any network."""
    calls = []
    with patch.object(alert_channels, "enqueue", side_effect=lambda alert: calls.append(alert) or True):
        yield calls


def _wl(kind, entries, **extra):
    wl_id = watchlists.create({"name": kind, "kind": kind, "entries": entries, **extra})
    return next(w for w in watchlists.list_watchlists() if w.id == wl_id)


class TestMatching:
    def test_aircraft_by_registration_ignores_dashes_and_case(self):
        wl = _wl("aircraft", "a6eda, 4840D6")
        assert watchlists.match(wl, normalize("acars", {"type": "acars", "tail": "A6-EDA", "text": "x"})) == "a6eda"
        assert watchlists.match(wl, normalize("adsb", {"type": "aircraft", "icao": "4840d6"})) == "4840D6"
        # The right identity on the wrong kind of station does not match
        assert watchlists.match(wl, normalize("aprs", {"type": "aprs", "callsign": "A6EDA"})) is None

    def test_prefix(self):
        wl = _wl("aircraft", "KLM*")
        assert (
            watchlists.match(wl, normalize("adsb", {"type": "aircraft", "icao": "1", "callsign": "KLM1023"})) == "KLM*"
        )
        assert watchlists.match(wl, normalize("adsb", {"type": "aircraft", "icao": "2", "callsign": "BAW1"})) is None

    def test_callsign_ssid(self):
        any_ssid = _wl("callsign", "LY1ABC")
        one_ssid = _wl("callsign", "LY1ABC-9")
        nine = normalize("aprs", {"type": "aprs", "callsign": "LY1ABC-9", "comment": "x"})
        seven = normalize("aprs", {"type": "aprs", "callsign": "LY1ABC-7", "comment": "x"})
        assert watchlists.match(any_ssid, nine) and watchlists.match(any_ssid, seven)
        assert watchlists.match(one_ssid, nine) and not watchlists.match(one_ssid, seven)

    def test_device_mac_formats(self):
        wl = _wl("device", "aa-bb-cc-dd-ee-ff")
        msg = normalize("bluetooth", {"type": "device_update", "address": "AA:BB:CC:DD:EE:FF"}, "device_update")
        assert watchlists.match(wl, msg)

    def test_frequency_units_ranges_and_tolerance(self):
        wl = _wl("frequency", "162025 kHz\n144-146", tolerance_khz=2)
        assert watchlists.match(wl, normalize("acars", {"type": "acars", "tail": "X", "freq": 162.026})) == "162025 kHz"
        assert watchlists.match(wl, normalize("acars", {"type": "acars", "tail": "X", "freq": 162.030})) is None
        assert watchlists.match(wl, normalize("acars", {"type": "acars", "tail": "X", "freq": 145.5})) == "144-146"

    def test_keyword(self):
        wl = _wl("keyword", "mayday, structure fire")
        assert watchlists.match(
            wl, normalize("pager", {"type": "message", "address": "1", "message": "STRUCTURE FIRE elm"})
        )
        assert not watchlists.match(wl, normalize("pager", {"type": "message", "address": "1", "message": "all clear"}))

    def test_bad_input_is_refused(self):
        with pytest.raises(ValueError):
            watchlists.create({"name": "x", "kind": "frequency", "entries": "not-a-freq"})
        with pytest.raises(ValueError):
            watchlists.create({"name": "x", "kind": "planets", "entries": "mars"})


class TestLimits:
    def test_watchlist_fires_once_per_cooldown(self, manager, sent):
        _wl("aircraft", "4840D6")
        alerts = []
        with patch.object(manager, "_queue_event", side_effect=alerts.append):
            for _ in range(3):
                manager.process_event("adsb", {"type": "aircraft", "icao": "4840D6"}, "aircraft")
        assert len(alerts) == 1
        assert alerts[0]["title"] == "aircraft: 4840D6"

    def test_rule_cooldown_stops_a_flood(self, manager, sent):
        manager.add_rule({"name": "Tracker", "mode": "bluetooth", "match": {"is_tracker": True}})
        alerts = []
        with patch.object(manager, "_queue_event", side_effect=alerts.append):
            for _ in range(5):
                manager.process_event("bluetooth", {"address": "AA:BB", "is_tracker": True}, "device_update")
            manager.process_event("bluetooth", {"address": "CC:DD", "is_tracker": True}, "device_update")
        assert [a["ident"] for a in alerts] == ["AA:BB", "CC:DD"]

    def test_hourly_cap_holds_back_pushes_but_keeps_history(self, manager, sent):
        alert_channels.create({"kind": "webhook", "config": {"url": "https://example.invalid/hook"}})
        manager.update_limits({"max_per_hour": 2})
        _wl("keyword", "fire")
        alerts = []
        with patch.object(manager, "_queue_event", side_effect=alerts.append):
            for i in range(4):
                manager.process_event("pager", {"type": "message", "address": str(i), "message": "fire"}, "message")
        assert [a["delivery"] for a in alerts] == ["sent", "sent", "rate_limited", "rate_limited"]
        assert len(sent) == 2
        assert [e["delivery"] for e in manager.list_events(limit=4)] == ["rate_limited", "rate_limited", "sent", "sent"]

    def test_without_a_channel_nothing_is_pushed(self, manager, sent):
        _wl("keyword", "fire")
        alerts = []
        with patch.object(manager, "_queue_event", side_effect=alerts.append):
            manager.process_event("pager", {"type": "message", "address": "1", "message": "fire"}, "message")
        assert alerts[0]["delivery"] == "no_channel"
        assert sent == []

    @pytest.mark.parametrize(
        "start,end,now,quiet",
        [
            ("22:00", "07:00", "23:30", True),
            ("22:00", "07:00", "06:59", True),
            ("22:00", "07:00", "07:00", False),
            ("09:00", "17:00", "12:00", True),
            ("09:00", "17:00", "18:00", False),
            ("", "", "12:00", False),
        ],
    )
    def test_quiet_hours(self, start, end, now, quiet):
        assert _in_quiet_hours(start, end, datetime.strptime(now, "%H:%M")) is quiet

    def test_bad_limits_are_refused(self, manager):
        with pytest.raises(ValueError):
            manager.update_limits({"quiet_start": "25:00"})
        with pytest.raises(ValueError):
            manager.update_limits({"max_per_hour": -1})


class TestChannels:
    def test_secrets_are_never_returned_and_blank_keeps_them(self):
        cid = alert_channels.create(
            {"kind": "telegram", "name": "phone", "config": {"bot_token": "123:SECRET", "chat_id": "42"}}
        )
        shown = alert_channels.list_channels()[0]
        assert "SECRET" not in json.dumps(shown)
        assert shown["config"] == {"chat_id": "42", "bot_token_set": True}

        alert_channels.update(cid, {"config": {"bot_token": "", "chat_id": "43"}})
        with get_db() as conn:
            stored = json.loads(conn.execute("SELECT config FROM alert_channels WHERE id = ?", (cid,)).fetchone()[0])
        assert stored == {"bot_token": "123:SECRET", "chat_id": "43"}

    def test_validation(self):
        with pytest.raises(ValueError):
            alert_channels.create({"kind": "ntfy", "config": {"server": "https://ntfy.sh"}})
        with pytest.raises(ValueError):
            alert_channels.create({"kind": "webhook", "config": {"url": "file:///etc/passwd"}})

    def test_ntfy_request(self):
        posts = []
        with patch.object(alert_channels, "_post", side_effect=lambda *a: posts.append(a)):
            alert_channels.send_one(
                "ntfy",
                {"server": "https://ntfy.sh/", "topic": "my topic", "token": "tk"},
                {"title": "Watch: KLM*", "message": "ADSB KLM1023", "severity": "high", "mode": "adsb"},
            )
        url, body, headers = posts[0]
        assert url == "https://ntfy.sh/my%20topic"
        assert body == b"ADSB KLM1023"
        assert headers["Priority"] == "4"
        assert headers["Authorization"] == "Bearer tk"

    def test_test_result_hides_error_text(self):
        alert_channels.create({"kind": "telegram", "config": {"bot_token": "123:SECRET", "chat_id": "1"}})
        with patch.object(alert_channels, "_post", side_effect=OSError("https://api.telegram.org/bot123:SECRET")):
            results = alert_channels.send_test()
        assert results == [{"channel": "telegram", "kind": "telegram", "ok": False, "error": "OSError"}]


class TestRoutes:
    def test_watchlist_crud(self, client):
        resp = client.post(
            "/alerts/watchlists", json={"name": "Coast", "kind": "vessel", "entries": "244123456\nEVER GIVEN"}
        )
        wl_id = resp.get_json()["watchlist_id"]
        listed = client.get("/alerts/watchlists").get_json()["watchlists"]
        assert listed[0]["entries"] == ["244123456", "EVER GIVEN"]

        assert client.patch(f"/alerts/watchlists/{wl_id}", json={"enabled": False}).status_code == 200
        assert client.patch(f"/alerts/watchlists/{wl_id}", json={"kind": "frequency"}).status_code == 400
        assert client.delete(f"/alerts/watchlists/{wl_id}").status_code == 200
        assert client.delete(f"/alerts/watchlists/{wl_id}").status_code == 404

    def test_test_endpoint_without_channels(self, client):
        assert client.post("/alerts/test").status_code == 400
