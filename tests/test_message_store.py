"""The decoded-message database: normalizing, storing, searching, retention."""

from __future__ import annotations

import pytest

from utils import message_store
from utils.message_normalize import normalize


@pytest.fixture
def store():
    message_store.update_settings(dict(message_store.DEFAULTS))
    message_store.clear()
    yield message_store
    message_store.update_settings(dict(message_store.DEFAULTS))
    message_store.clear()


def _put(mode, event, event_type=None):
    return message_store.record(normalize(mode, event, event_type or event.get("type")))


class TestNormalize:
    def test_pager_message(self):
        msg = normalize(
            "pager", {"type": "message", "protocol": "POCSAG512", "address": "1234567", "message": "FIRE AT ELM ST"}
        )
        assert msg.ident == "1234567"
        assert msg.text == "FIRE AT ELM ST"

    def test_acars_identities_and_frequency_in_mhz(self):
        msg = normalize(
            "acars", {"type": "acars", "flight": "KL1023", "tail": "PH-BXA", "freq": 131.725, "text": "ETA 1210"}
        )
        assert msg.ident == "PH-BXA"
        assert "KL1023" in msg.identities()
        assert msg.freq_hz == pytest.approx(131.725e6)
        assert msg.kind == "aircraft"

    def test_adsb_is_tracked_with_position(self):
        msg = normalize("adsb", {"type": "aircraft", "icao": "4840D6", "callsign": "KLM1023", "lat": 52.3, "lon": 4.7})
        assert msg.tracked
        assert (msg.lat, msg.lon) == (52.3, 4.7)

    def test_drone_position_list(self):
        msg = normalize(
            "drone", {"type": "contact", "data": {"id": "c1", "serial_number": "1581F", "position": [51.5, -0.1]}}
        )
        assert msg.ident == "1581F"
        assert (msg.lat, msg.lon) == (51.5, -0.1)

    @pytest.mark.parametrize(
        "mode,event",
        [
            ("pager", {"type": "status", "text": "started"}),
            ("sensor", {"type": "raw", "text": "noise"}),
            ("subghz", {"type": "rx_level", "level": -40}),
            ("morse", {"type": "morse_char", "char": "E"}),
            ("waterfall", {"type": "anything", "frequency": 100.0}),
            ("pager", {"type": "message"}),  # nothing to identify or search
        ],
    )
    def test_non_traffic_is_skipped(self, mode, event):
        assert normalize(mode, event, event.get("type")) is None


class TestStore:
    def test_words_are_anded_and_star_is_a_prefix(self, store):
        _put("pager", {"type": "message", "address": "1", "message": "structure fire on Elm street"})
        _put("pager", {"type": "message", "address": "2", "message": "fire drill cancelled"})
        _put("pager", {"type": "message", "address": "3", "message": "elm tree down"})

        def idents(q):
            return [m["ident"] for m in store.search({"q": q})["messages"]]

        assert idents("fire elm") == ["1"]
        assert sorted(idents("fire")) == ["1", "2"]
        assert sorted(idents("canc*")) == ["2"]

    def test_query_punctuation_is_searched_not_parsed(self, store):
        _put("bluetooth", {"type": "device_update", "address": "AA:BB:CC:DD:EE:FF", "name": "Tag"})
        found = store.search({"q": 'AA:BB:CC:DD:EE:FF "'})["messages"]
        assert [m["ident"] for m in found] == ["AA:BB:CC:DD:EE:FF"]
        assert store.search({"q": "NEAR AND"})["messages"] == []

    def test_filters_and_paging(self, store):
        for i in range(5):
            _put("pager", {"type": "message", "address": str(i), "message": f"msg {i}"})
        _put("aprs", {"type": "aprs", "callsign": "LY1ABC-9", "lat": 54.7, "lon": 25.3, "comment": "hi"})

        assert [m["mode"] for m in store.search({"modes": ["aprs"]})["messages"]] == ["aprs"]
        assert [m["ident"] for m in store.search({"has_position": True})["messages"]] == ["LY1ABC-9"]

        page1 = store.search({"modes": ["pager"]}, limit=3)
        assert [m["ident"] for m in page1["messages"]] == ["4", "3", "2"]
        page2 = store.search({"modes": ["pager"], "before_id": page1["next_before_id"]}, limit=3)
        assert [m["ident"] for m in page2["messages"]] == ["1", "0"]
        assert page2["next_before_id"] is None

    def test_tracked_objects_are_kept_once_per_interval(self, store):
        assert _put("adsb", {"type": "aircraft", "icao": "4840D6", "lat": 52.0, "lon": 4.0})
        assert not _put("adsb", {"type": "aircraft", "icao": "4840D6", "lat": 52.1, "lon": 4.1})
        assert _put("adsb", {"type": "aircraft", "icao": "406B90", "lat": 51.0, "lon": 0.0})
        # A geofence crossing is news, even right after a position report
        assert _put("adsb", {"type": "geofence", "icao": "4840D6", "zone": "home"})
        assert _put("adsb", {"type": "geofence", "icao": "4840D6", "zone": "home"})
        # Discrete messages are never throttled
        assert _put("pager", {"type": "message", "address": "1", "message": "a"})
        assert _put("pager", {"type": "message", "address": "1", "message": "a"})

    def test_row_limit_deletes_oldest(self, store):
        store.update_settings({"max_rows": 3})
        for i in range(5):
            _put("pager", {"type": "message", "address": str(i), "message": "x"})
        store.apply_retention()
        assert [m["ident"] for m in store.search({})["messages"]] == ["4", "3", "2"]

    def test_switched_off_stores_nothing(self, store):
        store.update_settings({"enabled": False})
        assert not _put("pager", {"type": "message", "address": "1", "message": "x"})
        assert store.stats()["total"] == 0

    def test_full_payload_is_kept(self, store):
        _put("acars", {"type": "acars", "flight": "KL1023", "text": "hello", "label": "H1", "extra": {"a": 1}})
        row_id = store.search({})["messages"][0]["id"]
        assert store.get(row_id)["payload"]["extra"] == {"a": 1}


class TestPipeline:
    def test_pipeline_event_lands_in_store(self, store):
        from utils import event_pipeline

        event_pipeline.process_event(
            "pager", {"type": "message", "address": "77", "message": "via pipeline"}, "message"
        )
        assert [m["ident"] for m in store.search({"q": "pipeline"})["messages"]] == ["77"]


class TestRoutes:
    def test_search_and_export(self, client, store):
        _put("pager", {"type": "message", "address": "1", "message": "alpha bravo"})
        _put("pager", {"type": "message", "address": "2", "message": "charlie"})

        resp = client.get("/messages/search?q=alpha")
        assert resp.status_code == 200
        assert [m["ident"] for m in resp.get_json()["messages"]] == ["1"]

        csv_text = client.get("/messages/export?format=csv&mode=pager").get_data(as_text=True)
        lines = csv_text.strip().splitlines()
        assert lines[0].startswith("id,time,mode")
        assert len(lines) == 3

        rows = client.get("/messages/export?format=json&q=charlie").get_json()
        assert [r["ident"] for r in rows] == ["2"]

    def test_bad_settings_are_refused(self, client, store):
        assert client.patch("/messages/settings", json={"max_rows": -1}).status_code == 400
        assert client.patch("/messages/settings", json={"nope": 1}).status_code == 400
        resp = client.patch("/messages/settings", json={"max_days": 30})
        assert resp.get_json()["settings"]["max_days"] == 30

    def test_clear(self, client, store):
        _put("pager", {"type": "message", "address": "1", "message": "x"})
        assert client.delete("/messages").get_json()["deleted"] == 1
