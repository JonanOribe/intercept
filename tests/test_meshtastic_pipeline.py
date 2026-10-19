"""Meshtastic text messages reach the event pipeline: alerts, watchlists, message store."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

import routes.meshtastic as mesh_routes
from utils import message_store, watchlists
from utils.alerts import AlertManager
from utils.database import get_db
from utils.meshtastic import MeshtasticMessage
from utils.message_normalize import normalize


def _message(text="QRV on the hill", packet_id=1001):
    return MeshtasticMessage(
        from_id="!a1b2c3d4",
        to_id="^all",
        message=text,
        portnum="TEXT_MESSAGE_APP",
        channel=0,
        rssi=-90,
        snr=6.5,
        hop_limit=3,
        timestamp=datetime.now(timezone.utc),
        from_name="Base Camp",
        raw_packet={"id": packet_id},
    )


@pytest.fixture
def submitted():
    calls = []
    with patch.object(mesh_routes, "submit", side_effect=lambda *a: calls.append(a)):
        yield calls


class TestCallback:
    def test_a_new_message_is_submitted(self, submitted):
        with patch.object(mesh_routes, "store_meshtastic_message", return_value=True):
            mesh_routes._message_callback(_message())
        assert len(submitted) == 1
        mode, event, event_type = submitted[0]
        assert (mode, event_type) == ("meshtastic", "message")
        assert event["message"] == "QRV on the hill"

    def test_a_rebroadcast_is_not_submitted_again(self, submitted):
        with patch.object(mesh_routes, "store_meshtastic_message", return_value=False):
            mesh_routes._message_callback(_message())
        assert submitted == []

    def test_a_storage_failure_still_submits(self, submitted):
        with patch.object(mesh_routes, "store_meshtastic_message", side_effect=OSError("disk")):
            mesh_routes._message_callback(_message())
        assert len(submitted) == 1


class TestNormalize:
    def test_message_shape(self):
        msg = normalize("meshtastic", _message().to_dict(), "message")
        assert msg.ident == "!a1b2c3d4"
        assert "Base Camp" in msg.identities()
        assert msg.text == "QRV on the hill"
        assert msg.summary == "Base Camp: QRV on the hill"
        # Chat is news, not a position report: never throttled
        assert not msg.tracked

    def test_positions_are_still_tracked(self):
        msg = normalize("meshtastic", {"id": "!a1b2c3d4", "callsign": "Base Camp", "lat": 1.0, "lon": 2.0}, "position")
        assert msg.tracked


class TestEndToEnd:
    @pytest.fixture(autouse=True)
    def clean(self):
        message_store.update_settings(dict(message_store.DEFAULTS))
        message_store.clear()
        with get_db() as conn:
            conn.execute("DELETE FROM watchlists")
        watchlists.invalidate_cache()
        yield
        message_store.clear()
        with get_db() as conn:
            conn.execute("DELETE FROM watchlists")
        watchlists.invalidate_cache()

    def test_every_message_is_stored(self):
        from utils import event_pipeline

        for i, text in enumerate(("first", "second")):
            event_pipeline.process_event("meshtastic", _message(text, packet_id=i).to_dict(), "message")
        found = message_store.search({"modes": ["meshtastic"]})["messages"]
        assert [m["text"] for m in found] == ["second", "first"]

    @pytest.mark.parametrize(
        "kind,entry",
        [("callsign", "base camp"), ("callsign", "!A1B2C3D4"), ("keyword", "on the hill")],
    )
    def test_watchlists_hear_mesh_chat(self, kind, entry):
        watchlists.create({"name": "mesh", "kind": kind, "entries": entry})
        manager = AlertManager()
        alerts = []
        with patch.object(manager, "_queue_event", side_effect=alerts.append):
            manager.process_event("meshtastic", _message().to_dict(), "message")
        assert [a["title"] for a in alerts] == [f"mesh: {entry}"]
