"""Ground station observation profiles: save, read back, list, delete."""


def test_saved_profile_is_returned_and_listed(client):
    """Saving a profile reads it back from the database, so a row the code
    cannot parse turns into an HTML 500 the dashboard reports as invalid JSON."""
    payload = {
        "norad_id": 25544,
        "name": "ISS (ZARYA)",
        "frequency_mhz": 145.8,
        "decoder_type": "fm",
        "tasks": ["telemetry_ax25", "record_iq"],
    }
    resp = client.post("/ground_station/profiles", json=payload)
    assert resp.status_code == 201, resp.get_data(as_text=True)[:200]
    assert resp.get_json()["tasks"] == ["telemetry_ax25", "record_iq"]

    assert client.get("/ground_station/profiles/25544").get_json()["name"] == "ISS (ZARYA)"
    assert 25544 in [p["norad_id"] for p in client.get("/ground_station/profiles").get_json()]

    client.delete("/ground_station/profiles/25544")
