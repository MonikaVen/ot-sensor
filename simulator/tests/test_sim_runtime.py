from fastapi.testclient import TestClient

from opv_sim.runtime import SimRuntime
from otlab.pgn import decode_fields


def test_sim_runtime_spoof_then_underway():
    rt = SimRuntime("dev", "gps-spoof-primary")
    plant, _frames = rt.tick()
    assert plant.attack_id == "gps-spoof-primary"
    assert plant.phase == "inject"
    rt.set_intensity(0)
    plant, frames = rt.tick()
    assert rt.snapshot()["attack_id"] is None
    assert plant.attack_id is None
    assert frames


def test_intensity_slider_scales_spoof():
    off = SimRuntime("dev", "gps-spoof-primary")
    off.set_intensity(0)
    on = SimRuntime("dev", "gps-spoof-primary")
    on.set_intensity(1)
    p_off, f_off = off.tick()
    p_on, f_on = on.tick()

    def g1(frames):
        pos = [decode_fields(f) for f in frames if decode_fields(f).get("pgn") == 129025]
        return next(p for p in pos if p["sa"] == 16)

    assert abs(g1(f_off)["lat_deg"] - p_off.lat_deg) < 1e-6
    assert abs(g1(f_on)["lat_deg"] - p_on.lat_deg) > 1e-4


def test_snapshot_emissions_name_talkers():
    rt = SimRuntime("dev", "gps-spoof-primary")
    rt.tick()
    rows = rt.snapshot()["emissions"]
    assert rows
    sas = {r["sa"] for r in rows}
    assert "16" in sas and "0" in sas
    gnss = next(r for r in rows if r["sa"] == "16" and r["pgn"] == 129025)
    assert gnss["name"] == "GNSS-1"
    assert "lat" in gnss["summary"]
    plant = rt.snapshot()["plant"]
    assert plant["lat_deg"] is not None and plant["lon_deg"] is not None
    assert plant["sog_kn"] > 0 and plant["sog_ms"] > 0
    assert rt.snapshot()["track"]
    assert rt.snapshot()["track"][-1]["lat_deg"] == plant["lat_deg"]


def test_device_toggle_removes_talker():
    rt = SimRuntime("dev", "")
    rt.set_attack("spoof", False)
    rt.set_device("16", False)
    _plant, frames = rt.tick()
    sas = {decode_fields(f)["sa"] for f in frames}
    assert 16 not in sas
    assert 0 in sas


def test_read_and_write_flood_emit_rogue_frames():
    rt = SimRuntime("dev", "")
    rt.set_attack("spoof", False)
    rt.set_attack("read_flood", True)
    _p, read_frames = rt.tick()
    reads = [decode_fields(f) for f in read_frames if decode_fields(f).get("pgn") == 59904]
    assert len(reads) >= 10
    assert all(r["sa"] == 44 for r in reads)
    rt.set_attack("read_flood", False)
    rt.set_attack("write_flood", True)
    _p, write_frames = rt.tick()
    writes = [decode_fields(f) for f in write_frames if decode_fields(f).get("pgn") == 127237]
    assert len(writes) >= 10
    assert all(w["sa"] == 44 for w in writes)


def test_sim_control_api_sets_attack():
    from opv_sim.app import app, runtime

    runtime.reset("gps-spoof-primary")
    runtime.running = False
    with TestClient(app) as client:
        r = client.get("/api/health")
        assert r.status_code == 200
        r = client.post("/api/control", json={"action": "intensity", "intensity": 0})
        assert r.json()["snapshot"]["intensity"] == 0
        assert r.json()["snapshot"]["attack_id"] is None
        r = client.post("/api/control", json={"action": "toggle_attack", "attack": "spoof", "enabled": True})
        assert r.json()["snapshot"]["attacks"]["spoof"] is True
        assert r.json()["snapshot"]["attack_id"] == "gps-spoof-primary"
        r = client.post("/api/control", json={"action": "toggle_device", "device": "16", "enabled": False})
        assert r.json()["snapshot"]["devices"]["16"] is False
        r = client.get("/")
        assert r.status_code == 200
        assert 'data-attack="spoof"' in r.text
        assert 'data-attack="gyro"' in r.text
        assert 'data-attack="velocity"' in r.text
        assert 'id="own-globe"' in r.text
        assert "Gyro heading" in r.text
        assert "Latitude" in r.text
        assert "Longitude" in r.text
        assert "Velocity" in r.text
        assert 'id="ship-plot"' not in r.text
        assert 'id="attacks"' in r.text
        assert 'id="devices"' in r.text
        assert "#log li.attack" in r.text
        assert "#log li.read" in r.text


def test_attack_emissions_share_red_kind():
    rt = SimRuntime("dev", "")
    rt.set_attack("spoof", False)
    rt.set_attack("read", True)
    rt.tick()
    kinds = {e["kind"] for e in rt.snapshot()["emissions"]}
    assert "read" in kinds
    rt.set_attack("read", False)
    rt.set_attack("write", True)
    rt.tick()
    kinds = {e["kind"] for e in rt.snapshot()["emissions"]}
    assert "write" in kinds
    rt.set_attack("write", False)
    rt.set_attack("pgn_flood", True)
    rt.set_device("35", True)
    rt.tick()
    floods = [e for e in rt.snapshot()["emissions"] if e["kind"] == "flood"]
    assert floods
    assert all(e["sa"] == "35" and e["pgn"] == 127250 for e in floods)


def test_gyro_spoof_offsets_heading_pgn():
    rt = SimRuntime("dev", "")
    rt.set_attack("spoof", False)
    rt.set_attack("gyro", True)
    plant, frames = rt.tick()
    heading = next(
        decode_fields(f)
        for f in frames
        if decode_fields(f).get("pgn") == 127250 and decode_fields(f)["sa"] == 35
    )
    delta = abs((heading["heading_deg"] - plant.heading_deg + 180) % 360 - 180)
    assert delta > 20
    assert plant.attack_id == "heading-spoof"
    snap = rt.snapshot()
    assert snap["attack_id"] == "heading-spoof"
    assert snap["attacks"]["gyro"] is True
    gyro = next(e for e in snap["emissions"] if e["sa"] == "35" and e["pgn"] == 127250)
    assert gyro["kind"] == "gyro"
    assert gyro["spoofed"] is True
    assert "heading" in gyro["summary"]
    own = snap["ownship"]
    assert abs((own["heading_deg"] - plant.heading_deg + 180) % 360 - 180) > 20
    assert abs(own["sog_kn"] - plant.sog_kn) < 0.05


def test_velocity_spoof_offsets_sog():
    rt = SimRuntime("dev", "")
    rt.set_attack("spoof", False)
    rt.set_attack("velocity", True)
    plant, frames = rt.tick()
    cog = next(
        decode_fields(f)
        for f in frames
        if decode_fields(f).get("pgn") == 129026 and decode_fields(f)["sa"] == 16
    )
    g2 = next(
        decode_fields(f)
        for f in frames
        if decode_fields(f).get("pgn") == 129026 and decode_fields(f)["sa"] == 17
    )
    assert cog["sog_kn"] > plant.sog_kn + 4
    assert abs(g2["sog_kn"] - plant.sog_kn) < 0.2
    snap = rt.snapshot()
    assert snap["attack_id"] == "sog-spoof"
    assert snap["attacks"]["velocity"] is True
    row = next(e for e in snap["emissions"] if e["sa"] == "16" and e["pgn"] == 129026)
    assert row["kind"] == "velocity"
    assert row["spoofed"] is True
    own = snap["ownship"]
    assert own["sog_kn"] == cog["sog_kn"] or abs(own["sog_kn"] - cog["sog_kn"]) < 0.2
    assert abs(own["lat_deg"] - plant.lat_deg) < 1e-6


def test_tap_endpoint_exposes_raw_frames():
    from opv_sim.app import app, runtime

    runtime.reset("gps-spoof-primary")
    runtime.running = False
    runtime.tick()
    with TestClient(app) as client:
        r = client.get("/api/snapshot")
        assert r.status_code == 200
        assert r.json()["ticks"] >= 1
        r = client.get("/api/tap")
        assert r.status_code == 200
        body = r.json()
        assert body["ticks"] >= 1
        assert body["frames"]
        row = body["frames"][0]
        assert "can_id" in row and "data_hex" in row and "segment" in row
        assert bytes.fromhex(row["data_hex"])
