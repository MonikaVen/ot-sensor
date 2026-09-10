from fastapi.testclient import TestClient
import random

from opv_sim.runtime import SimRuntime
from opv_sim.twins import ATTACK_CATALOG, DEVICE_CATALOG
from otlab.pgn import decode_fields


def hist_v(item):
    return item["v"] if isinstance(item, dict) else item


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
    assert gnss["attack_label"] == "GNSS-1 spoof"
    assert gnss["command"].startswith("PGN 129025")
    assert "lat" in gnss["summary"]
    archive = rt.snapshot()["log_archive"]
    hit = next(r for r in archive if r["sa"] == "16" and r["pgn"] == 129025)
    assert hit["tick"] == 1
    assert hit["attack_label"] == "GNSS-1 spoof"
    assert any(r["attack_label"] == "benign" and r["command"].startswith("PGN ") for r in archive)
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
        assert 'data-attack="ais"' in r.text
        assert 'data-attack="rogue_master"' in r.text
        assert 'data-attack="engine_cmd"' in r.text
        assert 'data-attack="gateway_bypass"' in r.text
        assert 'data-attack="error_flood"' in r.text
        assert 'id="hz"' in r.text
        assert 'id="sog"' in r.text
        assert 'id="frames"' in r.text
        assert "T0848" in r.text
        assert "T1692.001" in r.text
        assert 'id="own-globe"' in r.text
        assert "Gyro heading" in r.text
        assert "Latitude" in r.text
        assert "Longitude" in r.text
        assert "Velocity" in r.text
        assert 'id="ship-plot"' not in r.text
        assert 'id="attacks"' in r.text
        assert 'id="devices"' in r.text
        assert "#log li.attack" in r.text
        assert "#log li.spoofed" in r.text
        assert "#d45b4c" in r.text
        assert 'data-rail="plots"' not in r.text
        assert 'id="page-plots"' in r.text
        assert 'id="page-injector"' in r.text
        assert 'id="plot-attack"' in r.text
        assert 'id="plot-device"' in r.text
        assert "All attacks" in r.text
        assert "All devices" in r.text
        assert 'id="export-csv"' in r.text
        assert 'id="export-plots"' not in r.text
        assert 'id="collective-svg"' in r.text
        assert "Benign and attacks" in r.text
        assert 'id="hz-rand"' in r.text
        assert "GNSS-1 spoof" in r.text
        assert 'data-sa="40"' in r.text
        assert 'data-sa="48"' in r.text
        assert 'data-sa="28"' in r.text
        assert 'data-sa="88"' in r.text
        assert "127257" in r.text
        assert "127245" in r.text
        assert "127489" in r.text
        assert "129794" in r.text
        assert "127237 status" in r.text


def test_histograms_benign_and_attack_per_overlay():
    rt = SimRuntime("dev", "")
    rt.set_attack("spoof", False)
    for _ in range(4):
        rt.tick()
    rows = {h["key"]: h for h in rt.histogram_payload()}
    assert set(rows) == {k for k, *_ in ATTACK_CATALOG}
    assert rows["spoof"]["benign"]
    assert rows["spoof"]["unit"] == "lat °"
    assert not rows["spoof"]["attack"]
    assert rows["spoof"]["active"] is False
    lat_benign = hist_v(rows["spoof"]["benign"][-1])
    heading_benign = hist_v(rows["gyro"]["benign"][-1])
    flood_benign = hist_v(rows["pgn_flood"]["benign"][-1])
    assert rows["spoof"]["benign"][-1]["t"]
    assert rows["spoof"]["benign"][-1].get("sa") == "16"
    archive = rt.snapshot()["log_archive"]
    assert archive
    assert any(row["sa"] == "16" for row in archive)
    rt.set_attack("spoof", True)
    rt.tick()
    rows = {h["key"]: h for h in rt.histogram_payload()}
    assert rows["spoof"]["attack"]
    assert rows["spoof"]["active"] is True
    assert abs(hist_v(rows["spoof"]["attack"][-1]) - lat_benign) > 1e-4
    rt.set_attack("spoof", False)
    rt.set_attack("gyro", True)
    rt.tick()
    rows = {h["key"]: h for h in rt.histogram_payload()}
    assert rows["gyro"]["attack"]
    assert abs(hist_v(rows["gyro"]["attack"][-1]) - heading_benign) > 5
    rt.set_attack("gyro", False)
    rt.set_attack("pgn_flood", True)
    rt.set_device("35", True)
    rt.tick()
    rows = {h["key"]: h for h in rt.histogram_payload()}
    assert hist_v(rows["pgn_flood"]["attack"][-1]) > flood_benign
    assert rows["pgn_flood"]["unit"] == "frames/tick"


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
        assert body["histograms"]
        keys = {h["key"] for h in body["histograms"]}
        assert keys == {k for k, *_ in ATTACK_CATALOG}
        spoof = next(h for h in body["histograms"] if h["key"] == "spoof")
        assert spoof["attack"]
        assert "v" in spoof["attack"][-1]


def test_frequency_scales_flood_and_attack_log():
    rt = SimRuntime("dev", "")
    rt.set_attack("spoof", False)
    rt.set_attack("pgn_flood", True)
    rt.set_device("35", True)
    rt.set_frequency(4)
    rt.tick()
    floods = [e for e in rt.snapshot()["emissions"] if e["kind"] == "flood"]
    assert len(floods) >= 4
    assert all(e["hz"] == 4 and e["technique"] == "T0814" for e in floods)
    labels = [r for r in rt.sim.labels.records if r.pgn == 127250 and r.technique == "T0814"]
    assert len(labels) >= 4
    assert labels[0].frequency_hz == 4
    rt.set_frequency(12)
    rt.tick()
    floods = [e for e in rt.snapshot()["emissions"] if e["kind"] == "flood"]
    assert len(floods) >= 12


def test_frequency_repeats_spoof_in_attack_log():
    rt = SimRuntime("dev", "gps-spoof-primary")
    rt.set_frequency(5)
    rt.tick()
    pos = [e for e in rt.snapshot()["emissions"] if e["sa"] == "16" and e["pgn"] == 129025]
    assert len(pos) == 5
    assert pos[0]["technique"] == "T1692.002"
    assert pos[0]["hz"] == 5
    frames = [f for f in rt.last_frames if decode_fields(f).get("pgn") == 129025 and decode_fields(f)["sa"] == 16]
    assert len(frames) == 1


def test_frequency_randomize_varies_hz():
    random.seed(1)
    rt = SimRuntime("dev", "")
    rt.set_attack("spoof", False)
    rt.set_frequency_random(True)
    assert rt.frequency_random is True
    seen = {rt.frequency}
    for _ in range(20):
        rt.tick()
        seen.add(rt.frequency)
        assert 1 <= rt.frequency <= 32
    assert len(seen) > 1
    snap = rt.snapshot()
    assert snap["frequency_random"] is True
    assert snap["frequency"] in seen
    rt.set_frequency(9)
    assert rt.frequency_random is False
    assert rt.frequency == 9
    rt.tick()
    assert rt.frequency == 9


def test_new_mitre_overlays():
    rt = SimRuntime("dev", "")
    rt.set_attack("spoof", False)
    rt.set_frequency(3)

    rt.set_attack("ais", True)
    plant, frames = rt.tick()
    ais = [decode_fields(f) for f in frames if decode_fields(f).get("pgn") == 129038]
    assert ais and abs(ais[0]["lat_deg"] - plant.lat_deg) > 1e-4
    assert any(e["kind"] == "ais" and e["technique"] == "T1692.002" for e in rt.snapshot()["emissions"])
    rt.set_attack("ais", False)

    rt.set_attack("engine_cmd", True)
    _p, frames = rt.tick()
    cmds = [decode_fields(f) for f in frames if decode_fields(f).get("pgn") == 126208]
    assert len(cmds) == 3
    assert all(c["sa"] == 44 and c["operation_name"] == "engine_control" for c in cmds)
    assert any(e["kind"] == "engine" and e["technique"] == "T1692.001" for e in rt.snapshot()["emissions"])
    rt.set_attack("engine_cmd", False)

    rt.set_attack("rogue_master", True)
    _p, frames = rt.tick()
    claims = [decode_fields(f) for f in frames if decode_fields(f).get("pgn") == 60928]
    stolen = [c for c in claims if c["sa"] == 16 and str(c.get("iso_name") or "").startswith("ROGUE")]
    assert stolen
    assert any(e["kind"] == "rogue" and e["technique"] == "T0848" for e in rt.snapshot()["emissions"])
    rt.set_attack("rogue_master", False)

    rt.set_attack("gateway_bypass", True)
    _p, frames = rt.tick()
    bypass = [decode_fields(f) for f in frames if decode_fields(f).get("pgn") == 127488 and f.segment == "nav"]
    assert len(bypass) == 3
    assert any(e["kind"] == "bypass" and e["technique"] == "T1692" for e in rt.snapshot()["emissions"])
    rt.set_attack("gateway_bypass", False)

    rt.set_attack("spoof_both", True)
    plant, frames = rt.tick()
    pos = [decode_fields(f) for f in frames if decode_fields(f).get("pgn") == 129025]
    g1 = next(p for p in pos if p["sa"] == 16)
    g2 = next(p for p in pos if p["sa"] == 17)
    assert abs(g1["lat_deg"] - plant.lat_deg) > 1e-4
    assert abs(g2["lat_deg"] - plant.lat_deg) > 1e-4
    rt.set_attack("spoof_both", False)

    rt.set_attack("error_flood", True)
    _p, frames = rt.tick()
    errs = [f for f in frames if f.error]
    assert len(errs) == 3
    rt.set_attack("error_flood", False)

    rt.set_attack("rot", True)
    plant, frames = rt.tick()
    rot = next(decode_fields(f) for f in frames if decode_fields(f).get("pgn") == 127251)
    assert rot["rot_deg_s"] > plant.rot_deg_s + 4


def test_frequency_control_api():
    from opv_sim.app import app, runtime

    runtime.reset("")
    runtime.running = False
    with TestClient(app) as client:
        r = client.post("/api/control", json={"action": "frequency", "frequency": 7})
        assert r.json()["snapshot"]["frequency"] == 7
        assert r.json()["snapshot"]["frequency_random"] is False
        r = client.post("/api/control", json={"action": "frequency_random", "enabled": True})
        assert r.json()["snapshot"]["frequency_random"] is True
        r = client.post("/api/control", json={"action": "toggle_attack", "attack": "rogue_master", "enabled": True})
        assert r.json()["snapshot"]["attacks"]["rogue_master"] is True
        assert r.json()["snapshot"]["attack_id"] == "rogue-master"


def test_sog_and_frames_sliders():
    rt = SimRuntime("dev", "")
    rt.set_attack("spoof", False)
    plant, frames = rt.tick()
    assert plant.sog_kn == 12.0
    cog = next(
        decode_fields(f)
        for f in frames
        if decode_fields(f).get("pgn") == 129026 and decode_fields(f)["sa"] == 16
    )
    assert abs(cog["sog_kn"] - 12.0) < 0.2
    lat0 = plant.lat_deg

    rt.set_sog(0)
    plant, frames = rt.tick()
    assert plant.sog_kn == 0.0
    assert abs(plant.lat_deg - lat0) < 1e-5
    cog = next(
        decode_fields(f)
        for f in frames
        if decode_fields(f).get("pgn") == 129026 and decode_fields(f)["sa"] == 16
    )
    assert cog["sog_kn"] < 0.3
    rpm = next(
        decode_fields(f)
        for f in frames
        if decode_fields(f).get("pgn") == 127488 and decode_fields(f)["sa"] == 0
    )
    assert rpm["rpm"] < 50

    rt.set_sog(24)
    plant, frames = rt.tick()
    assert plant.sog_kn == 24.0
    cog = next(
        decode_fields(f)
        for f in frames
        if decode_fields(f).get("pgn") == 129026 and decode_fields(f)["sa"] == 16
    )
    assert abs(cog["sog_kn"] - 24.0) < 0.3

    rt.set_frames(3)
    _p, frames = rt.tick()
    assert rt.snapshot()["frame_copies"] == 3
    pos = [f for f in frames if decode_fields(f).get("pgn") == 129025 and decode_fields(f)["sa"] == 16]
    assert len(pos) == 3

    from opv_sim.app import app, runtime

    runtime.reset("")
    runtime.running = False
    with TestClient(app) as client:
        r = client.post("/api/control", json={"action": "sog", "sog": 6})
        assert r.json()["snapshot"]["sog_kn"] == 6.0
        r = client.post("/api/control", json={"action": "frames", "frames": 4})
        assert r.json()["snapshot"]["frame_copies"] == 4


def test_catalog_twins_publish_missing_pgns():
    rt = SimRuntime("dev", "")
    rt.set_attack("spoof", False)
    rt.set_device("24", True)
    rt.set_device("52", True)
    rt.set_device("56", True)
    _plant, frames = rt.tick()
    decoded = [decode_fields(f) for f in frames]
    pgns_by_sa: dict[int, set[int]] = {}
    for row in decoded:
        pgns_by_sa.setdefault(row["sa"], set()).add(row["pgn"])
    assert 127257 in pgns_by_sa[35]
    assert 129794 in pgns_by_sa[24]
    assert 127489 in pgns_by_sa[0] and 127489 in pgns_by_sa[1]
    assert 127245 in pgns_by_sa[52]
    assert 127250 not in pgns_by_sa.get(52, set())
    assert 128267 in pgns_by_sa[40] and 128259 in pgns_by_sa[40]
    assert 130306 in pgns_by_sa[48]
    assert 127493 in pgns_by_sa[4] and 127493 in pgns_by_sa[5]
    assert 127505 in pgns_by_sa[8] and 127505 in pgns_by_sa[84]
    assert 127508 in pgns_by_sa[28]
    assert 130311 in pgns_by_sa[80]
    assert 127501 in pgns_by_sa[88]
    status = next(r for r in decoded if r["sa"] == 56 and r["pgn"] == 127237)
    assert status["operation_name"] == "heading_control_status"
    assert status.get("privileged") is False
    snap = rt.snapshot()
    ap = next(e for e in snap["emissions"] if e["sa"] == "56" and e["pgn"] == 127237)
    assert ap["kind"] == "ok"
    assert "status" in ap["summary"]
    rud = next(e for e in snap["emissions"] if e["sa"] == "52" and e["pgn"] == 127245)
    assert rud["kind"] == "ok"
    assert "rudder" in rud["summary"]
    catalog_sas = {str(sa) for sa, *_rest in DEVICE_CATALOG}
    for sa in ("40", "48", "4", "5", "8", "21", "28", "32", "80", "84", "88", "12", "20", "60", "99"):
        assert sa in catalog_sas
        assert sa in rt.devices


def test_every_catalog_device_emits_when_enabled():
    rt = SimRuntime("dev", "")
    rt.set_attack("spoof", False)
    for sa, *_rest in DEVICE_CATALOG:
        rt.set_device(str(sa), True)
    _plant, frames = rt.tick()
    sas = {decode_fields(f)["sa"] for f in frames}
    missing = [sa for sa, *_rest in DEVICE_CATALOG if sa not in sas]
    assert missing == [], missing
    mfd = [decode_fields(f) for f in frames if decode_fields(f)["sa"] == 60]
    assert {r["pgn"] for r in mfd} >= {126992, 126993}
    decoy = [decode_fields(f) for f in frames if decode_fields(f)["sa"] == 99]
    assert 126993 in {r["pgn"] for r in decoy}
    _plant, frames = rt.tick()
    sas2 = {decode_fields(f)["sa"] for f in frames}
    missing2 = [sa for sa, *_rest in DEVICE_CATALOG if sa not in sas2]
    assert missing2 == [], missing2
    rt.set_device("60", False)
    rt.set_device("99", False)
    _plant, frames = rt.tick()
    off = {decode_fields(f)["sa"] for f in frames}
    assert 60 not in off
    assert 99 not in off
