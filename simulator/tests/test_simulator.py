import pytest

from opv_sim import ScenarioEngine
from opv_sim.lab import OpvSimulator
from opv_sim.labels import LabelTopic
from opv_sim.twins import IsolatingGateway
from otlab.bus import InMemoryCanBus
from otlab.pgn import encode_heading, encode_rpm
from otlab.can import unpack_id


def test_simulator_nmea2000_only():
    sim = OpvSimulator()
    assert not hasattr(sim, "modbus")
    assert not hasattr(sim, "n0183")
    plant, frames = sim.tick(0)
    assert frames
    assert all(hasattr(f, "can_id") for f in frames)
    assert all(f.segment in ("nav", "propulsion", "power", "aux") for f in frames)
    eng = ScenarioEngine("underway")
    a = eng.state_at(0)
    b = eng.state_at(10)
    assert b.lon_deg != a.lon_deg
    assert a.hdop < 2.5
    assert a.attack_id is None


def test_scenario_gps_spoof_phases():
    eng = ScenarioEngine("gps-spoof-underway", "gps-spoof-primary")
    assert eng.state_at(1).phase == "baseline"
    assert eng.state_at(10).phase == "ramp"
    assert eng.state_at(10).attack_id == "gps-spoof-primary"
    assert eng.state_at(30).phase == "hold"


def test_scenario_stamps_wall_clock():
    from datetime import datetime, timezone, timedelta

    before = datetime.now(timezone.utc) - timedelta(seconds=2)
    plant = ScenarioEngine("underway").state_at(8000)
    after = datetime.now(timezone.utc) + timedelta(seconds=2)
    assert before <= plant.t <= after


def test_twins_spoof_splits_gnss():
    sim = OpvSimulator(attack_id="gps-spoof-primary", scenario_id="gps-spoof-underway")
    plant, frames = sim.tick(10)
    from otlab.pgn import decode_fields

    pos = [decode_fields(f) for f in frames if decode_fields(f).get("pgn") == 129025]
    g1 = next(p for p in pos if p["sa"] == 16)
    g2 = next(p for p in pos if p["sa"] == 17)
    assert abs(g1["lat_deg"] - g2["lat_deg"]) > 1e-4


def test_twins_gyro_spoofs_heading():
    sim = OpvSimulator(attack_id="heading-spoof", scenario_id="underway")
    plant, frames = sim.tick(0)
    from otlab.pgn import decode_fields

    hdg = next(decode_fields(f) for f in frames if decode_fields(f).get("pgn") == 127250 and decode_fields(f)["sa"] == 35)
    delta = abs((hdg["heading_deg"] - plant.heading_deg + 180) % 360 - 180)
    assert delta > 20
    assert plant.attack_id == "heading-spoof"
    assert sim.labels.records
    assert any(r.victim_sa == 35 and r.pgn == 127250 for r in sim.labels.records)


def test_twins_velocity_spoofs_sog():
    sim = OpvSimulator(attack_id="sog-spoof", scenario_id="underway")
    plant, frames = sim.tick(0)
    from otlab.pgn import decode_fields

    g1 = next(decode_fields(f) for f in frames if decode_fields(f).get("pgn") == 129026 and decode_fields(f)["sa"] == 16)
    g2 = next(decode_fields(f) for f in frames if decode_fields(f).get("pgn") == 129026 and decode_fields(f)["sa"] == 17)
    assert g1["sog_kn"] > plant.sog_kn + 4
    assert abs(g2["sog_kn"] - plant.sog_kn) < 0.2
    assert plant.attack_id == "sog-spoof"


def test_labels_dev_only():
    sim = OpvSimulator(sim_mode="dev", attack_id="gps-spoof-primary")
    sim.tick(10)
    assert sim.labels.records
    with pytest.raises(RuntimeError):
        LabelTopic("prod", label_topic_configured=True)


def test_labels_absent_in_prod():
    sim = OpvSimulator(sim_mode="prod", attack_id="gps-spoof-primary")
    sim.tick(10)
    assert sim.labels.records == []
    assert sim.bus.peek_all()  # CAN still flows


def test_gateway_blocks_rpm_onto_nav():
    bus = InMemoryCanBus()
    gw = IsolatingGateway(bus)
    from datetime import datetime, timezone

    t = datetime.now(timezone.utc)
    rpm = encode_rpm(t, "propulsion", 0, 1400)
    assert gw.forward(rpm, "nav") is None
    hdg = encode_heading(t, "nav", 35, 90)
    assert gw.forward(hdg, "propulsion") is not None


def test_gateway_bypass_attack():
    bus = InMemoryCanBus()
    gw = IsolatingGateway(bus)
    from datetime import datetime, timezone

    t = datetime.now(timezone.utc)
    rpm = encode_rpm(t, "propulsion", 0, 1400)
    out = gw.force_bypass(rpm, "nav")
    assert out.segment == "nav"
    assert unpack_id(out.can_id)["pgn"] == 127488
