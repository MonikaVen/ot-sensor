from datetime import datetime, timezone
from pathlib import Path

import pytest

from ot_sensor.adapters import ModbusAdapter, Nmea0183Adapter, Nmea2000Adapter
from ot_sensor.assets import AssetDetector
from ot_sensor.eval_join import EvalJoin
from ot_sensor.features import FeatureStage
from ot_sensor.graph import CommsGraph
from ot_sensor.honeypot import Honeypot
from ot_sensor.incidents import IncidentCorrelator
from ot_sensor.onnx_enrich import OnnxEnrich
from ot_sensor.rules import RulesEnrich
from ot_sensor.slm import LocalSlm
from ot_sensor.stix import StixExporter
from otlab.pgn import encode_heading, encode_position
from opv_sim import ScenarioEngine
from ot_sensor.paths import lab_root


REPO = lab_root()


def test_n2k_adapter_listen_only_prod():
    with pytest.raises(RuntimeError):
        Nmea2000Adapter(writes=True, mode="prod")
    ad = Nmea2000Adapter(mode="prod")
    t = datetime.now(timezone.utc)
    ev = ad.convert(encode_position(t, "nav", 16, 54.5, 18.7))
    assert ev.protocol == "nmea2000"
    assert ev.source_asset_id == "16"
    assert ev.object_address == "129025"
    assert ev.is_write is False


def test_n0183_adapter():
    t = datetime.now(timezone.utc)
    ev = Nmea0183Adapter().convert("$HEHDT,90.0,T*1F", t)
    assert ev.protocol == "nmea0183"
    assert ev.source_asset_id == "HE"
    assert ev.value_after["heading_deg"] == 90.0


def test_modbus_adapter_reads():
    t = datetime.now(timezone.utc)
    evs = ModbusAdapter().convert({"rpm_port": 1400}, t)
    assert evs[0].protocol == "modbus"
    assert evs[0].is_write is False


def test_honeypot_rotation_and_retain(tmp_path):
    hp = Honeypot(tmp_path, "dev", rotate_max_bytes=180, retain_max_files=2)
    t = datetime.now(timezone.utc)
    plant = ScenarioEngine().state_at(0)
    from opv_sim.twins import AttackInjector, DeviceTwins
    from otlab.bus import InMemoryCanBus

    bus = InMemoryCanBus()
    twins = DeviceTwins(bus, AttackInjector("dev"))
    for i in range(30):
        frames = twins.publish(plant)
        for fr in frames:
            hp.write_frame(fr)
    hp.rotate(t)
    assert hp.rotation >= 1
    assert all(p.suffixes[-2:] == [".jsonl", ".gz"] or p.name.endswith(".jsonl.gz") for p in hp.closed)
    assert len(hp.closed) <= 2


def test_asset_criticality_and_dependents():
    det = AssetDetector(REPO / "docs/architecture/samples/sources/asset-criticality.yaml")
    t = datetime.now(timezone.utc)
    ad = Nmea2000Adapter()
    ev = ad.convert(encode_position(t, "nav", 16, 54.5, 18.7))
    rec = det.observe(ev)
    assert rec.criticality == 5
    assert rec.nis2_service == "navigation"
    assert "56" in rec.dependents  # autopilot


def test_comms_graph_new_edge():
    g = CommsGraph()
    t = datetime.now(timezone.utc)
    ev = Nmea2000Adapter().convert(encode_heading(t, "nav", 44, 90))
    g.observe(ev)
    assert any(c["change"] == "new_edge" for c in g.changes)


def test_features_split_and_rules_fire():
    from otlab.geo import dest_point
    from otlab.pgn import encode_cog_sog, encode_dops, encode_position, encode_sats

    t = datetime.now(timezone.utc)
    ad = Nmea2000Adapter()
    lat, lon = dest_point(54.5, 18.7, 180, 90)
    events = [
        ad.convert(encode_position(t, "nav", 16, lat, lon)),
        ad.convert(encode_position(t, "nav", 17, 54.5, 18.7)),
        ad.convert(encode_dops(t, "nav", 16, 0.8)),
        ad.convert(encode_sats(t, "nav", 16, 12, lat, lon)),
        ad.convert(encode_cog_sog(t, "nav", 16, 115, 12)),
        ad.convert(encode_heading(t, "nav", 35, 90)),
    ]
    win = FeatureStage().window(events)
    assert win.features["gnss1_gnss2_split_m"] > 50
    hit = RulesEnrich().gps_spoof_nav(win)
    assert hit.fired
    assert hit.techniques == ["T1692.002"]


def test_onnx_lstm_runs_or_unavailable():
    win = FeatureStage().window(
        [Nmea2000Adapter().convert(encode_heading(datetime.now(timezone.utc), "nav", 35, 90))]
    )
    score = OnnxEnrich(REPO / "docs/architecture/samples/models/throughput-lstm/1.0.0").score(win)
    assert score.status in ("ok", "model_unavailable")
    if score.status == "ok":
        assert "flood_score" in score.scores


def test_incidents_risk_nis2():
    from ot_sensor.assets import AssetRecord
    from ot_sensor.onnx_enrich import ModelScore
    from ot_sensor.rules import RuleHit

    t = datetime.now(timezone.utc)
    events = [Nmea2000Adapter().convert(encode_position(t, "nav", 16, 54.5, 18.7))]
    win = FeatureStage().window(events)
    hit = RuleHit(win.event_id, "gps-spoof-nav", "1.0.0", True, "critical", ["T1692.002"], ["T0832", "T0829"])
    score = ModelScore(win.event_id, "throughput-lstm", "1.0.0", {"flood_score": 0.01}, "ok")
    corr = IncidentCorrelator("prod")
    alert = corr.join(win, score, hit)
    assets = [
        AssetRecord("16", "nav", "GNSS-1", True, 5, "navigation", [], ["56", "24", "60"]),
    ]
    inc = corr.correlate(alert, win, assets)
    assert inc is not None
    assert inc.risk.nis2_significant
    assert inc.nis2 is not None
    assert inc.nis2.human_confirm is False
    # dedup second hop
    inc2 = corr.correlate(alert, win, assets)
    assert inc2.incident_id == inc.incident_id
    assert inc2.alert_count == 2


def test_slm_fail_closed_no_gguf():
    from ot_sensor.incidents import Incident, RiskScore

    t = datetime.now(timezone.utc)
    inc = Incident(
        "inc-1",
        "open",
        t,
        t,
        "critical",
        RiskScore(86, 40, 22, 16, 8, 5, ["56"], True),
        None,
        "nmea2000",
        "n2k-nav",
        "nav",
        ["16"],
        ["T1692.002"],
        ["T0832"],
        1,
        [],
        {},
        "prod",
    )
    with pytest.raises(RuntimeError):
        LocalSlm(None, "https://api.openai.com", "prod")
    cop = LocalSlm(None, None, "prod").assess(inc)
    assert cop.status == "llm_unavailable"
    assert "risk 86" in cop.alert_title


def test_stix_local_not_taxii(tmp_path):
    from ot_sensor.incidents import Incident, RiskScore
    from ot_sensor.slm import CopilotAssessment

    t = datetime.now(timezone.utc)
    inc = Incident(
        "inc-1", "open", t, t, "critical",
        RiskScore(86, 40, 22, 16, 8, 5, [], True), None,
        "nmea2000", "n2k-nav", "nav", ["16"], ["T1692.002"], [], 1, [], {}, "prod",
    )
    cop = CopilotAssessment("inc-1", "watchstander-slm", "1.0.0", "local", "llm_unavailable", "t", "b", [], ["T1692.002"], 0, [], "attack")
    ref = StixExporter(tmp_path, "prod").write(inc, cop)
    assert Path(ref.path).exists()
    assert ref.taxii_shared is False


def test_eval_join_dev_only():
    with pytest.raises(RuntimeError):
        EvalJoin("prod", label_topic_set=True)
    assert EvalJoin("prod").enabled is False
