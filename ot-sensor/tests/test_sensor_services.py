from datetime import datetime, timezone
from pathlib import Path
import json

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
    assert all(p.name.endswith(".jsonl.gz") for p in hp.closed)
    by_seg: dict[str, int] = {}
    for p in hp.closed:
        by_seg[p.parent.name] = by_seg.get(p.parent.name, 0) + 1
        assert "-n" in p.name and "-b" in p.name and "-k" in p.name and "-r" in p.name
        assert "open-" not in p.name
    assert by_seg
    assert all(n <= 2 for n in by_seg.values())
    assert hp.written > 0
    assert (tmp_path / "_manifest.jsonl").is_file()
    hp.wipe()
    assert hp.usage()["bytes"] == 0
    assert hp.written == 0
    assert hp.feed() == []
    assert list(tmp_path.rglob("*")) == [] or not any(p.is_file() for p in tmp_path.rglob("*"))


def test_honeypot_live_feed(tmp_path):
    import base64
    import json

    hp = Honeypot(tmp_path, "dev", rotate_max_bytes=50_000, retain_max_files=4, live_max=5)
    plant = ScenarioEngine().state_at(0)
    from opv_sim.twins import AttackInjector, DeviceTwins
    from otlab.bus import InMemoryCanBus

    bus = InMemoryCanBus()
    twins = DeviceTwins(bus, AttackInjector("dev"))
    frames = twins.publish(plant)
    assert frames
    for fr in frames:
        hp.write_frame(fr)
    feed = hp.feed()
    assert feed
    assert len(feed) <= 5
    row = feed[0]
    assert row["payload_hex"]
    assert "can_id" in row
    assert "pgn" not in row
    raw = hp._path.read_text(encoding="utf-8").splitlines()[0]
    rec = json.loads(raw)
    assert base64.b64decode(rec["payload_b64"])
    assert rec["kind"] in {"can", "error", "empty"}
    segs = {fr.segment for fr in frames}
    assert segs <= set(hp._slots)
    hp.wipe()
    assert hp.feed() == []


def test_honeypot_drop_when_all_held(tmp_path):
    hp = Honeypot(tmp_path, "dev", rotate_max_bytes=120, retain_max_files=1)
    t = datetime.now(timezone.utc)
    plant = ScenarioEngine().state_at(0)
    from opv_sim.twins import AttackInjector, DeviceTwins
    from otlab.bus import InMemoryCanBus

    bus = InMemoryCanBus()
    twins = DeviceTwins(bus, AttackInjector("dev"))
    for _ in range(8):
        for fr in twins.publish(plant):
            hp.write_frame(fr)
    hp.rotate(t)
    assert hp.closed
    for p in list(hp.closed):
        hp.hold_paths.add(str(p))
    before = hp.dropped
    written = hp.written
    for _ in range(8):
        for fr in twins.publish(plant):
            hp.write_frame(fr)
    assert hp.dropped > before
    assert hp.written >= written
    for p in hp.closed:
        assert p.exists()
    for path, _seq in hp.open_files():
        assert "open-" in path.name



def test_asset_criticality_and_dependents():
    det = AssetDetector(REPO / "docs/architecture/samples/sources/asset-criticality.yaml")
    t = datetime.now(timezone.utc)
    ad = Nmea2000Adapter()
    ev = ad.convert(encode_position(t, "nav", 16, 54.5, 18.7))
    rec = det.observe(ev)
    assert rec.criticality == 5
    assert rec.nis2_service == "navigation"
    assert "56" in rec.dependents  # autopilot
    assert rec.expected is True
    assert "pgn:129025" in rec.detected_via


def test_asset_autodetect_unknown_and_claim():
    from otlab.pgn import encode_claim, encode_heading

    det = AssetDetector(REPO / "docs/architecture/samples/sources/asset-criticality.yaml")
    t = datetime.now(timezone.utc)
    ad = Nmea2000Adapter()
    assert det.live == {}
    rogue = det.observe(ad.convert(encode_heading(t, "nav", 44, 90)))
    assert rogue.expected is False
    assert rogue.name == "heading sensor"
    assert rogue.criticality == 2
    assert any(c["change"] == "new_asset" and c["asset_id"] == "44" for c in det.changes)
    claimed = det.observe(ad.convert(encode_claim(t, "nav", 77, "ROGUE")))
    assert claimed.expected is False
    assert claimed.identity["iso_name"] == "ROGUE"
    assert claimed.name == "ROGUE"
    assert "address_claim" in claimed.detected_via


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
    quiet = RulesEnrich()
    quiet.settings.apply(clauses={"gnss1_gnss2_split_m": 10_000})
    assert quiet.gps_spoof_nav(win).fired is False


def test_lab_rule_packs_iso_request_and_unexpected_talker():
    from otlab.pgn import encode_heading_control, encode_iso_request

    t = datetime.now(timezone.utc)
    ad = Nmea2000Adapter()
    win = FeatureStage().window([ad.convert(encode_iso_request(t, "nav", 44, 16, 129025))])
    assert win.features["iso_request_count"] >= 1
    assert win.features["unexpected_talker_count"] >= 1
    by = {h.rule_id: h for h in RulesEnrich().evaluate(win)}
    assert by["n2k-iso-request"].fired
    assert by["unexpected-talker"].fired
    assert by["gps-spoof-nav"].fired is False
    assert by["n2k-heading-control"].fired is False

    win = FeatureStage().window([ad.convert(encode_heading_control(t, "nav", 44, 90))])
    by = {h.rule_id: h for h in RulesEnrich().evaluate(win)}
    assert by["n2k-heading-control"].fired
    assert by["unexpected-talker"].fired

    status_win = FeatureStage().window(
        [ad.convert(encode_heading_control(t, "nav", 56, 90, status=True))]
    )
    status_ev = ad.convert(encode_heading_control(t, "nav", 56, 90, status=True))
    assert status_ev.is_write is False
    assert status_ev.privileged is False
    assert status_win.features["heading_control_count"] == 0
    by = {h.rule_id: h for h in RulesEnrich().evaluate(status_win)}
    assert by["n2k-heading-control"].fired is False

    flood = FeatureStage().window([ad.convert(encode_heading(t, "nav", 35, 90)) for _ in range(20)])
    by = {h.rule_id: h for h in RulesEnrich().evaluate(flood)}
    assert by["pgn-flood"].fired
    assert by["unexpected-talker"].fired is False


def test_throughput_lstm_tracks_then_flags_jump():
    from ot_sensor.lstm import ThroughputLstm

    model = ThroughputLstm()
    last = None
    for _ in range(20):
        last = model.step(40.0)
    assert last is not None
    assert last["fired"] is False
    assert last["residual_fps"] < 40
    jump = model.step(400.0)
    assert jump["threshold_fps"] == jump["predicted_fps"]
    assert jump["actual_fps"] > jump["threshold_fps"]
    assert jump["crossed"] is True
    assert jump["fired"] is True


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


def test_slm_fail_closed_no_gguf(monkeypatch):
    from ot_sensor.incidents import Incident, RiskScore

    monkeypatch.setattr("ot_sensor.slm.ollama_ready", lambda: False)
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
    assert cop.runtime == "none"
    assert "risk 86" in cop.alert_title


def test_slm_ok_when_ollama_ready(monkeypatch):
    from ot_sensor.incidents import Incident, RiskScore

    monkeypatch.setattr("ot_sensor.slm.ollama_ready", lambda: True)
    monkeypatch.setattr("ot_sensor.slm.base_model", lambda runtime=None: "qwen2:1.5b")
    monkeypatch.setattr("ot_sensor.slm.resolve_model", lambda: "cyberpal")
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
        "dev",
    )
    slm = LocalSlm(None, None, "dev")
    assert slm.ready()
    assert slm.runtime() == "qwen2:1.5b"
    cop = slm.assess(inc)
    assert cop.status == "ok"
    assert cop.runtime == "qwen2:1.5b"
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


def test_cyberpal_picks_small_slm(monkeypatch):
    import ot_sensor.cyberpal as c

    monkeypatch.setattr(c, "ollama_tags", lambda: ["qwen2:1.5b", "qwen2:latest", "cyberpal-2.0-4b", "qwen2"])
    assert c._pick(c.ollama_tags()) == "qwen2:1.5b"
    monkeypatch.setattr(c, "ollama_tags", lambda: ["cyberpal:latest", "qwen2:1.5b", "qwen2"])
    assert c._pick(c.ollama_tags()) == "cyberpal"
    assert c.base_model("cyberpal") == "qwen2:1.5b"
    looped = "Observe spoofed talkers. Observe spoofed talkers. Distrust GNSS-1. Observe spoofed talkers."
    assert c._collapse(looped) == "Observe spoofed talkers. Distrust GNSS-1."


def test_cyberpal_briefing_strips_raw_and_isolates_sessions(tmp_path, monkeypatch):
    from ot_sensor.assistant import CyberPalAssistant, briefing_payload

    monkeypatch.setattr("ot_sensor.assistant.ollama_ready", lambda: False)
    payload = briefing_payload(
        {
            "incident_id": "inc-0001",
            "state": "open",
            "severity": "critical",
            "families": ["gnss-spoof"],
            "asset_ids": ["16"],
            "techniques": ["T1692.002"],
            "risk": {"total": 86, "nis2_significant": True, "dependent_asset_ids": ["56"]},
            "alerts": [{"event_id": "e1", "fired_rules": ["gps-spoof-nav"], "evidence_summary": {"top_features": ["gnss_dr_residual_m"]}}],
            "copilot": {"status": "llm_unavailable", "alert_title": "t", "alert_body": "b", "recommend": ["Distrust GNSS-1"]},
        },
        [{"asset_id": "16", "name": "GNSS-1", "segment": "nav", "criticality": 5, "dependents": ["56"]}],
    )
    blob = json.dumps(payload)
    assert "payload_hex" not in blob
    assert "attack_id" not in blob
    assert payload["assets"][0]["name"] == "GNSS-1"
    fat = briefing_payload(
        {
            "incident_id": "inc-fat",
            "alerts": [
                {
                    "event_id": f"e{i}",
                    "fired_rules": ["gps-spoof-nav"],
                    "rules": [{"rule_id": "gps-spoof-nav", "fired": True, "clauses_fired": ["gnss_dr_residual_m"]}],
                    "models": [{"model_id": "throughput-lstm", "scores": {"a": 0.1}, "fired": True}],
                    "graph": [{"src": "16", "dst": "56", "pgn": 129025}],
                    "evidence_summary": {"top_features": ["gnss_dr_residual_m"] * 20},
                }
                for i in range(20)
            ],
        }
    )
    assert len(json.dumps(fat, default=str)) < 8000
    assert len(fat["alerts"]) <= 10
    assert fat["fired_rules"][0]["rule_id"] == "gps-spoof-nav"
    asst = CyberPalAssistant(REPO, tmp_path)
    a = asst.ask("inc-0001", "Why did this fire?", {"incident_id": "inc-0001", **payload})
    b = asst.ask("inc-0002", "Which assets?", {"incident_id": "inc-0002", "families": ["flood"], "asset_ids": ["44"], "alerts": []})
    assert a["incident_id"] == "inc-0001"
    assert b["incident_id"] == "inc-0002"
    assert asst.sessions["inc-0001"].messages[0]["content"] != asst.sessions["inc-0002"].messages[0]["content"]
