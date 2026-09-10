from ot_sensor.lab_runtime import LabRuntime
from ot_sensor.paths import lab_root


REPO = lab_root()


def test_runtime_inventory_and_incident(tmp_path):
    rt = LabRuntime(REPO, tmp_path, "dev")
    snap = rt.snapshot()
    assert snap["assets"] == []
    assert snap["incidents"] == []
    for _ in range(8):
        rt.step()
    snap = rt.snapshot()
    names = {a["name"] for a in snap["assets"]}
    assert "GNSS-1" in names
    assert "engine-port" in names
    assert "echo" in names
    assert "battery" in names
    assert "autopilot" not in names
    assert all(a["live"] or a["channels_seen"] for a in snap["assets"])
    assert (tmp_path / "assets" / "dev" / "opv1" / "inventory.json").exists()
    assert snap["stats"]["events"] > 0
    assert snap["comms"]
    assert snap["incidents"]
    assert any(i["risk"]["nis2_significant"] for i in snap["incidents"])
    inc = next(i for i in snap["incidents"] if i["risk"]["nis2_significant"])
    assert inc["incident_id"] in snap["new_incident_ids"]
    rt.ack_alerts([inc["incident_id"]])
    assert inc["incident_id"] not in rt.snapshot()["new_incident_ids"]
    flow = snap["message_flow"]
    assert flow
    assert snap["attack_started_at"]
    assert snap["attack_started_at"] == next(m["t"] for m in reversed(flow) if m["spoofed"])
    assert any(m["sa"] == "16" and m["spoofed"] and m["pgn"] == 129025 for m in flow)
    by = {a["asset_id"]: a["traffic"] for a in snap["assets"]}
    assert by["16"] == "attack"
    assert by["17"] == "benign"
    rt.sim.set_attack("spoof", False)
    rt.sim.set_device("17", False)
    rt.step()
    by = {a["asset_id"]: a["traffic"] for a in rt.snapshot()["assets"]}
    assert by["16"] == "benign"
    assert by["17"] == "silent"
    rt.sim.set_attack("read", True)
    rt.step()
    by = {a["asset_id"]: a["traffic"] for a in rt.snapshot()["assets"]}
    assert by["44"] == "attack"
    assert by["16"] == "attack"
    hist = {h["key"]: h for h in snap["histograms"]}
    assert "spoof" in hist and "gyro" in hist and "pgn_flood" in hist
    assert hist["spoof"]["attack"]
    rt.sim.set_attack("read", False)
    rt.sim.set_attack("gyro", True)
    rt.step()
    flow = rt.snapshot()["message_flow"]
    assert any((m.get("kind") == "gyro" or m.get("spoofed")) and m["sa"] == "35" for m in flow)
    assert any(m.get("kind") == "read" for m in flow)


def test_api_health_and_step(tmp_path):
    from fastapi.testclient import TestClient
    from opv_sim.runtime import SimRuntime
    from ot_sensor.app import app, runtime

    runtime.tap_url = None
    runtime.drive_sim = True
    runtime.running = False
    runtime.work = tmp_path
    runtime.sim = SimRuntime("dev", "gps-spoof-primary")
    runtime.sim.reset("gps-spoof-primary")
    runtime.reset()
    with TestClient(app) as client:
        runtime.running = False
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["ok"] is True
        r = client.get("/api/snapshot")
        assert r.status_code == 200
        assert isinstance(r.json()["assets"], list)
        r = client.post("/api/control", json={"action": "step"})
        assert r.status_code == 200
        assert r.json()["snapshot"]["ticks"] >= 1
        snap = client.get("/api/snapshot").json()
        ids = [p["rule_id"] for p in snap["rules"]["packs"]]
        assert ids[0] == "gps-spoof-nav"
        assert "n2k-iso-request" in ids
        assert "n2k-heading-control" in ids
        assert "pgn-flood" in ids
        assert "unexpected-talker" in ids
        assert snap["rules"]["packs"][0]["live"] is True
        assert snap["rules"]["packs"][0]["series"]
        gps = next(p for p in snap["rules"]["packs"] if p["rule_id"] == "gps-spoof-nav")
        assert gps["series"][-1]["values"].get("gnss1_gnss2_split_m") is not None
        assert "gnss1_lat_deg" in (gps["series"][-1].get("readings") or {})
        models = snap["models"]["packs"]
        assert models[0]["model_id"] == "throughput-lstm"
        assert models[0]["live"] is True
        assert models[0]["series"]
        assert "actual_fps" in models[0]["series"][-1]
        assert "predicted_fps" in models[0]["series"][-1]
        assert "threshold_fps" in models[0]["series"][-1]
        last = models[0]["series"][-1]
        assert last["threshold_fps"] == last["predicted_fps"]
        pack = snap["rules"]["packs"][0]
        assert pack["enabled"] is True
        r = client.post("/api/rules", json={"rule_id": "gps-spoof-nav", "enabled": False, "clauses": {"gnss_dr_residual_m": 80}})
        assert r.json()["ok"] is True
        pack = r.json()["snapshot"]["rules"]["packs"][0]
        assert pack["enabled"] is False
        residual = next(c for g in pack["groups"] for c in g["clauses"] if c["id"] == "gnss_dr_residual_m")
        assert residual["value"] == 80
        r = client.post("/api/rules", json={"rule_id": "n2k-iso-request", "enabled": False})
        assert r.json()["ok"] is True
        iso = next(p for p in r.json()["snapshot"]["rules"]["packs"] if p["rule_id"] == "n2k-iso-request")
        assert iso["enabled"] is False
        r = client.post("/api/rules", json={"rule_id": "no-such-rule", "enabled": False})
        assert r.json()["ok"] is False
        client.post("/api/rules", json={"rule_id": "gps-spoof-nav", "enabled": True, "clauses": {"gnss_dr_residual_m": 50}})
        r = client.post("/api/control", json={"action": "reset"})
        assert r.json()["ok"] is True
        assert r.json()["snapshot"]["assets"] == []
        assert r.json()["snapshot"]["ticks"] == 0
        iso = next(p for p in r.json()["snapshot"]["rules"]["packs"] if p["rule_id"] == "n2k-iso-request")
        assert iso["enabled"] is False
        client.post("/api/control", json={"action": "step"})
        client.post("/api/control", json={"action": "step"})
        hp = client.get("/api/snapshot").json()["honeypot"]
        assert hp["bytes"] > 0
        assert hp["feed"]
        live = client.get("/api/honeypot").json()
        assert live["written"] == hp["written"]
        assert live["feed"]
        r = client.post("/api/control", json={"action": "clear_honeypot"})
        assert r.json()["ok"] is True
        assert r.json()["snapshot"]["honeypot"]["bytes"] == 0


def test_ingest_from_simulator_tap(tmp_path, monkeypatch):
    from opv_sim.runtime import SimRuntime
    from ot_sensor.tap import wire_to_frame

    sim = SimRuntime("dev", "gps-spoof-primary")
    payload = None
    for _ in range(8):
        sim.tick()
        payload = sim.tap()
    assert payload and payload["frames"]
    fr = wire_to_frame(payload["frames"][0])
    assert fr.can_id == payload["frames"][0]["can_id"]
    assert fr.data.hex() == payload["frames"][0]["data_hex"]

    payloads = []
    sim = SimRuntime("dev", "gps-spoof-primary")
    for _ in range(8):
        sim.tick()
        payloads.append(sim.tap())
    n = {"i": 0}

    def fake_pull(_url: str):
        i = min(n["i"], len(payloads) - 1)
        n["i"] += 1
        return payloads[i]

    rt = LabRuntime(REPO, tmp_path, "dev", tap_url="http://127.0.0.1:8444")
    monkeypatch.setattr("ot_sensor.lab_runtime.pull_tap", fake_pull)
    for _ in range(8):
        rt.step()
    snap = rt.snapshot()
    assert snap["tap_url"] == "http://127.0.0.1:8444"
    assert snap["tap_error"] is None
    names = {a["name"] for a in snap["assets"]}
    assert "GNSS-1" in names
    assert snap["stats"]["events"] > 0


def test_reset_clears_sensor_history(tmp_path):
    rt = LabRuntime(REPO, tmp_path, "dev")
    for _ in range(8):
        rt.step()
    assert rt.snapshot()["assets"]
    assert rt.snapshot()["incidents"]
    assert rt.snapshot()["message_flow"]
    inv = tmp_path / "assets" / "dev" / "opv1" / "inventory.json"
    assert inv.exists()
    rt.reset()
    snap = rt.snapshot()
    assert snap["assets"] == []
    assert snap["incidents"] == []
    assert snap["message_flow"] == []
    assert snap["ticks"] == 0
    assert snap["attack_started_at"] is None
    assert not inv.exists()
    rt.step()
    assert rt.snapshot()["assets"]


def test_honeypot_snapshot_and_clear(tmp_path):
    rt = LabRuntime(REPO, tmp_path, "dev")
    for _ in range(6):
        rt.step()
    snap = rt.snapshot()
    hp = snap["honeypot"]
    assert hp["bytes"] > 0
    assert hp["written"] > 0
    assert hp["feed"]
    row = hp["feed"][0]
    assert "payload_hex" in row and "can_id" in row
    assert "pgn" not in row
    assert hp["series"]
    assert hp["entries"]
    assert "t" in hp["entries"][-1]
    n_assets = len(snap["assets"])
    rt.clear_honeypot()
    cleared = rt.snapshot()["honeypot"]
    assert cleared["bytes"] == 0
    assert cleared["written"] == 0
    assert cleared["feed"] == []
    assert cleared["files"] == 0
    assert len(rt.snapshot()["assets"]) == n_assets


def test_assistant_session_per_incident(tmp_path, monkeypatch):
    monkeypatch.setattr("ot_sensor.assistant.ollama_ready", lambda: False)
    monkeypatch.setattr("ot_sensor.slm.ollama_ready", lambda: False)
    rt = LabRuntime(REPO, tmp_path, "dev")
    for _ in range(8):
        rt.step()
    snap = rt.snapshot()
    assert snap["assistant"]["model"] == "cyberpal"
    assert any(s["id"] == "assistant" for s in snap["services"])
    slm = next(s for s in snap["services"] if s["id"] == "slm")
    assert slm["status"] == "llm_unavailable"
    ids = [i["incident_id"] for i in snap["incidents"]]
    assert ids
    first = rt.assistant_handle(ids[0])
    assert first["ok"] is True
    assert first["interpretation"]
    assert first["source"] == "heuristic"
    assert "T1692" in first["interpretation"] or "gps" in first["interpretation"].lower() or "rule" in first["interpretation"].lower()
    asked = rt.assistant_handle(ids[0], "Why did this incident fire?")
    assert asked["messages"][0]["content"] == "Why did this incident fire?"
    assert asked["messages"][-1]["role"] == "assistant"
    other = ids[1] if len(ids) > 1 else None
    if other:
        b = rt.assistant_handle(other, "Which assets are affected?")
        assert b["incident_id"] == other
        assert rt.assistant.sessions[ids[0]].messages[0]["content"] != rt.assistant.sessions[other].messages[0]["content"]
    miss = rt.assistant_handle("inc-missing")
    assert miss["ok"] is False
    rt.reset()
    assert rt.assistant.sessions == {}


def test_slm_pill_shows_ollama_model(tmp_path, monkeypatch):
    monkeypatch.setattr("ot_sensor.slm.ollama_ready", lambda: True)
    monkeypatch.setattr("ot_sensor.slm.base_model", lambda runtime=None: "qwen2:1.5b")
    monkeypatch.setattr("ot_sensor.slm.resolve_model", lambda: "cyberpal")
    monkeypatch.setattr("ot_sensor.assistant.ollama_ready", lambda: True)
    rt = LabRuntime(REPO, tmp_path, "dev")
    snap = rt.snapshot()
    slm = next(s for s in snap["services"] if s["id"] == "slm")
    assert slm["status"] == "ok"
    assert slm["detail"] == "qwen2:1.5b"
    asst = next(s for s in snap["services"] if s["id"] == "assistant")
    assert asst["status"] == "ok"


