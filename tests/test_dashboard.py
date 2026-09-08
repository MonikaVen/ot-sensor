from pathlib import Path

from ot_sensor.lab_runtime import LabRuntime


REPO = Path(__file__).resolve().parents[1]


def test_runtime_inventory_and_incident(tmp_path):
    rt = LabRuntime(REPO, tmp_path, "dev", "gps-spoof-primary")
    snap = rt.snapshot()
    names = {a["name"] for a in snap["assets"]}
    assert "GNSS-1" in names
    assert "engine-port" in names
    assert snap["incidents"] == []
    for _ in range(8):
        rt.step()
    snap = rt.snapshot()
    assert snap["stats"]["events"] > 0
    assert snap["comms"]
    assert snap["incidents"]
    assert any(i["risk"]["nis2_significant"] for i in snap["incidents"])
    inc = next(i for i in snap["incidents"] if i["risk"]["nis2_significant"])
    assert inc["incident_id"] in snap["new_incident_ids"]
    rt.ack_alerts([inc["incident_id"]])
    assert inc["incident_id"] not in rt.snapshot()["new_incident_ids"]


def test_api_health_and_step(tmp_path):
    from fastapi.testclient import TestClient
    from ot_sensor.app import app, runtime

    runtime.running = False
    runtime.work = tmp_path
    runtime.reset("gps-spoof-primary")
    with TestClient(app) as client:
        runtime.running = False
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["ok"] is True
        r = client.get("/api/snapshot")
        assert r.status_code == 200
        assert r.json()["assets"]
        r = client.post("/api/control", json={"action": "step"})
        assert r.status_code == 200
        assert r.json()["snapshot"]["ticks"] >= 1
