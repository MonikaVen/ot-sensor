from pathlib import Path

from ot_sensor.paths import lab_root
from ot_sensor.pipeline import run_spoof_lab


REPO = lab_root()


def test_gps_spoof_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setattr("ot_sensor.slm.ollama_ready", lambda: False)
    sim, sensor, result = run_spoof_lab(REPO, tmp_path, mode="dev", ticks=12)
    win, score, hit, inc = result
    assert hit.fired
    assert inc is not None
    assert inc.risk.nis2_significant
    assert sensor.last_copilot.status == "llm_unavailable"
    assert sensor.last_stix and Path(sensor.last_stix.path).exists()
    assert sensor.last_eval and "T1692.002" in sensor.last_eval["label_techniques"]
    assert sim.labels.records


def test_prod_has_no_eval_labels(tmp_path):
    sim, sensor, result = run_spoof_lab(REPO, tmp_path, mode="prod", ticks=12)
    _, _, hit, inc = result
    assert hit.fired
    assert inc is not None
    assert sim.labels.records == []
    assert sensor.last_eval is None
