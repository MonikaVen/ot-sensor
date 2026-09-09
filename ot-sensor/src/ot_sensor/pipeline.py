"""Wire simulator ticks into sensor services."""

from __future__ import annotations

from collections import deque
from pathlib import Path

from opv_sim.lab import OpvSimulator
from ot_sensor.adapters import ModbusAdapter, Nmea0183Adapter, Nmea2000Adapter
from ot_sensor.assets import AssetDetector
from ot_sensor.eval_join import EvalJoin
from ot_sensor.features import FeatureStage
from ot_sensor.graph import CommsGraph
from ot_sensor.honeypot import Honeypot
from ot_sensor.incidents import IncidentCorrelator
from ot_sensor.lstm import ThroughputLstm
from ot_sensor.onnx_enrich import ModelScore, OnnxEnrich
from ot_sensor.rules import RulesEnrich
from ot_sensor.slm import LocalSlm
from ot_sensor.stix import StixExporter


class SensorPipeline:
    def __init__(
        self,
        mode: str,
        repo: Path,
        work: Path,
        llm_endpoint: str | None = None,
        label_topic_set: bool = False,
    ) -> None:
        if mode == "prod" and llm_endpoint:
            raise RuntimeError("LLM_ENDPOINT is fatal in SENSOR_MODE=prod")
        self.mode = mode
        self.n2k = Nmea2000Adapter(mode=mode)
        self.n0183 = Nmea0183Adapter()
        self.modbus = ModbusAdapter()
        hp_cfg = repo / "docs/architecture/samples/sources/honeypot.yaml"
        self.honeypot = Honeypot(
            work / "hp",
            mode,
            config_path=hp_cfg if hp_cfg.is_file() else None,
            rotate_max_bytes=65536,
            retain_max_files=8,
            live_max=120,
        )
        crit = repo / "docs/architecture/samples/sources/asset-criticality.yaml"
        self.assets = AssetDetector(crit)
        self.inventory_path = work / "assets" / mode / "opv1" / "inventory.json"
        self.graph = CommsGraph()
        self.features = FeatureStage()
        onnx_dir = repo / "docs/architecture/samples/models/throughput-lstm/1.0.0"
        self.onnx = OnnxEnrich(onnx_dir)
        self.lstm = ThroughputLstm()
        self.window_hist: deque = deque(maxlen=20)
        self.last_lstm: dict | None = None
        self.rules = RulesEnrich()
        self.incidents = IncidentCorrelator(mode)
        self.slm = LocalSlm(repo / "docs/architecture/samples/models/watchstander-slm/1.0.0", llm_endpoint, mode)
        self.stix = StixExporter(work / "stix", mode)
        self.eval = EvalJoin(mode, label_topic_set)
        self.events = []
        self.last_incident = None
        self.last_alert = None
        self.last_copilot = None
        self.copilots: dict = {}
        self.last_stix = None
        self.last_eval = None

    def ingest_frames(self, frames) -> list:
        new = []
        for fr in frames:
            self.honeypot.write_frame(fr)
            ev = self.n2k.convert(fr)
            self.events.append(ev)
            self.assets.observe(ev)
            self.graph.observe(ev)
            new.append(ev)
        if new:
            self.assets.write_inventory(self.inventory_path)
        return new

    def detect(self, events=None):
        batch = events if events is not None else self.events
        if not batch:
            return None
        win = self.features.window(batch)
        self.window_hist.append(win)
        seq = self.features.lstm_seq(list(self.window_hist))
        score = self.onnx.score(win, seq)
        fps = float(win.features.get("recent_frames_per_s") or win.features.get("frames_per_s_norm", 0) * 1500.0)
        lstm = self.lstm.step(fps)
        self.last_lstm = lstm
        merged = dict(score.scores)
        merged["flood_score"] = max(float(merged.get("flood_score") or 0.0), float(lstm["flood_score"]))
        merged["actual_fps"] = lstm["actual_fps"]
        merged["predicted_fps"] = lstm["predicted_fps"]
        merged["threshold_fps"] = lstm["threshold_fps"]
        merged["residual_fps"] = lstm["residual_fps"]
        if lstm.get("fired"):
            merged["flood_score"] = max(merged["flood_score"], 1.0)
        status = "ok" if score.status == "ok" or lstm["steps"] else score.status
        score = ModelScore(win.event_id, score.model_id, score.version, merged, status)
        hits = self.rules.evaluate(win)
        hit = self.rules.primary(hits)
        graph = list(self.graph.changes[-8:])
        alert = self.incidents.join(win, score, hits, graph=graph)
        self.last_alert = alert
        assets = [self.assets.live[a] for a in win.asset_ids if a in self.assets.live]
        control = any(getattr(e, "is_control", False) or getattr(e, "is_write", False) for e in batch)
        inc = self.incidents.correlate(alert, win, assets, control=control, graph=graph)
        if inc and inc.state == "open":
            cop = self.slm.assess(inc)
            self.copilots[inc.incident_id] = cop
            self.last_copilot = cop
            self.last_stix = self.stix.write(inc, cop)
            self.last_incident = inc
        elif inc:
            self.last_incident = inc
        return win, score, hit, inc

    def run_window(self):
        return self.detect(self.events)


def run_spoof_lab(repo: Path, work: Path, mode: str = "dev", ticks: int = 12):
    sim = OpvSimulator(sim_mode=mode, attack_id="gps-spoof-primary", scenario_id="gps-spoof-underway")
    sensor = SensorPipeline(mode, repo, work)
    for i in range(ticks):
        plant, frames = sim.tick(float(6 + i))  # start in ramp
        sensor.ingest_frames(frames)
    result = sensor.run_window()
    if sensor.last_incident:
        sensor.last_eval = sensor.eval.score(sensor.last_incident, sim.labels.records)
    return sim, sensor, result
