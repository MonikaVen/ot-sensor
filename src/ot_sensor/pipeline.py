"""Wire simulator ticks into sensor services."""

from __future__ import annotations

from pathlib import Path

from opv_sim.lab import OpvSimulator
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
        self.honeypot = Honeypot(work / "hp", mode, rotate_max_bytes=400, retain_max_files=3)
        crit = repo / "docs/architecture/samples/sources/asset-criticality.yaml"
        self.assets = AssetDetector(crit)
        self.graph = CommsGraph()
        self.features = FeatureStage()
        onnx_dir = repo / "docs/architecture/samples/models/throughput-lstm/1.0.0"
        self.onnx = OnnxEnrich(onnx_dir)
        self.rules = RulesEnrich()
        self.incidents = IncidentCorrelator(mode)
        self.slm = LocalSlm(repo / "docs/architecture/samples/models/watchstander-slm/1.0.0", llm_endpoint, mode)
        self.stix = StixExporter(work / "stix", mode)
        self.eval = EvalJoin(mode, label_topic_set)
        self.events = []
        self.last_incident = None
        self.last_copilot = None
        self.last_stix = None
        self.last_eval = None

    def ingest_frames(self, frames) -> None:
        for fr in frames:
            self.honeypot.write_frame(fr)
            ev = self.n2k.convert(fr)
            self.events.append(ev)
            self.assets.observe(ev)
            self.graph.observe(ev)

    def run_window(self):
        if not self.events:
            return None
        win = self.features.window(self.events)
        seq = self.features.lstm_seq([win])
        score = self.onnx.score(win, seq)
        hit = self.rules.gps_spoof_nav(win)
        alert = self.incidents.join(win, score, hit)
        assets = [self.assets.live[a] for a in win.asset_ids if a in self.assets.live]
        inc = self.incidents.correlate(alert, win, assets)
        if inc and inc.state == "open":
            self.last_copilot = self.slm.assess(inc)
            self.last_stix = self.stix.write(inc, self.last_copilot)
            self.last_incident = inc
        elif inc:
            self.last_incident = inc
        return win, score, hit, inc


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
