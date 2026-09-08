"""Attack-family classifier. Sibling of ONNX and rules. Same FeatureWindow.event_id.

Lab v0 is a pinned heuristic. A later ONNX classifier is a drop-in: same
ClassifierScore contract, no change to the correlator.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from otlab import OTEvent
from ot_sensor.features import FeatureWindow


@dataclass
class ClassifierScore:
    event_id: str
    model_id: str
    version: str
    family: str
    label: str
    confidence: float
    scores: dict[str, float] = field(default_factory=dict)
    status: str = "ok"


class ClassifierEnrich:
    model_id = "attack-classifier"
    version = "0.1.0"

    def classify(self, window: FeatureWindow, events: list[OTEvent] | None = None) -> ClassifierScore:
        f = window.features
        writes = [e for e in (events or []) if e.is_write or (e.is_control and e.is_write)]
        control_writes = [e for e in (events or []) if e.is_write]
        scores: dict[str, float] = {}

        if control_writes and any(
            (e.parser_fields.get("segment") or window.segment) == "propulsion" for e in control_writes
        ):
            conf = 0.9
            return ClassifierScore(
                window.event_id,
                self.model_id,
                self.version,
                "plc_manipulation",
                "PLC manipulation",
                conf,
                {"plc_manipulation": conf},
            )

        dr = float(f.get("gnss_dr_residual_m", 0))
        split = float(f.get("gnss1_gnss2_split_m", 0))
        hdop = float(f.get("hdop", 99))
        spoof = 0.0
        if hdop < 2.5 and (dr > 50 or split > 30):
            spoof = min(0.99, 0.55 + max(dr, split) / 400.0)
        scores["gnss_spoof"] = spoof

        flood = min(1.0, float(f.get("frames_per_s_norm", 0)))
        scores["bus_flood"] = flood

        family, label, conf = "undetermined", "undetermined", 0.1
        if spoof >= 0.7:
            family, label, conf = "gnss_spoof", "GNSS position spoof", spoof
        elif flood >= 0.8:
            family, label, conf = "bus_flood", "Bus flood", flood
        elif writes:
            family, label, conf = "unauthorized_command", "Unauthorized command", 0.6

        return ClassifierScore(
            window.event_id,
            self.model_id,
            self.version,
            family,
            label,
            conf,
            scores,
        )
