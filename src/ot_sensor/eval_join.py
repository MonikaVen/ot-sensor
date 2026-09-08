"""dev-only eval join. Never in the SLM prompt."""

from __future__ import annotations

from otlab import LabelRecord
from ot_sensor.incidents import Incident


class EvalJoin:
    def __init__(self, mode: str, label_topic_set: bool = False) -> None:
        if mode == "prod" and label_topic_set:
            raise RuntimeError("LABEL_TOPIC is fatal in SENSOR_MODE=prod")
        self.enabled = mode == "dev"

    def score(self, inc: Incident, labels: list[LabelRecord]) -> dict | None:
        if not self.enabled or not labels:
            return None
        techniques = {lab.technique for lab in labels}
        hit = set(inc.techniques) & techniques
        return {"incident_id": inc.incident_id, "label_techniques": sorted(techniques), "overlap": sorted(hit)}
