"""Label topic. Exists only in SIM_MODE=dev."""

from __future__ import annotations

from otlab import LabelRecord


class LabelTopic:
    def __init__(self, sim_mode: str, label_topic_configured: bool = False) -> None:
        if sim_mode == "prod" and label_topic_configured:
            raise RuntimeError("LABEL_TOPIC is fatal in SIM_MODE=prod")
        self.enabled = sim_mode == "dev"
        self.records: list[LabelRecord] = []

    def publish(self, rec: LabelRecord | None) -> None:
        if rec is None or not self.enabled:
            return
        self.records.append(rec)
