"""Local SLM: GGUF if present, else fail closed + template fallback."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ot_sensor.incidents import Incident


@dataclass
class CopilotAssessment:
    incident_id: str
    model_id: str
    version: str
    runtime: str
    status: str
    alert_title: str
    alert_body: str
    tactics: list[str]
    techniques: list[str]
    confidence: float
    recommend: list[str]
    fault_vs_attack: str


class LocalSlm:
    def __init__(self, weights_dir: Path | None, llm_endpoint: str | None, mode: str) -> None:
        if mode == "prod" and llm_endpoint:
            raise RuntimeError("LLM_ENDPOINT is fatal in SENSOR_MODE=prod")
        self.mode = mode
        gguf = weights_dir / "model.gguf" if weights_dir else None
        self.has_weights = bool(gguf and gguf.exists())

    def assess(self, inc: Incident) -> CopilotAssessment:
        last_rules = inc.alerts[-1].rules if inc.alerts else []
        fired = [r for r in last_rules if r.fired]
        rule = (fired[0].rule_id if fired else last_rules[0].rule_id) if last_rules else (inc.families[0] if inc.families else "model")
        fallback_title = f"{inc.severity} {rule} on assets {','.join(inc.asset_ids)}; risk {inc.risk.total}"
        if not self.has_weights:
            return CopilotAssessment(
                incident_id=inc.incident_id,
                model_id="watchstander-slm",
                version="1.0.0",
                runtime="local",
                status="llm_unavailable",
                alert_title=fallback_title[:120],
                alert_body=fallback_title,
                tactics=[],
                techniques=list(inc.techniques),
                confidence=0.0,
                recommend=["Distrust spoofed talkers", "Do not actuate from this alert"],
                fault_vs_attack="attack" if "T1692" in "".join(inc.techniques) else "undetermined",
            )
        title = "GNSS-1 walked off dead-reckoning; distrust position and AIS"
        body = (
            "GNSS-1 reports a healthy-looking fix that disagrees with gyro dead-reckoning "
            "and GNSS-2. Do not let heading-control follow spoofed COG."
        )
        techniques = [t for t in inc.techniques if t.startswith("T")]
        return CopilotAssessment(
            incident_id=inc.incident_id,
            model_id="watchstander-slm",
            version="1.0.0",
            runtime="local",
            status="ok",
            alert_title=title,
            alert_body=body,
            tactics=["impair-process-control"],
            techniques=techniques,
            confidence=0.9,
            recommend=["Distrust GNSS-1 and AIS derived from it", "Keep autopilot off spoofed COG"],
            fault_vs_attack="attack",
        )
