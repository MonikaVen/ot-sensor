"""STIX 2.1 local bundle. TAXII share is off until human confirm."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from ot_sensor.incidents import Incident
from ot_sensor.slm import CopilotAssessment


@dataclass
class StixBundleRef:
    incident_id: str
    path: str
    bundle_id: str
    report_id: str
    taxii_shared: bool
    published: datetime | None


class StixExporter:
    def __init__(self, root: Path, mode: str) -> None:
        self.root = Path(root)
        self.mode = mode

    def write(self, inc: Incident, copilot: CopilotAssessment) -> StixBundleRef:
        d = self.root / self.mode / "opv1"
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{inc.incident_id}.json"
        bid = f"bundle--{uuid4()}"
        rid = f"report--{uuid4()}"
        bundle = {
            "type": "bundle",
            "id": bid,
            "objects": [
                {
                    "type": "report",
                    "id": rid,
                    "name": copilot.alert_title,
                    "report_types": ["incident"],
                    "description": copilot.alert_body,
                },
                {"type": "note", "content": copilot.alert_body},
            ],
        }
        path.write_text(json.dumps(bundle, indent=2))
        return StixBundleRef(inc.incident_id, str(path), bid, rid, False, datetime.now(timezone.utc))
