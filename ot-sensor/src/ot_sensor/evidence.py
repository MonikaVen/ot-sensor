"""NIS2 evidence engine. Seals a package on every incident open/update.

The package is the defensible record: what was detected, on which assets,
with which models/rules, and what the operator did. The SLM never sees it
whole — only Incident.evidence_summary.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime
from pathlib import Path

from otlab import OTEvent
from ot_sensor import SENSOR_VERSION
from ot_sensor.assets import AssetRecord
from ot_sensor.classifier import ClassifierScore
from ot_sensor.features import FeatureWindow
from ot_sensor.honeypot import Honeypot
from ot_sensor.onnx_enrich import ModelScore
from ot_sensor.rules import RuleHit


MITRE = {
    "T1692.002": "Spoof Reporting Message",
    "T0832": "Loss of View",
    "T0829": "Loss of Control",
    "T0814": "Denial of Control",
    "T0855": "Unauthorized Command Message",
    "T0827": "Loss of Control (safety)",
    "T0831": "Manipulation of Control",
}


def _jsonable(obj):
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, list):
        return [_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    return obj


@dataclass
class EvidencePackage:
    evidence_id: str
    incident_id: str
    timestamps: dict
    affected_assets: list[dict]
    asset_criticality: dict
    affected_services: list[str]
    attack_classification: dict
    confidence: float
    anomaly_evidence: dict
    protocol_commands: list[dict]
    indicators: list[dict]
    mitre: dict
    network_topology: dict
    timeline: list[dict]
    operator_actions: list[dict]
    containment_actions: list[dict]
    impact_assessment: dict
    pcap_refs: list[dict]
    model_version: dict
    rule_version: dict
    classifier_version: dict
    sensor_version: str
    sha256: str = ""
    path: str = ""


class EvidenceEngine:
    def __init__(self, root: Path, mode: str) -> None:
        self.root = Path(root)
        self.mode = mode
        self.root.mkdir(parents=True, exist_ok=True)
        self.n = 0

    def seal(
        self,
        *,
        incident_id: str,
        t_open: datetime,
        t_last: datetime,
        window: FeatureWindow,
        events: list[OTEvent],
        assets: list[AssetRecord],
        graph_changes: list[dict],
        graph_edges: list,
        score: ModelScore,
        hit: RuleHit,
        clf: ClassifierScore,
        honeypot: Honeypot | None,
        operator_actions: list[dict],
        containment_actions: list[dict],
        risk,
        classification_label: str,
        protocol_evidence: str,
    ) -> EvidencePackage:
        self.n += 1
        eid = f"ev-{incident_id}-{self.n:04d}"
        crit = {a.asset_id: {"name": a.name, "criticality": a.criticality, "nis2_service": a.nis2_service} for a in assets}
        services = sorted({a.nis2_service for a in assets if a.nis2_service and a.nis2_service != "none"})
        commands = []
        iocs = []
        for e in events:
            if e.is_write or e.is_control or e.privileged:
                commands.append(
                    {
                        "t": e.timestamp.isoformat(),
                        "protocol": e.protocol,
                        "operation": e.operation_name,
                        "category": e.operation_category,
                        "object_address": e.object_address,
                        "src": e.source_asset_id,
                        "dst": e.destination_asset_id,
                        "is_write": e.is_write,
                        "is_control": e.is_control,
                        "privileged": e.privileged,
                    }
                )
            if e.source_asset_id:
                iocs.append(
                    {
                        "type": "ot-talker",
                        "asset_id": e.source_asset_id,
                        "protocol": e.protocol,
                        "object_address": e.object_address,
                    }
                )
        # unique IoCs
        seen = set()
        uniq = []
        for ioc in iocs:
            key = (ioc["asset_id"], ioc.get("object_address"))
            if key in seen:
                continue
            seen.add(key)
            uniq.append(ioc)

        pcap_refs = []
        if honeypot is not None:
            for p in honeypot.closed:
                honeypot.hold_paths.add(str(p))
                pcap_refs.append({"kind": "honeypot-jsonl", "path": str(p), "role": "pcap_equivalent"})
            for path, seq in honeypot.open_files():
                honeypot.hold_paths.add(str(path))
                pcap_refs.append(
                    {
                        "kind": "honeypot-jsonl",
                        "path": str(path),
                        "open": True,
                        "seq": seq,
                        "role": "pcap_equivalent",
                    }
                )

        techniques = list(hit.techniques)
        impacts = list(hit.impacts)
        pkg = EvidencePackage(
            evidence_id=eid,
            incident_id=incident_id,
            timestamps={
                "first_observed": window.t_start.isoformat(),
                "last_observed": t_last.isoformat(),
                "t_open": t_open.isoformat(),
                "t_package": t_last.isoformat(),
                "duration_s": (t_last - t_open).total_seconds() if t_last >= t_open else (window.t_end - window.t_start).total_seconds(),
            },
            affected_assets=[{"asset_id": a.asset_id, "name": a.name, "segment": a.segment, "criticality": a.criticality} for a in assets],
            asset_criticality=crit,
            affected_services=services,
            attack_classification={
                "family": clf.family,
                "label": classification_label or clf.label,
                "confidence": clf.confidence,
            },
            confidence=clf.confidence,
            anomaly_evidence={
                "features": dict(window.features),
                "top_features": [k for k, v in window.features.items() if k.startswith("gnss") or k in ("hdop", "flood_score", "frames_per_s_norm")],
                "lstm": {"model_id": score.model_id, "version": score.version, "scores": score.scores, "status": score.status},
                "window_s": (window.t_end - window.t_start).total_seconds(),
                "packet_count": len(window.member_event_ids),
                "protocol_evidence": protocol_evidence,
            },
            protocol_commands=commands,
            indicators=uniq,
            mitre={
                "techniques": [{"id": t, "name": MITRE.get(t, t)} for t in techniques],
                "impacts": [{"id": t, "name": MITRE.get(t, t)} for t in impacts],
                "framework": "ATT&CK for ICS",
            },
            network_topology={
                "segment": window.segment,
                "nodes": [a.asset_id for a in assets],
                "violating_edges": [c for c in graph_changes if c.get("change") in ("new_edge", "gateway_bypass")],
                "edge_count": len(graph_edges) if graph_edges is not None else 0,
            },
            timeline=_timeline(window, events, hit, score, clf, graph_changes),
            operator_actions=list(operator_actions),
            containment_actions=list(containment_actions),
            impact_assessment={
                "risk_total": risk.total,
                "nis2_significant": risk.nis2_significant,
                "max_criticality": risk.max_criticality,
                "dependents": list(risk.dependent_asset_ids),
                "detection_confidence": getattr(risk, "detection_confidence", 0.0),
                "process_impact": getattr(risk, "process_impact", 0),
                "exposure": getattr(risk, "exposure", 0),
                "essential_services": services,
            },
            pcap_refs=pcap_refs,
            model_version={"model_id": score.model_id, "version": score.version, "status": score.status},
            rule_version={"rule_id": hit.rule_id, "version": hit.version, "fired": hit.fired},
            classifier_version={"model_id": clf.model_id, "version": clf.version, "status": clf.status},
            sensor_version=SENSOR_VERSION,
        )
        body = _jsonable(pkg)
        raw = json.dumps(body, sort_keys=True, default=str).encode()
        pkg.sha256 = hashlib.sha256(raw).hexdigest()
        dest = self.root / self.mode / f"{incident_id}.json"
        dest.parent.mkdir(parents=True, exist_ok=True)
        payload = _jsonable(pkg)
        dest.write_text(json.dumps(payload, indent=2, default=str))
        pkg.path = str(dest)
        return pkg


def _timeline(window, events, hit, score, clf, graph_changes) -> list[dict]:
    rows = [
        {"t": window.t_start.isoformat(), "kind": "window_open", "detail": window.event_id},
        {"t": window.t_end.isoformat(), "kind": "window_close", "detail": f"n={len(window.member_event_ids)}"},
        {"t": window.t_end.isoformat(), "kind": "lstm", "detail": score.status, "scores": score.scores},
        {"t": window.t_end.isoformat(), "kind": "classifier", "detail": clf.family, "confidence": clf.confidence},
        {"t": window.t_end.isoformat(), "kind": "rule", "detail": hit.rule_id, "fired": hit.fired},
    ]
    for e in events[:40]:
        rows.append(
            {
                "t": e.timestamp.isoformat(),
                "kind": "ot_event",
                "src": e.source_asset_id,
                "operation": e.operation_name,
                "object_address": e.object_address,
            }
        )
    for c in graph_changes:
        rows.append({"t": window.t_end.isoformat(), "kind": c.get("change"), "src": c.get("src"), "dst": c.get("dst")})
    rows.sort(key=lambda r: r.get("t") or "")
    return rows
