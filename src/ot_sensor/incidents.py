"""Alert join, correlate, risk, NIS2 clocks. Does not call the SLM."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ot_sensor.assets import AssetRecord
from ot_sensor.features import FeatureWindow
from ot_sensor.onnx_enrich import ModelScore
from ot_sensor.rules import RuleHit


@dataclass
class RiskScore:
    total: int
    impact: int
    likelihood: int
    blast_radius: int
    control_plane: int
    max_criticality: int
    dependent_asset_ids: list[str]
    nis2_significant: bool


@dataclass
class Nis2UiAlert:
    incident_id: str
    t_aware: datetime
    early_warning_due: datetime
    notification_due: datetime
    stage: str = "early_warning"
    essential_service: str = "navigation"
    suspected_malicious: bool | None = True
    human_confirm: bool = False


@dataclass
class Alert:
    event_id: str
    timestamp: datetime
    models: list[ModelScore]
    rules: list[RuleHit]
    join_incomplete: bool


@dataclass
class Incident:
    incident_id: str
    state: str
    t_open: datetime
    t_last: datetime
    severity: str
    risk: RiskScore
    nis2: Nis2UiAlert | None
    protocol: str
    source: str
    segment: str
    asset_ids: list[str]
    techniques: list[str]
    impacts: list[str]
    alert_count: int
    alerts: list[Alert]
    evidence_summary: dict
    mode: str


def _risk(assets: list[AssetRecord], hit: RuleHit, score: ModelScore, control: bool) -> RiskScore:
    crits = [a.criticality for a in assets] or [1]
    deps = sorted({d for a in assets for d in a.dependents})
    max_c = max(crits)
    impact = min(40, max_c * 8)
    likelihood = 22 if hit.fired else (10 if score.scores.get("flood_score", 0) >= 0.8 else 4)
    if score.status != "ok":
        likelihood = min(likelihood, 12)
    blast = min(20, len(deps) * 4)
    control_plane = 8 if control else 0
    total = min(100, impact + likelihood + blast + control_plane)
    nis2 = total >= 70 or bool(set(hit.impacts) & {"T0827", "T0829", "T0831", "T0832"}) and any(
        a.nis2_service and a.nis2_service != "none" for a in assets
    )
    if control and max_c >= 4:
        nis2 = True
    return RiskScore(total, impact, likelihood, blast, control_plane, max_c, deps, nis2)


class IncidentCorrelator:
    def __init__(self, mode: str = "prod") -> None:
        self.mode = mode
        self.open: dict[str, Incident] = {}
        self.n = 0

    def join(self, window: FeatureWindow, score: ModelScore, hit: RuleHit, timeout: bool = False) -> Alert:
        return Alert(window.event_id, window.t_end, [score], [hit], join_incomplete=timeout)

    def correlate(
        self,
        alert: Alert,
        window: FeatureWindow,
        assets: list[AssetRecord],
        control: bool = False,
    ) -> Incident | None:
        hit = alert.rules[0]
        score = alert.models[0]
        dur = (window.t_end - window.t_start).total_seconds()
        flood = (
            score.scores.get("flood_score", 0) >= 0.8
            and window.features.get("frames_per_s_norm", 0) >= 0.35
            and dur >= 1.0
        )
        if not hit.fired and not flood:
            return None
        family = "flood" if flood and not hit.fired else "gps-spoof"
        key = f"{window.segment}:{family}"
        existing = self.open.get(key)
        if existing:
            existing.alert_count += 1
            existing.t_last = alert.timestamp
            existing.state = "update"
            existing.alerts.append(alert)
            return existing
        self.n += 1
        risk = _risk(assets, hit, score, control)
        iid = f"inc-{self.n:04d}"
        nis2 = None
        if risk.nis2_significant:
            nis2 = Nis2UiAlert(
                incident_id=iid,
                t_aware=alert.timestamp,
                early_warning_due=alert.timestamp + timedelta(hours=24),
                notification_due=alert.timestamp + timedelta(hours=72),
            )
        inc = Incident(
            incident_id=iid,
            state="open",
            t_open=alert.timestamp,
            t_last=alert.timestamp,
            severity=hit.severity or ("critical" if flood else "info"),
            risk=risk,
            nis2=nis2,
            protocol=window.protocol,
            source=window.source,
            segment=window.segment,
            asset_ids=window.asset_ids,
            techniques=hit.techniques or (["T0814"] if flood else []),
            impacts=hit.impacts,
            alert_count=1,
            alerts=[alert],
            evidence_summary={
                "top_features": [k for k, v in window.features.items() if k.startswith("gnss") or k in ("hdop", "flood_score")],
                "packet_count": len(window.member_event_ids),
                "window_s": (window.t_end - window.t_start).total_seconds(),
                "assets": window.asset_ids,
            },
            mode=self.mode,
        )
        self.open[key] = inc
        return inc
