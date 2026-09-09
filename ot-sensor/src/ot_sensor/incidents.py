"""Alert join, correlate, risk, NIS2 clocks. Does not call the SLM.

Stage A joins every ONNX score and rule hit that share an event_id.
Stage B folds those alerts into incidents. The SLM runs after this.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta

from ot_sensor.assets import AssetRecord
from ot_sensor.features import FeatureWindow
from ot_sensor.onnx_enrich import ModelScore
from ot_sensor.rules import RuleHit

CORRELATE_WINDOW_S = 120.0
QUIET_WINDOW_S = 30.0
ALERT_KEEP = 80
INCIDENT_ALERT_KEEP = 40

# Technique-family for Stage B keys. Same family on the same segment dedups.
FAMILY = {
    "gps-spoof-nav": "gnss-spoof",
    "pgn-flood": "flood",
    "n2k-heading-control": "control",
    "n2k-iso-request": "recon",
    "unexpected-talker": "unexpected",
}

_SEV_RANK = {"critical": 3, "warning": 2, "info": 1}


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
    source: str = ""
    segment: str = ""
    protocol: str = ""
    asset_ids: list[str] = field(default_factory=list)
    graph: list[dict] = field(default_factory=list)
    evidence_summary: dict = field(default_factory=dict)


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
    families: list[str] = field(default_factory=list)


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def _flood(models: list[ModelScore], window: FeatureWindow) -> bool:
    dur = (window.t_end - window.t_start).total_seconds()
    fps = window.features.get("frames_per_s_norm", 0)
    for score in models:
        if score.scores.get("flood_score", 0) >= 0.8 and fps >= 0.35 and dur >= 1.0:
            return True
        if score.scores.get("flood_score", 0) >= 1.0:
            return True
    return False


def _families(rules: list[RuleHit], flood: bool) -> list[str]:
    seen: list[str] = []
    for hit in rules:
        if not hit.fired:
            continue
        fam = FAMILY.get(hit.rule_id, hit.rule_id)
        if fam not in seen:
            seen.append(fam)
    if flood and "flood" not in seen:
        seen.append("flood")
    return seen


def _primary_hit(rules: list[RuleHit]) -> RuleHit | None:
    fired = [h for h in rules if h.fired]
    if fired:
        return max(fired, key=lambda h: (_SEV_RANK.get(h.severity or "info", 0), -rules.index(h)))
    return rules[0] if rules else None


def _union(values: list[str]) -> list[str]:
    out: list[str] = []
    for v in values:
        if v and v not in out:
            out.append(v)
    return out


def _risk(assets: list[AssetRecord], hits: list[RuleHit], scores: list[ModelScore], control: bool) -> RiskScore:
    crits = [a.criticality for a in assets] or [1]
    deps = sorted({d for a in assets for d in a.dependents})
    max_c = max(crits)
    impact = min(40, max_c * 8)
    fired = [h for h in hits if h.fired]
    flood = any(s.scores.get("flood_score", 0) >= 0.8 for s in scores)
    likelihood = 22 if fired else (10 if flood else 4)
    if any(s.status != "ok" for s in scores):
        likelihood = min(likelihood, 12)
    blast = min(20, len(deps) * 4)
    control_plane = 8 if control else 0
    total = min(100, impact + likelihood + blast + control_plane)
    impacts = {i for h in fired for i in h.impacts}
    nis2 = total >= 70 or bool(impacts & {"T0827", "T0829", "T0831", "T0832"}) and any(
        a.nis2_service and a.nis2_service != "none" for a in assets
    )
    if control and max_c >= 4:
        nis2 = True
    return RiskScore(total, impact, likelihood, blast, control_plane, max_c, deps, nis2)


def _evidence(window: FeatureWindow, alert: Alert, graph: list[dict] | None) -> dict:
    feats = window.features
    top = [
        k
        for k, v in feats.items()
        if k.startswith("gnss") or k in ("hdop", "sat_count", "flood_score", "recent_frames_per_s", "cog_heading_residual_deg")
    ]
    fired = [h.rule_id for h in alert.rules if h.fired]
    scores = {}
    for m in alert.models:
        scores[m.model_id] = {k: v for k, v in m.scores.items() if v is not None}
    return {
        "top_features": top,
        "packet_count": len(window.member_event_ids),
        "window_s": (window.t_end - window.t_start).total_seconds(),
        "assets": list(window.asset_ids),
        "rules_fired": fired,
        "models": scores,
        "graph": list(graph or [])[-8:],
    }


class IncidentCorrelator:
    def __init__(self, mode: str = "prod") -> None:
        self.mode = mode
        self.open: dict[str, Incident] = {}
        self.closed: list[Incident] = []
        self.recent: list[Alert] = []
        self.n = 0

    def join(
        self,
        window: FeatureWindow,
        models: ModelScore | list[ModelScore],
        rules: RuleHit | list[RuleHit],
        timeout: bool = False,
        graph: list[dict] | None = None,
    ) -> Alert:
        """Stage A: one alert per event_id after ONNX and rules have both written."""
        model_list = _as_list(models)
        rule_list = _as_list(rules)
        alert = Alert(
            event_id=window.event_id,
            timestamp=window.t_end,
            models=model_list,
            rules=rule_list,
            join_incomplete=timeout,
            source=window.source,
            segment=window.segment,
            protocol=window.protocol,
            asset_ids=list(window.asset_ids),
            graph=list(graph or [])[-8:],
        )
        alert.evidence_summary = _evidence(window, alert, graph)
        return alert

    def correlate(
        self,
        alert: Alert,
        window: FeatureWindow,
        assets: list[AssetRecord],
        control: bool = False,
        graph: list[dict] | None = None,
    ) -> Incident | None:
        """Stage B: fold the joined alert into incidents. Call only after enrichment."""
        if graph and not alert.graph:
            alert = replace(alert, graph=list(graph)[-8:], evidence_summary=_evidence(window, alert, graph))
        self._close_quiet(alert.timestamp)
        flood = _flood(alert.models, window)
        families = _families(alert.rules, flood)
        if not families:
            return None
        self.recent.append(alert)
        self.recent = self.recent[-ALERT_KEEP:]
        updated: list[Incident] = []
        for family in families:
            updated.append(self._upsert(family, alert, window, assets, control))
        return max(updated, key=lambda inc: (inc.risk.total, inc.alert_count))

    def _upsert(
        self,
        family: str,
        alert: Alert,
        window: FeatureWindow,
        assets: list[AssetRecord],
        control: bool,
    ) -> Incident:
        key = f"{window.source}:{window.segment}:{family}"
        existing = self.open.get(key)
        if existing and (alert.timestamp - existing.t_last).total_seconds() <= CORRELATE_WINDOW_S:
            existing.alert_count += 1
            existing.t_last = alert.timestamp
            existing.state = "update"
            existing.alerts.append(alert)
            existing.alerts = existing.alerts[-INCIDENT_ALERT_KEEP:]
            existing.asset_ids = _union(list(existing.asset_ids) + list(window.asset_ids))
            existing.techniques = _union(list(existing.techniques) + [t for h in alert.rules if h.fired for t in h.techniques])
            existing.impacts = _union(list(existing.impacts) + [i for h in alert.rules if h.fired for i in h.impacts])
            if family not in existing.families:
                existing.families.append(family)
            existing.evidence_summary = dict(alert.evidence_summary or existing.evidence_summary)
            hit = _primary_hit(alert.rules)
            if hit and _SEV_RANK.get(hit.severity or "info", 0) >= _SEV_RANK.get(existing.severity or "info", 0):
                existing.severity = hit.severity or existing.severity
            existing.risk = _risk(assets or _placeholder_assets(existing), alert.rules, alert.models, control)
            if existing.risk.nis2_significant and existing.nis2 is None:
                existing.nis2 = _nis2(existing.incident_id, alert.timestamp)
            return existing
        self.n += 1
        hit = _primary_hit(alert.rules)
        risk = _risk(assets, alert.rules, alert.models, control)
        iid = f"inc-{self.n:04d}"
        severity = (hit.severity if hit and hit.fired else None) or ("critical" if family == "flood" else "info")
        techniques = _union([t for h in alert.rules if h.fired for t in h.techniques] or (["T0814"] if family == "flood" else []))
        impacts = _union([i for h in alert.rules if h.fired for i in h.impacts])
        inc = Incident(
            incident_id=iid,
            state="open",
            t_open=alert.timestamp,
            t_last=alert.timestamp,
            severity=severity,
            risk=risk,
            nis2=_nis2(iid, alert.timestamp) if risk.nis2_significant else None,
            protocol=window.protocol,
            source=window.source,
            segment=window.segment,
            asset_ids=list(window.asset_ids),
            techniques=techniques,
            impacts=impacts,
            alert_count=1,
            alerts=[alert],
            evidence_summary=dict(alert.evidence_summary or {}),
            mode=self.mode,
            families=[family],
        )
        self.open[key] = inc
        return inc

    def _close_quiet(self, now: datetime) -> None:
        drop = []
        for key, inc in self.open.items():
            if (now - inc.t_last).total_seconds() >= QUIET_WINDOW_S:
                inc.state = "closed"
                self.closed.append(inc)
                drop.append(key)
        for key in drop:
            del self.open[key]
        self.closed = self.closed[-ALERT_KEEP:]


def _nis2(incident_id: str, t_aware: datetime) -> Nis2UiAlert:
    return Nis2UiAlert(
        incident_id=incident_id,
        t_aware=t_aware,
        early_warning_due=t_aware + timedelta(hours=24),
        notification_due=t_aware + timedelta(hours=72),
    )


def _placeholder_assets(inc: Incident) -> list[AssetRecord]:
    return [
        AssetRecord(aid, inc.segment, aid, True, inc.risk.max_criticality, "navigation", [], list(inc.risk.dependent_asset_ids))
        for aid in inc.asset_ids
    ]
