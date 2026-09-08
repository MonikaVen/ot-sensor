"""Rules enrich. Parallel to ONNX. Same FeatureWindow.event_id."""

from __future__ import annotations

from dataclasses import dataclass, field

from ot_sensor.features import FeatureWindow


@dataclass
class RuleHit:
    event_id: str
    rule_id: str
    version: str
    fired: bool
    severity: str | None
    techniques: list[str] = field(default_factory=list)
    impacts: list[str] = field(default_factory=list)
    clauses_fired: list[str] = field(default_factory=list)
    clauses_suppressed: list[str] = field(default_factory=list)
    status: str = "ok"


class RulesEnrich:
    def gps_spoof_nav(self, window: FeatureWindow) -> RuleHit:
        f = window.features
        fired_all = []
        supp = []
        if f.get("gnss_dr_residual_m", 0) > 50:
            fired_all.append("gnss_dr_residual_m")
        if f.get("hdop", 99) < 2.5:
            fired_all.append("hdop")
        if f.get("sat_count", 0) >= 8:
            fired_all.append("sat_count")
        if f.get("heading_rot_consistent", 0) == 1.0:
            fired_all.append("heading_rot_consistent")
        if f.get("cog_heading_residual_deg", 0) > 15:
            fired_all.append("cog_heading_residual_deg")
        any_ok = f.get("gnss1_gnss2_split_m", 0) > 30
        if any_ok:
            fired_all.append("gnss1_gnss2_split_m")
        if f.get("hdop", 0) > 6:
            supp.append("hdop>6")
        if f.get("sat_count_drop", 0) > 4:
            supp.append("sat_count_drop")
        all_ok = {"gnss_dr_residual_m", "hdop", "sat_count", "heading_rot_consistent", "cog_heading_residual_deg"}.issubset(set(fired_all))
        fired = all_ok and any_ok and not supp
        return RuleHit(
            event_id=window.event_id,
            rule_id="gps-spoof-nav",
            version="1.0.0",
            fired=fired,
            severity="critical" if fired else None,
            techniques=["T1692.002"] if fired else [],
            impacts=["T0832", "T0829"] if fired else [],
            clauses_fired=fired_all,
            clauses_suppressed=supp,
        )
