"""Rules enrich. Parallel to ONNX. Same FeatureWindow.event_id."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields

from ot_sensor.features import FeatureWindow

NUMERIC_CLAUSES = (
    "gnss_dr_residual_m",
    "hdop_healthy",
    "sat_count_min",
    "cog_heading_residual_deg",
    "gnss1_gnss2_split_m",
    "hdop_degraded",
    "sat_count_drop",
)


@dataclass
class GpsSpoofNavSettings:
    """Editable gps-spoof-nav pack. Defaults match the architecture spec."""

    rule_id: str = "gps-spoof-nav"
    version: str = "1.0.0"
    enabled: bool = True
    severity: str = "critical"
    gnss_dr_residual_m: float = 50.0
    hdop_healthy: float = 2.5
    sat_count_min: float = 8.0
    heading_rot_consistent: bool = True
    cog_heading_residual_deg: float = 15.0
    gnss1_gnss2_split_m: float = 30.0
    hdop_degraded: float = 6.0
    sat_count_drop: float = 4.0

    def widget(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "title": "GNSS spoof (nav)",
            "blurb": "Healthy-looking fix that walks off dead-reckoning. Does not fire on GNSS-degraded.",
            "enabled": self.enabled,
            "severity": self.severity,
            "techniques": ["T1692.002"],
            "impacts": ["T0832", "T0829"],
            "groups": [
                {
                    "id": "all",
                    "label": "All of",
                    "clauses": [
                        _clause("gnss_dr_residual_m", "GNSS vs DR residual", ">", self.gnss_dr_residual_m, "m", "gnss_dr_residual_m"),
                        _clause("hdop_healthy", "HDOP (healthy)", "<", self.hdop_healthy, "", "hdop"),
                        _clause("sat_count_min", "Satellites", "≥", self.sat_count_min, "", "sat_count"),
                        {
                            "id": "heading_rot_consistent",
                            "feature": "heading_rot_consistent",
                            "label": "Heading / ROT consistent",
                            "op": "==",
                            "value": self.heading_rot_consistent,
                            "unit": "",
                            "type": "bool",
                        },
                        _clause("cog_heading_residual_deg", "COG vs heading", ">", self.cog_heading_residual_deg, "°", "cog_heading_residual_deg"),
                    ],
                },
                {
                    "id": "any",
                    "label": "Any of",
                    "clauses": [
                        _clause("gnss1_gnss2_split_m", "GNSS-1 vs GNSS-2 split", ">", self.gnss1_gnss2_split_m, "m", "gnss1_gnss2_split_m"),
                    ],
                },
                {
                    "id": "not",
                    "label": "None of (suppress)",
                    "clauses": [
                        _clause("hdop_degraded", "HDOP collapsed", ">", self.hdop_degraded, "", "hdop"),
                        _clause("sat_count_drop", "Sat count drop", ">", self.sat_count_drop, "", "sat_count_drop"),
                    ],
                },
            ],
        }

    def apply(self, enabled: bool | None = None, severity: str | None = None, clauses: dict | None = None) -> None:
        if enabled is not None:
            self.enabled = bool(enabled)
        if severity is not None:
            if severity not in ("info", "warning", "critical"):
                raise ValueError("severity")
            self.severity = severity
        if not clauses:
            return
        names = {f.name for f in fields(self)}
        for key, raw in clauses.items():
            if key not in names or key in {"rule_id", "version", "enabled", "severity"}:
                continue
            if key == "heading_rot_consistent":
                self.heading_rot_consistent = bool(raw)
                continue
            if key not in NUMERIC_CLAUSES:
                continue
            val = float(raw)
            if val < 0:
                raise ValueError(key)
            setattr(self, key, val)


def _clause(cid: str, label: str, op: str, value: float, unit: str, feature: str) -> dict:
    return {
        "id": cid,
        "feature": feature,
        "label": label,
        "op": op,
        "value": value,
        "unit": unit,
        "type": "number",
    }


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


@dataclass
class ThresholdClause:
    id: str
    feature: str
    label: str
    op: str
    value: float
    unit: str = ""


@dataclass
class ThresholdRuleSettings:
    """Single-group count/rate pack (ISO Request, heading write, flood, unexpected SA)."""

    rule_id: str
    title: str
    blurb: str
    version: str = "1.0.0"
    enabled: bool = True
    severity: str = "warning"
    techniques: tuple[str, ...] = ()
    impacts: tuple[str, ...] = ()
    group: str = "all"
    clauses: list[ThresholdClause] = field(default_factory=list)

    def widget(self) -> dict:
        label = {"all": "All of", "any": "Any of", "not": "None of (suppress)"}.get(self.group, self.group)
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "title": self.title,
            "blurb": self.blurb,
            "enabled": self.enabled,
            "severity": self.severity,
            "techniques": list(self.techniques),
            "impacts": list(self.impacts),
            "groups": [
                {
                    "id": self.group,
                    "label": label,
                    "clauses": [_clause(c.id, c.label, c.op, c.value, c.unit, c.feature) for c in self.clauses],
                }
            ],
        }

    def apply(self, enabled: bool | None = None, severity: str | None = None, clauses: dict | None = None) -> None:
        if enabled is not None:
            self.enabled = bool(enabled)
        if severity is not None:
            if severity not in ("info", "warning", "critical"):
                raise ValueError("severity")
            self.severity = severity
        if not clauses:
            return
        by_id = {c.id: c for c in self.clauses}
        for key, raw in clauses.items():
            clause = by_id.get(key)
            if clause is None:
                continue
            val = float(raw)
            if val < 0:
                raise ValueError(key)
            clause.value = val

    def evaluate(self, window: FeatureWindow) -> RuleHit:
        f = window.features
        met: list[str] = []
        for clause in self.clauses:
            live = float(f.get(clause.feature, 0) or 0)
            if _cmp(live, clause.op, clause.value):
                met.append(clause.id)
        if self.group == "any":
            logic = bool(met)
        else:
            logic = len(met) == len(self.clauses)
        fired = bool(self.enabled) and logic and bool(self.clauses)
        return RuleHit(
            event_id=window.event_id,
            rule_id=self.rule_id,
            version=self.version,
            fired=fired,
            severity=self.severity if fired else None,
            techniques=list(self.techniques) if fired else [],
            impacts=list(self.impacts) if fired else [],
            clauses_fired=met,
            status="disabled" if not self.enabled else "ok",
        )


def _cmp(live: float, op: str, threshold: float) -> bool:
    if op in (">=", "≥"):
        return live >= threshold
    if op in ("<=", "≤"):
        return live <= threshold
    if op == ">":
        return live > threshold
    if op == "<":
        return live < threshold
    if op == "==":
        return live == threshold
    return live >= threshold


def _lab_rules() -> list[ThresholdRuleSettings]:
    return [
        ThresholdRuleSettings(
            rule_id="n2k-iso-request",
            title="ISO Request (read)",
            blurb="PGN 59904 request for another device's PGN. Lab pair: injector Read / Read flood.",
            severity="warning",
            techniques=("T0801",),
            impacts=("T0811",),
            group="all",
            clauses=[
                ThresholdClause("iso_request_count", "iso_request_count", "ISO Request frames", "≥", 1.0),
            ],
        ),
        ThresholdRuleSettings(
            rule_id="n2k-heading-control",
            title="Heading control (write)",
            blurb="PGN 127237 heading/track control from a talker that should only report. Lab pair: injector Write.",
            severity="warning",
            techniques=("T0855",),
            impacts=("T0829",),
            group="all",
            clauses=[
                ThresholdClause("heading_control_count", "heading_control_count", "Heading-control frames", "≥", 1.0),
            ],
        ),
        ThresholdRuleSettings(
            rule_id="pgn-flood",
            title="PGN flood",
            blurb="Burst of heading reports or ISO Requests on the recent window. Lab pair: PGN flood / Read flood. ONNX flood_score stays a sibling head.",
            severity="warning",
            techniques=("T0814",),
            impacts=("T0814",),
            group="any",
            clauses=[
                ThresholdClause("heading_pgn_per_s", "heading_pgn_per_s", "Heading PGN rate", ">", 5.0, "/s"),
                ThresholdClause("iso_request_per_s", "iso_request_per_s", "ISO Request rate", ">", 8.0, "/s"),
            ],
        ),
        ThresholdRuleSettings(
            rule_id="unexpected-talker",
            title="Unexpected talker",
            blurb="Source address not in the OPV vessel model. Lab pair: rogue SA 44 on Read/Write.",
            severity="warning",
            techniques=("T0846",),
            impacts=("T0888",),
            group="all",
            clauses=[
                ThresholdClause("unexpected_talker_count", "unexpected_talker_count", "Unexpected SAs", "≥", 1.0),
            ],
        ),
    ]


def _annotate_pack(pack: dict, live: dict, hit: RuleHit | None) -> dict:
    fired = set(hit.clauses_fired) if hit else set()
    suppressed = set(hit.clauses_suppressed) if hit else set()
    pack["fired"] = bool(hit and hit.fired)
    for group in pack["groups"]:
        for clause in group["clauses"]:
            feat = clause["feature"]
            clause["live"] = live.get(feat)
            clause["met"] = feat in fired or clause["id"] in fired
            if group["id"] == "not":
                clause["met"] = any(
                    s.startswith("hdop") if feat == "hdop" else s == "sat_count_drop" for s in suppressed
                )
    return pack


class RulesEnrich:
    def __init__(self, settings: GpsSpoofNavSettings | None = None) -> None:
        self.settings = settings or GpsSpoofNavSettings()
        self.extra = _lab_rules()
        self.last_hits: list[RuleHit] = []

    def gps_spoof_nav(self, window: FeatureWindow) -> RuleHit:
        s = self.settings
        f = window.features
        fired_all: list[str] = []
        supp: list[str] = []
        if f.get("gnss_dr_residual_m", 0) > s.gnss_dr_residual_m:
            fired_all.append("gnss_dr_residual_m")
        if f.get("hdop", 99) < s.hdop_healthy:
            fired_all.append("hdop")
        if f.get("sat_count", 0) >= s.sat_count_min:
            fired_all.append("sat_count")
        if not s.heading_rot_consistent or f.get("heading_rot_consistent", 0) == 1.0:
            fired_all.append("heading_rot_consistent")
        if f.get("cog_heading_residual_deg", 0) > s.cog_heading_residual_deg:
            fired_all.append("cog_heading_residual_deg")
        any_ok = f.get("gnss1_gnss2_split_m", 0) > s.gnss1_gnss2_split_m
        if any_ok:
            fired_all.append("gnss1_gnss2_split_m")
        if f.get("hdop", 0) > s.hdop_degraded:
            supp.append("hdop>6")
        if f.get("sat_count_drop", 0) > s.sat_count_drop:
            supp.append("sat_count_drop")
        needed = {"gnss_dr_residual_m", "hdop", "sat_count", "heading_rot_consistent", "cog_heading_residual_deg"}
        all_ok = needed.issubset(set(fired_all))
        fired = bool(s.enabled) and all_ok and any_ok and not supp
        return RuleHit(
            event_id=window.event_id,
            rule_id=s.rule_id,
            version=s.version,
            fired=fired,
            severity=s.severity if fired else None,
            techniques=["T1692.002"] if fired else [],
            impacts=["T0832", "T0829"] if fired else [],
            clauses_fired=fired_all,
            clauses_suppressed=supp,
            status="disabled" if not s.enabled else "ok",
        )

    def evaluate(self, window: FeatureWindow) -> list[RuleHit]:
        hits = [self.gps_spoof_nav(window)]
        hits.extend(r.evaluate(window) for r in self.extra)
        self.last_hits = hits
        return hits

    def primary(self, hits: list[RuleHit] | None = None) -> RuleHit | None:
        pack = hits if hits is not None else self.last_hits
        if not pack:
            return None
        rank = {"critical": 3, "warning": 2, "info": 1}
        fired = [h for h in pack if h.fired]
        if not fired:
            return pack[0]
        return max(fired, key=lambda h: (rank.get(h.severity or "info", 0), -pack.index(h)))

    def apply(
        self,
        rule_id: str,
        enabled: bool | None = None,
        severity: str | None = None,
        clauses: dict | None = None,
    ) -> None:
        if rule_id == self.settings.rule_id:
            self.settings.apply(enabled=enabled, severity=severity, clauses=clauses)
            return
        for pack in self.extra:
            if pack.rule_id == rule_id:
                pack.apply(enabled=enabled, severity=severity, clauses=clauses)
                return
        raise ValueError("unknown rule")

    def snapshot(self, features: dict | None = None, hit: RuleHit | None = None) -> dict:
        live = features or {}
        by_id = {h.rule_id: h for h in self.last_hits}
        if hit is not None:
            by_id.setdefault(hit.rule_id, hit)
        packs = [_annotate_pack(self.settings.widget(), live, by_id.get(self.settings.rule_id))]
        packs.extend(_annotate_pack(p.widget(), live, by_id.get(p.rule_id)) for p in self.extra)
        primary = hit if hit is not None else self.primary()
        return {
            "packs": packs,
            "last_hit": asdict(primary) if primary else None,
            "last_hits": [asdict(h) for h in self.last_hits],
            "features": dict(live),
        }
