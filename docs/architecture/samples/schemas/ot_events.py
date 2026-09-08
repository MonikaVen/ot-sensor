"""Data schemas for OT sensor services.

Adapters emit OTEvent. Every downstream service consumes or produces one of
the types below. Protocol-native details live in OTEvent.parser_fields only.
"""

from datetime import datetime


class OTEvent:
    event_id: str
    timestamp: datetime

    protocol: str

    source_asset_id: str | None
    destination_asset_id: str | None

    operation_category: str
    operation_name: str

    object_type: str | None
    object_address: str | None

    value_before: object | None
    value_after: object | None

    is_write: bool
    is_control: bool
    is_configuration: bool
    privileged: bool

    parser_fields: dict


class HoneypotRecord:
    seq: int
    timestamp: datetime
    source: str
    protocol: str
    segment: str
    iface: str
    kind: str
    nbytes: int
    sha256: str
    payload_b64: str
    event_id: str | None


class HoneypotFile:
    path: str
    mode: str
    hull: str
    segment: str
    iface: str
    utc_open: datetime
    utc_close: datetime | None
    n_records: int
    nbytes: int
    kinds: list[str]
    rotation: int
    open_pid: int | None
    on_hold: bool
    retained_until: datetime | None
    purged: bool


class HoneypotRetention:
    rotate_max_bytes: int
    rotate_max_age_s: int
    retain_max_bytes_per_segment: int
    retain_max_files_per_segment: int
    retain_max_age_s: int
    hold_open_incidents: bool
    dropped_records: int


class AssetRecord:
    asset_id: str
    protocol: str
    source: str
    segment: str
    name: str | None
    identity: dict
    channels_seen: list[str]
    first_seen: datetime
    last_seen: datetime
    expected: bool
    role: str | None
    criticality: int
    nis2_service: str | None
    depends_on: list[str]
    dependents: list[str]


class AssetChange:
    event_id: str
    timestamp: datetime
    change: str
    asset: AssetRecord
    vs_model: str


class DependencyEdge:
    asset_id: str
    depends_on: str
    function: str


class GraphEdge:
    src_asset_id: str
    dst_asset_id: str
    protocol: str
    source: str
    segment: str
    operation_name: str | None
    expected: bool
    rate_per_s: float
    last_seen: datetime


class GraphChange:
    event_id: str
    timestamp: datetime
    change: str
    edge: GraphEdge | None
    node_asset_id: str | None
    vs_model: str


class FeatureWindow:
    event_id: str
    t_start: datetime
    t_end: datetime
    source: str
    protocol: str
    segment: str
    asset_ids: list[str]
    member_event_ids: list[str]
    features: dict[str, float]


class ModelScore:
    event_id: str
    model_id: str
    version: str
    scores: dict[str, float]
    explain_method: str | None
    top_features: list[dict]
    status: str


class RuleHit:
    event_id: str
    rule_id: str
    version: str
    fired: bool
    severity: str | None
    techniques: list[str]
    impacts: list[str]
    clauses_fired: list[str]
    clauses_suppressed: list[str]
    status: str


class Alert:
    event_id: str
    timestamp: datetime
    models: list[ModelScore]
    rules: list[RuleHit]
    join_incomplete: bool


class RiskScore:
    total: int
    impact: int
    likelihood: int
    blast_radius: int
    control_plane: int
    max_criticality: int
    dependent_asset_ids: list[str]
    nis2_significant: bool


class Nis2UiAlert:
    incident_id: str
    t_aware: datetime
    early_warning_due: datetime
    notification_due: datetime
    final_report_due: datetime | None
    stage: str
    suspected_malicious: bool | None
    cross_border: bool | None
    essential_service: str
    recipients_notify: bool
    csirt_submitted: dict
    human_confirm: bool


class Evidence:
    evidence_id: str
    event_id: str
    incident_id: str
    window: dict
    assets: list[str]
    contributing_event_ids: list[str]
    features: dict[str, float]
    models: list[ModelScore]
    rules: list[RuleHit]
    honeypot: dict | None


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
    assets: list[AssetChange]
    graph: list[GraphChange]
    evidence_ref: str
    evidence_summary: dict
    stix_ref: str | None
    catalog_ver: str
    mode: str


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


class LlmSpec:
    model_id: str
    version: str
    runtime: str
    file: str
    quant: str
    ctx: int
    json_schema: str
    timeout_s: int
    prod_network: str
    catalog_ver: str


class StixBundleRef:
    incident_id: str
    path: str
    bundle_id: str
    report_id: str
    taxii_shared: bool
    published: datetime | None


class ModelSpec:
    model_id: str
    version: str
    feature_schema: list[str]
    window: dict
    explain: dict
    catalog_ver: str


class RuleSpec:
    rule_id: str
    version: str
    scope: dict
    window: dict
    predicates: dict
    then: dict
    catalog_ver: str


class VesselModel:
    hull: str
    protocol: str
    segment: str
    expected_assets: list[AssetRecord]
    expected_edges: list[GraphEdge]
    expected_dependencies: list[DependencyEdge]
