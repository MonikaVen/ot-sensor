export type ServiceStatus = {
  id: string;
  label: string;
  status: string;
  detail?: string | null;
};

export type Asset = {
  asset_id: string;
  name: string;
  segment: string;
  criticality: number;
  nis2_service: string | null;
  expected: boolean;
  live: boolean;
  talking?: boolean;
  traffic?: "benign" | "attack" | "silent";
  first_seen: string | null;
  last_seen: string | null;
  channels_seen: string[];
  depends_on: string[];
  dependents: string[];
  incident_ids: string[];
  role?: string | null;
  detected_via?: string[];
};

export type CommsEdge = {
  src: string;
  dst: string | null;
  segment: string;
  expected?: boolean;
  live?: boolean;
  kind: string;
  last_seen?: string;
};

export type DepEdge = {
  src: string;
  dst: string;
  segment: string;
  kind: string;
};

export type AlertRule = {
  event_id?: string;
  rule_id: string;
  version: string;
  fired: boolean;
  severity: string | null;
  status: string;
  techniques: string[];
  impacts: string[];
  clauses_fired: string[];
  clauses_suppressed?: string[];
};

export type AlertModel = {
  event_id?: string;
  model_id: string;
  version: string;
  scores: Record<string, number>;
  status: string;
  fired: boolean;
};

export type Alert = {
  event_id: string;
  timestamp: string;
  join_incomplete: boolean;
  source: string;
  segment: string;
  protocol: string;
  asset_ids: string[];
  models: AlertModel[];
  rules: AlertRule[];
  graph: Array<Record<string, string>>;
  evidence_summary: Record<string, unknown>;
  fired_rules: string[];
  fired_models: string[];
};

export type Incident = {
  incident_id: string;
  state: string;
  t_open: string;
  t_last: string;
  severity: string;
  families: string[];
  title: string;
  body: string;
  protocol: string;
  source: string;
  segment: string;
  asset_ids: string[];
  techniques: string[];
  impacts: string[];
  alert_count: number;
  alerts: Alert[];
  evidence_summary: Record<string, unknown>;
  risk: {
    total: number;
    impact: number;
    likelihood: number;
    blast_radius: number;
    control_plane: number;
    max_criticality: number;
    dependent_asset_ids: string[];
    nis2_significant: boolean;
  };
  nis2: {
    incident_id: string;
    t_aware: string;
    early_warning_due: string;
    notification_due: string;
    stage: string;
    essential_service: string;
    human_confirm: boolean;
  } | null;
  copilot?: {
    status: string;
    runtime?: string;
    alert_title: string;
    alert_body: string;
    recommend: string[];
  } | null;
};

export type FlowMessage = {
  t: string;
  sa: string;
  name: string;
  pgn: number;
  pgn_name: string;
  segment: string;
  summary: string;
  hex: string;
  spoofed: boolean;
  kind?: string;
  technique?: string | null;
};

export type HistogramRow = {
  key: string;
  label: string;
  technique: string;
  unit: string;
  benign: number[];
  attack: number[];
  active: boolean;
};

export type Snapshot = {
  sensor_version: string;
  mode: string;
  hull: string;
  running: boolean;
  tap_url: string | null;
  tap_error: string | null;
  attack_id: string | null;
  elapsed_s: number;
  ticks: number;
  t: string;
  plant: {
    t: string | null;
    lat_deg: number | null;
    lon_deg: number | null;
    heading_deg: number | null;
    sog_kn: number | null;
    phase: string;
    attack_id: string | null;
  } | null;
  stats: {
    frames_this_tick: number;
    events: number;
    open_incidents: number;
    alerts?: number;
    honeypot_seq: number;
    honeypot_bytes?: number;
  };
  services: ServiceStatus[];
  assets: Asset[];
  comms: CommsEdge[];
  dependencies: DepEdge[];
  graph_changes: Array<Record<string, string>>;
  incidents: Incident[];
  alerts?: Alert[];
  new_incident_ids: string[];
  copilot: {
    incident_id: string;
    status: string;
    runtime?: string;
    alert_title: string;
    alert_body: string;
    recommend: string[];
  } | null;
  stix_path: string | null;
  attack_started_at?: string | null;
  message_flow?: FlowMessage[];
  histograms?: HistogramRow[];
  flow_asset?: { asset_id: string; name: string };
  rules?: {
    packs: RulePack[];
    last_hit: {
      rule_id: string;
      fired: boolean;
      severity: string | null;
      status: string;
      clauses_fired: string[];
      clauses_suppressed: string[];
    } | null;
    last_hits?: Array<{
      rule_id: string;
      fired: boolean;
      severity: string | null;
      status: string;
    }>;
    features: Record<string, number>;
  };
  models?: {
    packs: ModelPack[];
  };
  honeypot?: HoneypotSnap;
    assistant?: {
    model: string;
    runtime?: string | null;
    base_model?: string | null;
    status: string;
    loaded: boolean;
    last_error?: string | null;
    sessions?: string[];
  };
};

export type TapSample = {
  t: string;
  segment: string;
  can_id: number;
  data_hex: string;
  error: boolean;
};

export type HoneypotFile = {
  name: string;
  path: string;
  bytes: number;
  open: boolean;
  t?: string;
};

export type HoneypotFeed = {
  t: string;
  segment: string;
  iface?: string;
  seq: number;
  nbytes: number;
  kind: string;
  sha256?: string;
  payload_hex?: string;
  payload_b64?: string;
  can_id?: number;
  error?: boolean;
};

export type HoneypotSnap = {
  bytes: number;
  bytes_open: number;
  bytes_closed: number;
  files: number;
  seq: number;
  written?: number;
  dropped: number;
  rotation: number;
  rotate_max_bytes: number;
  retain_max_files: number;
  open_path: string | null;
  open_paths?: string[];
  root: string;
  entries: HoneypotFile[];
  feed: HoneypotFeed[];
  series?: Array<{ t: number; bytes: number; files: number; written?: number }>;
};

export type AssistantMessage = {
  role: "user" | "assistant";
  content: string;
};

export type AssistantSession = {
  ok?: boolean;
  error?: string;
  incident_id: string;
  interpretation: string;
  messages: AssistantMessage[];
  status: string;
  source?: string;
  model?: string;
  runtime?: string | null;
  base_model?: string | null;
  last_error?: string | null;
  loaded?: boolean;
  alert_count?: number;
};

export type RuleClause = {
  id: string;
  feature: string;
  label: string;
  op: string;
  value: number | boolean;
  unit: string;
  type: "number" | "bool";
  live?: number | null;
  met?: boolean;
};

export type RulePack = {
  rule_id: string;
  version: string;
  title: string;
  blurb: string;
  enabled: boolean;
  severity: string;
  techniques: string[];
  impacts: string[];
  fired?: boolean;
  live?: boolean;
  series?: Array<{
    t: number;
    values: Record<string, number>;
    thresholds: Record<string, number>;
    readings?: Record<string, number>;
    fired?: boolean;
  }>;
  groups: Array<{ id: string; label: string; clauses: RuleClause[] }>;
};

export type ModelPack = {
  model_id: string;
  version: string;
  title: string;
  blurb: string;
  live: boolean;
  onnx_loaded?: boolean;
  status: string;
  detected?: boolean;
  scores: Record<string, number | null | undefined>;
  thresholds: Record<string, number>;
  techniques: string[];
  impacts: string[];
  series: Array<{
    t: number;
    actual_fps?: number | null;
    predicted_fps?: number | null;
    threshold_fps?: number | null;
    flood_score?: number | null;
    residual_fps?: number | null;
    fired?: boolean;
    crossed?: boolean;
  }>;
};
