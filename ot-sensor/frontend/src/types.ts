export type ServiceStatus = {
  id: string;
  label: string;
  status: string;
};

export type Asset = {
  asset_id: string;
  name: string;
  segment: string;
  criticality: number;
  nis2_service: string | null;
  expected: boolean;
  live: boolean;
  last_seen: string | null;
  channels_seen: string[];
  depends_on: string[];
  dependents: string[];
  incident_ids: string[];
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

export type Incident = {
  incident_id: string;
  state: string;
  t_open: string;
  t_last: string;
  severity: string;
  title: string;
  body: string;
  protocol: string;
  source: string;
  segment: string;
  asset_ids: string[];
  techniques: string[];
  impacts: string[];
  alert_count: number;
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
};

export type Snapshot = {
  sensor_version: string;
  mode: string;
  hull: string;
  running: boolean;
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
    honeypot_seq: number;
  };
  services: ServiceStatus[];
  assets: Asset[];
  comms: CommsEdge[];
  dependencies: DepEdge[];
  graph_changes: Array<Record<string, string>>;
  incidents: Incident[];
  new_incident_ids: string[];
  copilot: {
    incident_id: string;
    status: string;
    alert_title: string;
    alert_body: string;
    recommend: string[];
  } | null;
  stix_path: string | null;
};
