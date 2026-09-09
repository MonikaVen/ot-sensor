import {
  Button,
  Callout,
  Card,
  CardBody,
  CardHeader,
  Code,
  Divider,
  Grid,
  H1,
  H2,
  H3,
  Link,
  Pill,
  Row,
  Stack,
  Stat,
  Table,
  Text,
  computeDAGLayout,
  useCanvasAction,
  useCanvasState,
  useHostTheme,
} from "cursor/canvas";

type View =
  | "pipeline"
  | "models"
  | "rules"
  | "attck"
  | "honeypot"
  | "assets"
  | "topology"
  | "stix"
  | "sources"
  | "network"
  | "workflows";
type Mode = "dev" | "prod";
type Sources = "n2k" | "modbus" | "both";
type GraphOverlay = "expected" | "live";
type GraphNodeKind = "expected" | "rogue";
type GraphEdgeKind = "expected" | "new" | "bypass";

const SENSOR_NODES = [
  { id: "tap", label: "N2K TAP" },
  { id: "mb", label: "Modbus adapter" },
  { id: "other", label: "Other protocol" },
  { id: "ingest", label: "Ingest bus" },
  { id: "honeypot", label: "Honeypot" },
  { id: "rawlog", label: "Raw log files" },
  { id: "decode", label: "PGN decode" },
  { id: "assets", label: "Asset detector" },
  { id: "graph", label: "Comms graph" },
  { id: "bytewax", label: "Bytewax" },
  { id: "onnx", label: "ONNX enrich" },
  { id: "rules", label: "Rules enrich" },
  { id: "incidents", label: "Incidents" },
  { id: "llm", label: "Local SLM" },
  { id: "slm", label: "SLM weights" },
  { id: "assistant", label: "CyberPal" },
  { id: "stix", label: "STIX 2.1" },
  { id: "ops", label: "Operator" },
  { id: "registry", label: "Model registry" },
  { id: "rulepack", label: "Rule pack" },
  { id: "attck", label: "ATT&CK ICS" },
  { id: "topo", label: "Vessel topology" },
];

const SENSOR_EDGES = [
  { from: "tap", to: "honeypot" },
  { from: "tap", to: "decode" },
  { from: "decode", to: "ingest" },
  { from: "mb", to: "honeypot" },
  { from: "mb", to: "ingest" },
  { from: "other", to: "honeypot" },
  { from: "other", to: "ingest" },
  { from: "ingest", to: "bytewax" },
  { from: "ingest", to: "assets" },
  { from: "ingest", to: "graph" },
  { from: "assets", to: "graph" },
  { from: "topo", to: "graph" },
  { from: "honeypot", to: "rawlog" },
  { from: "bytewax", to: "onnx" },
  { from: "bytewax", to: "rules" },
  { from: "registry", to: "onnx" },
  { from: "rulepack", to: "rules" },
  { from: "onnx", to: "incidents" },
  { from: "rules", to: "incidents" },
  { from: "assets", to: "incidents" },
  { from: "graph", to: "incidents" },
  { from: "incidents", to: "llm" },
  { from: "slm", to: "llm" },
  { from: "incidents", to: "assistant" },
  { from: "incidents", to: "stix" },
  { from: "assistant", to: "ops" },
  { from: "attck", to: "llm" },
  { from: "attck", to: "stix" },
  { from: "topo", to: "llm" },
  { from: "llm", to: "stix" },
  { from: "llm", to: "ops" },
  { from: "stix", to: "ops" },
];

const OTEVENT_FIELDS: Array<[string, string, string]> = [
  ["event_id", "str", "Stable id for this observation"],
  ["timestamp", "datetime", "Event time"],
  ["protocol", "str", "nmea2000 | modbus | nmea0183 | …"],
  ["source_asset_id", "str | None", "Talker / client"],
  ["destination_asset_id", "str | None", "Unicast target; None if broadcast"],
  ["operation_category", "str", "report | command | read | write | identity | poll"],
  ["operation_name", "str", "Mapped name, e.g. gnss_position"],
  ["object_type", "str | None", "pgn | modbus_reg | nmea_sentence | …"],
  ["object_address", "str | None", "129029, hr:40001, GGA"],
  ["value_before", "object | None", "Prior value when known"],
  ["value_after", "object | None", "Current / new value"],
  ["is_write", "bool", "Observed write or command"],
  ["is_control", "bool", "Actuation path"],
  ["is_configuration", "bool", "Identity, maps, setpoints"],
  ["privileged", "bool", "Claim, admin, config"],
  ["parser_fields", "dict", "Canonical fields, source id, segment, catalog"],
];

type ServiceSchema = {
  className: string;
  summary: string;
  consumes: string;
  emits: string;
  fields: Array<[string, string, string]>;
};

const SERVICE_SCHEMAS: Record<string, ServiceSchema> = {
  tap: {
    className: "OTEvent",
    summary: "NMEA 2000 adapter maps CAN/PGN onto OTEvent. Listen-only TAP.",
    consumes: "SocketCAN / pcap frames",
    emits: "OTEvent",
    fields: OTEVENT_FIELDS,
  },
  decode: {
    className: "OTEvent",
    summary: "PGN decode fills object_type=pgn, object_address=PGN, assets from SA/DA.",
    consumes: "N2K frames",
    emits: "OTEvent",
    fields: OTEVENT_FIELDS,
  },
  mb: {
    className: "OTEvent",
    summary: "Modbus adapter. Polls are read; a write PDU on the wire still sets is_write.",
    consumes: "Modbus PDU / poll",
    emits: "OTEvent",
    fields: OTEVENT_FIELDS,
  },
  other: {
    className: "OTEvent",
    summary: "Any mapped protocol (e.g. NMEA 0183). Same OTEvent contract.",
    consumes: "Protocol PDU",
    emits: "OTEvent",
    fields: OTEVENT_FIELDS,
  },
  ingest: {
    className: "OTEvent",
    summary: "Fan-out bus. The only contract Bytewax, assets, graph, and honeypot links need.",
    consumes: "OTEvent",
    emits: "OTEvent",
    fields: OTEVENT_FIELDS,
  },
  honeypot: {
    className: "HoneypotRecord",
    summary: "Raw inflow regardless of parse. event_id set only if decode produced an OTEvent.",
    consumes: "Raw bytes + optional OTEvent",
    emits: "HoneypotRecord",
    fields: [
      ["seq", "int", "Sequence in the current file"],
      ["timestamp", "datetime", "Capture time"],
      ["source", "str", "sources.yaml id"],
      ["protocol", "str", "nmea2000 | modbus | …"],
      ["segment", "str", "nav | propulsion | power | aux"],
      ["iface", "str", "TAP or socket name"],
      ["kind", "str", "can | error | modbus | nmea0183 | …"],
      ["nbytes", "int", "Raw length"],
      ["sha256", "str", "Hash of raw bytes"],
      ["payload_b64", "str", "Uninterpreted blob"],
      ["event_id", "str | None", "Set when an OTEvent was also emitted"],
    ],
  },
  rawlog: {
    className: "HoneypotFile",
    summary: "Closed log filename encodes capture data. Rotate 128 MiB / 1 h; retain 2 GiB and 48 files per segment, 30 d. Forensic pointer uses this path.",
    consumes: "HoneypotRecord",
    emits: "HoneypotFile",
    fields: [
      ["path", "str", "Closed hp-…jsonl.gz name"],
      ["mode", "str", "dev | prod"],
      ["hull", "str", "Vessel id"],
      ["segment", "str", "Backbone"],
      ["iface", "str", "Punctuation stripped"],
      ["utc_open", "datetime", "Window start"],
      ["utc_close", "datetime | None", "None while open-{pid}"],
      ["n_records", "int", "JSONL count"],
      ["nbytes", "int", "Payload bytes"],
      ["kinds", "list[str]", "Capture kind tokens"],
      ["rotation", "int", "rNNNN"],
      ["open_pid", "int | None", "Set only while growing"],
      ["on_hold", "bool", "Incident still points here"],
      ["retained_until", "datetime | None", "NIS2 / retain.max_age"],
      ["purged", "bool", "Unlinked; sha256 stays in manifest"],
    ],
  },
  assets: {
    className: "AssetRecord / AssetChange",
    summary: "Live talker catalog vs vessel model. Change events fold into incidents.",
    consumes: "OTEvent",
    emits: "AssetRecord, AssetChange",
    fields: [
      ["asset_id", "str", "Same space as OTEvent source_asset_id"],
      ["protocol", "str", "nmea2000 | modbus | …"],
      ["source", "str", "sources.yaml id"],
      ["segment", "str", "From parser_fields"],
      ["name", "str | None", "ISO NAME / product / talker"],
      ["identity", "dict", "Protocol-native identity bag"],
      ["channels_seen", "list[str]", "object_address values"],
      ["expected", "bool", "In the OPV model"],
      ["change", "str", "On AssetChange: new_asset, name_change, …"],
      ["event_id", "str", "On AssetChange; joins the alert"],
    ],
  },
  graph: {
    className: "GraphEdge / GraphChange",
    summary: "Who talks to whom from source_asset_id → destination_asset_id.",
    consumes: "OTEvent + AssetRecord + VesselModel",
    emits: "GraphEdge, GraphChange",
    fields: [
      ["src_asset_id", "str", "OTEvent.source_asset_id"],
      ["dst_asset_id", "str", "OTEvent.destination_asset_id or expanded consumer"],
      ["protocol", "str", "Edge protocol"],
      ["operation_name", "str | None", "From OTEvent"],
      ["expected", "bool", "In the vessel model"],
      ["rate_per_s", "float", "Rolling rate"],
      ["change", "str", "On GraphChange: new_edge, gateway_bypass, …"],
      ["event_id", "str", "On GraphChange"],
    ],
  },
  bytewax: {
    className: "FeatureWindow",
    summary: "Windows OTEvent streams. Canonical features from parser_fields, not native addresses.",
    consumes: "OTEvent",
    emits: "FeatureWindow",
    fields: [
      ["event_id", "str", "Id for this window (copied to ONNX and rules)"],
      ["t_start / t_end", "datetime", "Window bounds"],
      ["source", "str", "sources.yaml id"],
      ["protocol", "str", "nmea2000 | modbus | …"],
      ["segment", "str", "nav | propulsion | power | aux"],
      ["asset_ids", "list[str]", "Talkers in the window"],
      ["member_event_ids", "list[str]", "OTEvent ids, not the 10 Hz dump"],
      ["features", "dict[str, float]", "Canonical residuals and rates"],
    ],
  },
  onnx: {
    className: "ModelScore",
    summary: "ONNX branch. Failed load → status=model_unavailable; no invented scores.",
    consumes: "FeatureWindow",
    emits: "ModelScore",
    fields: [
      ["event_id", "str", "Same as FeatureWindow"],
      ["model_id", "str", "physics-ae, throughput-lstm, …"],
      ["version", "str", "Semver from registry"],
      ["scores", "dict[str, float]", "anomaly, flood_score, fault_likelihood, …"],
      ["explain_method", "str | None", "residual | occlusion | …"],
      ["top_features", "list[dict]", "Attribution shares"],
      ["status", "str", "ok | model_unavailable | explain_unavailable"],
    ],
  },
  registry: {
    className: "ModelSpec",
    summary: "config.yaml + weights. Not an event stream.",
    consumes: "—",
    emits: "ModelSpec",
    fields: [
      ["model_id", "str", "Registry identity"],
      ["version", "str", "Semver"],
      ["feature_schema", "list[str]", "Must match FeatureWindow.features"],
      ["window", "dict", "duration_s, hop_s"],
      ["explain", "dict", "method, top_k"],
      ["catalog_ver", "str", "Pinned decode catalog"],
    ],
  },
  rules: {
    className: "RuleHit",
    summary: "Parallel to ONNX. Same FeatureWindow.event_id.",
    consumes: "FeatureWindow",
    emits: "RuleHit",
    fields: [
      ["event_id", "str", "Same as FeatureWindow"],
      ["rule_id", "str", "gps-spoof-nav, …"],
      ["version", "str", "Semver"],
      ["fired", "bool", "Predicate result"],
      ["severity", "str | None", "If fired"],
      ["techniques", "list[str]", "ATT&CK ICS ids"],
      ["impacts", "list[str]", "T0829, T0832, …"],
      ["clauses_fired", "list[str]", "Evidence for the operator view"],
      ["status", "str", "ok | rule_unavailable"],
    ],
  },
  rulepack: {
    className: "RuleSpec",
    summary: "rule.yaml. Not an event stream.",
    consumes: "—",
    emits: "RuleSpec",
    fields: [
      ["rule_id", "str", "Pack identity"],
      ["version", "str", "Semver"],
      ["scope", "dict", "segments, object_address / pgns"],
      ["window", "dict", "Must match FeatureWindow"],
      ["predicates", "dict", "all / any / not"],
      ["then", "dict", "fire, severity, techniques"],
      ["catalog_ver", "str", "Pinned catalog"],
    ],
  },
  incidents: {
    className: "Incident",
    summary: "Join ModelScore + RuleHit by event_id into Alert, correlate into Incident + Evidence.",
    consumes: "ModelScore, RuleHit, AssetChange, GraphChange",
    emits: "Alert, Incident, Evidence",
    fields: [
      ["incident_id", "str", "Correlation id"],
      ["state", "str", "open | update | closed"],
      ["severity", "str", "Max of member alerts"],
      ["protocol / source / segment", "str", "From member OTEvents"],
      ["asset_ids", "list[str]", "Talkers in the incident"],
      ["techniques / impacts", "list[str]", "From rules; SLM may not add new ids"],
      ["alerts", "list[Alert]", "Joined by event_id"],
      ["evidence_ref", "str", "Full store; not the LLM dump"],
      ["evidence_summary", "dict", "top features, packet_count, window"],
      ["stix_ref", "str | None", "Local bundle path after export"],
    ],
  },
  llm: {
    className: "CopilotAssessment",
    summary:
      "Ollama SLM (qwen2:1.5b default) writes watchstander alert_title / alert_body. Does not fire detections. prod denies LLM_ENDPOINT.",
    consumes: "Incident",
    emits: "CopilotAssessment",
    fields: [
      ["incident_id", "str", "Incident this assessment belongs to"],
      ["model_id / version", "str", "watchstander-slm pin"],
      ["runtime", "str", "qwen2:1.5b | gguf | none"],
      ["status", "str", "ok | llm_unavailable | schema_invalid"],
      ["alert_title", "str", "≤120 chars; incident list and NIS2 subject"],
      ["alert_body", "str", "≤1200 chars; watchstander text / STIX note"],
      ["tactics / techniques", "list[str]", "Subset of incident ∪ retrieved ATT&CK"],
      ["confidence", "float", "Bound to scores and rule fires, not an SLM self-score"],
      ["recommend", "list[str]", "Detect / contain only"],
      ["fault_vs_attack", "str", "attack | fault | undetermined"],
    ],
  },
  assistant: {
    className: "AssistantSession",
    summary:
      "CyberPal investigation. One session per incident. Correlation JSON only — no raw CAN, honeypot blobs, or attack_id.",
    consumes: "Incident + related assets",
    emits: "AssistantSession",
    fields: [
      ["incident_id", "str", "Session key"],
      ["interpretation", "str", "Briefing from correlation"],
      ["messages", "list", "User / assistant turns for this incident"],
      ["source", "str", "cyberpal | heuristic"],
      ["status", "str", "ok | llm_unavailable"],
    ],
  },
  slm: {
    className: "LlmSpec",
    summary:
      "Ollama pack. Missing daemon or tag → llm_unavailable; incident still stands.",
    consumes: "—",
    emits: "LlmSpec",
    fields: [
      ["model_id", "str", "watchstander-slm"],
      ["version", "str", "Semver"],
      ["runtime", "str", "ollama"],
      ["ollama_from", "str", "qwen2:1.5b default; OTLAB_SLM_MODEL override"],
      ["prod_network", "str", "deny"],
    ],
  },
  attck: {
    className: "attack-pattern (STIX)",
    summary: "Vendored ATT&CK for ICS. Retrieval for the local SLM and STIX export.",
    consumes: "—",
    emits: "STIX attack-pattern",
    fields: [
      ["external_id", "str", "T1692.002, T0814, …"],
      ["name", "str", "Technique title"],
      ["url", "str", "attack.mitre.org"],
      ["spec_version", "str", "STIX 2.1"],
    ],
  },
  stix: {
    className: "StixBundleRef",
    summary: "Outbound STIX 2.1. No raw payloads, no GT. TAXII share is operator-confirmed.",
    consumes: "Incident + CopilotAssessment",
    emits: "StixBundleRef",
    fields: [
      ["incident_id", "str", "Incident exported"],
      ["path", "str", "reports/stix/{mode}/{hull}/{incident_id}.json"],
      ["bundle_id", "str", "bundle--UUID"],
      ["report_id", "str", "report--UUID"],
      ["taxii_shared", "bool", "False until operator Share"],
      ["published", "datetime | None", "When the report object was written"],
    ],
  },
  ops: {
    className: "Incident + Evidence",
    summary: "Operator surfaces. Full evidence packet list stays here, not in the LLM or STIX.",
    consumes: "Incident, Evidence, CopilotAssessment, StixBundleRef",
    emits: "— (display)",
    fields: [
      ["incident_id", "str", "Open incident"],
      ["alert_title", "str", "From local SLM or template fallback"],
      ["alert_body", "str", "Watchstander text; llm_unavailable banner if needed"],
      ["evidence_id", "str", "Lineage store"],
      ["contributing_event_ids", "list[str]", "OTEvent ids that moved the score"],
      ["stix_ref", "str | None", "Local bundle; Share is a human action"],
    ],
  },
  topo: {
    className: "VesselModel",
    summary: "Expected assets and comms edges per protocol and segment.",
    consumes: "—",
    emits: "VesselModel",
    fields: [
      ["hull", "str", "Vessel id"],
      ["protocol", "str", "nmea2000 | modbus | …"],
      ["segment", "str", "nav | propulsion | power | aux"],
      ["expected_assets", "list[AssetRecord]", "Allowed talkers"],
      ["expected_edges", "list[GraphEdge]", "Allowed who-talks-to-whom"],
    ],
  },
};

function SchemaPanel({ nodeId, label }: { nodeId: string; label: string }) {
  const schema = SERVICE_SCHEMAS[nodeId] ?? SERVICE_SCHEMAS.ingest;
  return (
    <Stack gap={12}>
      <H3>
        {label} — <Code>{schema.className}</Code>
      </H3>
      <Text>{schema.summary}</Text>
      <Grid columns={2} gap={12}>
        <Stat value={schema.consumes} label="Consumes" />
        <Stat value={schema.emits} label="Emits" />
      </Grid>
      <Table
        headers={["Field", "Type", "Role"]}
        rows={schema.fields}
        striped
      />
    </Stack>
  );
}

function FlowChart({
  nodes,
  edges,
  direction,
  accentIds,
  selectedId,
  onSelect,
}: {
  nodes: Array<{ id: string; label: string }>;
  edges: Array<{ from: string; to: string }>;
  direction: "vertical" | "horizontal";
  accentIds: Set<string>;
  selectedId?: string;
  onSelect?: (id: string) => void;
}) {
  const theme = useHostTheme();
  const nodeWidth = 128;
  const nodeHeight = 40;
  const layout = computeDAGLayout({
    nodes: nodes.map((n) => ({ id: n.id })),
    edges,
    direction,
    nodeWidth,
    nodeHeight,
    rankGap: 48,
    nodeGap: 20,
    padding: 12,
  });
  const labels = Object.fromEntries(nodes.map((n) => [n.id, n.label]));

  return (
    <div
      style={{
        position: "relative",
        width: layout.width,
        height: layout.height,
        maxWidth: "100%",
        overflow: "auto",
      }}
    >
      <svg
        width={layout.width}
        height={layout.height}
        style={{ position: "absolute", inset: 0, pointerEvents: "none" }}
      >
        {layout.edges.map((e, i) => (
          <line
            key={`${e.from}-${e.to}-${i}`}
            x1={e.sourceX}
            y1={e.sourceY}
            x2={e.targetX}
            y2={e.targetY}
            stroke={theme.stroke.secondary}
            strokeWidth={1}
            strokeDasharray={e.isBackEdge ? "4 3" : undefined}
          />
        ))}
      </svg>
      {layout.nodes.map((n) => {
        const selected = selectedId === n.id;
        return (
          <button
            key={n.id}
            type="button"
            onClick={() => onSelect?.(n.id)}
            style={{
              position: "absolute",
              left: n.x,
              top: n.y,
              width: nodeWidth,
              height: nodeHeight,
              boxSizing: "border-box",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: theme.bg.elevated,
              border: `1px solid ${
                selected || accentIds.has(n.id)
                  ? theme.accent.primary
                  : theme.stroke.primary
              }`,
              borderRadius: 6,
              padding: "0 6px",
              fontSize: 11,
              color: theme.text.primary,
              textAlign: "center",
              lineHeight: 1.2,
              cursor: onSelect ? "pointer" : "default",
              appearance: "none",
              fontFamily: "inherit",
            }}
          >
            {labels[n.id]}
          </button>
        );
      })}
    </div>
  );
}

const COMMS_NODES_EXPECTED: Array<{
  id: string;
  label: string;
  kind: GraphNodeKind;
}> = [
  { id: "gnss1", label: "GNSS-1 SA 16", kind: "expected" },
  { id: "gnss2", label: "GNSS-2 SA 17", kind: "expected" },
  { id: "gyro", label: "Gyro SA 35", kind: "expected" },
  { id: "ais", label: "AIS SA 24", kind: "expected" },
  { id: "ap", label: "Autopilot SA 56", kind: "expected" },
  { id: "mfd", label: "MFD SA 60", kind: "expected" },
  { id: "rudder", label: "Rudder SA 52", kind: "expected" },
  { id: "gw", label: "GW nav→prop", kind: "expected" },
  { id: "eng", label: "Engine SA 0", kind: "expected" },
];

const COMMS_EDGES_EXPECTED: Array<{
  from: string;
  to: string;
  kind: GraphEdgeKind;
}> = [
  { from: "gnss1", to: "mfd", kind: "expected" },
  { from: "gnss1", to: "ap", kind: "expected" },
  { from: "gnss2", to: "mfd", kind: "expected" },
  { from: "gyro", to: "mfd", kind: "expected" },
  { from: "gyro", to: "ap", kind: "expected" },
  { from: "ais", to: "mfd", kind: "expected" },
  { from: "ap", to: "rudder", kind: "expected" },
  { from: "mfd", to: "ap", kind: "expected" },
  { from: "gyro", to: "gw", kind: "expected" },
  { from: "gnss1", to: "gw", kind: "expected" },
  { from: "gw", to: "eng", kind: "expected" },
];

const COMMS_NODES_LIVE: Array<{
  id: string;
  label: string;
  kind: GraphNodeKind;
}> = [...COMMS_NODES_EXPECTED, { id: "rogue", label: "Rogue SA 44", kind: "rogue" }];

const COMMS_EDGES_LIVE: Array<{
  from: string;
  to: string;
  kind: GraphEdgeKind;
}> = [
  ...COMMS_EDGES_EXPECTED,
  { from: "rogue", to: "ap", kind: "new" },
  { from: "eng", to: "mfd", kind: "bypass" },
];

function CommGraph({
  nodes,
  edges,
}: {
  nodes: Array<{ id: string; label: string; kind: GraphNodeKind }>;
  edges: Array<{ from: string; to: string; kind: GraphEdgeKind }>;
}) {
  const theme = useHostTheme();
  const nodeWidth = 118;
  const nodeHeight = 36;
  const layout = computeDAGLayout({
    nodes: nodes.map((n) => ({ id: n.id })),
    edges: edges.map((e) => ({ from: e.from, to: e.to })),
    direction: "horizontal",
    nodeWidth,
    nodeHeight,
    rankGap: 40,
    nodeGap: 16,
    padding: 12,
  });
  const labels = Object.fromEntries(nodes.map((n) => [n.id, n.label]));
  const nodeKind = Object.fromEntries(nodes.map((n) => [n.id, n.kind]));
  const edgeKind = Object.fromEntries(
    edges.map((e) => [`${e.from}->${e.to}`, e.kind]),
  );

  return (
    <div
      style={{
        position: "relative",
        width: layout.width,
        height: layout.height,
        maxWidth: "100%",
        overflow: "auto",
      }}
    >
      <svg
        width={layout.width}
        height={layout.height}
        style={{ position: "absolute", inset: 0, pointerEvents: "none" }}
      >
        {layout.edges.map((e, i) => {
          const kind = edgeKind[`${e.from}->${e.to}`] ?? "expected";
          const stroke =
            kind === "new"
              ? theme.accent.primary
              : kind === "bypass"
                ? theme.diff.stripRemoved
                : theme.stroke.secondary;
          return (
            <line
              key={`${e.from}-${e.to}-${i}`}
              x1={e.sourceX}
              y1={e.sourceY}
              x2={e.targetX}
              y2={e.targetY}
              stroke={stroke}
              strokeWidth={kind === "expected" ? 1 : 2}
              strokeDasharray={
                kind === "expected" && e.isBackEdge ? "4 3" : undefined
              }
            />
          );
        })}
      </svg>
      {layout.nodes.map((n) => {
        const rogue = nodeKind[n.id] === "rogue";
        return (
          <div
            key={n.id}
            style={{
              position: "absolute",
              left: n.x,
              top: n.y,
              width: nodeWidth,
              height: nodeHeight,
              boxSizing: "border-box",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: theme.bg.elevated,
              border: `1px solid ${rogue ? theme.accent.primary : theme.stroke.primary}`,
              borderRadius: 6,
              padding: "0 6px",
              fontSize: 11,
              color: theme.text.primary,
              textAlign: "center",
              lineHeight: 1.2,
            }}
          >
            {labels[n.id]}
          </div>
        );
      })}
    </div>
  );
}

function SourcesView() {
  return (
    <Stack gap={16}>
      <H2>Protocol sources</H2>
      <Text>
        Ingest is described in{" "}
        <Code>docs/architecture/samples/sources/sources.yaml</Code>. Each source
        is an adapter instance. Adapters emit <Code>OTEvent</Code>; Bytewax,
        ONNX, rules, incidents, the LLM, and STIX do not import a protocol
        library. Native leftovers stay in <Code>parser_fields</Code>.
      </Text>
      <Table
        headers={["Field", "Type", "Role"]}
        rows={OTEVENT_FIELDS}
        striped
      />
      <Text size="small" tone="tertiary">
        <Code>class OTEvent</Code> — the only contract downstream of the
        adapters. Canonical names live in <Code>parser_fields</Code>.
      </Text>
      <Table
        headers={["protocol", "Transport", "asset_ref", "Map"]}
        rows={[
          ["nmea2000", "SocketCAN / pcap TAP", "source address", "PGN catalog"],
          ["modbus", "TCP poll or TAP :502", "unit-id", "modbus.yaml registers"],
          ["nmea0183", "UDP / serial (example)", "talker id", "nmea0183-nav.yaml"],
        ]}
        striped
      />
      <Table
        headers={["Canonical field", "N2K native", "Other native"]}
        rows={[
          ["lat_deg / lon_deg", "PGN 129025 / 129029", "0183 GGA / RMC"],
          ["heading_deg", "PGN 127250", "0183 HDT"],
          ["rpm", "PGN 127488", "Modbus HR 0"],
          ["oil_temp_c", "PGN 127489", "Modbus IR 10"],
        ]}
        striped
      />
      <Callout tone="info" title="Adding a protocol">
        Implement <Code>ot_sensor.adapters.&lt;protocol&gt;</Code> (or set{" "}
        <Code>adapter:</Code>), map natives onto{" "}
        <Code>canonical-fields.yaml</Code>, list a source in{" "}
        <Code>sources.yaml</Code>. No pipeline change if the canonical names
        already exist. <Code>prod</Code> is fatal if any source sets{" "}
        <Code>writes: true</Code>.
      </Callout>
      <Callout tone="success" title="Independence">
        An adapter that is down emits <Code>source_unavailable</Code> for that
        source id. Other sources and the rest of the pipeline continue.
      </Callout>
    </Stack>
  );
}

function TopologyView({ mode }: { mode: Mode }) {
  const [overlay, setOverlay] = useCanvasState<GraphOverlay>(
    "graphOverlay",
    "live",
  );
  const isLive = overlay === "live";
  const nodes = isLive ? COMMS_NODES_LIVE : COMMS_NODES_EXPECTED;
  const edges = isLive ? COMMS_EDGES_LIVE : COMMS_EDGES_EXPECTED;

  return (
    <Stack gap={16}>
      <H2>Topology / communication graph</H2>
      <Text>
        Assets are nodes; this service is the edges. Live SA→DA pairs (broadcast
        expanded to modeled consumers, gateway allowlists as cross-segment
        edges) overlay the expected OPV model. Lateral movement, rogue devices,
        and architecture violations show up as extra nodes or forbidden pairs —
        not as a PGN dump. The LLM receives only violating <Code>graph[]</Code>{" "}
        on an incident.
      </Text>
      <Grid columns={3} gap={12}>
        <Stat value={String(nodes.length)} label="Talkers in view" />
        <Stat value={String(edges.length)} label="Directed pairs" />
        <Stat
          value={isLive ? "2" : "0"}
          label="Violations"
          tone={isLive ? "danger" : "success"}
        />
      </Grid>
      <Row gap={8} wrap align="center">
        <Text size="small" weight="semibold">
          Overlay
        </Text>
        <Pill
          active={overlay === "expected"}
          onClick={() => setOverlay("expected")}
        >
          Expected model
        </Pill>
        <Pill active={overlay === "live"} onClick={() => setOverlay("live")}>
          Live (attack overlay)
        </Pill>
      </Row>
      <CommGraph nodes={nodes} edges={edges} />
      <Text size="small" tone="tertiary">
        Nav backbone, Underway. Broadcast expanded to consumers. Dashed line is
        an expected request cycle (MFD ↔ autopilot). Accent node/edge = rogue
        unicast. Removed-strip edge = gateway bypass.
      </Text>
      <Table
        headers={["Kind", "Stroke", "Meaning"]}
        rows={[
          ["Expected", "Neutral", "Allowed publisher, unicast, or gateway allowlist"],
          ["New / rogue", "Accent", "Talker or pair absent from the vessel model"],
          ["Bypass", "Removed", "PGN crossed segments outside the allowlist"],
        ]}
        striped
      />
      {isLive ? (
        <Table
          headers={["Live pair", "change", "Why it is visible"]}
          rows={[
            [
              "SA 44 → autopilot SA 56, PGN 127237",
              "new_node + unexpected_da",
              "Rogue commanding heading/track (T1692.001)",
            ],
            [
              "Engine SA 0 → MFD SA 60, PGN 127488 on nav",
              "gateway_bypass",
              "Isolation failure; RPM on the bridge bus",
            ],
          ]}
          rowTone={["danger", "warning"]}
          striped
        />
      ) : (
        <Callout tone="info" title="Expected nav pairs">
          GNSS and gyro fan out to MFD and autopilot. Autopilot unicasts to the
          rudder. Heading and COG/SOG may cross the gateway to propulsion
          displays. Engine RPM must not appear on nav.
        </Callout>
      )}
      {mode === "dev" ? (
        <Callout tone="info" title="dev — decoy SA 99">
          Edges to the honeypot decoy are <Code>decoy_edge</Code>, not
          automatically a bypass. In prod the same SA is <Code>new_node</Code>.
        </Callout>
      ) : (
        <Callout tone="success" title="prod — no decoy">
          SA 99 must not appear. If it does, the graph emits{" "}
          <Code>new_node</Code> / <Code>new_edge</Code>. Graph rows never carry
          ground-truth labels.
        </Callout>
      )}
    </Stack>
  );
}

function PipelineView({ mode }: { mode: Mode }) {
  return (
    <Stack gap={16}>
      <H2>Ingest and Bytewax stages</H2>
      <Text>
        Adapters from <Code>sources.yaml</Code> emit <Code>OTEvent</Code>. NMEA
        2000 is one adapter (SocketCAN/pcap, PGN decode). Modbus and any other
        mapped protocol join the same ingest bus. Bytewax windows{" "}
        <Code>OTEvent</Code> streams and binds physics to canonical names in{" "}
        <Code>parser_fields</Code>.
      </Text>
      <Table
        headers={["Stage", "Role"]}
        rows={[
          ["1. Normalize", "Source/protocol metadata, dual clocks, no silent drops"],
          ["2. Window", "Tumbling rates; sliding gaps and completeness"],
          ["3. Features", "Inter-arrival, deltas, error rate, identity churn, canonical residuals"],
          ["4. Vessel join", "Expected assets / channels / comms edges for this source"],
          ["5. event_id", "UUID/ULID for this feature window"],
          ["6a. ONNX", "Parallel infer from config.yaml"],
          ["6b. Rules", "Parallel predicates from rule.yaml"],
          ["7. Correlate", "Alert join by event_id, then incidents (not 1:1 dump)"],
          ["8. Emit", "Open/update incident; local SLM writes alert_title / alert_body"],
          ["9. STIX", "2.1 bundle from incident + SLM; TAXII optional"],
          ["Honeypot (parallel)", "Same TAP → raw logs; filename encodes capture data"],
          ["Asset detector", "Decode + kind=can → inventory; change events to incidents"],
          ["Comms graph", "Live vs expected SA→DA; violating edges to incidents"],
        ]}
        striped
      />
      <H3>Physics residuals</H3>
      <Table
        headers={["Residual", "Inputs", "Why"]}
        rows={[
          ["GNSS vs dead-reckoning", "129029 / 129025 vs heading + SOG", "Spoof vs GNSS-degraded fault"],
          ["GNSS-1 vs GNSS-2", "SA 16 vs SA 17", "gps-spoof-primary splits receivers"],
          ["DOP healthy but jump", "129539 vs position residual", "Spoof keeps quality flags good"],
          ["SOG vs RPM", "129026 vs 127488", "Engine reporting lie vs plant mismatch"],
          ["Heading vs ROT", "127250 vs 127251", "Gyro spoof vs inconsistent attitude"],
          ["COG vs heading", "129026 vs 127250", "Spoofed course with true gyro"],
          ["Depth vs last valid", "128267", "Injected depth vs sounder fault"],
        ]}
        striped
      />
      <Callout tone="info" title="Worked overlay: gps-spoof-underway">
        During ramp/hold, residuals fire with low <Code>fault_likelihood</Code>.
        Rule <Code>gps-spoof-nav</Code> fires on the same <Code>event_id</Code>.
        Correlation folds both into one incident. Co-pilot maps T1692.002,
        T0832, T0829 — not GNSS-degraded. Labels stay on the eval join.
      </Callout>
      <Callout tone="info" title="Recovery">
        Bytewax snapshots persist window and baseline state across restarts so
        detector memory is not reset on a brief outage.
      </Callout>
      {mode === "prod" ? (
        <Callout tone="success" title="prod — no ground truth">
          The dataflow does not bind a label topic. Startup is fatal if{" "}
          <Code>LABEL_TOPIC</Code> is set. Inbound GT frames, if any, are dropped
          and counted. Enriched events carry <Code>mode: prod</Code> and no{" "}
          <Code>label</Code> field.
        </Callout>
      ) : (
        <Callout tone="info" title="dev — labels are off-bus">
          A parallel eval join <Code>{"{ event_id, label }"}</Code> scores models,
          rules, and the co-pilot after emit. Labels never enter the LLM prompt or the
          CAN TAP, so <Code>prod</Code> payloads stay identical.
        </Callout>
      )}
    </Stack>
  );
}

function HoneypotView() {
  return (
    <Stack gap={16}>
      <H2>Honeypot data collector</H2>
      <Text>
        TAP-side sink in parallel with PGN decode. It appends every inflow unit
        to log files even when the payload is not valid NMEA 2000. The collector
        does not transmit on a live backbone. A simulator decoy (SA 99) may
        address-claim in the lab so unauthorized commands have a victim; the
        sensor only records.
      </Text>
      <Table
        headers={["Inflow", "Logged?"]}
        rows={[
          ["Valid N2K / CAN 2.0B", "Yes"],
          ["Unknown or proprietary PGN", "Yes"],
          ["CRC fail, error frame, truncated SocketCAN", "Yes"],
          ["Non-CAN (NMEA 0183, USB junk, Ethernet, zeros)", "Yes"],
          ["Empty or oversized reads", "Yes"],
        ]}
        rowTone={["success", "success", "success", "success", "success"]}
        striped
      />
      <H3>Filename encodes the data</H3>
      <Text size="small">
        Closed files rename from <Code>…-open-{"{pid}"}.jsonl</Code> to a
        self-describing name. Ground truth is never in the path.
      </Text>
      <Table
        headers={["Token", "Encoded data"]}
        rows={[
          ["hp", "Collector id"],
          ["mode", "dev or prod"],
          ["hull", "Vessel id from sensor config"],
          ["segment / iface", "Backbone and TAP (iface punctuation stripped)"],
          ["utc_open / utc_close", "Window YYYYMMDDTHHMMSSZ"],
          ["n{count} / b{nbytes}", "Record count and raw payload bytes"],
          ["k{kinds}", "Sorted kind hints, + joined (can+error)"],
          ["r{seq}", "Rotation index"],
        ]}
        striped
      />
      <Text size="small" tone="secondary">
        Example:{" "}
        <Code>
          hp-prod-opv1-nav-vcannav-20260908T190000Z-20260908T195959Z-n18420-b2202010-kcan+error-r0007.jsonl.gz
        </Code>
      </Text>
      <H3>Log envelope</H3>
      <Text size="small">
        JSONL metadata plus opaque <Code>payload_b64</Code>. <Code>kind</Code> is
        a capture hint, not a decode verdict. No schema check on the blob.
        Forensic pointers use the closed filename, not <Code>open-{"{pid}"}</Code>.
      </Text>
      <Table
        headers={["Field", "Role"]}
        rows={[
          ["t, segment, iface, seq", "When, which backbone, which TAP, file sequence"],
          ["nbytes", "Raw unit length"],
          ["kind", "can / error / truncated / non_can / empty / unknown"],
          ["sha256", "Hash of the raw bytes"],
          ["payload_b64", "Uninterpreted inflow — write even if it will not parse"],
        ]}
        striped
      />
      <Callout tone="info" title="Rotation and retention">
        Close the current file at 128 MiB or 1 h. Keep at most 2 GiB / 48
        closed files / 30 days per segment. Oldest closed file is unlinked
        first. Files named on an open incident are held. Gzip is async — the
        TAP thread never waits. If everything is on hold and the cap is hit,
        drop new units (<Code>honeypot_dropped</Code>) rather than blocking
        SocketCAN.
      </Callout>
      <Callout tone="warning" title="Not LLM input">
        Incident construction may attach a forensic pointer (log file + seq
        range) when a model or rule fires. The SLM still sees only the
        incident.
      </Callout>
    </Stack>
  );
}

function AssetsView() {
  return (
    <Stack gap={16}>
      <H2>Asset detector service</H2>
      <Text>
        Listen-only inventory of N2K talkers. Consumes decode plus honeypot
        units with <Code>kind=can</Code>. Diffs the live catalog against the
        static OPV model. Does not transmit. Change events fold into incidents
        as <Code>assets[]</Code>; the full inventory is not dumped into the LLM.
        Node identity feeds the communication graph; edges live there.
      </Text>
      <Table
        headers={["change", "Meaning"]}
        rows={[
          ["new_asset", "SA/NAME not in the model"],
          ["missing_asset", "Expected talker silent beyond catalog interval"],
          ["name_change", "Same SA, different ISO 11783 NAME"],
          ["unexpected_segment", "Known NAME on the wrong backbone"],
          ["pgn_set_drift", "PGNs added or dropped vs model"],
          ["decoy_contact", "Traffic to/from honeypot SA 99"],
        ]}
        rowTone={["warning", "info", "danger", "warning", "info", "warning"]}
        striped
      />
      <Table
        headers={["Signal", "Source"]}
        rows={[
          ["Source address", "29-bit CAN ID"],
          ["NAME / function", "PGN 60928 address claimed"],
          ["Product info", "PGN 126996"],
          ["PGN set and rates", "126464 + observed traffic"],
          ["Catalog path", "assets/{mode}/{hull}/inventory.json"],
        ]}
        striped
      />
      <Callout tone="info" title="prod">
        Decoy SA 99 must not appear. If it does, the detector emits{" "}
        <Code>new_asset</Code>. Inventory rows never carry ground-truth labels.
      </Callout>
    </Stack>
  );
}

function ModelsView() {
  return (
    <Stack gap={16}>
      <H2>ONNX registry</H2>
      <Text>
        Operators do not embed weights. Each model is{" "}
        <Code>models/&lt;id&gt;/&lt;semver&gt;/</Code> with{" "}
        <Code>config.yaml</Code>, <Code>model.onnx</Code>, and a model card.
        Failed loads emit <Code>model_unavailable</Code> and skip that head.
      </Text>
      <Grid columns={2} gap={12}>
        <Card>
          <CardHeader trailing={<Pill size="sm">physics</Pill>}>
            physics-ae
          </CardHeader>
          <CardBody>
            <Text size="small">
              Residual autoencoder on analog PGNs (position, heading, RPM,
              depth). Outputs reconstruction error per feature.
            </Text>
          </CardBody>
        </Card>
        <Card>
          <CardHeader trailing={<Pill size="sm">sequence</Pill>}>
            claim-flood-seq
          </CardHeader>
          <CardBody>
            <Text size="small">
              Sequence classifier for address-claim storms and Rogue Master
              versus benign burst.
            </Text>
          </CardBody>
        </Card>
        <Card>
          <CardHeader trailing={<Pill size="sm">sample LSTM</Pill>}>
            throughput-lstm 1.0.0
          </CardHeader>
          <CardBody>
            <Text size="small">
              20×8 bus-load LSTM. Fires when <Code>flood_score &gt;= 0.80</Code>{" "}
              (T0814). Lab: benign ≈ 0.00, flood ≈ 0.99. Quiet on
              gps-spoof-underway. Weights at{" "}
              <Code>docs/architecture/samples/models/throughput-lstm/1.0.0/model.onnx</Code>.
            </Text>
          </CardBody>
        </Card>
        <Card>
          <CardHeader trailing={<Pill size="sm">joint</Pill>}>
            multi-head
          </CardHeader>
          <CardBody>
            <Text size="small">
              Joint <Code>anomaly</Code>, <Code>attack_family</Code>,{" "}
              <Code>fault_likelihood</Code> so the LLM does not invent the ML
              result.
            </Text>
          </CardBody>
        </Card>
      </Grid>
      <H3>throughput-lstm input</H3>
      <Table
        headers={["Tensor", "Shape", "Notes"]}
        rows={[
          ["bus_seq", "[batch, 20, 8]", "100 ms steps, 2 s window, features normalized per config.yaml"],
          ["flood_score", "[batch, 1]", "Sigmoid. info 0.40 / warning 0.65 / critical fire 0.80"],
        ]}
        striped
      />
      <H3>config.yaml fields</H3>
      <Table
        headers={["Field", "Purpose"]}
        rows={[
          ["model_id / version", "Registry identity"],
          ["feature_schema", "Ordered names matching Bytewax output"],
          ["window", "Duration and hop; must match stage 2"],
          ["inputs / outputs", "ONNX tensor names and shapes"],
          ["score_to_severity", "Info / warning / critical thresholds"],
          ["scope.segments / pgns", "Where this model may run"],
          ["catalog_ver", "Pinned PGN catalog"],
        ]}
        striped
      />
    </Stack>
  );
}

function RulesView() {
  return (
    <Stack gap={16}>
      <H2>Rules in parallel with ONNX</H2>
      <Text>
        Rules consume the same feature window and <Code>event_id</Code> as ONNX.
        They do not wait on inference. Packs live in{" "}
        <Code>rules/&lt;id&gt;/&lt;semver&gt;/rule.yaml</Code>. A failed pack
        emits <Code>rule_unavailable</Code> and does not block models.
      </Text>
      <Card>
        <CardHeader trailing={<Pill size="sm">critical</Pill>}>
          gps-spoof-nav
        </CardHeader>
        <CardBody>
          <Stack gap={8}>
            <Text size="small">
              On-bus GPS spoof: healthy-looking fix that walks off
              dead-reckoning. Scope <Code>nav</Code>, PGNs 129025 / 129026 /
              129029 / 129539. Window 30 s / hop 5 s. Maps T1692.002, T0832,
              T0829.
            </Text>
            <Table
              headers={["Clause", "Predicate"]}
              rows={[
                ["all", "DR residual > 50 m for ≥15 s"],
                ["all", "HDOP < 2.5 and sat_count ≥ 8"],
                ["all", "heading/ROT consistent; COG vs heading > 15°"],
                ["any", "GNSS-1 vs GNSS-2 split > 30 m, or both walk off"],
                ["not", "HDOP > 6 or sat_count drop > 4 (GNSS-degraded)"],
              ]}
              striped
            />
          </Stack>
        </CardBody>
      </Card>
      <H3>Alert correlation / incidents</H3>
      <Text>
        Stage A joins ONNX and rules by <Code>event_id</Code> into an alert (
        <Code>JOIN_TIMEOUT</Code> → <Code>join_incomplete</Code>, never invent
        scores). Stage B correlates alerts into incidents inside{" "}
        <Code>CORRELATE_WINDOW</Code> (default 120 s). The LLM is called on
        incident open and material updates, not on every hop. Ground truth is
        never collected.
      </Text>
      <Table
        headers={["Rule", "Behavior"]}
        rows={[
          ["Key", "(source, segment, asset_ref or technique-family)"],
          ["Merge", "GPS spoof + physics-ae + GNSS split + AIS-follow → one incident"],
          ["Dedup", "throughput-lstm every hop → one flood incident, alert_count++"],
          ["Promote", "name_change / decoy_contact attach to the open incident"],
          ["Close", "No matching alert for QUIET_WINDOW → state closed"],
        ]}
        striped
      />
      <Callout tone="info" title="Barrier">
        Timeout must not invent scores or rule hits. Eval labels join by{" "}
        <Code>incident_id</Code> after the SLM returns, never inside this
        object.
      </Callout>
    </Stack>
  );
}

function AttckView({ mode }: { mode: Mode }) {
  return (
    <Stack gap={16}>
      <H2>Local SLM writes the alert text</H2>
      <Text>
        Detection is ONNX + rules + correlation. The small LLM does{" "}
        <Text weight="semibold">not</Text> fire alerts. On incident open it
        checks local Ollama (<Code>OTLAB_SLM_MODEL</Code>, default{" "}
        <Code>qwen2:1.5b</Code>) and marks the Local SLM pill{" "}
        <Code>ok</Code> with that tag. Alert title/body stay a compact
        template so TAP ingest is not blocked on generate.{" "}
        {mode === "dev"
          ? "In dev, technique IDs are scored against the label join after the fact. Loopback LLM_ENDPOINT is allowed for tests."
          : "In prod there is no label join. LLM_ENDPOINT is a fatal startup error."}{" "}
        Timeout, missing weights, or bad JSON → <Code>llm_unavailable</Code>{" "}
        and a template fallback. Risk and NIS2 clocks do not wait on the SLM.
      </Text>
      <Grid columns={3} gap={12}>
        <Stat value="1.5B" label="qwen2:1.5b default" />
        <Stat value="2 s" label="Ollama tags check" />
        <Stat
          value={mode === "dev" ? "Loopback ok" : "No remote"}
          label="Network"
          tone={mode === "dev" ? "info" : "success"}
        />
      </Grid>
      <Table
        headers={["Field", "Rule"]}
        rows={[
          ["alert_title", "≤120 chars. Incident list and NIS2 subject"],
          ["alert_body", "≤1200 chars. Watchstander text; STIX note"],
          ["techniques", "Subset of incident ∪ retrieved ATT&CK; extras dropped"],
          ["fault_vs_attack", "Follows fault_likelihood and rule not clauses"],
          ["Must not set", "severity, risk.total, nis2_significant"],
        ]}
        striped
      />
      <Callout tone="info" title="gps-spoof-underway example">
        Title: GNSS-1 walked off dead-reckoning; distrust position and AIS.
        Body tells the watchstander HDOP stayed low (not GNSS-degraded) and
        not to let autopilot follow spoofed COG. Fallback if Ollama is
        down: <Code>critical gps-spoof-nav on assets 16; risk 86</Code>.
      </Callout>
      <Callout tone="warning" title="No unsupervised actuation">
        SLM tools must not write PGNs, change engine or autopilot state, or
        close a gateway without a human confirmation path outside this service.
      </Callout>
      <H3>ICS techniques on this bus</H3>
      <Table
        headers={["ID", "Name", "N2K presentation"]}
        rows={[
          [
            <Link href="https://attack.mitre.org/techniques/T1692/">T1692</Link>,
            "Unauthorized Message",
            "Injected PGN not from the legitimate talker",
          ],
          [
            <Link href="https://attack.mitre.org/techniques/T1692/001/">
              T1692.001
            </Link>,
            "Command Message",
            "Autopilot / engine / thruster commands",
          ],
          [
            <Link href="https://attack.mitre.org/techniques/T1692/002/">
              T1692.002
            </Link>,
            "Reporting Message",
            "GNSS, AIS, heading, RPM, depth spoof",
          ],
          [
            <Link href="https://attack.mitre.org/techniques/T0856/">T0856</Link>,
            "Spoof Reporting Message",
            "Legacy alias for reporting spoof",
          ],
          [
            <Link href="https://attack.mitre.org/techniques/T0848/">T0848</Link>,
            "Rogue Master",
            "ISO 11783 address claim / NAME spoof, SA theft",
          ],
          [
            <Link href="https://attack.mitre.org/techniques/T0814/">T0814</Link>,
            "Denial of Service",
            "PGN flood, error frames, Fast Packet exhaustion",
          ],
        ]}
        rowTone={["danger", "danger", "warning", "warning", "danger", "warning"]}
        striped
      />
      <H3>Impact attachments</H3>
      <Table
        headers={["ID", "Name", "Marine OT meaning"]}
        rows={[
          [
            <Link href="https://attack.mitre.org/techniques/T0829/">T0829</Link>,
            "Loss of View",
            "Untrustworthy position, heading, or AIS on the bridge",
          ],
          [
            <Link href="https://attack.mitre.org/techniques/T0827/">T0827</Link>,
            "Loss of Control",
            "Autopilot or machinery commands unreliable",
          ],
          [
            <Link href="https://attack.mitre.org/techniques/T0832/">T0832</Link>,
            "Manipulation of View",
            "Displays show attacker-chosen nav or plant state",
          ],
          [
            <Link href="https://attack.mitre.org/techniques/T0831/">T0831</Link>,
            "Manipulation of Control",
            "Unauthorized heading, RPM, or thruster effect",
          ],
        ]}
        striped
      />
      <Text size="small" tone="secondary">
        RF GNSS spoofing is an off-bus precursor. The lab overlay{" "}
        <Code>gps-spoof-underway</Code> presents on N2K as T1692.002 / T0856
        reporting PGNs with healthy DOPs. Enterprise ATT&amp;CK is used only when
        activity leaves the bus.
      </Text>
    </Stack>
  );
}

function StixView({ mode }: { mode: Mode }) {
  const isDev = mode === "dev";
  return (
    <Stack gap={16}>
      <H2>STIX 2.1 reporting</H2>
      <Text>
        Outbound intel after the local SLM returns. Retrieval of ATT&amp;CK
        is vendored JSON on the host; this stage writes a bundle
        from the incident, <Code>evidence_summary</Code>, and{" "}
        <Code>alert_body</Code>. Raw CAN, honeypot blobs, and ground truth never go in the
        bundle. There is no first-class STIX 2.1 incident object — the shareable
        unit is a <Code>report</Code> plus a <Code>grouping</Code> (
        <Code>suspicious-activity</Code>).
      </Text>
      <Grid columns={3} gap={12}>
        <Stat value="2.1" label="STIX spec" />
        <Stat value="Local file" label="Default sink" />
        <Stat
          value={isDev ? "Lab TAXII optional" : "Share confirms"}
          label="TAXII 2.1"
          tone={isDev ? "info" : "warning"}
        />
      </Grid>
      <Table
        headers={["STIX type", "Role"]}
        rows={[
          ["identity", "This sensor (system). Hull omitted when STIX_REDACT_HULL"],
          ["infrastructure", "Segment backbone, control-system — not CMS"],
          ["attack-pattern", "ATT&CK ICS via mitre-attack external_id"],
          ["observed-data", "Window + packet_count; no payloads"],
          ["x-ot-window", "Custom SCO: protocol, source, segment, channels, asset_refs"],
          ["sighting", "Of attack-pattern; count = alert_count"],
          ["note", "SLM alert_body, abstract"],
          ["course-of-action", "Detect/contain only — not actuation"],
          ["grouping", "suspicious-activity for this incident_id"],
          ["report", "report_types incident; object_refs of the rest"],
        ]}
        striped
      />
      <H3>Worked bundle — gps-spoof-underway</H3>
      <Text size="small" tone="secondary">
        Local path{" "}
        <Code>reports/stix/{mode}/opv1/inc-01J….json</Code>
        . Window 19:00:30–19:01:00Z. T1692.002 sighting, impacts T0832 / T0829
        as extra attack-patterns. Custom window lists PGNs 129025 / 129026 /
        129029 / 129539 and SA 16, 17, 35.
      </Text>
      <Table
        headers={["Object", "id (abbrev)", "Points at"]}
        rows={[
          ["identity", "identity--1111…", "OT sensor"],
          ["infrastructure", "infrastructure--aaaa…", "OPV nav NMEA 2000"],
          ["attack-pattern", "attack-pattern--0f1e…", "T1692.002"],
          ["observed-data", "observed-data--aaaa…", "18 observed; x-ot-window"],
          ["sighting", "sighting--9999…", "pattern + observed-data; count 12"],
          ["note", "note--1234…", "Healthy GNSS-1 walked off DR; not GNSS-degraded"],
          ["course-of-action", "course-of-action--c0a1…", "Prefer gyro + GNSS-2"],
          ["report", "report--b100…", "NMEA 2000 reporting spoof on nav"],
        ]}
        striped
      />
      <Table
        headers={["In the bundle?", "dev", "prod"]}
        rows={[
          ["Techniques, scores, window, evidence_summary", "Yes", "Yes"],
          ["Raw CAN / payload_b64 / packet list", "No", "No"],
          ["Ground truth / attack_id", "No", "No"],
          ["Honeypot filename", "Optional local", "Omit on TAXII"],
          ["Hull id", "Allowed locally", "Redact on TAXII"],
        ]}
        rowTone={[undefined, "success", "success", undefined, isDev ? "info" : "warning"]}
        striped
      />
      {isDev ? (
        <Callout tone="info" title="dev TAXII">
          A lab collection may ingest the same sanitized bundle. Labels stay on
          the eval join. Startup is still fatal if a sink asks for GT.
        </Callout>
      ) : (
        <Callout tone="warning" title="prod — off-ship is a human action">
          Local write is automatic on incident open, update, and closed.
          TAXII collection <Code>ot-incidents</Code> is off until an operator
          confirms Share. Same confirmation path as TAP or gateway changes.
        </Callout>
      )}
    </Stack>
  );
}

function NetworkView() {
  return (
    <Stack gap={12}>
      <H2>Host network</H2>
      <Text>
        Watchstander UI on <Code>:8443</Code> polls the simulator TAP. CyberPal
        talks to local Ollama. The sensor never writes the bus.
      </Text>
      <Table
        headers={["Listener", "Process", "Role"]}
        rows={[
          ["127.0.0.1:8443", "ot-dashboard", "Map, rules, models, correlation, honeypot, assistant"],
          ["127.0.0.1:8443 /api/snapshot", "LabRuntime", "Operator poll"],
          ["127.0.0.1:8443 /api/assistant", "CyberPalAssistant", "One session per incident_id"],
          ["127.0.0.1:11434", "Ollama cyberpal-2.0-4b", "Investigation only"],
          ["sim :8444 /api/tap", "TapMirror GET", "Listen-only CAN ingest"],
        ]}
        striped
      />
      <Callout tone="danger" title="No injector on the dashboard">
        Attack arming is <Code>opv-sim --serve</Code> on :8444. Dashboard Reset
        clears TAP history only.
      </Callout>
    </Stack>
  );
}

function WorkflowsView() {
  return (
    <Stack gap={12}>
      <H2>Active workflows</H2>
      <Table
        headers={["Workflow", "Status", "Path"]}
        rows={[
          ["Live TAP ingest", "active", "GET /api/tap → N2K adapter → OTEvent"],
          ["GPS spoof detection", "active", "gps-spoof-nav ∥ throughput-lstm → Incident → NIS2"],
          ["Watchstander text", "active", "LocalSlm ok when Ollama lists OTLAB_SLM_MODEL"],
          ["CyberPal investigation", "active", "correlation JSON → one Ollama session per incident"],
          ["Honeypot capture", "active", "raw TAP → otlab-work/hp + Honeypot tab"],
          ["Batch CLI", "active", "uv run ot-sensor --ticks 10"],
          ["SocketCAN vcan_*", "spec", "Not in this tree"],
          ["TAXII share", "spec", "Local STIX file only"],
        ]}
        rowTone={[
          "success",
          "success",
          "success",
          "success",
          "success",
          "success",
          "info",
          "info",
        ]}
        striped
      />
    </Stack>
  );
}

export default function OtSensorNmea2000Architecture() {
  const [view, setView] = useCanvasState<View>("view", "pipeline");
  const [mode, setMode] = useCanvasState<Mode>("mode", "prod");
  const [selectedService, setSelectedService] = useCanvasState(
    "selectedService",
    "ingest",
  );
  const dispatch = useCanvasAction();
  const isDev = mode === "dev";
  const selectedLabel =
    SENSOR_NODES.find((n) => n.id === selectedService)?.label ?? "Ingest bus";
  const accentIds = new Set([
    "onnx",
    "rules",
    "incidents",
    "llm",
    "slm",
    "assistant",
    "honeypot",
    "assets",
    "graph",
    "stix",
    "ingest",
  ]);

  return (
    <Stack gap={20}>
      <Stack gap={8}>
        <H1>OT sensor</H1>
        <Text tone="secondary">
          Config-driven protocol adapters emit <Code>OTEvent</Code>. NMEA 2000,
          Modbus, and any other mapped protocol join the same ingest bus.
          Click a service on the dataflow to see its schema. Ground truth exists
          only in <Code>dev</Code>; <Code>prod</Code> has no label topic.
        </Text>
      </Stack>
      <Grid columns={4} gap={12}>
        <Stat value="Listen-only" label="Adapter writes" />
        <Stat value="4" label="OPV TAP segments" />
        <Stat
          value={isDev ? "dev" : "prod"}
          label="SENSOR_MODE"
          tone={isDev ? "warning" : "success"}
        />
        <Stat
          value={isDev ? "Eval join" : "None"}
          label="Ground truth"
          tone={isDev ? "warning" : "success"}
        />
      </Grid>
      <Row gap={8} wrap align="center">
        <Text size="small" weight="semibold">
          Mode
        </Text>
        <Pill active={mode === "prod"} onClick={() => setMode("prod")}>
          prod
        </Pill>
        <Pill active={mode === "dev"} onClick={() => setMode("dev")}>
          dev
        </Pill>
        <Text size="small" tone="tertiary">
          View
        </Text>
        <Pill active={view === "pipeline"} onClick={() => setView("pipeline")}>
          Pipeline
        </Pill>
        <Pill active={view === "sources"} onClick={() => setView("sources")}>
          Sources
        </Pill>
        <Pill active={view === "models"} onClick={() => setView("models")}>
          Models
        </Pill>
        <Pill active={view === "rules"} onClick={() => setView("rules")}>
          Rules + incidents
        </Pill>
        <Pill active={view === "attck"} onClick={() => setView("attck")}>
          ATT&amp;CK + SLM
        </Pill>
        <Pill active={view === "honeypot"} onClick={() => setView("honeypot")}>
          Honeypot
        </Pill>
        <Pill active={view === "assets"} onClick={() => setView("assets")}>
          Assets
        </Pill>
        <Pill
          active={view === "topology"}
          onClick={() => setView("topology")}
        >
          Topology
        </Pill>
        <Pill active={view === "stix"} onClick={() => setView("stix")}>
          STIX
        </Pill>
        <Pill active={view === "network"} onClick={() => setView("network")}>
          Network
        </Pill>
        <Pill active={view === "workflows"} onClick={() => setView("workflows")}>
          Workflows
        </Pill>
        <Button
          variant="ghost"
          onClick={() =>
            dispatch({
              type: "openFile",
              path: "docs/architecture/ot-sensor-nmea2000.md",
            })
          }
        >
          Open spec
        </Button>
      </Row>
      <Divider />
      <H2>Dataflow ({mode})</H2>
      <FlowChart
        nodes={SENSOR_NODES}
        edges={SENSOR_EDGES}
        direction="horizontal"
        accentIds={accentIds}
        selectedId={selectedService}
        onSelect={setSelectedService}
      />
      <Text size="small" tone="tertiary">
        Click a service to see its data schema. Adapters emit{" "}
        <Code>OTEvent</Code> only. Raw logs do not go to the LLM or into STIX.
      </Text>
      <Divider />
      <H2>Data schema</H2>
      <SchemaPanel nodeId={selectedService} label={selectedLabel} />
      <Table
        headers={["Channel", "dev", "prod"]}
        rows={[
          ["CAN + segment", "vcan / pcap / lab sniffer", "Ship TAP"],
          [
            "Other protocols",
            "Per sources.yaml (Modbus, 0183, …)",
            "Same maps; read-only; no GT",
          ],
          [
            "Label topic",
            "Subscribe; off-bus eval join",
            "Not bound — fatal if LABEL_TOPIC set",
          ],
          ["Local SLM", "Ollama on host; incident prompt, no GT", "Same; LLM_ENDPOINT fatal"],
          ["Honeypot logs", "Self-describing filenames; raw, any format", "Same; no GT in name or body"],
          ["Asset inventory", "Live catalog + change events", "Live catalog + change events; no GT"],
          ["Comms graph", "Expected vs live overlay", "Same; no GT"],
          ["STIX 2.1", "Local bundle; TAXII optional", "Local; TAXII needs Share"],
          ["Operator scenario link", "From eval join", "Hidden"],
        ]}
        rowTone={[undefined, isDev ? "warning" : "success", undefined, isDev ? "info" : "success"]}
        striped
      />
      <Divider />
      {view === "pipeline" ? <PipelineView mode={mode} /> : null}
      {view === "sources" ? <SourcesView /> : null}
      {view === "models" ? <ModelsView /> : null}
      {view === "rules" ? <RulesView /> : null}
      {view === "attck" ? <AttckView mode={mode} /> : null}
      {view === "honeypot" ? <HoneypotView /> : null}
      {view === "assets" ? <AssetsView /> : null}
      {view === "topology" ? <TopologyView mode={mode} /> : null}
      {view === "stix" ? <StixView mode={mode} /> : null}
      {view === "network" ? <NetworkView /> : null}
      {view === "workflows" ? <WorkflowsView /> : null}
    </Stack>
  );
}
