import {
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
  Pill,
  Row,
  Stack,
  Stat,
  Table,
  Text,
  computeDAGLayout,
  useCanvasState,
  useHostTheme,
} from "cursor/canvas";

type SystemId = "sim" | "sensor";
type Mode = "dev" | "prod";
type View = "services" | "network" | "workflows";
type Field = [string, string, string];

type Service = {
  id: string;
  system: SystemId;
  label: string;
  summary: string;
  module: string;
  port: string;
  proto: string;
  consumes: string;
  emits: string;
  inFields: Field[];
  outFields: Field[];
  hideInProd?: boolean;
  specOnly?: boolean;
};

const OTEVENT: Field[] = [
  ["event_id", "str", "Stable id copied to scores and evidence"],
  ["timestamp", "datetime", "Event time"],
  ["protocol", "str", "nmea2000 (live TAP); adapters also map modbus / nmea0183"],
  ["source_asset_id", "str | None", "Talker SA"],
  ["destination_asset_id", "str | None", "Unicast DA; None if broadcast"],
  ["operation_name", "str", "gnss_position, address_claim, …"],
  ["object_address", "str | None", "PGN"],
  ["is_write / is_control / privileged", "bool", "Observed flags; sensor still listen-only"],
  ["parser_fields", "dict", "Canonical fields, source, segment, catalog"],
];

const CAN_FRAME: Field[] = [
  ["t", "datetime", "Plant clock"],
  ["segment", "str", "nav | propulsion | power | aux"],
  ["can_id", "int", "29-bit NMEA 2000"],
  ["data_hex", "str", "Payload hex; Fast Packet assembled in the adapter"],
  ["error", "bool", "Error frame"],
];

const SERVICES: Service[] = [
  {
    id: "scenario",
    system: "sim",
    label: "Scenario engine",
    summary: "Underway kinematics. Drives N2K twins. Lab only.",
    module: "opv_sim.ScenarioEngine",
    port: "in-process",
    proto: "tick",
    consumes: "scenario_id, SIM_MODE",
    emits: "PlantState",
    inFields: [
      ["scenario_id", "str", "underway | gps-spoof-underway"],
      ["sim_mode", "str", "dev | prod"],
    ],
    outFields: [
      ["t", "datetime", "Scenario clock"],
      ["lat_deg / lon_deg / sog_kn / heading_deg", "float", "Nav plant"],
      ["rpm_port / rpm_stbd", "float", "Propulsion plant"],
      ["phase", "str", "baseline | ramp | hold | recover"],
    ],
  },
  {
    id: "twins",
    system: "sim",
    label: "Device twins",
    summary: "ISO 11783 NAME + SA publishers. Frames stay in-memory in this tree.",
    module: "opv_sim.twins.DeviceTwins",
    port: "InMemoryCanBus",
    proto: "CAN",
    consumes: "PlantState + overlay",
    emits: "CanFrame",
    inFields: [
      ["plant", "PlantState", "Kinematics"],
      ["attacks", "dict", "spoof, gyro, velocity, pgn_flood, …"],
    ],
    outFields: CAN_FRAME,
  },
  {
    id: "gateways",
    system: "sim",
    label: "Isolating gateways",
    summary: "Allowlisted cross-segment forward. Engine commands never onto nav.",
    module: "opv_sim.twins.IsolatingGateway",
    port: "in-process",
    proto: "CAN filter",
    consumes: "CanFrame",
    emits: "CanFrame (allowlist)",
    inFields: [["frame", "CanFrame", "From a trunk"]],
    outFields: [
      ["frame", "CanFrame", "Forwarded if allowlisted"],
      ["dropped", "bool", "Architecture violation if forced through"],
    ],
  },
  {
    id: "injector",
    system: "sim",
    label: "Attack injector",
    summary: "Overlays false PGNs. Labels stay off-bus. UI on :8444 only — never on the sensor dashboard.",
    module: "opv_sim.twins.AttackInjector",
    port: "127.0.0.1:8444",
    proto: "HTTP + overlay",
    consumes: "POST /api/control",
    emits: "overlay + LabelRecord (dev)",
    inFields: [
      ["action", "str", "toggle_attack | reset | start | pause"],
      ["attack", "str", "spoof | gyro | velocity | pgn_flood | …"],
      ["enabled", "bool", "Arm or clear that overlay"],
    ],
    outFields: [
      ["attacks", "dict[str, bool]", "Live injector map"],
      ["attack_id", "str | None", "gps-spoof-primary when spoof is on"],
      ["label", "LabelRecord", "dev only; never on CAN"],
    ],
  },
  {
    id: "tapapi",
    system: "sim",
    label: "TAP API",
    summary: "Listen-only HTTP snapshot of the last plant tick. Sensor polls this; it never writes the bus.",
    module: "opv_sim.app GET /api/tap",
    port: "127.0.0.1:8444",
    proto: "HTTP JSON",
    consumes: "SimRuntime.tick",
    emits: "TapSnapshot",
    inFields: [["elapsed_s", "float", "Plant time"]],
    outFields: [
      ["frames[]", "list[CanFrame]", "Last hop; data_hex only"],
      ["plant", "PlantState", "Kinematics for the injector UI"],
      ["attacks", "dict", "Which overlays are armed"],
      ["attack_id", "str | None", "Present on the sim; sensor TAP path must not use it as GT"],
    ],
  },
  {
    id: "labels",
    system: "sim",
    label: "Label topic",
    summary: "dev-only in-memory records. Fatal if LABEL_TOPIC is set in SIM_MODE=prod.",
    module: "opv_sim.LabelTopic",
    port: "in-memory",
    proto: "eval only",
    consumes: "LabelRecord",
    emits: "LabelRecord",
    hideInProd: true,
    inFields: [
      ["attack_id", "str", "gps-spoof-primary, …"],
      ["technique", "str", "T1692.002"],
    ],
    outFields: [
      ["t / victim_sa / pgn / segment", "…", "Eval join key"],
      ["scenario_id", "str", "Never on CAN"],
    ],
  },
  {
    id: "tap",
    system: "sensor",
    label: "TAP client",
    summary: "Polls the simulator. Listen-only. Dashboard does not tick the plant.",
    module: "ot_sensor.tap.TapMirror",
    port: "GET {sim}/api/tap",
    proto: "HTTP JSON",
    consumes: "TapSnapshot",
    emits: "CanFrame",
    inFields: CAN_FRAME,
    outFields: CAN_FRAME,
  },
  {
    id: "n2k",
    system: "sensor",
    label: "N2K adapter",
    summary: "Maps CAN/PGN onto OTEvent. Writes on the wire are observed flags, never transmitted.",
    module: "ot_sensor.adapters.Nmea2000Adapter",
    port: "in-process",
    proto: "NMEA 2000",
    consumes: "CanFrame",
    emits: "OTEvent",
    inFields: CAN_FRAME,
    outFields: OTEVENT,
  },
  {
    id: "honeypot",
    system: "sensor",
    label: "Honeypot",
    summary: "Raw inflow regardless of parse. Rotate + retain. Not LLM input.",
    module: "ot_sensor.honeypot.HoneypotService",
    port: "otlab-work/hp",
    proto: "JSONL",
    consumes: "raw bytes + optional OTEvent",
    emits: "HoneypotRecord / feed",
    inFields: [
      ["payload", "bytes", "Uninterpreted"],
      ["iface / segment", "str", "Capture path"],
    ],
    outFields: [
      ["seq / sha256 / nbytes", "…", "Envelope"],
      ["path", "str", "hp-…-rNNNN.jsonl.gz"],
      ["feed[]", "list", "Dashboard Honeypot tab"],
    ],
  },
  {
    id: "assets",
    system: "sensor",
    label: "Asset detector",
    summary: "Live TAP talkers joined to the vessel YAML. Silent catalog assets stay hidden.",
    module: "ot_sensor.assets.AssetDetector",
    port: "in-process",
    proto: "OTEvent",
    consumes: "OTEvent",
    emits: "AssetRecord / AssetChange",
    inFields: [
      ["source_asset_id", "str", "From OTEvent"],
      ["asset-criticality.yaml", "file", "Join, not inferred"],
    ],
    outFields: [
      ["asset_id / criticality / nis2_service", "…", "Inventory row"],
      ["depends_on / dependents", "list[str]", "Blast radius"],
      ["traffic", "str", "benign | attack | idle"],
    ],
  },
  {
    id: "graph",
    system: "sensor",
    label: "Comms graph",
    summary: "Who talks to whom. Distinct from the dependency overlay.",
    module: "ot_sensor.graph.CommsGraph",
    port: "in-process",
    proto: "OTEvent",
    consumes: "OTEvent + AssetRecord + VesselModel",
    emits: "GraphEdge / GraphChange",
    inFields: [
      ["src / dst", "str", "Asset ids"],
      ["expected_edges", "list", "Vessel model"],
    ],
    outFields: [
      ["expected", "bool", "Allowlist"],
      ["change", "str", "new_edge, gateway_bypass, …"],
    ],
  },
  {
    id: "bytewax",
    system: "sensor",
    label: "Feature stage",
    summary: "Bytewax contract in-process (FeatureWindow + event_id). A later worker can replace this stage.",
    module: "ot_sensor.features.FeatureStage",
    port: "in-process",
    proto: "windows",
    consumes: "OTEvent",
    emits: "FeatureWindow",
    inFields: OTEVENT.slice(0, 6),
    outFields: [
      ["event_id", "str", "Shared with ONNX and rules"],
      ["t_start / t_end", "datetime", "Window"],
      ["features", "dict[str, float]", "GNSS split, DR residual, rates"],
      ["member_event_ids", "list[str]", "Not the 10 Hz dump"],
    ],
  },
  {
    id: "onnx",
    system: "sensor",
    label: "ONNX enrich",
    summary: "Parallel to rules. Fail closed: model_unavailable.",
    module: "ot_sensor.onnx_enrich.OnnxEnrich",
    port: "in-process",
    proto: "ONNX Runtime",
    consumes: "FeatureWindow",
    emits: "ModelScore",
    inFields: [
      ["event_id", "str", "Same window"],
      ["features", "dict", "Pinned by throughput-lstm config.yaml"],
    ],
    outFields: [
      ["model_id / version", "str", "throughput-lstm"],
      ["scores", "dict[str, float]", "flood_score, …"],
      ["status", "str", "ok | model_unavailable"],
    ],
  },
  {
    id: "rules",
    system: "sensor",
    label: "Rules enrich",
    summary: "Parallel to ONNX. Same FeatureWindow.event_id. Operator can retune clauses on the dashboard.",
    module: "ot_sensor.rules.RulesEnrich",
    port: "POST /api/rules",
    proto: "predicates",
    consumes: "FeatureWindow",
    emits: "RuleHit",
    inFields: [
      ["event_id", "str", "Same window"],
      ["features", "dict", "gps-spoof-nav predicates"],
    ],
    outFields: [
      ["rule_id", "str", "gps-spoof-nav"],
      ["fired / severity", "bool / str", "If predicates hold"],
      ["techniques / impacts", "list[str]", "ATT&CK ICS"],
      ["clauses_fired", "list[str]", "Operator evidence"],
    ],
  },
  {
    id: "incidents",
    system: "sensor",
    label: "Incidents",
    summary: "Join by event_id, correlate, risk, NIS2 clocks. Does not wait on the SLM.",
    module: "ot_sensor.incidents.IncidentCorrelator",
    port: "in-process",
    proto: "correlation",
    consumes: "ModelScore, RuleHit, AssetChange, GraphChange",
    emits: "Alert, Incident, Evidence, RiskScore",
    inFields: [
      ["event_id", "str", "Join key"],
      ["JOIN_TIMEOUT", "s", "join_incomplete; never invent scores"],
    ],
    outFields: [
      ["incident_id / state / severity", "str", "open | update | closed"],
      ["risk.total / nis2_significant", "int / bool", "Transparent 0–100"],
      ["alerts[]", "list[Alert]", "Joined enrichers"],
      ["evidence_summary", "dict", "SLM / CyberPal input; not raw CAN"],
    ],
  },
  {
    id: "slm",
    system: "sensor",
    label: "Watchstander SLM",
    summary: "Writes alert_title / alert_body. Does not detect. Ollama tag (OTLAB_SLM_MODEL) → ok; down → llm_unavailable template. prod denies LLM_ENDPOINT.",
    module: "ot_sensor.slm.LocalSlm",
    port: "Ollama :11434",
    proto: "HTTP /api/tags",
    consumes: "Incident",
    emits: "CopilotAssessment",
    inFields: [
      ["evidence_summary", "dict", "Compact incident only"],
      ["allow_techniques", "list[str]", "Incident ∪ vendored ATT&CK"],
    ],
    outFields: [
      ["alert_title / alert_body", "str", "≤120 / ≤1200"],
      ["status", "str", "ok | llm_unavailable | schema_invalid"],
      ["recommend", "list[str]", "Observe / distrust only"],
    ],
  },
  {
    id: "assistant",
    system: "sensor",
    label: "CyberPal assistant",
    summary: "Investigation only. One session per incident. Correlation JSON — no raw CAN, honeypot blobs, or attack_id.",
    module: "ot_sensor.assistant.CyberPalAssistant",
    port: "/api/assistant + Ollama :11434",
    proto: "HTTP chat",
    consumes: "Incident + related assets",
    emits: "AssistantSession",
    inFields: [
      ["incident_id", "str", "Session key"],
      ["briefing", "dict", "Fired rules/models, graph, risk, NIS2, assets"],
      ["message", "str | None", "Investigation question"],
    ],
    outFields: [
      ["interpretation", "str", "Watchstander briefing"],
      ["messages[]", "list", "User / assistant turns for this incident only"],
      ["source", "str", "cyberpal | heuristic"],
    ],
  },
  {
    id: "stix",
    system: "sensor",
    label: "STIX 2.1",
    summary: "Local bundle. TAXII share is not in this tree.",
    module: "ot_sensor.stix.StixExporter",
    port: "otlab-work/stix",
    proto: "file",
    consumes: "Incident + CopilotAssessment",
    emits: "StixBundleRef",
    inFields: [
      ["incident_id", "str", "Exported unit"],
      ["alert_body", "str", "STIX note"],
    ],
    outFields: [
      ["path", "str", "stix/{mode}/{hull}/{id}.json"],
      ["taxii_shared", "bool", "Always false here"],
    ],
  },
  {
    id: "ui",
    system: "sensor",
    label: "Operator dashboard",
    summary: "Listen-only watchstander UI. Map, rules, models, correlation, honeypot, assistant. No injector toggles.",
    module: "ot_sensor.app",
    port: "127.0.0.1:8443",
    proto: "HTTP",
    consumes: "GET /api/snapshot",
    emits: "display + ack / rules / assistant",
    inFields: [
      ["snapshot", "dict", "Assets, incidents, services, honeypot"],
      ["incident_id", "str", "Selected case"],
    ],
    outFields: [
      ["ack", "POST /api/ack", "Clear new-incident toast"],
      ["rules", "POST /api/rules", "Retune clauses"],
      ["assistant", "GET|POST /api/assistant", "Per-incident session"],
    ],
  },
  {
    id: "eval",
    system: "sensor",
    label: "Eval join",
    summary: "dev only. Joins labels after emit. Never in the SLM or CyberPal prompt.",
    module: "ot_sensor.eval_join.EvalJoin",
    port: "in-process",
    proto: "dev",
    consumes: "LabelRecord + Incident",
    emits: "score record",
    hideInProd: true,
    inFields: [
      ["labels", "list", "From the in-process sim"],
      ["incident_id", "str", "After SLM returns"],
    ],
    outFields: [
      ["attack_id ↔ incident_id", "str", "Scoring only"],
      ["gt_in_prompt", "bool", "Always false"],
    ],
  },
];

const SIM_EDGES: Array<{ from: string; to: string; via: string }> = [
  { from: "scenario", to: "twins", via: "PlantState" },
  { from: "injector", to: "twins", via: "overlay" },
  { from: "twins", to: "gateways", via: "CAN" },
  { from: "gateways", to: "tapapi", via: "frames" },
  { from: "injector", to: "labels", via: "dev labels" },
  { from: "twins", to: "tapapi", via: "frames" },
];

const SENSOR_EDGES: Array<{ from: string; to: string; via: string }> = [
  { from: "tap", to: "n2k", via: "CanFrame" },
  { from: "tap", to: "honeypot", via: "raw" },
  { from: "n2k", to: "assets", via: "OTEvent" },
  { from: "n2k", to: "graph", via: "OTEvent" },
  { from: "n2k", to: "bytewax", via: "OTEvent" },
  { from: "assets", to: "graph", via: "AssetRecord" },
  { from: "bytewax", to: "onnx", via: "FeatureWindow" },
  { from: "bytewax", to: "rules", via: "FeatureWindow" },
  { from: "onnx", to: "incidents", via: "ModelScore" },
  { from: "rules", to: "incidents", via: "RuleHit" },
  { from: "assets", to: "incidents", via: "AssetChange" },
  { from: "graph", to: "incidents", via: "GraphChange" },
  { from: "honeypot", to: "ui", via: "feed" },
  { from: "incidents", to: "slm", via: "Incident" },
  { from: "incidents", to: "assistant", via: "correlation JSON" },
  { from: "incidents", to: "stix", via: "Incident" },
  { from: "slm", to: "stix", via: "CopilotAssessment" },
  { from: "incidents", to: "ui", via: "snapshot" },
  { from: "slm", to: "ui", via: "alert text" },
  { from: "assistant", to: "ui", via: "/api/assistant" },
  { from: "labels", to: "eval", via: "dev" },
  { from: "incidents", to: "eval", via: "dev" },
];

const LAB_EDGES: Array<{ from: string; to: string; via: string }> = [
  { from: "tapapi", to: "tap", via: "GET /api/tap" },
];

const WORKFLOWS: Array<{
  id: string;
  system: SystemId;
  name: string;
  status: "active" | "fallback" | "spec";
  path: string;
  notes: string;
}> = [
  {
    id: "live-tap",
    system: "sensor",
    name: "Live TAP ingest",
    status: "active",
    path: "opv-sim tick → GET /api/tap → Nmea2000Adapter → OTEvent",
    notes: "Dashboard polls every 0.8 s. Sensor never ticks the plant.",
  },
  {
    id: "spoof",
    system: "sensor",
    name: "GPS spoof detection",
    status: "active",
    path: "injector spoof → gps-spoof-nav + LSTM → Incident → NIS2 clocks",
    notes: "Healthy-DOP walk-off vs GNSS-degraded. Listen-only recommend.",
  },
  {
    id: "watchstander",
    system: "sensor",
    name: "Watchstander alert text",
    status: "active",
    path: "Incident → LocalSlm → CopilotAssessment",
    notes: "Ollama tag via OTLAB_SLM_MODEL; template if llm_unavailable.",
  },
  {
    id: "cyberpal",
    system: "sensor",
    name: "CyberPal investigation",
    status: "active",
    path: "Incident JSON → Ollama qwen2:1.5b (alias cyberpal) → one session per incident_id",
    notes: "Assistant tab. No bus writes, no honeypot hex, no attack_id.",
  },
  {
    id: "hp",
    system: "sensor",
    name: "Honeypot capture",
    status: "active",
    path: "raw TAP → HoneypotService → otlab-work/hp + dashboard feed",
    notes: "Rotate / retain. Forensic pointer only on the incident.",
  },
  {
    id: "batch",
    system: "sensor",
    name: "Batch CLI lab",
    status: "active",
    path: "uv run ot-sensor --ticks 10 (in-process sim)",
    notes: "Same adapters and correlator; no HTTP TAP.",
  },
  {
    id: "eval",
    system: "sensor",
    name: "Dev eval join",
    status: "active",
    path: "LabelTopic → EvalJoin after emit",
    notes: "prod: LABEL_TOPIC is fatal. Labels never enter SLM/CyberPal.",
  },
  {
    id: "inject-ui",
    system: "sim",
    name: "Injector UI",
    status: "active",
    path: "browser :8444 → POST /api/control → AttackInjector",
    notes: "Arm spoof / gyro / velocity / flood. Not on the sensor dashboard.",
  },
  {
    id: "tap-serve",
    system: "sim",
    name: "Serve TAP + plant",
    status: "active",
    path: "uv run opv-sim --serve → tick loop → GET /api/tap",
    notes: "In-memory CAN. SocketCAN vcan_* is not in this tree.",
  },
  {
    id: "vcan",
    system: "sim",
    name: "Linux vcan TAP",
    status: "spec",
    path: "vcan_nav / vcan_prop / vcan_pwr / vcan_aux",
    notes: "Ship-shaped TAP. CI uses InMemoryCanBus instead.",
  },
];

function visibleServices(system: SystemId, mode: Mode): Service[] {
  return SERVICES.filter((s) => {
    if (s.system !== system) return false;
    if (mode === "prod" && s.hideInProd) return false;
    return true;
  });
}

function visibleEdges(
  system: SystemId,
  mode: Mode,
): Array<{ from: string; to: string; via: string }> {
  const ids = new Set(visibleServices(system, mode).map((s) => s.id));
  const base = system === "sim" ? SIM_EDGES : SENSOR_EDGES;
  return base.filter((e) => ids.has(e.from) && ids.has(e.to));
}

function BoxGraph({
  nodes,
  edges,
  selectedId,
  onSelect,
  showMeta,
  modules,
  ports,
}: {
  nodes: Array<{ id: string; label: string }>;
  edges: Array<{ from: string; to: string; via?: string }>;
  selectedId: string;
  onSelect: (id: string) => void;
  showMeta: boolean;
  modules: Record<string, string>;
  ports: Record<string, string>;
}) {
  const theme = useHostTheme();
  const nodeWidth = showMeta ? 160 : 136;
  const nodeHeight = showMeta ? 58 : 40;
  const layout = computeDAGLayout({
    nodes: nodes.map((n) => ({ id: n.id })),
    edges: edges.map((e) => ({ from: e.from, to: e.to })),
    direction: "horizontal",
    nodeWidth,
    nodeHeight,
    rankGap: showMeta ? 56 : 44,
    nodeGap: 16,
    padding: 12,
  });
  const labels = Object.fromEntries(nodes.map((n) => [n.id, n.label]));
  const via = Object.fromEntries(edges.map((e) => [`${e.from}->${e.to}`, e.via ?? ""]));

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
          const label = via[`${e.from}->${e.to}`];
          const mx = (e.sourceX + e.targetX) / 2;
          const my = (e.sourceY + e.targetY) / 2;
          return (
            <g key={`${e.from}-${e.to}-${i}`}>
              <line
                x1={e.sourceX}
                y1={e.sourceY}
                x2={e.targetX}
                y2={e.targetY}
                stroke={theme.stroke.secondary}
                strokeWidth={1}
                strokeDasharray={e.isBackEdge ? "4 3" : undefined}
              />
              {showMeta && label ? (
                <text
                  x={mx}
                  y={my - 4}
                  textAnchor="middle"
                  fill={theme.text.tertiary}
                  fontSize={9}
                  fontFamily="inherit"
                >
                  {label}
                </text>
              ) : null}
            </g>
          );
        })}
      </svg>
      {layout.nodes.map((n) => {
        const selected = selectedId === n.id;
        return (
          <button
            key={n.id}
            type="button"
            onClick={() => onSelect(n.id)}
            style={{
              position: "absolute",
              left: n.x,
              top: n.y,
              width: nodeWidth,
              height: nodeHeight,
              boxSizing: "border-box",
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              background: theme.bg.elevated,
              border: `1px solid ${selected ? theme.accent.primary : theme.stroke.primary}`,
              borderRadius: 6,
              padding: "2px 6px",
              color: theme.text.primary,
              cursor: "pointer",
              appearance: "none",
              fontFamily: "inherit",
            }}
          >
            <span style={{ fontSize: 11, lineHeight: 1.2, textAlign: "center" }}>
              {labels[n.id]}
            </span>
            {showMeta ? (
              <>
                <span style={{ fontSize: 9, color: theme.text.secondary, lineHeight: 1.2 }}>
                  {ports[n.id]}
                </span>
                <span
                  style={{
                    fontSize: 8,
                    color: theme.text.tertiary,
                    lineHeight: 1.2,
                    maxWidth: "100%",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {modules[n.id]}
                </span>
              </>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

function SchemaDetail({ svc }: { svc: Service }) {
  return (
    <Stack gap={12}>
      <H3>
        {svc.label} — <Code>{svc.emits}</Code>
      </H3>
      <Text>{svc.summary}</Text>
      <Grid columns={4} gap={12}>
        <Stat value={svc.module} label="Module" />
        <Stat value={svc.port} label="Bind / path" />
        <Stat value={svc.consumes} label="Input" />
        <Stat value={svc.emits} label="Output" />
      </Grid>
      <H3>Input schema</H3>
      <Table headers={["Field", "Type", "Role"]} rows={svc.inFields} striped />
      <H3>Output schema</H3>
      <Table headers={["Field", "Type", "Role"]} rows={svc.outFields} striped />
    </Stack>
  );
}

function WorkflowsView({ system }: { system: SystemId }) {
  const rows = WORKFLOWS.filter((w) => w.system === system);
  return (
    <Stack gap={12}>
      <H2>Active workflows</H2>
      <Text>
        What this tree actually runs. Spec-only rows stay in the architecture
        docs until a TAP reader or TAXII listener lands.
      </Text>
      <Table
        headers={["Workflow", "Status", "Path", "Notes"]}
        rows={rows.map((w) => [w.name, w.status, w.path, w.notes])}
        rowTone={rows.map((w) =>
          w.status === "active" ? "success" : w.status === "fallback" ? "warning" : "info",
        )}
        striped
      />
    </Stack>
  );
}

function NetworkHostView({ system }: { system: SystemId }) {
  if (system === "sim") {
    return (
      <Stack gap={12}>
        <H2>Host network (this lab)</H2>
        <Table
          headers={["Listener", "Process", "Clients"]}
          rows={[
            ["127.0.0.1:8444 /", "opv-sim --serve", "Operator browser (injector UI)"],
            ["127.0.0.1:8444 /api/tap", "opv-sim", "ot-dashboard TAP client (GET only)"],
            ["127.0.0.1:8444 /api/control", "opv-sim", "Injector UI; never the sensor"],
            ["in-memory CAN", "SimRuntime.tick", "Device twins + gateways"],
          ]}
          striped
        />
        <Callout tone="danger" title="Listen-only TAP">
          The sensor polls <Code>GET /api/tap</Code>. It does not POST control,
          does not open SocketCAN, and does not write PGN.
        </Callout>
      </Stack>
    );
  }
  return (
    <Stack gap={12}>
      <H2>Host network (this lab)</H2>
      <Table
        headers={["Listener", "Process", "Clients"]}
        rows={[
          ["127.0.0.1:8443 /", "ot-dashboard", "Operator browser (watchstander)"],
          ["127.0.0.1:8443 /api/snapshot", "ot-dashboard", "Vite UI poll"],
          ["127.0.0.1:8443 /api/assistant", "CyberPalAssistant", "Assistant tab; one session per incident"],
          ["127.0.0.1:11434", "Ollama cyberpal-2.0-4b", "Investigation chat only"],
          ["sim :8444 /api/tap", "TapMirror", "Dashboard ingest (GET)"],
        ]}
        striped
      />
      <Callout tone="info" title="No injector on :8443">
        Attack arming stays on the simulator. Reset on the dashboard clears TAP
        history only.
      </Callout>
    </Stack>
  );
}

export default function OtLabSchema() {
  const [system, setSystem] = useCanvasState<SystemId>("system", "sensor");
  const [mode, setMode] = useCanvasState<Mode>("mode", "dev");
  const [view, setView] = useCanvasState<View>("view", "services");
  const [selected, setSelected] = useCanvasState<string>("svc", "n2k");

  const services = visibleServices(system, mode);
  const svc = services.find((s) => s.id === selected) ?? services[0] ?? SERVICES[0];
  const edges = visibleEdges(system, mode);
  const nodes = services.map((s) => ({ id: s.id, label: s.label }));
  const modules = Object.fromEntries(services.map((s) => [s.id, s.module]));
  const ports = Object.fromEntries(services.map((s) => [s.id, s.port]));

  const extraPeerNodes: Array<{ id: string; label: string }> = [];
  let graphEdges = edges;
  if (view === "network" && system === "sensor") {
    extraPeerNodes.push({ id: "tapapi", label: "Sim TAP API" });
    graphEdges = [
      ...edges,
      ...LAB_EDGES.filter((e) => services.some((s) => s.id === e.to)),
    ];
  }
  if (view === "network" && system === "sim") {
    extraPeerNodes.push({ id: "tap", label: "Sensor TAP client" });
    graphEdges = [
      ...edges,
      ...LAB_EDGES.filter((e) => services.some((s) => s.id === e.from)),
    ];
  }

  const graphNodes = [
    ...nodes,
    ...extraPeerNodes.filter((p) => !nodes.some((n) => n.id === p.id)),
  ];
  graphEdges = graphEdges.filter(
    (e) => graphNodes.some((n) => n.id === e.from) && graphNodes.some((n) => n.id === e.to),
  );

  const peerModules: Record<string, string> = {
    tapapi: "opv_sim.app",
    tap: "ot_sensor.tap",
  };
  const peerPorts: Record<string, string> = {
    tapapi: "GET :8444/api/tap",
    tap: "poll 0.8 s",
  };

  const selectSystem = (next: SystemId) => {
    setSystem(next);
    setSelected(next === "sim" ? "injector" : "n2k");
  };

  const activeCount = WORKFLOWS.filter((w) => w.system === system && w.status === "active").length;

  return (
    <Stack gap={16}>
      <Stack gap={6}>
        <H1>OT lab schema</H1>
        <Text tone="secondary">
          Click a box for description and input/output schemas. This canvas
          matches the runnable uv workspace: in-memory CAN, HTTP TAP on{" "}
          <Code>:8444</Code>, watchstander on <Code>:8443</Code>.
        </Text>
      </Stack>
      <Row gap={8} wrap align="center">
        <Text size="small" weight="semibold">
          System
        </Text>
        <Pill active={system === "sim"} onClick={() => selectSystem("sim")}>
          Simulator
        </Pill>
        <Pill active={system === "sensor"} onClick={() => selectSystem("sensor")}>
          OT sensor
        </Pill>
        <Text size="small" tone="tertiary">
          Mode
        </Text>
        <Pill active={mode === "prod"} onClick={() => setMode("prod")}>
          {system === "sim" ? "SIM_MODE=prod" : "SENSOR_MODE=prod"}
        </Pill>
        <Pill active={mode === "dev"} onClick={() => setMode("dev")}>
          {system === "sim" ? "SIM_MODE=dev" : "SENSOR_MODE=dev"}
        </Pill>
        <Text size="small" tone="tertiary">
          View
        </Text>
        <Pill active={view === "services"} onClick={() => setView("services")}>
          Services
        </Pill>
        <Pill active={view === "network"} onClick={() => setView("network")}>
          Network
        </Pill>
        <Pill active={view === "workflows"} onClick={() => setView("workflows")}>
          Workflows
        </Pill>
      </Row>
      <Grid columns={4} gap={12}>
        <Stat value={String(services.length)} label="Services" />
        <Stat
          value={mode === "dev" ? "Labels on" : "No GT"}
          label="Ground truth"
          tone={mode === "dev" ? "warning" : "success"}
        />
        <Stat value={String(activeCount)} label="Active workflows" tone="success" />
        <Stat value={system === "sim" ? ":8444" : ":8443"} label="Operator bind" />
      </Grid>
      {view === "workflows" ? (
        <WorkflowsView system={system} />
      ) : (
        <>
          <BoxGraph
            nodes={view === "network" ? graphNodes : nodes}
            edges={view === "network" ? graphEdges : edges}
            selectedId={svc.id}
            onSelect={(id) => {
              const hit = SERVICES.find((s) => s.id === id);
              if (!hit) return;
              if (hit.hideInProd && mode === "prod") return;
              if (hit.system !== system) setSystem(hit.system);
              setSelected(id);
            }}
            showMeta={view === "network"}
            modules={{ ...peerModules, ...modules }}
            ports={{ ...peerPorts, ...ports }}
          />
          <Text size="small" tone="tertiary">
            {view === "network"
              ? "Edge labels are the live contract. Click a box on this system for schemas."
              : system === "sim"
                ? "Simulator is never deployed on the vessel. prod means unlabeled CAN for certifying a prod sensor."
                : "Adapters emit OTEvent. CyberPal and the SLM see correlation JSON only."}
          </Text>
          {view === "network" ? <NetworkHostView system={system} /> : null}
          <Divider />
          <H2>Selected service</H2>
          <SchemaDetail svc={svc} />
        </>
      )}
      {view === "workflows" ? (
        <Grid columns={2} gap={12}>
          <Card>
            <CardHeader>Install</CardHeader>
            <CardBody>
              <Text size="small">
                {system === "sim" ? (
                  <>
                    <Code>uv sync --package opv-sim</Code> then{" "}
                    <Code>uv run opv-sim --serve --mode dev --port 8444</Code>
                  </>
                ) : (
                  <>
                    <Code>uv sync --package ot-sensor --extra onnx --extra ui</Code>
                    , build <Code>ot-sensor/frontend</Code>, then{" "}
                    <Code>uv run ot-dashboard --mode dev --port 8443 --sim-url http://127.0.0.1:8444</Code>
                  </>
                )}
              </Text>
            </CardBody>
          </Card>
          <Card>
            <CardHeader>Readme</CardHeader>
            <CardBody>
              <Text size="small">
                {system === "sim"
                  ? "simulator/README.md — services, TAP contract, injector."
                  : "ot-sensor/README.md — services, dashboard tabs, CyberPal import."}
              </Text>
            </CardBody>
          </Card>
        </Grid>
      ) : null}
    </Stack>
  );
}
