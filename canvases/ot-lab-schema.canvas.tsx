import {
  Callout,
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
type View = "services" | "network";
type Field = [string, string, string];

type Service = {
  id: string;
  system: SystemId;
  label: string;
  summary: string;
  image: string;
  port: string;
  proto: string;
  consumes: string;
  emits: string;
  inFields: Field[];
  outFields: Field[];
  hideInProd?: boolean;
  prodDown?: boolean;
};

const OTEVENT: Field[] = [
  ["event_id", "str", "Stable id copied to scores and evidence"],
  ["timestamp", "datetime", "Event time"],
  ["protocol", "str", "nmea2000 | modbus | nmea0183"],
  ["source_asset_id", "str | None", "Talker / client"],
  ["destination_asset_id", "str | None", "Unicast DA; None if broadcast"],
  ["operation_name", "str", "gnss_position, address_claim, …"],
  ["object_address", "str | None", "PGN / register / sentence"],
  ["is_write / is_control / privileged", "bool", "Observed flags; sensor still listen-only"],
  ["parser_fields", "dict", "Canonical fields, source, segment, catalog"],
];

const SERVICES: Service[] = [
  {
    id: "scenario",
    system: "sim",
    label: "Scenario engine",
    summary: "Physics and underway kinematics. Drives N2K twins. Not on the vessel.",
    image: "learnplay/opv-sim:scenario",
    port: "9100/tcp",
    proto: "HTTP control",
    consumes: "scenario.yaml",
    emits: "PlantState",
    inFields: [
      ["scenario_id", "str", "underway, gps-spoof-underway, …"],
      ["sim_mode", "str", "dev | prod"],
    ],
    outFields: [
      ["t", "datetime", "Scenario clock"],
      ["lat_deg / lon_deg / sog_kn / heading_deg", "float", "Nav plant"],
      ["rpm_port / rpm_stbd", "float", "Propulsion plant"],
      ["attack_id", "str | None", "dev only; never on CAN"],
    ],
  },
  {
    id: "twins",
    system: "sim",
    label: "Device twins",
    summary: "ISO 11783 NAME + SA publishers on four Mini N2K trunks.",
    image: "learnplay/opv-sim:twins",
    port: "vcan_*",
    proto: "SocketCAN",
    consumes: "PlantState",
    emits: "CanFrame",
    inFields: [
      ["plant", "PlantState", "Kinematics for N2K twins"],
      ["overlay", "dict | None", "From injector"],
    ],
    outFields: [
      ["iface", "str", "vcan_nav | vcan_prop | vcan_pwr | vcan_aux"],
      ["can_id", "int", "29-bit"],
      ["pgn / sa / da", "int", "Unpacked ID"],
      ["payload", "bytes", "8-byte or Fast Packet"],
    ],
  },
  {
    id: "gateways",
    system: "sim",
    label: "Isolating gateways",
    summary: "Allowlisted cross-segment forwarding. Engine commands never on nav.",
    image: "learnplay/opv-sim:gw",
    port: "vcan_*",
    proto: "SocketCAN",
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
    summary: "Overlays false PGNs. Labels stay off-bus.",
    image: "learnplay/opv-sim:injector",
    port: "9101/tcp",
    proto: "HTTP",
    consumes: "scenario + PlantState",
    emits: "overlay + LabelRecord",
    inFields: [
      ["scenario_id", "str", "Which overlay"],
      ["sim_mode", "str", "prod = no label publisher"],
    ],
    outFields: [
      ["victim_sa / pgn / segment", "…", "On-bus lie"],
      ["label", "LabelRecord", "dev NATS only"],
    ],
  },
  {
    id: "labels",
    system: "sim",
    label: "Label topic",
    summary: "dev-only parallel NATS. Fatal if bound in SIM_MODE=prod.",
    image: "nats:2.10.22",
    port: "4223/tcp",
    proto: "NATS",
    consumes: "LabelRecord",
    emits: "LabelRecord",
    hideInProd: true,
    inFields: [
      ["attack_id", "str", "gps-spoof-underway, …"],
      ["technique", "str", "T1692.002"],
    ],
    outFields: [
      ["t / victim_sa / pgn / segment", "…", "Eval join key"],
      ["scenario_id", "str", "Never on CAN"],
    ],
  },
  {
    id: "cms",
    system: "sim",
    label: "CMS stub",
    summary: "Read-only nav export. CMS does not sit on N2K.",
    image: "learnplay/opv-sim:cms-stub",
    port: "9180/tcp",
    proto: "HTTP",
    consumes: "gateway allowlist",
    emits: "NavExport",
    inFields: [["pgns", "list", "position, COG/SOG, heading"]],
    outFields: [["json", "NavExport", "lat, lon, cog, heading"]],
  },
  {
    id: "n2k",
    system: "sensor",
    label: "N2K adapter",
    summary: "Listen-only TAP. Four ifaces. Maps CAN/PGN onto OTEvent.",
    image: "learnplay/ot-sensor:n2k",
    port: "vcan_* / can0–3",
    proto: "SocketCAN",
    consumes: "CanFrame",
    emits: "OTEvent",
    inFields: [
      ["iface", "str", "vcan_nav or ship TAP"],
      ["catalog", "str", "pgn-2026.03.json"],
    ],
    outFields: OTEVENT,
  },
  {
    id: "modbus",
    system: "sensor",
    label: "Modbus adapter",
    summary: "Read-only poll. FC 01–04. Client to the sim/PLC.",
    image: "learnplay/ot-sensor:modbus",
    port: "→ 1502/tcp",
    proto: "Modbus TCP",
    consumes: "Modbus PDU",
    emits: "OTEvent",
    inFields: [
      ["host:port", "str", "127.0.0.1:1502"],
      ["unit_id", "int", "1"],
      ["writes", "bool", "fatal if true in prod"],
    ],
    outFields: OTEVENT,
  },
  {
    id: "n0183",
    system: "sensor",
    label: "NMEA 0183 adapter",
    summary: "Example third protocol. UDP bind.",
    image: "learnplay/ot-sensor:n0183",
    port: "10110/udp",
    proto: "NMEA 0183",
    consumes: "NmeaSentence",
    emits: "OTEvent",
    inFields: [
      ["bind", "str", "0.0.0.0:10110"],
      ["map", "str", "nmea0183-nav.yaml"],
    ],
    outFields: OTEVENT,
  },
  {
    id: "ingest",
    system: "sensor",
    label: "Ingest bus",
    summary: "NATS JetStream. Only contract downstream services need.",
    image: "nats:2.10.22",
    port: "4222/tcp",
    proto: "NATS",
    consumes: "OTEvent",
    emits: "OTEvent (otevent.>)",
    inFields: OTEVENT,
    outFields: [
      ["subject", "str", "otevent.{source}.{segment}"],
      ["payload", "OTEvent", "Unchanged"],
    ],
  },
  {
    id: "honeypot",
    system: "sensor",
    label: "Honeypot",
    summary: "Raw inflow regardless of parse. Rotate 128 MiB/1 h; retain 2 GiB and 30 d per segment. Not LLM input.",
    image: "learnplay/ot-sensor:honeypot",
    port: "9201/tcp",
    proto: "HTTP metrics",
    consumes: "raw bytes + optional OTEvent",
    emits: "HoneypotRecord / HoneypotFile",
    inFields: [
      ["payload", "bytes", "Uninterpreted"],
      ["iface / segment", "str", "Capture path"],
    ],
    outFields: [
      ["seq / sha256 / nbytes", "…", "Envelope"],
      ["path", "str", "hp-…-rNNNN.jsonl.gz"],
      ["on_hold / purged", "bool", "Incident hold; unlinked after retain cap"],
      ["dropped_records", "int", "Counted if cap hit and all files held"],
    ],
  },
  {
    id: "assets",
    system: "sensor",
    label: "Asset detector",
    summary: "Live catalog + criticality + depends_on. Diffs the OPV model.",
    image: "learnplay/ot-sensor:assets",
    port: "9202/tcp",
    proto: "HTTP",
    consumes: "OTEvent",
    emits: "AssetRecord / AssetChange",
    inFields: [
      ["source_asset_id", "str", "From OTEvent"],
      ["criticality.yaml", "file", "Join, not inferred"],
    ],
    outFields: [
      ["asset_id / criticality / nis2_service", "…", "Inventory row"],
      ["depends_on / dependents", "list[str]", "Blast radius"],
      ["change", "str", "new_asset, critical_missing, …"],
    ],
  },
  {
    id: "graph",
    system: "sensor",
    label: "Comms graph",
    summary: "Who talks to whom. Distinct from the dependency graph.",
    image: "learnplay/ot-sensor:graph",
    port: "9203/tcp",
    proto: "HTTP",
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
    label: "Bytewax",
    summary: "Windows, residuals, event_id. Dual clocks. Drops nothing silently.",
    image: "learnplay/ot-sensor:bytewax",
    port: "9204/tcp",
    proto: "NATS + HTTP",
    consumes: "OTEvent",
    emits: "FeatureWindow",
    inFields: OTEVENT.slice(0, 6),
    outFields: [
      ["event_id", "str", "Shared with ONNX and rules"],
      ["t_start / t_end", "datetime", "Window"],
      ["features", "dict[str, float]", "Canonical residuals and rates"],
      ["member_event_ids", "list[str]", "Not the 10 Hz dump"],
    ],
  },
  {
    id: "onnx",
    system: "sensor",
    label: "ONNX enrich",
    summary: "Parallel to rules. Fail closed: model_unavailable.",
    image: "learnplay/ot-sensor:onnx",
    port: "9205/tcp",
    proto: "NATS + HTTP",
    consumes: "FeatureWindow",
    emits: "ModelScore",
    inFields: [
      ["event_id", "str", "Same window"],
      ["features", "dict", "Pinned by config.yaml"],
    ],
    outFields: [
      ["model_id / version", "str", "throughput-lstm, physics-ae, …"],
      ["scores", "dict[str, float]", "flood_score, anomaly, …"],
      ["status", "str", "ok | model_unavailable"],
    ],
  },
  {
    id: "rules",
    system: "sensor",
    label: "Rules enrich",
    summary: "Parallel to ONNX. Same FeatureWindow.event_id.",
    image: "learnplay/ot-sensor:rules",
    port: "9206/tcp",
    proto: "NATS + HTTP",
    consumes: "FeatureWindow",
    emits: "RuleHit",
    inFields: [
      ["event_id", "str", "Same window"],
      ["features", "dict", "gps-spoof-nav predicates"],
    ],
    outFields: [
      ["rule_id", "str", "gps-spoof-nav, …"],
      ["fired / severity", "bool / str", "If predicates hold"],
      ["techniques / impacts", "list[str]", "ATT&CK ICS"],
      ["status", "str", "ok | rule_unavailable"],
    ],
  },
  {
    id: "incidents",
    system: "sensor",
    label: "Incidents",
    summary: "Join by event_id, correlate, risk score, NIS2 clocks. Not an LLM.",
    image: "learnplay/ot-sensor:incidents",
    port: "9207/tcp",
    proto: "NATS + HTTP",
    consumes: "ModelScore, RuleHit, AssetChange, GraphChange",
    emits: "Alert, Incident, Evidence, RiskScore, Nis2UiAlert",
    inFields: [
      ["event_id", "str", "Join key"],
      ["JOIN_TIMEOUT", "s", "join_incomplete; never invent scores"],
    ],
    outFields: [
      ["incident_id / state / severity", "str", "open | update | closed"],
      ["risk.total / nis2_significant", "int / bool", "Transparent 0–100"],
      ["alerts[]", "list[Alert]", "Joined enrichers"],
      ["evidence_summary", "dict", "SLM input; not raw CAN"],
    ],
  },
  {
    id: "slm",
    system: "sensor",
    label: "Local SLM",
    summary: "GGUF writes alert_title / alert_body. Does not fire detections. prod denies LLM_ENDPOINT.",
    image: "learnplay/ot-sensor:slm",
    port: "127.0.0.1:9208/tcp",
    proto: "HTTP loopback",
    consumes: "Incident",
    emits: "CopilotAssessment",
    inFields: [
      ["evidence_summary", "dict", "Only compact incident"],
      ["allow_techniques", "list[str]", "Incident ∪ vendored ATT&CK"],
    ],
    outFields: [
      ["alert_title / alert_body", "str", "≤120 / ≤1200"],
      ["status", "str", "ok | llm_unavailable | schema_invalid"],
      ["runtime", "str", "local"],
    ],
  },
  {
    id: "stix",
    system: "sensor",
    label: "STIX 2.1",
    summary: "Local bundle always. TAXII share is a later human action.",
    image: "learnplay/ot-sensor:stix",
    port: "9209/tcp",
    proto: "HTTP",
    consumes: "Incident + CopilotAssessment",
    emits: "StixBundleRef",
    inFields: [
      ["incident_id", "str", "Exported unit"],
      ["alert_body", "str", "STIX note"],
    ],
    outFields: [
      ["path", "str", "reports/stix/{mode}/{hull}/{id}.json"],
      ["taxii_shared", "bool", "False until Share"],
    ],
  },
  {
    id: "ui",
    system: "sensor",
    label: "Operator UI",
    summary: "Incidents, evidence, NIS2 clocks, TAXII Share. Full packet list stays here.",
    image: "learnplay/ot-sensor:ui",
    port: "8443/tcp",
    proto: "HTTPS",
    consumes: "Incident, Evidence, CopilotAssessment, StixBundleRef",
    emits: "— (display + human confirm)",
    inFields: [
      ["alert_title", "str", "List row"],
      ["nis2", "Nis2UiAlert | None", "When significant"],
    ],
    outFields: [
      ["human_confirm", "bool", "TAXII / NIS2 / actuation"],
      ["share", "bool", "Off-ship"],
    ],
  },
  {
    id: "taxii",
    system: "sensor",
    label: "TAXII 2.1",
    summary: "Optional collection ot-incidents. Off until operator Share. Down in prod until confirmed.",
    image: "learnplay/ot-sensor:taxii",
    port: "8444/tcp",
    proto: "HTTPS TAXII",
    consumes: "StixBundleRef",
    emits: "TAXII collection",
    prodDown: true,
    inFields: [
      ["bundle", "STIX 2.1", "No payloads, no GT"],
      ["STIX_TAXII", "str", "off unless Share"],
    ],
    outFields: [["ot-incidents", "collection", "Off-ship"]],
  },
  {
    id: "eval",
    system: "sensor",
    label: "Eval join",
    summary: "dev only. Joins labels after emit. Never in the SLM prompt.",
    image: "learnplay/ot-sensor:eval",
    port: "9210/tcp",
    proto: "NATS",
    consumes: "LabelRecord + Incident",
    emits: "score record",
    hideInProd: true,
    inFields: [
      ["LABEL_TOPIC", "str", "nats://labels:4223"],
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
  { from: "scenario", to: "injector", via: "9101/tcp" },
  { from: "injector", to: "twins", via: "overlay" },
  { from: "injector", to: "labels", via: "4223/tcp" },
  { from: "twins", to: "gateways", via: "vcan_*" },
  { from: "gateways", to: "cms", via: "9180/tcp" },
];

const SENSOR_EDGES: Array<{ from: string; to: string; via: string }> = [
  { from: "n2k", to: "ingest", via: "otevent.>" },
  { from: "modbus", to: "ingest", via: "otevent.>" },
  { from: "n0183", to: "ingest", via: "otevent.>" },
  { from: "n2k", to: "honeypot", via: "raw" },
  { from: "modbus", to: "honeypot", via: "raw" },
  { from: "n0183", to: "honeypot", via: "raw" },
  { from: "ingest", to: "bytewax", via: "4222/tcp" },
  { from: "ingest", to: "assets", via: "4222/tcp" },
  { from: "ingest", to: "graph", via: "4222/tcp" },
  { from: "assets", to: "graph", via: "9202" },
  { from: "bytewax", to: "onnx", via: "features.>" },
  { from: "bytewax", to: "rules", via: "features.>" },
  { from: "onnx", to: "incidents", via: "9205" },
  { from: "rules", to: "incidents", via: "9206" },
  { from: "assets", to: "incidents", via: "9202" },
  { from: "graph", to: "incidents", via: "9203" },
  { from: "honeypot", to: "incidents", via: "pointer" },
  { from: "incidents", to: "slm", via: "127.0.0.1:9208" },
  { from: "incidents", to: "ui", via: "9207" },
  { from: "slm", to: "stix", via: "9208" },
  { from: "incidents", to: "stix", via: "9207" },
  { from: "stix", to: "taxii", via: "8444/tcp" },
  { from: "stix", to: "ui", via: "9209" },
  { from: "labels", to: "eval", via: "4223/tcp" },
  { from: "incidents", to: "eval", via: "9210/tcp" },
];

const LAB_EDGES: Array<{ from: string; to: string; via: string }> = [
  { from: "gateways", to: "n2k", via: "vcan_*" },
  { from: "labels", to: "eval", via: "4223/tcp" },
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
  images,
  ports,
  downIds,
}: {
  nodes: Array<{ id: string; label: string }>;
  edges: Array<{ from: string; to: string; via?: string }>;
  selectedId: string;
  onSelect: (id: string) => void;
  showMeta: boolean;
  images: Record<string, string>;
  ports: Record<string, string>;
  downIds: Set<string>;
}) {
  const theme = useHostTheme();
  const nodeWidth = showMeta ? 154 : 132;
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
        const down = downIds.has(n.id);
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
              border: `1px solid ${
                selected ? theme.accent.primary : theme.stroke.primary
              }`,
              borderRadius: 6,
              padding: "2px 6px",
              color: theme.text.primary,
              cursor: "pointer",
              appearance: "none",
              fontFamily: "inherit",
              opacity: down ? 0.55 : 1,
            }}
          >
            <span style={{ fontSize: 11, lineHeight: 1.2, textAlign: "center" }}>
              {labels[n.id]}
            </span>
            {showMeta ? (
              <>
                <span
                  style={{
                    fontSize: 9,
                    color: theme.text.secondary,
                    lineHeight: 1.2,
                  }}
                >
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
                  {images[n.id]}
                </span>
              </>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

function SchemaDetail({ svc, mode }: { svc: Service; mode: Mode }) {
  const down = mode === "prod" && svc.prodDown;
  return (
    <Stack gap={12}>
      <H3>
        {svc.label} — <Code>{svc.emits}</Code>
      </H3>
      <Text>{svc.summary}</Text>
      {down ? (
        <Callout tone="warning" title="prod — not listening">
          Process may exist but <Code>{svc.port}</Code> is not published until
          an operator confirms Share. Same confirmation path as actuation.
        </Callout>
      ) : null}
      <Grid columns={4} gap={12}>
        <Stat value={svc.port} label="Port" />
        <Stat value={svc.proto} label="Protocol" />
        <Stat value={svc.image} label="Image" />
        <Stat
          value={mode}
          label="Mode"
          tone={mode === "dev" ? "warning" : "success"}
        />
      </Grid>
      <Grid columns={2} gap={12}>
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

export default function OtLabSchema() {
  const [system, setSystem] = useCanvasState<SystemId>("system", "sensor");
  const [mode, setMode] = useCanvasState<Mode>("mode", "prod");
  const [view, setView] = useCanvasState<View>("view", "services");
  const [selected, setSelected] = useCanvasState<string>("svc", "ingest");

  const services = visibleServices(system, mode);
  const svc =
    services.find((s) => s.id === selected) ?? services[0] ?? SERVICES[0];
  const edges = visibleEdges(system, mode);
  const downIds = new Set(
    services.filter((s) => mode === "prod" && s.prodDown).map((s) => s.id),
  );
  const nodes = services.map((s) => ({ id: s.id, label: s.label }));
  const images = Object.fromEntries(services.map((s) => [s.id, s.image]));
  const ports = Object.fromEntries(services.map((s) => [s.id, s.port]));

  const netNodes = nodes;
  const netEdges =
    view === "network" && system === "sensor"
      ? [
          ...edges,
          ...LAB_EDGES.filter(
            (e) =>
              services.some((s) => s.id === e.to) &&
              (mode === "dev" || e.from !== "labels"),
          ).map((e) => ({ from: e.from, to: e.to, via: e.via })),
        ]
      : view === "network" && system === "sim"
        ? [
            ...edges,
            ...LAB_EDGES.filter((e) => services.some((s) => s.id === e.from)),
          ]
        : edges;

  const extraPeerNodes: Array<{ id: string; label: string }> = [];
  if (view === "network" && system === "sensor") {
    extraPeerNodes.push(
      { id: "gateways", label: "Sim gateways" },
    );
    if (mode === "dev") extraPeerNodes.push({ id: "labels", label: "Sim labels" });
  }
  if (view === "network" && system === "sim") {
    extraPeerNodes.push(
      { id: "n2k", label: "Sensor N2K" },
    );
  }

  const graphNodes = [
    ...netNodes,
    ...extraPeerNodes.filter((p) => !netNodes.some((n) => n.id === p.id)),
  ];
  const graphEdges = netEdges.filter(
    (e) =>
      graphNodes.some((n) => n.id === e.from) &&
      graphNodes.some((n) => n.id === e.to),
  );

  const peerImages: Record<string, string> = {
    gateways: "learnplay/opv-sim:gw",
    labels: "nats:2.10.22",
    n2k: "learnplay/ot-sensor:n2k",
  };
  const peerPorts: Record<string, string> = {
    gateways: "vcan_*",
    labels: "4223/tcp",
    n2k: "vcan_*",
  };

  const selectSystem = (next: SystemId) => {
    setSystem(next);
    setSelected(next === "sim" ? "scenario" : "ingest");
  };

  return (
    <Stack gap={16}>
      <Stack gap={6}>
        <H1>OT lab schema</H1>
        <Text tone="secondary">
          Click a box for input/output schemas, default ports, and image names.
          Simulator is NMEA 2000 only (<Code>vcan_*</Code> / in-memory CAN).
          Tests: <Code>pytest tests</Code>.
        </Text>
      </Stack>
      <Row gap={8} wrap align="center">
        <Text size="small" weight="semibold">
          System
        </Text>
        <Pill active={system === "sim"} onClick={() => selectSystem("sim")}>
          Simulator
        </Pill>
        <Pill
          active={system === "sensor"}
          onClick={() => selectSystem("sensor")}
        >
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
      </Row>
      <Grid columns={4} gap={12}>
        <Stat value={String(services.length)} label="Services" />
        <Stat
          value={mode === "dev" ? "Labels on" : "No GT"}
          label="Ground truth"
          tone={mode === "dev" ? "warning" : "success"}
        />
        <Stat
          value={system === "sim" ? "Lab only" : mode === "prod" ? "Ship" : "Lab TAP"}
          label="Where"
        />
        <Stat
          value={view === "network" ? "Ports + images" : "Click a box"}
          label="Diagram"
        />
      </Grid>
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
        images={{ ...peerImages, ...images }}
        ports={{ ...peerPorts, ...ports }}
        downIds={downIds}
      />
      {view === "network" ? (
        <Text size="small" tone="tertiary">
          Edge labels are bind ports or NATS subjects. Dimmed box = not
          published in this mode. Peer boxes (other system) are shown for wiring
          only — click a box on this system for schemas.
        </Text>
      ) : (
        <Text size="small" tone="tertiary">
          {system === "sim"
            ? "Simulator is never deployed on the vessel. prod here means unlabeled CAN for certifying a prod sensor."
            : "Adapters emit OTEvent only. Bytewax, ONNX, rules, incidents, SLM, and STIX do not import a protocol library."}
        </Text>
      )}
      {view === "network" ? (
        <>
          <H2>Docker networks</H2>
          <Table
            headers={["Network", "Members", "Ports"]}
            rows={
              system === "sim"
                ? [
                    ["ot-can", "twins, gateways, sensor n2k", "vcan_nav, vcan_prop, vcan_pwr, vcan_aux"],
                    ["ot-lab", "labels (dev)", "4223/tcp"],
                    ["ot-ctrl", "scenario, injector, cms", "9100, 9101, 9180/tcp"],
                  ]
                : [
                    ["ot-can", "n2k adapter (shared with sim)", "vcan_* or can0–3"],
                    ["ot-ot", "ingest, bytewax, onnx, rules, assets, graph, incidents, slm, stix, honeypot", "4222/tcp + 9201–9209"],
                    ["ot-ops", "ui", "8443/tcp"],
                    [
                      "ot-offship",
                      "taxii",
                      mode === "prod" ? "8444/tcp unpublished" : "8444/tcp lab",
                    ],
                  ]
            }
            striped
          />
          <Table
            headers={["Image", "Service", "Publish"]}
            rows={services.map((s) => [
              s.image,
              s.label,
              mode === "prod" && s.prodDown ? `${s.port} (down)` : s.port,
            ])}
            striped
          />
        </>
      ) : null}
      <Divider />
      <H2>Selected service</H2>
      <SchemaDetail svc={svc} mode={mode} />
    </Stack>
  );
}
