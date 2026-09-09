import {
  Button,
  Callout,
  Code,
  CollapsibleSection,
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

type View = "topology" | "devices" | "attacks" | "gps" | "network" | "workflows";
type Mode = "dev" | "prod";

const SIM_NODES = [
  { id: "scenario", label: "Scenario engine" },
  { id: "attack", label: "Attack injector" },
  { id: "twins", label: "Device twins" },
  { id: "nav", label: "Nav backbone" },
  { id: "prop", label: "Propulsion" },
  { id: "pwr", label: "Power" },
  { id: "aux", label: "Auxiliary" },
  { id: "gw", label: "Gateways" },
  { id: "vcan", label: "vcan TAP" },
  { id: "sensor", label: "OT sensor" },
];

const SIM_EDGES = [
  { from: "scenario", to: "twins" },
  { from: "attack", to: "twins" },
  { from: "twins", to: "nav" },
  { from: "twins", to: "prop" },
  { from: "twins", to: "pwr" },
  { from: "twins", to: "aux" },
  { from: "nav", to: "gw" },
  { from: "prop", to: "gw" },
  { from: "pwr", to: "gw" },
  { from: "aux", to: "gw" },
  { from: "gw", to: "vcan" },
  { from: "vcan", to: "sensor" },
];

type SimSchema = {
  className: string;
  summary: string;
  consumes: string;
  emits: string;
  fields: Array<[string, string, string]>;
};

const SIM_SCHEMAS: Record<string, SimSchema> = {
  scenario: {
    className: "PlantState",
    summary: "Underway kinematics. Drives twins. Lab only.",
    consumes: "scenario_id, SIM_MODE",
    emits: "PlantState",
    fields: [
      ["t", "datetime", "Scenario clock"],
      ["lat_deg / lon_deg / sog_kn / heading_deg", "float", "Nav plant"],
      ["phase", "str", "baseline | ramp | hold | recover"],
    ],
  },
  attack: {
    className: "AttackInjector",
    summary: "Overlays false PGNs. UI on :8444. Labels stay off-bus.",
    consumes: "POST /api/control",
    emits: "overlay + LabelRecord (dev)",
    fields: [
      ["attack", "str", "spoof | gyro | velocity | pgn_flood | …"],
      ["enabled", "bool", "Arm or clear"],
      ["attack_id", "str | None", "gps-spoof-primary when spoof is on"],
    ],
  },
  twins: {
    className: "CanFrame",
    summary: "ISO 11783 NAME + SA publishers on four trunks.",
    consumes: "PlantState + overlay",
    emits: "CanFrame",
    fields: [
      ["segment", "str", "nav | propulsion | power | aux"],
      ["can_id", "int", "29-bit"],
      ["data_hex", "str", "PGN payload"],
      ["sa", "int", "Source address"],
    ],
  },
  nav: {
    className: "CanFrame",
    summary: "Nav backbone twins: GNSS-1/2, gyro, AIS, AP, MFD, decoy SA 99.",
    consumes: "PlantState",
    emits: "PGN 129025/026/029/539, 127250, …",
    fields: [
      ["iface", "str", "vcan_nav (in-memory in this tree)"],
      ["pgn", "int", "Published PGN"],
    ],
  },
  prop: {
    className: "CanFrame",
    summary: "Twin diesels, gearbox, fuel, thruster.",
    consumes: "PlantState",
    emits: "PGN 127488/127489/127493",
    fields: [
      ["iface", "str", "vcan_prop"],
      ["sa", "int", "0 / 1 engines"],
    ],
  },
  pwr: {
    className: "CanFrame",
    summary: "Gensets, batteries, switchbank.",
    consumes: "PlantState",
    emits: "PGN 127508 / 127501",
    fields: [["iface", "str", "vcan_pwr"]],
  },
  aux: {
    className: "CanFrame",
    summary: "Tanks, environment, bilge / fire binaries.",
    consumes: "PlantState",
    emits: "PGN 130310 / 127505 / 127501",
    fields: [["iface", "str", "vcan_aux"]],
  },
  gw: {
    className: "IsolatingGateway",
    summary: "Allowlisted cross-segment forward. Engine commands never onto nav.",
    consumes: "CanFrame",
    emits: "CanFrame (allowlist)",
    fields: [
      ["path", "str", "nav → propulsion heading / COG/SOG"],
      ["dropped", "bool", "Architecture violation if forced"],
    ],
  },
  vcan: {
    className: "TapSnapshot",
    summary: "GET /api/tap. In-memory CAN in CI. SocketCAN vcan_* is spec-only here.",
    consumes: "SimRuntime.tick",
    emits: "frames[] + plant + attacks",
    fields: [
      ["frames", "list[CanFrame]", "Last hop"],
      ["plant", "PlantState", "Injector UI kinematics"],
      ["attacks", "dict", "Armed overlays"],
    ],
  },
  sensor: {
    className: "TapMirror",
    summary: "OT sensor TAP client. GET only. Never POSTs /api/control.",
    consumes: "GET /api/tap",
    emits: "CanFrame into Nmea2000Adapter",
    fields: [
      ["base_url", "str", "http://127.0.0.1:8444"],
      ["poll_s", "float", "0.8"],
    ],
  },
  labels: {
    className: "LabelRecord",
    summary: "dev-only. Never on CAN. Sensor eval join after emit.",
    consumes: "injector",
    emits: "LabelRecord",
    fields: [
      ["attack_id", "str", "gps-spoof-primary"],
      ["technique", "str", "T1692.002"],
      ["victim_sa / pgn / segment", "…", "Eval join key"],
    ],
  },
};

function SchemaPanel({ nodeId, label }: { nodeId: string; label: string }) {
  const schema = SIM_SCHEMAS[nodeId] ?? SIM_SCHEMAS.twins;
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
      <Table headers={["Field", "Type", "Role"]} rows={schema.fields} striped />
    </Stack>
  );
}

const DEV_LABEL_NODE = { id: "labels", label: "GT labels (dev)" };
const DEV_LABEL_EDGE = { from: "labels", to: "sensor" };

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
  const nodeWidth = 132;
  const nodeHeight = 40;
  const layout = computeDAGLayout({
    nodes: nodes.map((n) => ({ id: n.id })),
    edges,
    direction,
    nodeWidth,
    nodeHeight,
    rankGap: 44,
    nodeGap: 16,
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
                selected || accentIds.has(n.id) ? theme.accent.primary : theme.stroke.primary
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

function TopologyView({ mode }: { mode: Mode }) {
  const isDev = mode === "dev";
  return (
    <Stack gap={16}>
      <H2>Four isolated backbones</H2>
      <Text>
        Representative OPV / corvette marine OT — not a named hull. Each
        backbone is a Mini trunk, 120 Ω terminated, single power feed, ≤50
        nodes. Combat management, weapons, and Link-16 stay off N2K. A CMS stub
        may consume a read-only nav export only.
      </Text>
      <Table
        headers={["Segment", "Role", "Isolation intent"]}
        rows={[
          ["nav", "Bridge navigation and conning", "Integrity of position, heading, AIS"],
          ["propulsion", "Twin diesel, gearbox, fuel, thruster", "Machinery OT; no CMS nodes"],
          ["power", "Gensets, batteries, switchbank", "Electrical OT"],
          ["aux", "Tanks, environment, bilge / fire", "Hotel and damage-control adjacent"],
        ]}
        striped
      />
      <H3>Gateway allowlists</H3>
      <Table
        headers={["Path", "Policy"]}
        rows={[
          ["nav → propulsion", "Heading, COG/SOG, time for machinery displays"],
          ["nav → CMS stub", "Position, COG/SOG, heading (read-only)"],
          ["propulsion → nav", "Deny by default — no RPM or engine commands on the bridge"],
          ["power → aux", "Selected battery / genset status if hotel displays need it"],
          ["Any command PGN", "Deny unless explicitly listed"],
        ]}
        rowTone={[undefined, undefined, "danger", undefined, "warning"]}
        striped
      />
      <Grid columns={2} gap={12}>
        <Card>
          <CardHeader>vcan TAP contract</CardHeader>
          <CardBody>
            <Text size="small">
              One SocketCAN iface per segment: <Code>vcan_nav</Code>,{" "}
              <Code>vcan_prop</Code>, <Code>vcan_pwr</Code>,{" "}
              <Code>vcan_aux</Code>. Optional pcap writer and in-process CAN
              for CI. Frames are production-shaped — no simulator headers on
              the bus.
            </Text>
          </CardBody>
        </Card>
        <Card>
          <CardHeader trailing={<Pill size="sm">{isDev ? "dev" : "prod"}</Pill>}>
            Label topic
          </CardHeader>
          <CardBody>
            {isDev ? (
              <Text size="small">
                Parallel stream{" "}
                <Code>
                  {"{ t, attack_id, technique, victim_sa, pgn, segment, scenario_id }"}
                </Code>
                . Never on CAN. Used for training and post-hoc co-pilot scoring
                — not the LLM prompt.
              </Text>
            ) : (
              <Text size="small">
                Channel does not exist. No publisher, no empty topic, no “no
                attack” heartbeat. <Code>LABEL_TOPIC</Code> set under{" "}
                <Code>SIM_MODE=prod</Code> is a fatal error before any CAN iface
                opens.
              </Text>
            )}
          </CardBody>
        </Card>
      </Grid>
    </Stack>
  );
}

function DevicesView() {
  return (
    <Stack gap={12}>
      <H2>Device twins and PGNs</H2>
      <Text>
        Each twin has a stable source address and ISO 11783 NAME. Periodic
        publish includes jitter. Large GNSS and AIS use Fast Packet. Address
        ranges are lab defaults; the shared vessel model file is source of
        truth for the sensor join.
      </Text>
      <CollapsibleSection title="Navigation" count={9} defaultOpen>
        <Table
          headers={["Twin", "SA", "PGNs"]}
          rows={[
            ["GNSS-1 primary", "16", "129025, 129026, 129029, 129539, 126992"],
            ["GNSS-2 secondary", "17", "Same as GNSS-1, independent residual"],
            ["Gyro / heading", "35", "127250 heading, 127251 ROT, 127257 attitude"],
            ["AIS transponder", "24", "129038 Class A position, 129794 static"],
            ["Echo sounder", "40", "128267 depth, 128259 STW"],
            ["Wind", "48", "130306"],
            ["Rudder", "52", "127245"],
            ["Autopilot / MFD", "56 / 60", "127237 heading/track; MFD is consumer"],
            ["Honeypot decoy", "99", "Address-claim + NAME only; collector logs traffic to this SA"],
          ]}
          striped
        />
      </CollapsibleSection>
      <CollapsibleSection title="Propulsion" count={5}>
        <Table
          headers={["Twin", "SA", "PGNs"]}
          rows={[
            ["Engine port", "0", "127488 rapid, 127489 dynamic"],
            ["Engine stbd", "1", "127488, 127489"],
            ["Transmission port / stbd", "4 / 5", "127493"],
            ["Fuel / fluid", "8", "127505"],
            ["Bow thruster", "12", "Thruster / binary mapped in catalog"],
          ]}
          striped
        />
      </CollapsibleSection>
      <CollapsibleSection title="Power" count={3}>
        <Table
          headers={["Twin", "SA", "PGNs"]}
          rows={[
            ["Genset 1 / 2", "20 / 21", "Generator / converter status"],
            ["Battery bank", "28", "127508"],
            ["Switchbank", "32", "127501 binary status"],
          ]}
          striped
        />
      </CollapsibleSection>
      <CollapsibleSection title="Auxiliary" count={3}>
        <Table
          headers={["Twin", "SA", "PGNs"]}
          rows={[
            ["Environment", "80", "130310 / 130311"],
            ["Tanks (non-fuel)", "84", "127505"],
            ["Bilge / fire binaries", "88", "127501"],
          ]}
          striped
        />
      </CollapsibleSection>
      <H3>Scenarios</H3>
      <Table
        headers={["Scenario", "Kind", "Twin behavior"]}
        rows={[
          ["Underway", "Benign", "Dual GNSS, gyro, engines loaded, AIS transmitting"],
          ["Alongside", "Benign", "Near-zero SOG, hotel/genset bias, thruster available"],
          ["RAS approach", "Benign", "Tight heading / ROT coupling, GNSS valid"],
          ["Darken-ship", "Benign", "Reduced display traffic; plant still publishing"],
          ["GNSS-degraded", "Benign fault", "DOP collapse; DR still consistent — not a spoof"],
          ["gps-spoof-underway", "Attack overlay", "Underway + phased GPS spoof on nav"],
        ]}
        rowTone={[undefined, undefined, undefined, undefined, "info", "warning"]}
        striped
      />
    </Stack>
  );
}

function GpsSpoofView({ mode }: { mode: Mode }) {
  const isDev = mode === "dev";
  return (
    <Stack gap={16}>
      <H2>GPS spoofing — gps-spoof-underway</H2>
      <Text>
        Attack overlay on Underway. The injector never touches RF; GNSS twins
        (or a colliding SA) publish a false track on <Code>vcan_nav</Code>. The
        lie is meant to look like a healthy GPS fix that walks off
        dead-reckoning, not like <Code>GNSS-degraded</Code>.
      </Text>
      <Grid columns={4} gap={12}>
        <Stat value="30 s" label="baseline" />
        <Stat value="60 s" label="ramp (pull-off)" tone="warning" />
        <Stat value="90 s" label="hold" tone="danger" />
        <Stat value="20 s" label="recover" />
      </Grid>
      <H3>Timeline</H3>
      <Table
        headers={["Phase", "Duration", "Bus behavior"]}
        rows={[
          ["baseline", "30 s", "Both GNSS agree with gyro + SOG integration; DOPs healthy"],
          [
            "ramp",
            "60 s",
            "Track starts at truth and pulls off; satellite count and 129539 stay good",
          ],
          [
            "hold",
            "90 s",
            "Offset lat/lon and COG held; heading, ROT, RPM, depth stay true",
          ],
          [
            "recover",
            "20 s",
            "Spoof stops; GNSS-1 returns to kinematic truth",
          ],
        ]}
        rowTone={["success", "warning", "danger", "info"]}
        striped
      />
      <H3>Variants</H3>
      <Table
        headers={["attack_id", "Spoofed talker", "Why"]}
        rows={[
          ["gps-spoof-primary", "GNSS-1 SA 16 only", "Dual-receiver split; GNSS-2 stays true (default)"],
          ["gps-spoof-both", "GNSS-1 and GNSS-2", "Correlated spoof of both receivers"],
          ["gps-spoof-sa-collision", "Rogue claims SA 16", "Bus injection; may also present as T0848"],
        ]}
        rowTone={["warning", "danger", "danger"]}
        striped
      />
      <Text size="small" tone="secondary">
        AIS own-ship 129038 follows GNSS-1, matching a typical OPV transponder
        slaved to the primary fix.
      </Text>
      <H3>PGNs mutated vs left true</H3>
      <Table
        headers={["PGN", "Twin", "During spoof"]}
        rows={[
          ["129025 Position Rapid", "GNSS-1 (+ GNSS-2 if both)", "False lat/lon"],
          ["129026 COG/SOG", "same", "False COG; SOG near plant-consistent"],
          ["129029 GNSS Position Data", "same", "False position; fix still marked valid"],
          ["129539 GNSS DOPs", "same", "Stay low (healthy) — opposite of GNSS-degraded"],
          ["126992 System time", "GNSS", "Unchanged"],
          ["127250 / 127251", "Gyro", "True"],
          ["127488", "Engines", "True"],
          ["128267", "Echo sounder", "True"],
          ["129038 AIS Class A", "AIS", "Follows GNSS-1"],
        ]}
        rowTone={[
          "warning",
          "warning",
          "warning",
          "warning",
          undefined,
          "success",
          "success",
          "success",
          "warning",
        ]}
        striped
      />
      <H3>Spoof vs GNSS-degraded</H3>
      <Table
        headers={["Signal", "GPS spoof", "GNSS-degraded (benign)"]}
        rows={[
          ["129539 DOP", "Healthy", "High / invalid"],
          ["Satellite count", "Stable, high", "Drops"],
          ["Position vs DR", "Walks off", "Noisy but on-track"],
          ["GNSS-1 vs GNSS-2 (primary)", "Diverges", "Both degrade together"],
          ["fault_likelihood target", "Low", "High"],
        ]}
        striped
      />
      {isDev ? (
        <Callout tone="warning" title="dev labels">
          One label per mutated PGN during ramp and hold:{" "}
          <Code>
            scenario_id=gps-spoof-underway, technique=T1692.002, segment=nav
          </Code>
          . Baseline and recover are unlabeled so training learns the edges.
        </Callout>
      ) : (
        <Callout tone="success" title="prod — same CAN, no labels">
          The overlay still mutates PGNs for a blind test. The label topic does
          not exist.
        </Callout>
      )}
      <Callout tone="info" title="Expected co-pilot">
        Rule gps-spoof-nav fires on the same event_id as the ONNX scores.
        Correlation folds both into one incident before the LLM. Techniques:
        T1692.002 (reporting),
        impacts T0832 Manipulation of View and T0829 Loss of View. Recommend:
        distrust GNSS-1 and AIS derived from it, prefer gyro + DR / GNSS-2, do
        not let autopilot follow spoofed COG. No actuation.
      </Callout>
    </Stack>
  );
}

function AttacksView({ mode }: { mode: Mode }) {
  const isDev = mode === "dev";
  return (
    <Stack gap={16}>
      <H2>Attack injector</H2>
      <Text>
        Injections change CAN contents only. Ground-truth tags go on the label
        stream, never inside the payload. In <Code>prod</Code> the injector may
        still write attack PGNs for a blind test of a <Code>prod</Code> sensor;
        the label publisher is off.
      </Text>
      <Table
        headers={["Attack", "Segment", "ATT&CK", "Mechanism"]}
        rows={[
          [
            "GPS spoof (gps-spoof-underway)",
            "nav",
            <Link href="https://attack.mitre.org/techniques/T1692/002/">
              T1692.002
            </Link>,
            "Phased false 129025/129026/129029; DOPs stay healthy",
          ],
          [
            "AIS spoof",
            "nav",
            <Link href="https://attack.mitre.org/techniques/T1692/002/">
              T1692.002
            </Link>,
            "False 129038 / static PGNs",
          ],
          [
            "Heading spoof",
            "nav",
            <Link href="https://attack.mitre.org/techniques/T1692/002/">
              T1692.002
            </Link>,
            "False 127250 / 127251",
          ],
          [
            "Autopilot command",
            "nav",
            <Link href="https://attack.mitre.org/techniques/T1692/001/">
              T1692.001
            </Link>,
            "127237 from a non-autopilot SA",
          ],
          [
            "Engine command",
            "propulsion",
            <Link href="https://attack.mitre.org/techniques/T1692/001/">
              T1692.001
            </Link>,
            "Control PGN toward engine or thruster",
          ],
          [
            "Rogue Master",
            "any",
            <Link href="https://attack.mitre.org/techniques/T0848/">T0848</Link>,
            "Address claim / NAME spoof, SA theft",
          ],
          [
            "PGN flood",
            "any",
            <Link href="https://attack.mitre.org/techniques/T0814/">T0814</Link>,
            "High-rate flood; throughput-lstm sample fires on this pattern",
          ],
          [
            "Gateway bypass",
            "cross-segment",
            <Link href="https://attack.mitre.org/techniques/T1692/">T1692</Link>,
            "Command or engine PGN on nav; leak outside allowlist",
          ],
        ]}
        rowTone={[
          "warning",
          "warning",
          "warning",
          "danger",
          "danger",
          "danger",
          "warning",
          "danger",
        ]}
        striped
      />
      <Callout tone="info" title="RF GPS is not simulated at RF">
        Overlays reproduce the on-bus consequence so the sensor path is
        exercised. Use the GPS spoof view for phases, variants, and the
        contrast with GNSS-degraded.
      </Callout>
      {isDev ? (
        <Callout tone="warning" title="dev — labels published">
          Each injection is recorded on the parallel label topic for ONNX
          training and co-pilot scoring after inference.
        </Callout>
      ) : (
        <Callout tone="success" title="prod — no ground truth">
          Unlabeled / ship-shaped CAN only. Pair with a <Code>prod</Code> sensor
          to certify detection without labels. The simulator still never runs on
          the vessel.
        </Callout>
      )}
      <Callout tone="danger" title="Safety">
        Simulator processes must not open a physical CAN interface cabled to a
        vessel backbone. TAP is one-way into the sensor.{" "}
        <Code>SIM_MODE=prod</Code> with <Code>LABEL_TOPIC</Code> set must exit
        before opening CAN.
      </Callout>
    </Stack>
  );
}

function SimNetworkView() {
  return (
    <Stack gap={12}>
      <H2>Host network</H2>
      <Table
        headers={["Listener", "Process", "Clients"]}
        rows={[
          ["127.0.0.1:8444 /", "opv-sim --serve", "Operator browser (injector)"],
          ["127.0.0.1:8444 /api/tap", "SimRuntime", "ot-dashboard TAP client, GET only"],
          ["127.0.0.1:8444 /api/control", "SimRuntime", "Arm / reset overlays"],
          ["127.0.0.1:8444 /api/health", "SimRuntime", "mode + attack_id"],
          ["in-memory CAN", "DeviceTwins + gateways", "No SocketCAN in this tree"],
        ]}
        striped
      />
      <Callout tone="danger" title="Sensor does not control the injector">
        The watchstander on :8443 polls TAP. It must not POST /api/control.
      </Callout>
    </Stack>
  );
}

function SimWorkflowsView() {
  return (
    <Stack gap={12}>
      <H2>Active workflows</H2>
      <Table
        headers={["Workflow", "Status", "Path"]}
        rows={[
          ["Serve TAP + plant", "active", "uv run opv-sim --serve → tick 0.8 s → GET /api/tap"],
          ["Injector UI", "active", "browser :8444 → POST /api/control"],
          ["GPS spoof overlay", "active", "spoof → GNSS-1 129025/026/029 walk-off, DOPs healthy"],
          ["Heading / SOG / PGN flood", "active", "gyro, velocity, pgn_flood toggles"],
          ["Gateway allowlist", "active", "nav→prop heading/COG; RPM onto nav denied"],
          ["Dev labels", "active", "in-memory LabelTopic; prod LABEL_TOPIC fatal"],
          ["Linux vcan_* TAP", "spec", "Ship-shaped SocketCAN; CI uses InMemoryCanBus"],
        ]}
        rowTone={["success", "success", "success", "success", "success", "warning", "info"]}
        striped
      />
    </Stack>
  );
}

export default function Nmea2000OpvSimulatorArchitecture() {
  const [view, setView] = useCanvasState<View>("view", "topology");
  const [mode, setMode] = useCanvasState<Mode>("mode", "prod");
  const [selectedService, setSelectedService] = useCanvasState("selectedService", "twins");
  const dispatch = useCanvasAction();
  const isDev = mode === "dev";
  const nodes = isDev ? [...SIM_NODES, DEV_LABEL_NODE] : SIM_NODES;
  const edges = isDev ? [...SIM_EDGES, DEV_LABEL_EDGE] : SIM_EDGES;

  return (
    <Stack gap={20}>
      <Stack gap={8}>
        <H1>OPV NMEA 2000 simulator</H1>
        <Text tone="secondary">
          Lab IEC 61162-3 traffic for an offshore patrol vessel / corvette.
          <Code>dev</Code> publishes a parallel ground-truth topic;{" "}
          <Code>prod</Code> is unlabeled CAN for certifying a prod sensor. Neither
          mode is installed on the vessel.
        </Text>
      </Stack>
      <Grid columns={4} gap={12}>
        <Stat value="4" label="N2K segments" />
        <Stat
          value={isDev ? "dev" : "prod"}
          label="SIM_MODE"
          tone={isDev ? "warning" : "success"}
        />
        <Stat
          value={isDev ? "Published" : "Absent"}
          label="Ground truth"
          tone={isDev ? "warning" : "success"}
        />
        <Stat value="Lab only" label="Deploy target" tone="info" />
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
        <Pill active={view === "topology"} onClick={() => setView("topology")}>
          Topology
        </Pill>
        <Pill active={view === "devices"} onClick={() => setView("devices")}>
          Devices
        </Pill>
        <Pill active={view === "attacks"} onClick={() => setView("attacks")}>
          Attacks
        </Pill>
        <Pill active={view === "gps"} onClick={() => setView("gps")}>
          GPS spoof
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
              path: "docs/architecture/nmea2000-opv-simulator.md",
            })
          }
        >
          Open spec
        </Button>
      </Row>
      <Divider />
      <H2>Lab dataflow ({mode})</H2>
      <FlowChart
        nodes={nodes}
        edges={edges}
        direction="vertical"
        accentIds={new Set(isDev ? ["twins", "gw", "sensor", "labels"] : ["twins", "gw", "sensor"])}
        selectedId={selectedService}
        onSelect={setSelectedService}
      />
      <Text size="small" tone="tertiary">
        Click a service for its input/output schema. Accent-bordered nodes are
        twins, gateways, and the OT sensor TAP sink
        {isDev ? ", plus the dev-only label topic" : ""}. Ground truth is never
        in-band CAN.
      </Text>
      <Divider />
      <H2>Data schema</H2>
      <SchemaPanel
        nodeId={selectedService}
        label={SIM_NODES.concat(DEV_LABEL_NODE).find((n) => n.id === selectedService)?.label ?? selectedService}
      />
      <Table
        headers={["Channel", "dev + sensor dev", "prod + sensor prod", "Ship"]}
        rows={[
          ["CAN + segment", "vcan_*", "vcan_*", "Hardware TAP"],
          ["Label topic", "Present", "Absent", "Absent"],
          ["GT in LLM / SIEM", "No (eval join only)", "No", "No"],
        ]}
        rowTone={[undefined, isDev ? "warning" : "success", "success"]}
        striped
      />
      <Divider />
      {view === "topology" ? <TopologyView mode={mode} /> : null}
      {view === "devices" ? <DevicesView /> : null}
      {view === "attacks" ? <AttacksView mode={mode} /> : null}
      {view === "gps" ? <GpsSpoofView mode={mode} /> : null}
      {view === "network" ? <SimNetworkView /> : null}
      {view === "workflows" ? <SimWorkflowsView /> : null}
    </Stack>
  );
}
