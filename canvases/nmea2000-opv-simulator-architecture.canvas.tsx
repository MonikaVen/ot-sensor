import {
  Button,
  Callout,
  Card,
  CardBody,
  CardHeader,
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

type View = "topology" | "devices" | "attacks" | "gps";
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

const DEV_LABEL_NODE = { id: "labels", label: "GT labels (dev)" };
const DEV_LABEL_EDGE = { from: "labels", to: "sensor" };

function FlowChart({
  nodes,
  edges,
  direction,
  accentIds,
}: {
  nodes: Array<{ id: string; label: string }>;
  edges: Array<{ from: string; to: string }>;
  direction: "vertical" | "horizontal";
  accentIds: Set<string>;
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
      {layout.nodes.map((n) => (
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
            border: `1px solid ${accentIds.has(n.id) ? theme.accent.primary : theme.stroke.primary}`,
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
      ))}
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

export default function Nmea2000OpvSimulatorArchitecture() {
  const [view, setView] = useCanvasState<View>("view", "topology");
  const [mode, setMode] = useCanvasState<Mode>("mode", "prod");
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
      />
      <Text size="small" tone="tertiary">
        Accent-bordered nodes are device twins, isolating gateways, and the OT
        sensor TAP sink
        {isDev ? ", plus the dev-only label topic" : ""}. Ground truth is never
        in-band CAN.
      </Text>
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
    </Stack>
  );
}
