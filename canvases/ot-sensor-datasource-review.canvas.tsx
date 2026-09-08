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
  UsageBar,
  computeDAGLayout,
  useCanvasState,
  useHostTheme,
} from "cursor/canvas";

type View = "sources" | "gaps" | "trust";

const FLOW_NODES = [
  { id: "n2k", label: "N2K TAP" },
  { id: "mb", label: "Modbus" },
  { id: "n0183", label: "NMEA 0183" },
  { id: "labels", label: "Label topic" },
  { id: "local", label: "Vendored files" },
  { id: "time", label: "Trusted time" },
  { id: "charts", label: "ENC / charts" },
  { id: "sensor", label: "OT sensor" },
  { id: "ops", label: "Operator UI" },
  { id: "llm", label: "Local SLM" },
  { id: "taxii", label: "TAXII share" },
  { id: "csirt", label: "NIS2 CSIRT" },
  { id: "updates", label: "Artifact updates" },
];

const FLOW_EDGES = [
  { from: "n2k", to: "sensor" },
  { from: "mb", to: "sensor" },
  { from: "n0183", to: "sensor" },
  { from: "labels", to: "sensor" },
  { from: "local", to: "sensor" },
  { from: "time", to: "sensor" },
  { from: "charts", to: "sensor" },
  { from: "updates", to: "local" },
  { from: "sensor", to: "ops" },
  { from: "sensor", to: "llm" },
  { from: "sensor", to: "taxii" },
  { from: "sensor", to: "csirt" },
];

const UNSPECIFIED = new Set(["time", "charts", "updates"]);
const OPTIONAL = new Set(["mb", "n0183", "labels", "taxii", "csirt"]);

function Flow({
  nodes,
  edges,
}: {
  nodes: Array<{ id: string; label: string }>;
  edges: Array<{ from: string; to: string }>;
}) {
  const theme = useHostTheme();
  const nodeWidth = 118;
  const nodeHeight = 36;
  const layout = computeDAGLayout({
    nodes: nodes.map((n) => ({ id: n.id })),
    edges,
    direction: "horizontal",
    nodeWidth,
    nodeHeight,
    rankGap: 36,
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
            stroke={
              UNSPECIFIED.has(e.from) || UNSPECIFIED.has(e.to)
                ? theme.accent.primary
                : theme.stroke.secondary
            }
            strokeWidth={1}
            strokeDasharray={
              UNSPECIFIED.has(e.from) || UNSPECIFIED.has(e.to) ? "4 3" : undefined
            }
          />
        ))}
      </svg>
      {layout.nodes.map((n) => {
        const unspecified = UNSPECIFIED.has(n.id);
        const optional = OPTIONAL.has(n.id);
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
              border: `1px solid ${
                unspecified
                  ? theme.accent.primary
                  : n.id === "sensor"
                    ? theme.accent.primary
                    : theme.stroke.primary
              }`,
              borderRadius: 6,
              padding: "0 6px",
              fontSize: 11,
              color: theme.text.primary,
              textAlign: "center",
              lineHeight: 1.2,
              fontFamily: "inherit",
              opacity: optional && !unspecified ? 0.85 : 1,
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
      <H2>Every datasource the spec actually names</H2>
      <Text>
        Detection (Bytewax, ONNX, rules, correlator, asset/dependency graph) is
        designed to run from the TAP plus files on disk. Narrative, intel
        refresh, and statutory reporting are the only stages that reach off-ship
        — and those sinks are either optional or unspecified.
      </Text>
      <UsageBar
        total={100}
        topLeftLabel="What has to work with the satcom down"
        topRightLabel="Local 82 · Off-ship 18"
        segments={[
          { id: "tap", value: 28, color: "blue" },
          { id: "files", value: 22, color: "green" },
          { id: "models", value: 20, color: "purple" },
          { id: "slm", value: 12, color: "orange" },
          { id: "share", value: 18, color: "yellow" },
        ]}
      />
      <H3>Wire ingest (listen-only)</H3>
      <Table
        headers={["Source", "Where", "Required", "Notes"]}
        rows={[
          [
            "NMEA 2000 TAP ×4",
            "Ship / lab SocketCAN or pcap",
            "Primary",
            "IEC 61162-3. Never TX. Segment-tagged nav / propulsion / power / aux.",
          ],
          [
            "Modbus TCP poll or TAP",
            "sources.yaml, default off",
            "Optional",
            "Read-only in prod (FC 01–04). Same OTEvent contract.",
          ],
          [
            "NMEA 0183 UDP/serial",
            "Example adapter",
            "Optional",
            "Shows a third protocol can join without pipeline changes.",
          ],
          [
            "Simulator vcan / Modbus slave",
            "Lab only",
            "dev peer",
            "Not deployed on the vessel. Sensor must not import simulator internals.",
          ],
          [
            "Label topic",
            "Parallel to CAN",
            "dev only",
            "Eval/training join by event_id. Fatal if bound in prod.",
          ],
        ]}
        rowTone={["success", "info", "info", "neutral", "warning"]}
        striped
      />
      <H3>Vendored on the sensor host (no network)</H3>
      <Table
        headers={["Source", "Path / form", "Used by", "Gap"]}
        rows={[
          [
            "PGN catalog",
            "catalogs/pgn-2026.03.json (referenced, not in repo)",
            "N2K adapter, LLM semantics",
            "License and update story missing. Canboat-style, version-pinned.",
          ],
          [
            "Field maps",
            "canonical-fields.yaml, nmea0183-nav.yaml, modbus maps",
            "Adapters",
            "Specified.",
          ],
          [
            "Vessel model",
            "Static four-segment OPV topology",
            "Asset detector, comms graph, Bytewax join",
            "No CMMS / class-society sync.",
          ],
          [
            "Asset criticality + depends_on",
            "asset-criticality.yaml",
            "Risk score, NIS2 significant, blast radius",
            "Static YAML. No owner or review cycle.",
          ],
          [
            "ONNX registry",
            "models/<id>/<semver>/",
            "Enrich branch",
            "How signed weights reach the ship is unspecified.",
          ],
          [
            "Rule packs",
            "rules/<id>/<semver>/rule.yaml",
            "Parallel enrich",
            "Same update-channel gap as models.",
          ],
          [
            "watchstander-slm",
            "models/watchstander-slm/<semver>/ (GGUF not in git)",
            "Alert title/body after incidents",
            "Local llama.cpp. prod denies LLM_ENDPOINT. Signed-update channel still shared with ONNX.",
          ],
          [
            "ATT&CK for ICS",
            "Vendored STIX JSON or inbound TAXII",
            "Co-pilot retrieval, STIX export",
            "Prod should pin vendored; live MITRE TAXII is optional.",
          ],
        ]}
        striped
      />
      <H3>Off-ship (optional or unspecified)</H3>
      <Table
        headers={["Source / sink", "Direction", "Human gate", "Specified?"]}
        rows={[
          [
            "ATT&CK TAXII (inbound)",
            "Inbound catalog refresh",
            "No",
            "Optional. Alert generation uses vendored JSON.",
          ],
          [
            "STIX TAXII 2.1 ot-incidents",
            "Outbound intel",
            "Yes — Share",
            "Default off. Redact hull. No labels.",
          ],
          [
            "NIS2 CSIRT / competent authority",
            "Outbound Article 23",
            "Yes — human_confirm",
            "UI clocks specified. Recipient, form, and channel are not.",
          ],
          [
            "Trusted time (NTP/PTP/GNSS clock)",
            "Inbound",
            "—",
            "Dual clocks mentioned; source and anti-spoof not designed.",
          ],
          [
            "ENC / chart / tide",
            "Inbound",
            "—",
            "Depth residual cites “chart/nav context” with no feed.",
          ],
        ]}
        rowTone={["info", "success", "warning", "danger", "warning"]}
        striped
      />
      <Callout tone="info" title="Explicit non-goals (not missing)">
        Combat management, weapons, Link-16, radar video, EO/IR, and RF GNSS /
        AIS VHF stay off these buses. GPS spoof is detected from the on-bus
        consequence (PGNs), not from RF. The sensor must not auto-file to a
        CSIRT or auto-share TAXII.
      </Callout>
    </Stack>
  );
}

function GapsView() {
  return (
    <Stack gap={16}>
      <H2>What is actually missing</H2>
      <Text>
        Ranked for a shipboard <Code>prod</Code> install. Detection and
        watchstander alert text now run from TAP plus files on disk. Statutory
        clocks, catalog license, and long-term operations still need decisions.
      </Text>
      <H3>Must specify before prod</H3>
      <Table
        headers={["Gap", "Why it bites", "Minimum decision"]}
        rows={[
          [
            "Trusted time",
            "NIS2 24 h / 72 h / 1-month clocks start at t_aware. N2K PGN 126992 is attacker-writable (simulator even notes time-spoof as a separate overlay).",
            "Independent clock (NTP/PTP or holdover) plus treat bus time vs host time as a residual — never as the sole NIS2 clock.",
          ],
          [
            "PGN catalog provenance",
            "Decode, model pins, and LLM semantics depend on catalogs/pgn-2026.03.json, which is not in the samples tree. NMEA databases are licensed.",
            "Vendor or canboat pin, license, catalog_ver bump process.",
          ],
          [
            "Signed artifact channel",
            "Models, rules, SLM GGUF, maps, criticality, ATT&CK JSON, and the catalog will change after sail.",
            "Who signs, how a USB / satcom bundle is verified, rollback on failed load (already fail-closed per model).",
          ],
          [
            "Operator identity + audit",
            "TAXII Share, NIS2 submit, and any actuation share one “human confirm” sentence with no actor, role, or append-only audit.",
            "Local accounts or ship directory; every confirm writes who / when / what; prod has no GT widgets.",
          ],
          [
            "Evidence retention",
            "Final NIS2 report is due one month after notification. Honeypot retain.max_age_s is 30 d; open-incident files are held. Pointers survive purge as purged+sha256.",
            "Retain closed logs + evidence_ref for the statutory window; encrypt at rest; no GT in prod files.",
          ],
          [
            "TAP / sensor health",
            "Silent TAP looks like a quiet bus. critical_missing then fires on every asset.",
            "Interface up, frame heartbeat, TAP power, and source_unavailable already exist — bind them to a sensor-health incident distinct from OT.",
          ],
        ]}
        rowTone={[
          "danger",
          "warning",
          "warning",
          "warning",
          "warning",
          "warning",
        ]}
        striped
      />
      <H3>Should specify (detection quality / ops)</H3>
      <Table
        headers={["Gap", "Why"]}
        rows={[
          [
            "NIS2 recipient + form",
            "Article 23 needs national/sector CSIRT, early-warning fields, and a form. STIX is supporting intel, not the filing.",
          ],
          [
            "SIEM / syslog export",
            "Simulator table mentions SIEM; the sensor has no CEF/syslog/ECS sink besides STIX and the operator UI.",
          ],
          [
            "Criticality owner",
            "Blast radius and nis2_significant rest on a static YAML. Tie to the safety-management / asset register, with a review cadence.",
          ],
          [
            "Depth vs chart residual",
            "Bytewax lists “128267 vs scenario / last valid”. Without ENC, this is last-valid only — fine if declared; not a chart check.",
          ],
          [
            "Secrets",
            "LLM and TAXII credentials have no store, rotation, or airgap alternative.",
          ],
          [
            "Network placement",
            "Four TAPs, operator UI, and optional satcom need a drawing so the sensor host cannot become a gateway onto N2K.",
          ],
          [
            "Time-spoof overlay",
            "Simulator documents 126992 as unchanged in gps-spoof-underway. A dedicated time-spoof scenario would exercise the dual-clock residual.",
          ],
        ]}
        striped
      />
      <H3>Later / out of scope unless you change the mission</H3>
      <Table
        headers={["Item", "Verdict"]}
        rows={[
          ["RF GNSS / AIS VHF", "Keep as non-goal. On-bus consequence is the sensor’s job."],
          ["CMS, radar video, Link-16", "Out of band by design. Nav gateway export is read-only if a lab consumer is needed."],
          ["IEC 61162-450 / OPC UA / MQTT", "Adapter-shaped, not designed. Do not special-case the pipeline."],
          ["Fleet / multi-hull correlation", "Absent. One hull, one SENSOR_MODE."],
          ["Weather / tide / current", "Would tighten SOG vs RPM; not required for the GPS-spoof worked example."],
          ["Inbound threat intel beyond ATT&CK", "Maritime ISAC / IoC feeds would be a second inbound TAXII; not needed for v1."],
        ]}
        striped
      />
      <Callout tone="warning" title="Spec inconsistencies from the last increment">
        The service-schema table lists Incidents twice. The worked incident JSON
        does not yet include <Code>risk</Code> / <Code>nis2</Code> even though
        Stage C and the operator surface describe them. The PGN catalog file is
        referenced but not sampled. None of these change the datasource map, but
        they should be cleaned up before treating the spec as closed.
      </Callout>
    </Stack>
  );
}

function TrustView() {
  return (
    <Stack gap={16}>
      <H2>Trust boundaries</H2>
      <Text>
        Accent border / dashed edge = named in the architecture but not designed
        (trusted time, charts, artifact updates). Dimmer boxes are
        optional adapters or human-gated sinks.
      </Text>
      <Flow nodes={FLOW_NODES} edges={FLOW_EDGES} />
      <Text size="small" tone="tertiary">
        Label topic is dev-only and must not exist in prod. TAXII and CSIRT leave
        the ship only after human confirm. Alert text is a local GGUF;{" "}
        <Code>prod</Code> refuses <Code>LLM_ENDPOINT</Code>.
      </Text>
      <Grid columns={2} gap={12}>
        <Card>
          <CardHeader>Can run airgapped</CardHeader>
          <CardBody>
            <Text size="small">
              TAP decode, honeypot, asset inventory, dependency graph, comms
              graph, Bytewax, ONNX, rules, local SLM alert text, risk score, NIS2{" "}
              <Text weight="semibold">UI clocks</Text>,
              local STIX file, operator evidence view. ATT&amp;CK vendored.
            </Text>
          </CardBody>
        </Card>
        <Card>
          <CardHeader>Needs a declared off-ship path</CardHeader>
          <CardBody>
            <Text size="small">
              ATT&amp;CK refresh via TAXII, TAXII share, CSIRT filing,
              model/rule/catalog/SLM-weight updates, optional ENC. None of these
              should be implicit cloud calls.
            </Text>
          </CardBody>
        </Card>
      </Grid>
      <H3>Worked example still holds without externals</H3>
      <Table
        headers={["Incident", "External needed to detect?", "External needed to report?"]}
        rows={[
          [
            "gps-spoof-underway",
            "No — GNSS PGNs, gyro, DR residual, criticality YAML",
            "Alert text local SLM. NIS2 clocks local. CSIRT submit is human + unspecified channel",
          ],
          [
            "PGN flood / T0814",
            "No — bus_load + throughput-lstm on disk",
            "Same as above; STIX local file is enough for intel keep",
          ],
          [
            "Rogue command to autopilot",
            "No — comms graph vs vessel model",
            "Same",
          ],
          [
            "Depth lie vs chart",
            "Yes, if you meant ENC — today it is last-valid only",
            "Same",
          ],
        ]}
        striped
      />
    </Stack>
  );
}

export default function OtSensorDatasourceReview() {
  const [view, setView] = useCanvasState<View>("view", "sources");

  return (
    <Stack gap={20}>
      <Stack gap={8}>
        <H1>OT sensor — datasource review</H1>
        <Text tone="secondary">
          The holes that remain: trusted time, catalog license, signed update
          channel, and who confirms NIS2 / TAXII. Alert generation is a local
          GGUF, not a cloud API.
        </Text>
      </Stack>
      <Grid columns={4} gap={12}>
        <Stat value="5" label="Wire ingest (1 required)" tone="success" />
        <Stat value="8" label="On-disk pins" />
        <Stat value="5" label="Off-ship named" tone="warning" />
        <Stat value="3" label="Named but undesigned" tone="danger" />
      </Grid>
      <Row gap={8} wrap align="center">
        <Pill active={view === "sources"} onClick={() => setView("sources")}>
          Sources
        </Pill>
        <Pill active={view === "gaps"} onClick={() => setView("gaps")}>
          Gaps
        </Pill>
        <Pill active={view === "trust"} onClick={() => setView("trust")}>
          Trust map
        </Pill>
      </Row>
      <Divider />
      {view === "sources" ? <SourcesView /> : null}
      {view === "gaps" ? <GapsView /> : null}
      {view === "trust" ? <TrustView /> : null}
    </Stack>
  );
}
