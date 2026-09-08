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
  useCanvasState,
} from "cursor/canvas";

type View = "risks" | "already" | "caps";

export default function OtSensorThroughput() {
  const [view, setView] = useCanvasState<View>("view", "risks");

  return (
    <Stack gap={16}>
      <Stack gap={6}>
        <H1>High-throughput risks</H1>
        <Text tone="secondary">
          NMEA 2000 is 250 kbps per trunk. The sensor’s problem is not ONNX
          math — it is capturing a flood without dropping frames, without
          writing a JSONL line per frame forever, and without treating every
          LSTM hop as an SLM prompt.
        </Text>
      </Stack>
      <Grid columns={4} gap={12}>
        <Stat value="~1500" label="Frames/s per trunk at cap" />
        <Stat value="×4" label="Isolated TAPs" />
        <Stat value="10 Hz" label="LSTM hop (flood model)" />
        <Stat value="8 s" label="SLM budget" tone="warning" />
      </Grid>
      <Row gap={8} wrap>
        <Pill active={view === "risks"} onClick={() => setView("risks")}>
          Bottlenecks
        </Pill>
        <Pill active={view === "already"} onClick={() => setView("already")}>
          Already mitigated
        </Pill>
        <Pill active={view === "caps"} onClick={() => setView("caps")}>
          Caps to add
        </Pill>
      </Row>
      <Divider />
      {view === "risks" ? <RisksView /> : null}
      {view === "already" ? <AlreadyView /> : null}
      {view === "caps" ? <CapsView /> : null}
    </Stack>
  );
}

function RisksView() {
  return (
    <Stack gap={16}>
      <H2>Where a PGN flood actually hurts</H2>
      <Table
        headers={["Rank", "Stage", "Why it fails first", "Symptom"]}
        rows={[
          [
            "1",
            "SocketCAN RX",
            "Kernel socket buffer overruns long before Python decode. Default rmem is small.",
            "Silent frame loss. flood_score under-reads. Honeypot is incomplete.",
          ],
          [
            "2",
            "Honeypot JSONL",
            "JSONL+base64 per frame. Rotation 128 MiB/1 h; retain 2 GiB/48 files/30 d per segment. Gzip async.",
            "Without retain, disk fills. With retain, old flood files vanish unless on_hold.",
          ],
          [
            "3",
            "Per-frame OTEvent on NATS",
            "If adapters publish one message per CAN frame, ingest is a chatty bus, not a windowed one.",
            "Bytewax/NATS lag. JOIN_TIMEOUT → join_incomplete during the attack you care about.",
          ],
          [
            "4",
            "Broadcast graph expand",
            "DA=255 expanded to every modeled consumer, per frame, per trunk.",
            "Graph service CPU; live.json churn; false new_edge noise.",
          ],
          [
            "5",
            "Explain on every hop",
            "Occlusion over 20×8 is ~160 extra forwards per LSTM hop if always on.",
            "ONNX branch slower than 100 ms hop → skipped explain or stalled scores.",
          ],
          [
            "6",
            "SLM on “material update”",
            "If every flood hop is material, an 8B GGUF cannot keep up (8 s timeout).",
            "llm_unavailable storm, or incidents blocked if someone waits on the SLM.",
          ],
          [
            "7",
            "Evidence packet list",
            "Operator store that copies every contributing frame in a 2 s flood window is huge; a 30 s gps window is fine.",
            "UI/API hang. seq range into honeypot is the right grain — full rows are not.",
          ],
        ]}
        rowTone={[
          "danger",
          "danger",
          "warning",
          "warning",
          "warning",
          "warning",
          "info",
        ]}
        striped
      />
      <Callout tone="warning" title="Python is not the first limit">
        Four trunks at cap is ~6k frames/s. A tight C/Rust TAP + bounded
        honeypot can take that. A Python decode loop behind a default CAN
        socket cannot. Bytewax should see windows (~10–40/s), not raw frames.
      </Callout>
      <H3>Load the LSTM already assumes</H3>
      <Table
        headers={["Feature", "Normalize divisor", "Meaning"]}
        rows={[
          ["frames_per_s", "1500", "One fully loaded 250 kbps trunk"],
          ["bytes_per_s", "25000", "≈ 250 kbps"],
          ["mean_interarrival_ms", "50", "Healthy catalog cadence, not flood"],
          ["hop", "100 ms", "10 FeatureWindows/s/segment if bus-wide"],
        ]}
        striped
      />
      <Text size="small" tone="tertiary">
        Source: throughput-lstm 1.0.0 config.yaml · 20×100 ms window. Four
        segments in scope. Inference of a 16-hidden LSTM at 40 windows/s is
        cheap; capture and logging are not.
      </Text>
    </Stack>
  );
}

function AlreadyView() {
  return (
    <Stack gap={16}>
      <H2>What the spec already does right</H2>
      <Table
        headers={["Choice", "Throughput effect"]}
        rows={[
          [
            "SLM after incidents, not per hop",
            "8B model is off the hot path if “material update” excludes alert_count++.",
          ],
          [
            "LSTM hop dedup",
            "One flood incident, alert_count++. Correlator must not open a new incident per 100 ms.",
          ],
          [
            "ONNX ∥ rules",
            "A slow head does not block the other. model_unavailable / join_incomplete fail closed.",
          ],
          [
            "evidence_summary vs full packets",
            "SLM and STIX stay small. Risk is the operator evidence store, not the prompt.",
          ],
          [
            "Honeypot parallel to Bytewax",
            "Decode can shed PGNs; raw path is supposed to keep them. Only works if TAP does not block.",
          ],
          [
            "Windowed LSTM features, not raw CAN into ONNX",
            "20×8 floats per hop, not 1500 embeddings/s.",
          ],
        ]}
        striped
      />
      <Callout tone="info" title="gps-spoof-underway is not a throughput test">
        Spoof does not saturate the bus. The stress case is the PGN-flood
        overlay (T0814) on one or more trunks at once.
      </Callout>
    </Stack>
  );
}

function CapsView() {
  return (
    <Stack gap={16}>
      <H2>Caps the architecture still needs</H2>
      <Table
        headers={["Cap", "Default to pin"]}
        rows={[
          [
            "CAN socket",
            "Large SO_RCVBUF / TPACKET ring; count drops (si_drops). Separate TAP process from Bytewax.",
          ],
          [
            "Honeypot write",
            "JSONL inside the retained window. Async gzip. Purge oldest closed. If cap+all held: drop_new, never block RX.",
          ],
          [
            "Ingest grain",
            "Publish FeatureWindow and change events on NATS — not every OTEvent. Keep OTEvent local to the adapter process or a shared-memory ring.",
          ],
          [
            "Graph",
            "Expand broadcast on a 1 s rollup, not per frame. Rate-limit GraphChange emits.",
          ],
          [
            "Explain",
            "Attribution sampled (e.g. once per incident open / every N hops), not every 100 ms flood_score.",
          ],
          [
            "SLM",
            "Call on open, close, and severity/technique change only. alert_count++ is not material. Never block correlator on 9208.",
          ],
          [
            "Evidence",
            "Store seq_from/seq_to + top-k frames. Full list is a drill-down against the honeypot file.",
          ],
          [
            "Bytewax keys",
            "Bus-load models keyed by (source, segment), not per (SA, PGN). Analog residuals stay per-talker at catalog Hz.",
          ],
          [
            "Backpressure",
            "Shed decode (keep honeypot + bus_load features) when hop deadline missed. Prefer a flood incident over a stalled pipeline.",
          ],
        ]}
        striped
      />
      <Text size="small" tone="tertiary">
        These are implementation pins, not new services. The lean compose map
        still holds if the TAP+honeypot container is the only process allowed
        to touch SocketCAN.
      </Text>
    </Stack>
  );
}
