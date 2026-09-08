# OT sensor

Passive detection pipeline for marine operational technology. **Ingest is protocol-agnostic:** adapters described in configuration read NMEA 2000, Modbus, or any other mapped protocol and emit **`OTEvent`**. Bytewax, ONNX, rules, incidents, the local SLM, and STIX never import a protocol library.

NMEA 2000 (IEC 61162-3) remains the primary worked example — a one-way TAP on an OPV backbone, or the simulator `vcan` interface in [nmea2000-opv-simulator.md](./nmea2000-opv-simulator.md). The sensor never transmits on a live bus.

Runtime is one of two modes: **`dev`** (lab, optional ground truth) or **`prod`** (ship capture, no ground truth). Mode is set at process start (`SENSOR_MODE=dev|prod`) and cannot be overridden by a second “enable labels” flag.

```
sources.yaml → protocol adapters (nmea2000 | modbus | nmea0183 | …)
                    ↓
            ingest bus (OTEvent)
                    ├→ Bytewax (window, features, event_id)
                    │       ├→ ONNX enrichment
                    │       └→ rules enrichment          (parallel; same event_id)
                    │               ↓
                    │       alert correlation / incident construction
                    │               ↓
                    │       local SLM        — watchstander alert text; evidence_summary only
                    │       operator evidence view
                    │               ↓
                    │       STIX 2.1 report
                    ├→ honeypot collector (raw logs; not on the LLM path)
                    ├→ asset detector → incident construction
                    └→ communication graph → incident construction

dev only (parallel, never on a protocol bus, never in the LLM prompt):
        simulator label topic → eval / training join by event_id
```

## Design principles

- **Normalize at the edge.** Adapters are the only code that knows a protocol. Everything downstream sees canonical fields on a source-agnostic ingest bus.
- **Listen-only.** No protocol writes in `prod` (no ISO 11783 address claim, no PGN publish, no Modbus 05/06/15/16, no OPC UA write). The honeypot collector is a sink, not a talker.
- **Segment-aware.** Every unit is tagged `nav` | `propulsion` | `power` | `aux` (from source config) so physics checks and ATT&CK mapping know which OPV zone it came from.
- **Keep the raw, bound the disk.** The honeypot collector stores every inflow unit even when it is not valid for that protocol. Files **rotate** and **old history is purged** so a flood cannot fill the disk. Decode failures must not drop evidence *inside* the retained window. **Filenames carry capture data** (mode, hull, segment, iface, time window, counts, kinds) so operators can select files without opening them.
- **Inventory the bus.** The asset detector builds a live talker catalog, tags **criticality**, and maintains a **dependency graph** (who needs whom to function). It diffs inventory against the static OPV model. It does not transmit.
- **Show who talks to whom.** The communication graph overlays live src→dst pairs on the expected vessel model so lateral movement, rogue talkers, and architecture violations are visible without reading protocol dumps.
- **Show the evidence.** Every ONNX score and rule fire is traceable to the packets, fields, sequence steps, assets, and time window that produced it. The SLM alert text is not a substitute.
- **Enrich before language.** The local SLM never sees raw frames, honeypot log blobs, or high-rate streams. It receives a **constructed incident**: correlated alerts, model scores, rule hits, asset changes, a compact `evidence_summary`, and retrieved context. It writes alert title/body; it does not fire detections.
- **Language stays on the host.** Watchstander alert text comes from a small GGUF model on the sensor. `prod` refuses a remote LLM endpoint. Load/timeout failure is `llm_unavailable`; the incident still stands.
- **ONNX and rules in parallel.** Both consume the same feature window. Neither blocks the other. They merge only in alert correlation / incident construction.
- **Config-driven models, rules, and protocols.** Pipeline code loads `sources.yaml`, `config.yaml` + `model.onnx`, and `rule.yaml`; swapping a protocol map or weights does not change operators.
- **No unsupervised actuation.** SLM output is alert title/body plus recommended detect/contain steps. A human confirms any isolation, gateway policy change, or **off-ship STIX/TAXII share**.
- **Share structured intel.** Closed (and materially updated) incidents export as STIX 2.1. The bundle carries ATT&CK ICS patterns, sightings, and a sanitized window — not raw frames, honeypot blobs, or ground truth.
- **No ground truth in prod.** Labels are not subscribed, stored, or rendered. `prod` refuses to start if a label topic is configured.

## Protocol sources (configuration)

Chosen at process start from [samples/sources/sources.yaml](./samples/sources/sources.yaml). Not a runtime toggle. Each **source** is an adapter instance: protocol + transport + segment + field map.

```
SENSOR_MODE=prod
# Optional filter on protocol id. Empty → every source with enabled: true.
# SENSOR_SOURCES=nmea2000
# SENSOR_SOURCES=nmea2000,modbus
# SENSOR_SOURCES=modbus
# SENSOR_SOURCES=nmea0183
```

Unknown tokens are a fatal startup error unless `sources.yaml` names an `adapter` module for that protocol. If a protocol is not listed (and not `enabled: true`), its config file is ignored — the pipeline does not import that library.

```
adapter nmea2000  ─┐
adapter modbus    ─┼→ ingest bus (OTEvent)
adapter <other>   ─┘
        ↓
Bytewax → ONNX ∥ rules → incidents → local SLM → STIX
        ↓
honeypot + asset detector + comms graph
```

### Ingest schema: `OTEvent`

Adapters emit **`OTEvent`**. This is the only contract Bytewax, ONNX, rules, assets, the graph, incidents, the LLM, and STIX need. Protocol-native leftovers stay in `parser_fields` (canonical field names, `source` id, `segment`, catalog). Downstream keys: `(protocol, source_asset_id, object_address)` plus `parser_fields["source"]` / `segment`.

```python
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
```

Full service schemas: [samples/schemas/ot_events.py](./samples/schemas/ot_events.py).

| Field | Role |
| --- | --- |
| `event_id` | Stable id for this observation (UUID/ULID). Copied to features, scores, evidence |
| `timestamp` | Event time (wall). Adapters may also stash `t_mono` in `parser_fields` |
| `protocol` | `nmea2000` \| `modbus` \| `nmea0183` \| … |
| `source_asset_id` | Talker / client (N2K SA, Modbus unit-id, 0183 talker, …) |
| `destination_asset_id` | Unicast target; `None` if broadcast / no DA |
| `operation_category` | `report` \| `command` \| `read` \| `write` \| `identity` \| `poll` \| … |
| `operation_name` | Mapped name (`gnss_position`, `write_holding_register`, `address_claim`) |
| `object_type` | `pgn` \| `modbus_reg` \| `nmea_sentence` \| `opcua_node` \| … |
| `object_address` | Native address (`129029`, `hr:40001`, `GGA`) |
| `value_before` / `value_after` | Prior/current value when known (writes, config); reporting uses `value_after` |
| `is_write` | Observed write or command (sensor TAP still listen-only) |
| `is_control` | Actuation path (autopilot, RPM command, coil that moves plant) |
| `is_configuration` | Identity, maps, setpoints, firmware |
| `privileged` | Address-claim, admin, config, or other high-privilege op |
| `parser_fields` | Canonical fields + `source`, `segment`, catalog; never required as a typed native struct |

N2K broadcast (`DA=255`) → `destination_asset_id=None`. A Modbus poll is `operation_category=read`, `is_write=False`. A holding-register write on the wire is `is_write=True` even though the **sensor** did not send it. `prod` adapters still refuse to originate writes.

A failed adapter emits `source_unavailable` in `operation_name` with empty assets; other sources continue.

### Adapter contract

| Requirement | Rule |
| --- | --- |
| Config | `id`, `protocol`, `segment`, transport, map/catalog |
| Output | `OTEvent` only |
| `prod` writes | Forbidden. Startup fatal if `writes: true` |
| Plugin | Default module `ot_sensor.adapters.<protocol>`, or explicit `adapter:` |
| Down | `source_unavailable`; do not block the ingest bus |

Adding a protocol: implement the adapter, add a field map onto [canonical-fields.yaml](./samples/sources/canonical-fields.yaml), list a source in `sources.yaml`. No Bytewax / ONNX / rule / LLM / STIX change if the canonical names already exist.

### Sample adapters

| `protocol` | Transport | `asset_ref` | `channel` | Map |
| --- | --- | --- | --- | --- |
| `nmea2000` | SocketCAN / pcap TAP | source address | PGN | PGN catalog → canonical fields |
| `modbus` | TCP poll or TAP :502 | unit-id | register / coil | [modbus.yaml](./samples/modbus/modbus.yaml) |
| `nmea0183` | UDP / serial (example) | talker id | sentence | [nmea0183-nav.yaml](./samples/sources/maps/nmea0183-nav.yaml) |

IEC 61162-450, OPC UA, MQTT, and vendor UDP attach the same way (`protocol` + map + adapter). They are not special-cased in the pipeline.

### Canonical fields (excerpt)

| Field | Unit | Typical native |
| --- | --- | --- |
| `lat_deg` / `lon_deg` | deg | PGN 129025 / 129029; NMEA 0183 GGA/RMC |
| `heading_deg` | deg | PGN 127250; HDT |
| `sog_kn` / `cog_deg` | kn / deg | PGN 129026; RMC |
| `rpm` | rpm | PGN 127488; Modbus HR 0 |
| `oil_temp_c` | °C | PGN 127489; Modbus IR 10 |
| `hdop` / `sat_count` | — | PGN 129539 / 129029; GGA |

### Modbus adapter

Enabled when a source has `protocol: modbus` (or `SENSOR_SOURCES` includes `modbus`). Read-only in `prod`: function codes 01/02/03/04 only. No writes (05/06/15/16).

See [samples/modbus/modbus.yaml](./samples/modbus/modbus.yaml). Register map rows bind to canonical names so residuals run without N2K PGNs.

### Independence

| Stage | Depends on a given protocol? |
| --- | --- |
| That protocol's adapter | Yes. Off when the source is not enabled |
| Honeypot | No. Logs whatever adapters open (`k` token may include `modbus`, `nmea0183`, …) |
| Asset detector / comms graph | No. Keys are `source_asset_id` / `destination_asset_id` |
| Bytewax / ONNX / rules / incidents / LLM / STIX | **No.** `OTEvent` / incidents only |

### Service schemas

Click a service on the architecture canvas to see the same types. Source: [ot_events.py](./samples/schemas/ot_events.py).

| Service | Consumes | Emits |
| --- | --- | --- |
| Protocol adapters (N2K, Modbus, other) | Wire / TAP / poll | `OTEvent` |
| PGN decode | N2K frames | `OTEvent` (`object_type=pgn`) |
| Ingest bus | `OTEvent` | `OTEvent` (fan-out) |
| Honeypot | Raw inflow | `HoneypotRecord` |
| Raw log files | `HoneypotRecord` | `HoneypotFile`, `HoneypotRetention` |
| Asset detector | `OTEvent` | `AssetRecord`, `AssetChange`, dependency graph |
| Incidents | scores, hits, asset/graph changes | `Alert`, `Incident`, `Evidence`, `RiskScore`, `Nis2UiAlert` |
| Bytewax | `OTEvent` | `FeatureWindow` |
| ONNX enrich | `FeatureWindow` | `ModelScore` |
| Rules enrich | `FeatureWindow` | `RuleHit` |
| Local SLM | `Incident` (`evidence_summary` only) | `CopilotAssessment` (`alert_title`, `alert_body`) |
| SLM weights | — | `LlmSpec` |
| STIX 2.1 | `Incident` + assessment | `StixBundleRef` |
| Operator | incidents, evidence, STIX | (display only) |
| Model registry | — | `ModelSpec` |
| Rule pack | — | `RuleSpec` |
| Vessel topology | — | `VesselModel` |

## Runtime modes

| | `dev` | `prod` |
| --- | --- | --- |
| Capture | N2K simulator / pcap / lab sniffer | Ship TAP (or other adapters if configured) |
| Label topic | May subscribe; join after emit for training and copilot **scoring** | Not bound. Startup fails if `LABEL_TOPIC` is set |
| `label` on events | Allowed on a side record for eval; omitted from the LLM prompt | Field absent. Any inbound label frames are dropped and counted |
| Operator UI | Scenario link when a label join hits | No scenario panel, no GT widgets |
| Simulator | Expected lab peer in `dev` | Not deployed on the vessel |
| Adapter writes | Still default off | Fatal if any source sets `writes: true` |
| LLM runtime | Local GGUF (`watchstander-slm`); lab may swap file | Local GGUF only. Startup fails if `LLM_ENDPOINT` is set |

`prod` is the ship binary. A lab can still run the **sensor in `prod`** against the simulator in unlabeled (`prod`) mode to certify that detection does not depend on labels.

## Ingest and decode

### Sample: NMEA 2000 TAP

When a source has `protocol: nmea2000`:

| Item | Contract |
| --- | --- |
| Standard | IEC 61162-3 / NMEA 2000 |
| Link | CAN 2.0B, 250 kbps, 29-bit identifiers |
| Capture | SocketCAN (`can0`, or simulator `vcanX`), optional pcap replay |
| Direction | TAP / sniffer, receive-only |
| Segment label | Set per interface: `nav`, `propulsion`, `power`, `aux` |

`prod` deploys one TAP per isolated backbone (four interfaces). `dev` uses the same decode path with pcap or simulator `vcan`. The honeypot collector reads the **same TAP** in parallel with decode; it does not require a successful PGN parse.

## Honeypot data collector

A TAP-side sink that **collects and stores raw inflow in log files regardless of format**. It is not the Bytewax path: decode, models, and rules may ignore a unit; the honeypot still writes it.

On a live ship the collector **does not transmit** (no address claim, no decoy PGN). Attracting traffic is the simulator’s job: a decoy twin (SA 99) can sit on `vcan_nav` so unauthorized commands have a victim address. The sensor only records.

### What is stored

Every capture unit from the iface, including:

| Inflow | Still logged? |
| --- | --- |
| Valid NMEA 2000 / CAN 2.0B frame | Yes |
| Unknown PGN, proprietary, or reserved ID | Yes |
| CRC / error frame / truncated SocketCAN | Yes |
| Non-CAN bytes (NMEA 0183 text, USB junk, Ethernet, zeros) | Yes |
| Empty or oversized reads | Yes |
| Mix of the above on one iface | Yes — each unit is an opaque blob |
| Any other adapter PDU (Modbus, NMEA 0183, …) | Yes (`kind` = protocol id) |

There is **no** schema check on the payload. Catalog version, UTF-8, and Fast Packet completeness are irrelevant to the writer.

### Log files (data in the name)

Append-only JSONL. The **filename is a queryable record** — mode, hull, segment, interface, time window, unit count, payload bytes, and capture kinds — so a glob can find evidence without reading the file. Ground-truth fields (`attack_id`, `scenario_id`, labels) are **never** in the name.

While a file is open (growing):

```
logs/honeypot/{segment}/hp-{mode}-{hull}-{segment}-{iface}-{utc_open}-open-{pid}.jsonl
```

On rotate, the file is renamed with closed-window stats, then gzipped:

```
hp-{mode}-{hull}-{segment}-{iface}-{utc_open}-{utc_close}-n{count}-b{nbytes}-k{kinds}-r{seq}.jsonl.gz
```

Example:

```
logs/honeypot/nav/hp-prod-opv1-nav-vcannav-20260908T190000Z-20260908T195959Z-n18420-b2202010-kcan+error-r0007.jsonl.gz
```

| Token | Data encoded |
| --- | --- |
| `hp` | Collector id |
| `{mode}` | `dev` or `prod` |
| `{hull}` | Vessel id from sensor config (not a MITRE label) |
| `{segment}` | `nav` / `propulsion` / `power` / `aux` |
| `{iface}` | TAP name, `/` and `_` stripped (`vcan_nav` → `vcannav`) |
| `{utc_open}` / `{utc_close}` | Window in UTC (`YYYYMMDDTHHMMSSZ`) |
| `n{count}` | JSONL records in the file |
| `b{nbytes}` | Sum of raw payload bytes |
| `k{kinds}` | Sorted unique `kind` hints, `+` joined (`can+error+unknown`) |
| `r{seq}` | Rotation index for that segment |
| `open-{pid}` | Incomplete file; do not treat as closed evidence |

Envelope (metadata only). `payload_b64` is uninterpreted:

```
{"t":"2026-09-08T19:00:01.012Z","segment":"nav","iface":"vcan_nav","seq":1842,"nbytes":13,"kind":"unknown","sha256":"…","payload_b64":"…"}
```

| Field | Meaning |
| --- | --- |
| `t`, `segment`, `iface`, `seq` | Capture clock, OPV backbone, interface, monotonic seq per file |
| `nbytes` | Length of the raw unit |
| `kind` | Capture-layer **hint** only: `can`, `error`, `truncated`, `non_can`, `empty`, `unknown` — not a decode verdict |
| `sha256` | Hash of the raw bytes |
| `payload_b64` | Raw inflow. Do not parse to decide whether to write |

Rotate on size **or** age, whichever first. Gzip **after** close, off the TAP thread. `prod` logs and filenames must **not** include label / `attack_id` / `scenario_id`. Every close and purge appends to `logs/honeypot/_manifest.jsonl` (path, sha256, nbytes, `purged`).

Config: [honeypot.yaml](./samples/sources/honeypot.yaml).

### Rotation and retention

History is **bounded**. Rotation closes the current file; retention deletes old **closed** files. The growing `open-{pid}` file is never unlinked.

| Knob | Default | Role |
| --- | --- | --- |
| `rotate.max_bytes` | 128 MiB | Close current file |
| `rotate.max_age_s` | 3600 (1 h) | Close current file |
| `retain.max_bytes_per_segment` | 2 GiB | Cap closed+open bytes on that backbone |
| `retain.max_files_per_segment` | 48 | Cap closed files |
| `retain.max_age_s` | 2592000 (30 d) | Aligns with the NIS2 final-report window |
| `hold_open_incidents` | true | Do not purge a file still named on an open/update incident |

Purge order: oldest closed file whose `on_hold` is false. Manifest keeps `sha256` after unlink so a stale forensic pointer can say `purged` instead of 404 with an empty hash.

If the cap is hit and **every** closed file is on hold, **do not block SocketCAN**. Stop appending (`honeypot_dropped++`) until a hold releases or an operator raises the cap. Dropping new units is preferable to RX overrun.

Forensic pointers on an **incident** use the **final filename**, not the `open-{pid}` name. After purge the pointer stays; `HoneypotFile.purged` is true.

### Isolation from the SLM

Honeypot files are **not** LLM input. If a model or rule fires, incident construction may attach a forensic pointer `{ iface, log_file, seq_from, seq_to }` so an operator can open the raw blob. The SLM still sees only the incident.

### Modes

| | `dev` | `prod` |
| --- | --- | --- |
| Collector | On; same TAP as decode; rotation + retention on | On; ship TAP; same caps |
| Disk cap | 2 GiB / segment default | Same; raise only with hold policy |
| Decoy twin (SA 99) | Simulator may publish NAME/address-claim | Not on the vessel; sensor never claims that SA |
| Ground truth in logs or filenames | Forbidden (eval stays on the label topic) | Forbidden |

## Asset detector service

Listen-only inventory of NMEA 2000 **assets** (talkers) on each TAP. It does not address-claim and does not write PGN. It consumes the decode stream plus CAN-shaped honeypot units (`kind=can`) so unknown PGNs still yield a source address.

```
decode + honeypot(can) → asset detector → inventory.json
                       → change events (event_id) → incident construction
                       → live catalog → Bytewax vessel join / LLM topology retrieval
```

### What it detects

| Signal | Source | Asset field |
| --- | --- | --- |
| Source address | 29-bit ID | `sa` |
| ISO 11783 NAME | PGN 60928 address claimed | `name`, function, industry, identity |
| Product info | PGN 126996 | model, software, serial |
| PGN list / observed PGNs | 126464 + traffic | `pgns_seen`, rates |
| Segment | TAP tag | `segment` |
| Honeypot decoy | SA 99 NAME in lab | `role: decoy` |

Keyed by `(segment, sa)`. NAME changes and SA collisions are first-class (Rogue Master / T0848).

### Diff against the OPV model

The static vessel file is the expected set. The detector emits **change events** (not raw frames) into alert correlation:

| `change` | Meaning |
| --- | --- |
| `new_asset` | SA/NAME not in the model (or not seen this underway) |
| `missing_asset` | Expected talker silent beyond its catalog interval |
| `name_change` | Same SA, different NAME |
| `unexpected_segment` | Known NAME on the wrong backbone |
| `pgn_set_drift` | New or missing PGNs vs model |
| `decoy_contact` | Traffic to/from honeypot SA 99 |

Change event (folded into an incident; may reach the LLM as `assets[]` on that incident):

```
{
  "event_id": "01J…",
  "service": "asset-detector",
  "change": "new_asset",
  "segment": "nav",
  "sa": 44,
  "name": "…",
  "pgns_seen": [127250],
  "vs_model": "absent"
}
```

Live catalog (operator + vessel join, not dumped into the LLM wholesale):

```
assets/{mode}/{hull}/inventory.json
```

Each row: `asset_id`, `segment`, `name`, `channels_seen`, `first_seen`, `last_seen`, `expected`, `role`, **`criticality`**, **`nis2_service`**, **`depends_on`**.

### Criticality and dependency graph

The detector does not invent criticality from traffic. It joins live assets to [asset-criticality.yaml](./samples/sources/asset-criticality.yaml). The **communication graph** is who talks to whom; this **dependency graph** is who must work for a function to stay safe.

| `criticality` | Meaning | OPV examples |
| --- | --- | --- |
| 5 | Safety-critical | GNSS-1/2, gyro, autopilot, rudder |
| 4 | Essential operations | Engines, thruster, AIS, genset |
| 3 | Supporting | MFD, echo sounder, wind |
| 2 | Hotel / aux | Tanks, environment |
| 1 | Lab / decoy | SA 99 |

`nis2_service` is the essential function for Article 23 impact: `navigation` | `propulsion` | `power` | `none`.

Dependencies (excerpt): GNSS-1/2 + gyro → autopilot → rudder; GNSS-1 → AIS and MFD; genset → thruster. A hit on GNSS-1 therefore has **blast radius** autopilot, rudder, AIS, MFD.

| `change` (extra) | Meaning |
| --- | --- |
| `critical_missing` | Expected asset with criticality ≥ 4 silent |
| `dependency_break` | Upstream of a critical function missing or spoofed |

Live catalog path unchanged. Full dependency adjacency is **not** dumped into the LLM; incidents get `risk.dependent_asset_ids` and max criticality only.

### Modes

| | `dev` | `prod` |
| --- | --- | --- |
| Detector | On | On |
| Decoy SA 99 | Expected `role: decoy` | Must **not** appear; if it does, `new_asset` |
| Ground truth | Not stored on inventory rows | Not stored |

## Topology / communication graph

Listen-only overlay of **who communicates with whom**. Assets are nodes; this service is the **edges**. It makes lateral movement, rogue devices, and architecture violations visible as new or forbidden pairs instead of a PGN dump.

It does not transmit. It consumes decode (`sa`, `da`, `pgn`, `segment`) plus the asset catalog for node identity, and diffs that live graph against the expected graph in the same four-segment OPV model the simulator uses (including isolating-gateway allowlists).

```
decode + asset catalog → communication graph → live.json
                       → edge/node diffs (event_id) → incident construction
                       → operator overlay (expected vs live)
```

Broadcast (N2K `DA=255`) is **expanded** to modeled consumers of that PGN so the picture is not a star into “everyone.” Unicast is `SA → DA`. Gateway allowlists are first-class cross-segment edges. Modbus (if started) is `poller → unit-id`.

### Expected vs live

| Graph | Path | Role |
| --- | --- | --- |
| Expected | `topology/{mode}/{hull}/expected.json` | Vessel model: allowed publishers, unicast pairs, gateway allowlist |
| Live | `topology/{mode}/{hull}/live.json` | Rolling window of observed pairs + rates |

Live is not dumped into the LLM. Incidents carry only **violating** nodes/edges as `graph[]`.

### What it detects

| `change` | Meaning | Typical tell |
| --- | --- | --- |
| `new_node` | Talker not in the model (rogue device). Merges with asset `new_asset` | Unknown SA / unit-id |
| `new_edge` | Pair never allowed: unicast or expanded-broadcast consumer | Lateral movement, unexpected command path |
| `unexpected_da` | Unicast to a device that must not receive this PGN | Autopilot command from a non-autopilot SA |
| `gateway_bypass` | PGN crossed segments outside the allowlist | RPM/engine on nav; nav command on propulsion |
| `broadcast_from_unexpected` | Command or plant PGN as global broadcast from a SA that must not | T1692 onto the whole backbone |
| `silent_edge` | Expected pair gone beyond catalog interval | Missing path / dead gateway |
| `decoy_edge` | Traffic to/from honeypot SA 99 | Lab only; `new_edge` in `prod` if SA 99 appears |

Change event (folded into an incident as `graph[]`):

```
{
  "event_id": "01J…",
  "service": "comms-graph",
  "change": "new_edge",
  "src": { "source": "nmea2000", "segment": "nav", "asset_ref": 44 },
  "dst": { "source": "nmea2000", "segment": "nav", "asset_ref": 56 },
  "pgn": 127237,
  "da": 56,
  "vs_model": "absent"
}
```

Worked overlays (same CAN as the simulator):

| Live pair | `change` | Why it matters |
| --- | --- | --- |
| SA 44 → autopilot SA 56, PGN 127237 | `new_node` + `unexpected_da` | Rogue commanding heading/track (T1692.001 / T0831) |
| Engine SA 0 → MFD SA 60, PGN 127488 on `nav` | `gateway_bypass` | Isolation failure; RPM on the bridge bus |
| GNSS-1 SA 16 → modeled consumers | none | Expected broadcast expansion |

### Modes

| | `dev` | `prod` |
| --- | --- | --- |
| Graph | On | On |
| Decoy SA 99 edges | Expected `decoy_edge` if the simulator decoy is up | Must **not** appear; if they do, `new_node` / `new_edge` |
| Ground truth | Not stored on graph rows | Not stored |

## Identifier and transport

The 29-bit CAN ID unpacks to priority, Parameter Group Number (PGN), source address (SA), and destination address (DA). Payload handling:

1. Single-frame PGNs (typical 8-byte).
2. NMEA Fast Packet reassembly for multi-frame GNSS, AIS, and similar.
3. ISO 11783 transport protocol (BAM / CMDT) where present.

Malformed frames, CRC errors, and incomplete Fast Packet sequences are retained as **decode-fault features**, not dropped. Address-claim (ISO 11783 NAME / SA contention) is a first-class stream.

### PGN catalog

Field decode uses a **versioned** catalog (canboat-style JSON or equivalent): PGN number, field layout, units, and expected transmit interval. Catalog version is attached to every decoded message so model feature schemas can pin a catalog revision.

Decoded record (logical):

```
{ t, segment, can_id, prio, pgn, sa, da, payload, fields, transport, catalog_ver }
```

## Bytewax dataflow

Stateful Python streaming, keyed by `(protocol, source_asset_id, object_address)` plus `parser_fields["source"]` and `segment`. Canonical names live in `parser_fields`. Recovery snapshots persist window and baseline state across restarts.

| Stage | Operator role |
| --- | --- |
| 1. Normalize | Attach source/protocol metadata, dual clocks, drop nothing silently |
| 2. Window | Tumbling (rate, bus load) and sliding (sequence gaps, completeness) |
| 3. Features | Inter-arrival, value deltas, error rate, identity churn, physics residuals on **canonical fields** |
| 4. Vessel join | Expected assets / channels / comms edges for this `source` from the OPV model |
| 5. Assign `event_id` | UUID (or ULID) for this feature window; copied to both enrichers |
| 6a. ONNX infer | Parallel. ONNX Runtime over the feature tensor in `config.yaml` |
| 6b. Rules eval | Parallel. Same window, `rule.yaml` predicates. Does not wait on 6a |
| 7. Correlate | Alert correlation / incident construction — not a 1:1 event dump to the LLM |
| 8. Emit | Open or update **incidents**; local SLM writes alert title/body |
| 9. Report | STIX 2.1 bundle from the incident + SLM output |

### Physics residuals (examples)

These are features, not verdicts. Models and the co-pilot consume **canonical field names**; PGN numbers below are the N2K mapping, not a pipeline dependency.

| Residual | Inputs | Why it matters |
| --- | --- | --- |
| GNSS vs dead-reckoning | 129029 / 129025 vs heading + STW / SOG integration | Position spoof or GNSS-degraded vs kinematic lie |
| GNSS-1 vs GNSS-2 | SA 16 vs SA 17 position / COG | `gps-spoof-primary` splits receivers; correlated spoof does not |
| DOP healthy but jump | 129539 vs position residual | Spoof keeps quality flags good; `GNSS-degraded` does not |
| SOG vs RPM | 129026 vs 127488 | Engine reporting spoof or shaft/prop mismatch |
| Heading vs rate-of-turn | 127250 vs 127251 | Gyro spoof or inconsistent attitude |
| COG vs heading | 129026 vs 127250 | Spoofed course with true gyro |
| Depth vs chart/nav context | 128267 vs scenario / last valid | Sensor fault vs injected depth |

Worked overlay: simulator `gps-spoof-underway` (see [nmea2000-opv-simulator.md](./nmea2000-opv-simulator.md#gps-spoofing-scenario)). Bytewax should emit residuals during `ramp`/`hold` with **low** `fault_likelihood` because DOPs stay healthy. Rule `gps-spoof-nav` should fire on the same window. Correlation folds those alerts into **one incident**; the co-pilot maps T1692.002 / T0832 / T0829 from that incident and must not call `GNSS-degraded` a spoof.

### Vessel model join

A static topology file (same four-segment OPV model the simulator uses) lists allowed assets, identity fields, channels, **and** allowed communication pairs per `protocol`. The **asset detector** supplies live nodes; the **communication graph** supplies live edges. Unexpected talker, identity change, channel on the wrong segment, or a forbidden pair becomes a feature plus an asset or graph `change` event.

## ONNX model registry

Pipeline operators do not embed weights. Each model is a directory:

```
models/<model_id>/<semver>/
  config.yaml      # feature schema, windows, tensors, severity map, allowed segments/PGNs
  model.onnx       # weights
  model-card.md    # training provenance, failure modes (fault vs attack)
```

### `config.yaml` (required fields)

- `model_id`, `version`
- `feature_schema` — ordered feature names matching Bytewax output
- `window` — duration and hop used at training time (must match stage 2)
- `inputs` / `outputs` — ONNX tensor names and shapes
- `score_to_severity` — thresholds for info / warning / critical
- `scope.segments` and `scope.pgns` — where this model may run
- `catalog_ver` — PGN catalog pin
- `explain.method` / `explain.top_k` — attribution used by the [evidence view](#explainability--evidence-view) (`residual` | `occlusion` | `integrated_gradients`). Missing or failed attribution emits `explain_unavailable`; the score still stands.

### Model set

| Model | Role | Output |
| --- | --- | --- |
| Physics residual autoencoder | Analog PGN consistency (position, heading, RPM, depth) | Reconstruction error, per-feature residual |
| Sequence classifier | Address-claim storms, Rogue Master, vs other | `attack_family` over {claim, other, benign} |
| **throughput-lstm** (sample) | High bus load / PGN flood sequences | `flood_score`; fires at `>= 0.80` → T0814 |
| Multi-head scorer | Joint anomaly vs attack-family vs fault | `{anomaly, attack_family, fault_likelihood}` |

The multi-head scorer exists so the LLM is **not** asked to invent the ML result. It explains scores it is given, alongside rule hits on the incident.

Unknown or failed model loads fail closed: the stage emits `model_unavailable` on the event and skips that head rather than blocking the rules path or the whole dataflow.

### Sample model: `throughput-lstm` 1.0.0

Checked-in sample under [docs/architecture/samples/models/throughput-lstm/1.0.0/](./samples/models/throughput-lstm/1.0.0/). LSTM (8 features × 20 steps → hidden 16 → sigmoid `flood_score`). Trained on synthetic benign vs flood windows via `export.py`. **Not** ship-captured weights.

| Item | Value |
| --- | --- |
| Weights | `model.onnx` (opset 17, input `bus_seq` `[batch, 20, 8]`, output `flood_score` `[batch, 1]`) |
| Config | `config.yaml` — fire when `flood_score >= 0.80` |
| Card | `model-card.md` |
| Scope | All four segments; all PGNs (`bus_load` is backbone-wide) |
| Techniques | [T0814](https://attack.mitre.org/techniques/T0814/) Denial of Service |
| Simulator pair | `PGN flood` overlay |
| Quiet on | `gps-spoof-underway` (spoof does not saturate the 250 kbps bus) |

Bytewax must apply the same `normalize` divisors as `config.yaml` before the ONNX branch. Incident construction attaches `{ model_id: throughput-lstm, scores: { flood_score } }` on alerts that share an `event_id` with rules, then **dedups** repeated flood scores into one incident.

Lab check after `export.py`: benign `flood_score ≈ 0.00`, flood `≈ 0.99`.

## Rules engine (parallel to ONNX)

Rules consume the **same** feature window and `event_id` as ONNX. They run as a sibling Bytewax branch (or a second process reading the feature topic). Join and correlation happen only in [alert correlation / incident construction](#alert-correlation--incident-construction).

```
rules/<rule_id>/<semver>/
  rule.yaml        # predicates, window, scope, severity, technique hints
  rule-card.md     # intent, false-positive classes, overlap with models
```

### `rule.yaml` (required fields)

- `rule_id`, `version`
- `window` — must match the feature stage (or be a declared multiple of it)
- `scope.segments` / `scope.pgns`
- `all` / `any` / `not` — predicates over named features
- `then.fire`, `then.severity`, `then.techniques`, `then.impacts`
- `catalog_ver`

A failed rule pack emits `rule_unavailable` for that id and does not block ONNX.

### Rule: `gps-spoof-nav`

Detects the on-bus consequence of [gps-spoof-underway](./nmea2000-opv-simulator.md#gps-spoofing-scenario). Fires on a **healthy-looking** fix that walks off dead-reckoning. Explicitly does **not** fire on `GNSS-degraded`.

```yaml
rule_id: gps-spoof-nav
version: 1.0.0
scope:
  segments: [nav]
  pgns: [129025, 129026, 129029, 129539]
window: { duration_s: 30, hop_s: 5 }
all:
  - gnss_dr_residual_m > 50 for duration_s >= 15
  - hdop < 2.5
  - sat_count >= 8
  - heading_rot_consistent == true
  - cog_heading_residual_deg > 15
any:
  - gnss1_gnss2_split_m > 30      # gps-spoof-primary
  - both_gnss_walk_off == true    # gps-spoof-both
not:
  - hdop > 6                      # GNSS-degraded
  - sat_count_drop > 4
then:
  fire: gps_spoof
  severity: critical
  techniques: [T1692.002]
  impacts: [T0832, T0829]
```

| Predicate | Role |
| --- | --- |
| DR residual + COG vs heading | Position/course lie against true gyro/plant |
| Healthy HDOP and sat count | Distinguishes spoof from `GNSS-degraded` |
| Heading/ROT consistent | Plant did not actually turn with the fake COG |
| GNSS-1 vs GNSS-2 **or** both walk-off | Covers `gps-spoof-primary` and `gps-spoof-both` |
| `not` DOP/sat collapse | Suppresses the benign fault class |

`gps-spoof-sa-collision` additionally lights `unexpected_talker` / address-claim features; this rule still fires on the reporting-PGN lie. Rogue Master stays a separate rule if added later.

Hit payload (attached under `rules[]` on the alert, then on the incident):

```
{
  "rule_id": "gps-spoof-nav",
  "version": "1.0.0",
  "fired": true,
  "severity": "critical",
  "techniques": ["T1692.002"],
  "impacts": ["T0832", "T0829"],
  "evidence": ["gnss_dr_residual_m", "hdop", "gnss1_gnss2_split_m"]
}
```

## Alert correlation / incident construction

Replaces a 1:1 `event_id` dump to the LLM. Enrichment fragments still **join** by `event_id` into an **alert**; alerts are then **correlated** into **incidents**. The local SLM is invoked on incident open and on material updates — not on every Bytewax hop.

### Stage A — alert join

Emit an alert when ONNX and rules have both written for that `event_id`, or when `JOIN_TIMEOUT` elapses (`join_incomplete`; never invent scores or rule hits).

| Input | Source |
| --- | --- |
| Feature snapshot | Bytewax stage 3–5 |
| `models[]` | ONNX branch (or `model_unavailable`) |
| `rules[]` | Rules branch (or `rule_unavailable`) |
| Decode / ingest context | `source`, segment, `asset_ref`, channels, catalog_ver, mode |
| Asset changes | Asset-detector events in the same window |
| Graph diffs | Communication-graph events in the same window (`new_edge`, `gateway_bypass`, …) |
| Honeypot pointer | Closed log filename + seq range, if any |

**Not collected:** ground-truth labels. Eval joins by `event_id` / `incident_id` after the LLM returns.

### Stage B — correlate into incidents

| Rule | Behavior |
| --- | --- |
| Key | `(source, segment, asset_ref or technique-family)` inside `CORRELATE_WINDOW` (default 120 s) |
| Merge | GPS spoof rule + physics-ae + GNSS-1/2 split + AIS-follow → **one** incident |
| Dedup | `throughput-lstm` firing every hop → one flood incident, `alert_count++` |
| Promote | `name_change`, `decoy_contact`, `new_edge`, or `gateway_bypass` attach to an open incident on the same SA / unit-id |
| Split | Different techniques on different assets stay separate incidents |
| Close | No matching alert for `QUIET_WINDOW` → `state: closed` |

Lifecycle: `open` → `update` → `closed`. Timeout must not invent models or rules.

### Stage C — risk score

The correlator assigns a **transparent** `risk` object on every open/update. It is not an LLM score and not ground truth.

| Component | Range | Inputs |
| --- | --- | --- |
| `impact` | 0–40 | Max `criticality` of member assets **and** their `dependents` |
| `likelihood` | 0–25 | Model scores, rule severity, `join_incomplete` (caps, does not invent) |
| `blast_radius` | 0–20 | Count / weight of downstream dependents in the asset dependency graph |
| `control_plane` | 0–15 | Any member `OTEvent` with `is_control` or `is_write` on criticality ≥ 4, or `privileged` |
| `total` | 0–100 | Sum of the four, capped |

`nis2_significant` is true when any of:

- `total >= NIS2_THRESHOLD` (default **70**)
- Impact technique T0827 / T0829 / T0831 / T0832 on a `nis2_service` other than `none`
- `is_control` on an asset with `criticality >= 4`

Worked overlay `gps-spoof-underway`: GNSS-1 criticality 5, dependents autopilot/rudder/AIS/MFD, impacts T0832/T0829 → `nis2_significant: true` even before flood-class bus load.

### NIS2 reporting (UI alert)

NIS2 Article 23 applies only to **significant** incidents. The sensor does **not** auto-file to a CSIRT. When `nis2_significant` becomes true, the operator UI raises a **NIS2 alert** and starts clocks from `t_aware` (= `t_open` of that transition):

| Stage | Clock | UI |
| --- | --- | --- |
| Early warning | 24 h from `t_aware` | Alert: suspected malicious? cross-border? |
| Incident notification | 72 h from `t_aware` | Update: severity, impact, IoCs from `evidence_summary` |
| Recipients | Without undue delay | Separate task if service recipients (bridge/crew systems) are affected |
| Final report | 1 month after the **notification** is submitted | Root cause, mitigation, cross-border; progress report if still open |

`Nis2UiAlert.human_confirm` must be true before any CSIRT/competent-authority submit — same confirmation path as TAXII Share and actuation. `prod` never includes GT. STIX bundle may be attached as supporting intel; it is not a substitute for the Article 23 form.

### Incident (what the LLM interprets)

```
{
  "incident_id": "inc-01J…",
  "state": "open",
  "t_open": "...",
  "t_last": "...",
  "severity": "critical",
  "source": "n2k-nav",
  "protocol": "nmea2000",
  "segment": "nav",
  "asset_refs": [16],
  "techniques": ["T1692.002"],
  "impacts": ["T0832", "T0829"],
  "alert_count": 12,
  "alerts": [
    {
      "event_id": "01J…",
      "models": [
        { "model_id": "physics-ae", "version": "1.4.0", "scores": { "anomaly": 0.91, "fault_likelihood": 0.08 } }
      ],
      "rules": [
        { "rule_id": "gps-spoof-nav", "version": "1.0.0", "fired": true }
      ]
    }
  ],
  "assets": [],
  "graph": [
    { "change": "new_edge", "src": 44, "dst": 56, "pgn": 127237, "segment": "nav" }
  ],
  "honeypot": { "log_file": "hp-prod-opv1-nav-…-r0007.jsonl.gz", "seq_from": 1800, "seq_to": 1842 },
  "evidence_ref": "ev-01J…",
  "evidence_summary": {
    "top_features": ["gnss_dr_residual_m", "cog_heading_residual_deg", "gnss1_gnss2_split_m"],
    "packet_count": 18,
    "window_s": 30,
    "assets": [16, 17, 35]
  },
  "catalog_ver": "2026.03",
  "mode": "prod",
  "stix_ref": "reports/stix/prod/opv1/inc-01J….json"
}
```

The LLM is not called for every alert. `dev` scores incidents against labels after the fact (`incident_id` ↔ `attack_id`), never by stuffing GT into this object.

## Explainability / evidence view

Required because ONNX is on the path. Operators must see **exactly** which packets, fields, sequences, assets, and time windows produced an anomaly or classification. The SLM `alert_body` sits **beside** this view; it does not replace it.

Attribution is computed at enrich time (ONNX branch and rules branch) and stored under `evidence_ref`. Incident construction copies a compact `evidence_summary` onto the object the LLM sees. The full packet list stays on the operator surface and is never prompt input.

```
ONNX / rules → evidence store (keyed by event_id)
incidents    → evidence_ref + evidence_summary
honeypot     → seq range for packet drill-down
                ↓
operator evidence view (full)     LLM (top-k features, counts, window only)
```

### Lineage (per `event_id`)

| Layer | Recorded | Source |
| --- | --- | --- |
| Time window | `t_start`, `t_end`, duration, hop, `catalog_ver`, `mode` | Bytewax stage 2 |
| Packets | TAP `seq`, `t`, `pgn`, `sa`, `da`, contributing field names | Decode + honeypot seq range |
| Fields | Named features / PGN fields and attribution share | Bytewax + model `explain.method` |
| Sequence | Per-step contribution (LSTM hops, claim-rate series) | ONNX sequence models |
| Assets | `asset_ref` / SA / NAME in the window | Asset detector |
| Rules | Which `all` / `any` / `not` clauses fired or suppressed | Rules branch |
| Graph | Violating edges in the same window, if any | Communication graph |

### Attribution methods

Declared in `config.yaml`. Failed attribution is `explain_unavailable` (score still valid; the view says attribution is missing).

| Model | Method | Operator sees |
| --- | --- | --- |
| physics-ae | Native per-feature reconstruction residual | Residual share per analog field |
| throughput-lstm | Occlusion (or integrated gradients) over 20×8 | Which hops and which bus-load channels |
| claim-flood-seq | Same over the claim-rate sequence | Which SAs / PGNs in the storm |
| multi-head | Head scores + top residual features | `anomaly` vs `fault_likelihood` split |
| rules | Predicate trace at fire time | Clause values, not a learned attribution |

### Evidence object (operator store)

```
{
  "evidence_id": "ev-01J…",
  "event_id": "01J…",
  "incident_id": "inc-01J…",
  "window": { "t_start": "2026-09-08T19:00:30Z", "t_end": "2026-09-08T19:01:00Z", "duration_s": 30, "hop_s": 5 },
  "assets": [
    { "sa": 16, "name": "GNSS-1", "segment": "nav" },
    { "sa": 17, "name": "GNSS-2", "segment": "nav" },
    { "sa": 35, "name": "Gyro", "segment": "nav" }
  ],
  "packets": [
    { "seq": 1812, "t": "2026-09-08T19:00:42Z", "pgn": 129029, "sa": 16, "da": 255, "fields": ["lat", "lon", "hdop", "sat_count"] }
  ],
  "features": { "gnss_dr_residual_m": 82.4, "hdop": 1.1, "cog_heading_residual_deg": 22.0, "gnss1_gnss2_split_m": 41.0 },
  "models": [
    {
      "model_id": "physics-ae",
      "version": "1.4.0",
      "method": "residual",
      "scores": { "anomaly": 0.91, "fault_likelihood": 0.08 },
      "top_features": [
        { "name": "gnss_dr_residual_m", "contribution": 0.62 },
        { "name": "cog_heading_residual_deg", "contribution": 0.18 },
        { "name": "gnss1_gnss2_split_m", "contribution": 0.14 }
      ]
    }
  ],
  "rules": [
    {
      "rule_id": "gps-spoof-nav",
      "clauses_fired": ["all.gnss_dr_residual_m", "all.hdop", "all.sat_count", "all.cog_heading"],
      "clauses_suppressed": ["not.hdop>6", "not.sat_count_drop"]
    }
  ],
  "honeypot": { "log_file": "hp-prod-opv1-nav-vcannav-20260908T190000Z-20260908T195959Z-n18420-b2202010-kcan+error-r0007.jsonl.gz", "seq_from": 1800, "seq_to": 1842 }
}
```

Ground-truth labels are **not** on this object. Packet rows jump to the closed honeypot filename + `seq`.

### Worked overlays

| Incident | Packets | Fields that moved the score | Sequence | Assets | Window |
| --- | --- | --- | --- | --- | --- |
| `gps-spoof-underway` | 129025 / 129026 / 129029 / 129539 from SA 16; GNSS-2 129029; gyro 127250 | `gnss_dr_residual_m`, `cog_heading_residual_deg`, `gnss1_gnss2_split_m`; HDOP stays healthy | physics-ae is not sequential | GNSS-1, GNSS-2, gyro | 30 s / hop 5 s during `ramp` |
| `PGN flood` | High-rate mixed PGNs on the TAP | `bus_load_pct`, `frames_per_s_norm` | Last LSTM hops dominate `flood_score` | Many SAs | 2 s / 20×100 ms |
| Contrast: `GNSS-degraded` | Same GNSS PGNs, quality collapse | `hdop`, `sat_count` — **not** DR residual | — | GNSS-1/2 | Same 30 s; `gps-spoof-nav` `not` clauses suppress |

### Modes

| | `dev` | `prod` |
| --- | --- | --- |
| Evidence store | On | On |
| GT on evidence rows | Forbidden | Forbidden |
| LLM | Local SLM; `evidence_summary` only | Local SLM; `evidence_summary` only. Remote endpoint fatal |

## Local SLM (alert generation)

Detection is ONNX + rules + correlation. The **small LLM does not fire alerts**. After an incident opens or materially updates, a GGUF model on the **sensor host** writes the watchstander-facing alert: `alert_title` (list row) and `alert_body` (detail / NIS2 draft). Same isolation as before: `evidence_summary` only, no raw CAN, no honeypot blobs, no labels.

Sample pack: [watchstander-slm 1.0.0](./samples/models/watchstander-slm/1.0.0/). Weights (`model.gguf`) are not in git.

```
models/watchstander-slm/<semver>/
  config.yaml
  operator-alert.schema.json
  model-card.md
  model.gguf                 # signed artifact; not in the repo
```

```
incident open/update
        → llama.cpp (constrained JSON)
        → CopilotAssessment (alert_title, alert_body, tactics, techniques, …)
        → operator list + STIX note
fail (load / timeout / bad JSON)
        → status=llm_unavailable
        → template fallback; incident / risk / NIS2 clocks unchanged
```

### Runtime

| | `dev` | `prod` |
| --- | --- | --- |
| Host | Sensor process, local GGUF | Same |
| Remote API | Allowed only if `LLM_ENDPOINT` is loopback for tests | **Fatal** if `LLM_ENDPOINT` is set |
| Size class | ~8B Q4_K_M (~5 GiB), 8 GiB RAM minimum, GPU optional | Same pin |
| Timeout | 8 s | 8 s |
| ATT&CK retrieval | Vendored JSON (optional lab TAXII) | Vendored JSON only |

`prod_network: deny` in `config.yaml`. The SLM shares the same signed-artifact channel as ONNX weights.

### Inputs

- The **incident** (`incident_id`, `state`, `severity`, `risk`, member `alerts[]` with `event_id`s, `models[]`, `rules[]`, `assets[]`, violating `graph[]` edges, honeypot pointer, `evidence_summary`).
- Retrieved ATT&CK for ICS objects (**vendored** STIX JSON). Inbound TAXII is not required to generate an alert.
- PGN semantics from the catalog.
- Compact topology / inventory snippet (not the full live adjacency).
- Model cards and rule cards (what a score or fire means, known false-positive classes).
- **Not** ground-truth labels. Even in `dev`, labels join after emit (`incident_id` ↔ `attack_id`).

### Outputs (`CopilotAssessment`)

Constrained decode against [operator-alert.schema.json](./samples/models/watchstander-slm/1.0.0/operator-alert.schema.json). Then post-validate.

| Field | Purpose |
| --- | --- |
| `alert_title` | ≤120 chars. Incident list and NIS2 early-warning subject |
| `alert_body` | ≤1200 chars. Watchstander explanation; STIX `note` |
| `tactics` / `techniques` | Must be ⊆ incident techniques ∪ retrieved ATT&CK ids in the prompt. Extra IDs dropped |
| `confidence` | Bound to model scores and rule fires — **not** an SLM self-score |
| `recommend` | Detect / contain only (TAP health, gateway allowlist review, isolate talker) |
| `fault_vs_attack` | `attack` \| `fault` \| `undetermined`. Must follow `fault_likelihood` and rule `not` clauses |
| `status` | `ok` \| `llm_unavailable` \| `schema_invalid` |
| `runtime` | `local` |

The SLM must **not** set `severity`, `risk.total`, or `nis2_significant`. Guardrail: no tool that writes PGN, changes engine/autopilot state, or closes a gateway.

### Template fallback (`llm_unavailable`)

```
{severity} {rule_id or model_id} on assets {asset_ids}; risk {total}
```

UI shows the fallback title and a banner; evidence view is unchanged.

### Worked overlay: `gps-spoof-underway`

Example `ok` output (not ground truth):

```
{
  "incident_id": "inc-01J…",
  "model_id": "watchstander-slm",
  "version": "1.0.0",
  "runtime": "local",
  "status": "ok",
  "alert_title": "GNSS-1 walked off dead-reckoning; distrust position and AIS",
  "alert_body": "GNSS-1 reports a healthy-looking fix that disagrees with gyro dead-reckoning and GNSS-2. Autopilot, rudder, AIS, and MFD depend on this fix. Do not let heading-control follow spoofed COG. Prefer gyro + GNSS-2. Not GNSS-degraded: HDOP stayed low.",
  "tactics": ["impair-process-control"],
  "techniques": ["T1692.002", "T0832", "T0829"],
  "fault_vs_attack": "attack",
  "recommend": [
    "Distrust GNSS-1 and AIS derived from it",
    "Keep autopilot off spoofed COG until GNSS-1 is isolated"
  ]
}
```

### ATT&CK for ICS mapping

Primary techniques for this bus. RF GNSS spoofing is an **off-bus precursor**; on N2K it still presents as unauthorized or spoofed reporting PGNs.

| ID | Name | Typical N2K presentation |
| --- | --- | --- |
| [T1692](https://attack.mitre.org/techniques/T1692/) | Unauthorized Message | Injected PGN that is not from the legitimate talker |
| [T1692.001](https://attack.mitre.org/techniques/T1692/001/) | Command Message | Autopilot heading/track control, engine/thruster commands |
| [T1692.002](https://attack.mitre.org/techniques/T1692/002/) | Reporting Message | GNSS, AIS, heading, RPM, depth, battery spoof |
| [T0856](https://attack.mitre.org/techniques/T0856/) | Spoof Reporting Message | Legacy alias for reporting spoof where still referenced |
| [T0848](https://attack.mitre.org/techniques/T0848/) | Rogue Master | ISO 11783 address claim / NAME spoof, SA theft |
| [T0814](https://attack.mitre.org/techniques/T0814/) | Denial of Service | PGN flood, error frames, Fast Packet exhaustion |

Impact techniques the co-pilot may attach after the above:

| ID | Name | Marine OT meaning |
| --- | --- | --- |
| [T0829](https://attack.mitre.org/techniques/T0829/) | Loss of View | Bridge loses trustworthy position/heading/AIS |
| [T0827](https://attack.mitre.org/techniques/T0827/) | Loss of Control | Autopilot or machinery commands denied or unreliable |
| [T0832](https://attack.mitre.org/techniques/T0832/) | Manipulation of View | Displays show attacker-chosen nav or machinery state |
| [T0831](https://attack.mitre.org/techniques/T0831/) | Manipulation of Control | Unauthorized heading/RPM/thruster effect |

Retrieval should prefer ICS objects. Enterprise ATT&CK is used only when the incident clearly leaves the bus (e.g. later C2 on IT), not to re-label CAN frames.

## STIX reporting

After the SLM returns `alert_title` / `alert_body` and structured tactics / techniques, the sensor writes a **STIX 2.1 bundle** for that incident. Retrieval of ATT&CK objects is **vendored JSON** on the host; this stage is **outbound reporting**.

It does not sit on CAN. It consumes the incident, `evidence_summary`, and SLM fields only.

```
incident + CopilotAssessment → STIX 2.1 bundle
        → reports/stix/{mode}/{hull}/{incident_id}.json     (always)
        → TAXII 2.1 collection ot-incidents                 (optional; off-ship needs a human)
```

Emit on incident **open**, material **update**, and **closed** (rewrite `last_seen`). Not on every Bytewax hop. `prod` refuses to start if a STIX sink is configured to include labels.

### Objects in the bundle

Prefer MITRE ATT&CK STIX IDs when the catalog is vendored. Otherwise mint a local `attack-pattern` with `external_references` (`source_name: mitre-attack`, `external_id: T1692.002`). There is no first-class STIX 2.1 `incident` object; the shareable unit is a `report` plus a `grouping` (`context: suspicious-activity`).

| STIX type | Role here |
| --- | --- |
| `identity` | This sensor (`identity_class: system`). Hull/vessel identity omitted when `STIX_REDACT_HULL=true` |
| `infrastructure` | Segment backbone (`infrastructure_types: control-system`), not CMS/weapons |
| `attack-pattern` | ATT&CK for ICS techniques and impacts from the co-pilot |
| `observed-data` | Window `first_observed` / `last_observed`, `number_observed` = packet_count |
| `x-ot-window` | Custom SCO: `protocol`, `source`, `segment`, channels, `asset_refs`. **No lat/lon, no payload** |
| `sighting` | `sighting_of_ref` → attack-pattern; `observed_data_refs`; `count` = alert_count |
| `note` | SLM `alert_body` (abstract). Not the packet list |
| `course-of-action` | Detect/contain recommendations. Not an actuation ticket |
| `grouping` | `context: suspicious-activity`, object_refs for this incident |
| `report` | `report_types: ["incident"]`, name from techniques + segment, `object_refs` of the rest |
| `indicator` | Only if a repeatable pattern exists (e.g. rogue SA + PGN). Optional; not minted for one-shot spoofs |

Relationships: `sighting` of `attack-pattern`; `observed-data` `object_refs` the custom window; `report` contains all of the above.

### Sanitization

| In the bundle? | `dev` | `prod` |
| --- | --- | --- |
| Technique IDs, scores, severity, window | Yes | Yes |
| `evidence_summary` (top features, packet_count, assets) | Yes | Yes |
| Raw CAN / `payload_b64` / honeypot blob | **No** | **No** |
| Full evidence packet list | **No** (operator view only) | **No** |
| Ground-truth / `attack_id` / scenario link | **No** | **No** |
| Honeypot **closed filename** + seq range | Optional pointer | Optional; off-ship TAXII omits by default |
| Hull id / precise lat-lon | Allowed locally | Redact when `STIX_REDACT_HULL` or TAXII |

### Worked bundle (`gps-spoof-underway`)

Local file: `reports/stix/prod/opv1/inc-01J….json`

```
{
  "type": "bundle",
  "id": "bundle--7c4e2a11-9b08-4d3f-a1c0-0b1c2d3e4f50",
  "objects": [
    {
      "type": "identity",
      "spec_version": "2.1",
      "id": "identity--11111111-2222-4333-8444-555555555555",
      "created": "2026-09-08T19:01:05Z",
      "modified": "2026-09-08T19:01:05Z",
      "name": "OT sensor",
      "identity_class": "system"
    },
    {
      "type": "infrastructure",
      "spec_version": "2.1",
      "id": "infrastructure--aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
      "created": "2026-09-08T19:01:05Z",
      "modified": "2026-09-08T19:01:05Z",
      "name": "OPV nav NMEA 2000",
      "infrastructure_types": ["control-system"]
    },
    {
      "type": "attack-pattern",
      "spec_version": "2.1",
      "id": "attack-pattern--0f1e2d3c-4b5a-4678-89ab-cdef01234567",
      "created": "2026-09-08T19:01:05Z",
      "modified": "2026-09-08T19:01:05Z",
      "name": "Spoof Reporting Message",
      "external_references": [
        { "source_name": "mitre-attack", "external_id": "T1692.002", "url": "https://attack.mitre.org/techniques/T1692/002/" }
      ]
    },
    {
      "type": "observed-data",
      "spec_version": "2.1",
      "id": "observed-data--aaaa1111-bbbb-4ccc-8ddd-eeee22223333",
      "created": "2026-09-08T19:01:05Z",
      "modified": "2026-09-08T19:01:05Z",
      "first_observed": "2026-09-08T19:00:30Z",
      "last_observed": "2026-09-08T19:01:00Z",
      "number_observed": 18,
      "object_refs": ["x-ot-window--ffff0000-1111-4222-8333-444455556666"]
    },
    {
      "type": "x-ot-window",
      "id": "x-ot-window--ffff0000-1111-4222-8333-444455556666",
      "protocol": "nmea2000",
      "source": "n2k-nav",
      "segment": "nav",
      "channels": [129025, 129026, 129029, 129539],
      "asset_refs": [16, 17, 35]
    },
    {
      "type": "sighting",
      "spec_version": "2.1",
      "id": "sighting--9999aaaa-bbbb-4ccc-8ddd-eeeeffff0000",
      "created": "2026-09-08T19:01:05Z",
      "modified": "2026-09-08T19:01:05Z",
      "count": 12,
      "first_seen": "2026-09-08T19:00:30Z",
      "last_seen": "2026-09-08T19:01:00Z",
      "sighting_of_ref": "attack-pattern--0f1e2d3c-4b5a-4678-89ab-cdef01234567",
      "observed_data_refs": ["observed-data--aaaa1111-bbbb-4ccc-8ddd-eeee22223333"],
      "where_sighted_refs": ["identity--11111111-2222-4333-8444-555555555555"]
    },
    {
      "type": "note",
      "spec_version": "2.1",
      "id": "note--12345678-90ab-4cde-8f01-23456789abcd",
      "created": "2026-09-08T19:01:05Z",
      "modified": "2026-09-08T19:01:05Z",
      "content": "Healthy-looking GNSS-1 walked off dead-reckoning; HDOP stayed low. Distrust GNSS-1 and AIS derived from it. Not GNSS-degraded.",
      "object_refs": ["sighting--9999aaaa-bbbb-4ccc-8ddd-eeeeffff0000"]
    },
    {
      "type": "course-of-action",
      "spec_version": "2.1",
      "id": "course-of-action--c0a1c0a1-c0a1-4c0a-8c0a-c0a1c0a1c0a1",
      "created": "2026-09-08T19:01:05Z",
      "modified": "2026-09-08T19:01:05Z",
      "name": "Prefer gyro + DR / GNSS-2; do not let autopilot follow spoofed COG",
      "description": "Detect/contain only. Human confirms any TAP or gateway change."
    },
    {
      "type": "grouping",
      "spec_version": "2.1",
      "id": "grouping--0a0a0a0a-0b0b-4c0c-8d0d-0e0e0e0e0e0e",
      "created": "2026-09-08T19:01:05Z",
      "modified": "2026-09-08T19:01:05Z",
      "name": "inc-01J…",
      "context": "suspicious-activity",
      "object_refs": [
        "sighting--9999aaaa-bbbb-4ccc-8ddd-eeeeffff0000",
        "observed-data--aaaa1111-bbbb-4ccc-8ddd-eeee22223333",
        "infrastructure--aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
      ]
    },
    {
      "type": "report",
      "spec_version": "2.1",
      "id": "report--b100b100-b100-4b10-8b10-b100b100b100",
      "created": "2026-09-08T19:01:05Z",
      "modified": "2026-09-08T19:01:05Z",
      "name": "NMEA 2000 reporting spoof on nav",
      "report_types": ["incident"],
      "published": "2026-09-08T19:01:05Z",
      "object_refs": [
        "identity--11111111-2222-4333-8444-555555555555",
        "infrastructure--aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "attack-pattern--0f1e2d3c-4b5a-4678-89ab-cdef01234567",
        "observed-data--aaaa1111-bbbb-4ccc-8ddd-eeee22223333",
        "sighting--9999aaaa-bbbb-4ccc-8ddd-eeeeffff0000",
        "note--12345678-90ab-4cde-8f01-23456789abcd",
        "course-of-action--c0a1c0a1-c0a1-4c0a-8c0a-c0a1c0a1c0a1",
        "grouping--0a0a0a0a-0b0b-4c0c-8d0d-0e0e0e0e0e0e"
      ]
    }
  ]
}
```

Impact techniques T0832 / T0829 are additional `attack-pattern` objects (or vendored MITRE IDs) referenced from the same `report`. `confidence` on the sighting is bound to model scores and rule fires, not to an LLM self-score.

### TAXII

| | Local bundle | TAXII 2.1 |
| --- | --- | --- |
| Default | On | Off (`STIX_TAXII=off`) |
| When | Incident open / update / closed | Operator **Share** on a closed (or explicitly selected) incident |
| Collection | — | `ot-incidents` |
| Off-ship | File stays on the sensor host | Human confirmation path, same as actuation |
| Labels | Never | Never |

`prod` startup is fatal if `TAXII_INCLUDE_LABELS` or a label topic is set. The exporter does not read the honeypot body.

### Modes

| | `dev` | `prod` |
| --- | --- | --- |
| Local STIX | On | On |
| GT in bundle | Forbidden | Forbidden |
| TAXII | Lab collection if enabled | Off unless operator share; redact hull by default |

## Operator surface

- Incident list grouped by segment, **risk score**, and suspected technique, with the SLM **`alert_title`** (or template fallback).
- **NIS2 UI alert** when `nis2_significant`: clocks for 24 h early warning, 72 h notification, 1-month final report; suspected malicious / cross-border / recipients; submit only after human confirm. Early-warning draft uses `alert_title` / `alert_body`.
- Incident detail: member alerts, **risk components**, criticality and dependents, PGN fields, residuals, model scores, **rule hits**, **asset changes**, **graph diffs**, join completeness (`join_incomplete`), SLM `alert_body` (or `llm_unavailable` banner). Optional honeypot pointer uses the **closed filename** (`hp-{mode}-{hull}-…-rNNNN.jsonl.gz`).
- Asset inventory: live vs expected talkers, **criticality**, **dependency graph**.
- Topology / communication graph: expected vs live overlay. Violating edges jump to the open incident. The full adjacency is not sent to the LLM.
- Evidence view: packets, fields, sequences, assets, and windows for the open incident (full store; not the LLM prompt).
- STIX 2.1: local bundle path plus optional TAXII **Share** (off-ship confirm). Scenario link only in `dev`, and only from the parallel eval join — never from the incident the LLM saw or the STIX bundle.

## Coupling to the simulator

The lab simulator is **NMEA 2000 only** (`vcan_*` / in-memory CAN + `segment`). The label topic is `dev`-only. Other sensor adapters in `sources.yaml` are for ship capture, not this simulator.

| Channel | Sensor `dev` | Sensor `prod` |
| --- | --- | --- |
| Normalized units | Same ingest contract | Same ingest contract |
| N2K TAP + `segment` | Lab simulator / pcap / sniffer | Ship TAP |
| Other protocols | Not emitted by this simulator | Ship maps only; read-only; no GT |
| Label topic | Subscribe; join off-bus for training and scoring | **Absent.** Bind attempt is a fatal config error |
| Honeypot logs | Self-describing filenames; raw inflow, any format | Same; no GT in name or body |
| Asset inventory | Live catalog + change events | Live catalog + change events; no GT |
| Comms graph | Expected vs live overlay; violating edges on incidents | Same; no GT |
| STIX 2.1 | Local bundle; TAXII optional | Local bundle; TAXII share is operator-confirmed; no GT |
| Local SLM | GGUF on host; incident prompt (no GT) | Same; `LLM_ENDPOINT` fatal |

The sensor does not import simulator internals. Byte-level captures are interchangeable per protocol so a `prod` sensor can be certified against an unlabeled simulator.

## Out of scope

Model training, MITRE dataset packaging, CMS / combat-system buses, and any transmit path onto a live NMEA 2000 network.

## Lab implementation

Code and tests: [ot-lab.md](./ot-lab.md). `FeatureStage` implements the Bytewax window contract in-process; ONNX and rules stay sibling enrichers. `pytest tests` covers each sensor service plus `gps-spoof-primary` end-to-end (`nis2_significant`, SLM fail-closed, local STIX).
