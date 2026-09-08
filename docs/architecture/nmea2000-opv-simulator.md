# NMEA 2000 simulator for an OPV / corvette

Separate system from the OT sensor. It emits IEC 61162-3 / NMEA 2000 traffic that matches a military offshore patrol vessel (OPV) / corvette marine-OT layout: four isolated backbones, device twins with ISO 11783 NAME and source addresses, isolating gateways, and an attack injector. Ground-truth labels are a **`dev`-only** parallel topic.

Combat management, weapons, and tactical datalinks stay **off** these buses. A CMS stub may consume gateway-exported navigation data; it does not sit on N2K.

The sensor TAP contract is defined in [ot-sensor-nmea2000.md](./ot-sensor-nmea2000.md). This simulator is the lab source of that TAP. It is **not** deployed on the vessel.

Runtime is `SIM_MODE=dev|prod`. `prod` here means **unlabeled / ship-shaped CAN** for certifying a `prod` sensor — not a ship install.

```
Scenario engine ─┐
                 ├→ device twins → nav | propulsion | power | aux
Attack injector ─┘                         │
                                           ▼
                                  isolating gateways
                                           │
                                       vcan TAP
                                           │
                                      OT sensor ingest

dev only:  attack injector also writes the label topic (parallel, never on CAN)
prod:      no label topic, no GT publisher
```

## Design principles

- **Physics-first benign traffic.** Kinematics drive GNSS, heading, SOG, RPM, and depth so residuals are realistic for ONNX training.
- **Segment isolation by default.** Gateways are one-way or tightly allowlisted. Engine commands never appear on the nav backbone.
- **Labels are parallel, not in-band.** Attack metadata is a separate topic so CAN remains byte-identical to a sniffer capture.
- **No ground truth in prod.** `SIM_MODE=prod` does not create, bind, or emit the label topic.
- **No shared transceiver with a live ship.** Lab `vcan` or an isolated USB-CAN adapter only.
- **NMEA 2000 only.** The simulator publishes IEC 61162-3 frames (device twins, gateways, injector). It does not start a Modbus slave or an NMEA 0183 talker. The sensor may still ingest other protocols on the ship; this process is not that source.

## Runtime modes

| | `dev` | `prod` |
| --- | --- | --- |
| Where it runs | Lab / CI | Lab only (certify unlabeled sensor path). Never on the vessel |
| CAN frames + `segment` | Yes | Yes (same byte contract) |
| Label topic | Published | **Not published.** Config that sets `LABEL_TOPIC` is a fatal error |
| Attack injector | Allowed when a scenario enables it; each injection is labeled | Allowed for blind tests (attacks on CAN only); **no** GT records |
| Pairing | Sensor `dev` (eval join) | Sensor `prod` (must detect without labels) |

## Vessel configuration (OPV / corvette)

Representative surface patrol craft, not a specific hull class. Four N2K Mini trunks, each with 120 Ω terminators, a single power feed, ≤50 nodes, drop length ≤6 m.

| Segment | Role | Isolation intent |
| --- | --- | --- |
| `nav` | Bridge navigation and conning | Highest integrity for position, heading, AIS |
| `propulsion` | Twin diesel, gearbox, fuel, bow thruster | Machinery OT; no CMS nodes |
| `power` | Gensets, battery banks, switchbank | Electrical OT |
| `aux` | Tanks, environment, bilge / fire binaries | Hotel and damage-control adjacent |

CMS, radar video, EO/IR, and Link-16 are out of band. If the lab needs a consumer, the **nav gateway export** (position, COG/SOG, heading) is a read-only feed.

## Backbones, devices, and PGNs

Each twin has a stable source address and ISO 11783 NAME. Periodic publish includes jitter. Large GNSS and AIS use Fast Packet.

### Navigation

| Device twin | Example SA | PGNs (illustrative) |
| --- | --- | --- |
| GNSS-1 (primary) | 16 | 129025 position rapid, 129026 COG/SOG, 129029 GNSS position data, 129539 DOPs, 126992 system time |
| GNSS-2 (secondary) | 17 | same as GNSS-1, independent residual |
| Gyro / heading | 35 | 127250 vessel heading, 127251 rate of turn, 127257 attitude |
| AIS transponder | 24 | 129038 Class A position, 129794 Class A static and voyage |
| Echo sounder | 40 | 128267 water depth, 128259 speed water referenced |
| Wind | 48 | 130306 wind data |
| Rudder | 52 | 127245 rudder |
| Autopilot | 56 | 127237 heading/track control (command + status as applicable) |
| MFD / bridge display | 60 | consumer; may request / display only |
| Honeypot decoy | 99 | Address-claim + NAME only. No operational PGNs. Target for unauthorized commands; sensor collector logs all inflow including traffic to this SA |

### Propulsion

| Device twin | Example SA | PGNs |
| --- | --- | --- |
| Engine port | 0 | 127488 rapid (RPM, boost, trim), 127489 dynamic (temps, pressures, load) |
| Engine stbd | 1 | 127488, 127489 |
| Transmission port / stbd | 4 / 5 | 127493 transmission parameters |
| Fuel / fluid | 8 | 127505 fluid level, trip fuel as configured |
| Bow thruster | 12 | thruster / binary or vendor PGNs mapped in catalog |

### Power

| Device twin | Example SA | PGNs |
| --- | --- | --- |
| Genset 1 / 2 | 20 / 21 | converter / generator status, AC/DC as catalogued |
| Battery bank | 28 | 127508 battery status |
| Switchbank | 32 | 127501 binary status report |

### Auxiliary

| Device twin | Example SA | PGNs |
| --- | --- | --- |
| Environment | 80 | 130310 / 130311 environmental parameters |
| Tanks (other than fuel) | 84 | 127505 fluid level |
| Bilge / fire binaries | 88 | 127501 binary status |

Address ranges above are **lab defaults**. The vessel model file consumed by both simulator and sensor is the source of truth.

## Isolating gateways

| Path | Policy |
| --- | --- |
| nav → propulsion | Allowlist: heading, COG/SOG, time (machinery displays) |
| nav → CMS stub | Allowlist: position, COG/SOG, heading (read-only export) |
| propulsion → nav | Deny by default (no RPM or engine commands on the bridge bus) |
| power → aux | Selected battery / genset status if hotel displays need it |
| Any → any command PGN | Deny unless explicitly listed |

Gateway violations in an attack scenario are first-class: the injector can force a **policy bypass** so the sensor sees `cross_segment_pgn` and a communication-graph `gateway_bypass` edge. The allowlists above are the **expected graph** the sensor diffs against.

## Simulator internals

### Scenario engine

Drives a kinematic and plant state so twins stay consistent. Attack overlays (such as [GPS spoofing](#gps-spoofing-scenario)) run on top of a benign base scenario; they do not replace kinematics.

| Scenario | Kind | What twins do |
| --- | --- | --- |
| Underway | Benign | Dual GNSS, gyro, engines loaded, AIS transmitting |
| Alongside | Benign | Near-zero SOG, gensets/hotel bias, thruster available |
| RAS approach | Benign | Tight heading/ROT coupling, GNSS still valid |
| Darken-ship | Benign | Reduced display traffic; plant still publishing |
| GNSS-degraded | Benign fault | GNSS quality/DOP collapse; dead-reckoning still consistent — **not** a spoof |
| GPS-spoof-underway | Attack overlay | Underway kinematics + GPS spoofing (see below) |

### Device twins

- Start-of-run ISO 11783 address claim.
- Periodic PGN at catalog intervals plus jitter.
- Fast Packet for 129029 / AIS static as required.
- Independent noise on GNSS-1 vs GNSS-2 so a single-receiver spoof is detectable.

### Bus emulation

- Linux `vcan` per segment (`vcan_nav`, `vcan_prop`, `vcan_pwr`, `vcan_aux`) so the sensor uses SocketCAN decode unchanged.
- Optional in-process CAN for CI without extra interfaces.
- Optional pcap writer for replay.

### Attack injector

Injections change CAN contents only. Ground-truth tags go on the **label stream**, never inside the payload. In `prod` the injector may still write attack PGNs (blind test) but the label publisher is compiled/configured off.

| Attack | Segment | ATT&CK | Mechanism |
| --- | --- | --- | --- |
| GPS spoof (`gps-spoof-underway`) | nav | T1692.002 | Phased false 129025 / 129026 / 129029 while DOPs stay healthy; see [GPS spoofing scenario](#gps-spoofing-scenario) |
| AIS spoof | nav | T1692.002 | False 129038 / static PGNs |
| Heading spoof | nav | T1692.002 | False 127250 / 127251 |
| Unauthorized autopilot command | nav | T1692.001 | 127237 (or equivalent) from non-autopilot SA |
| Unauthorized engine command | propulsion | T1692.001 | Control PGN toward engine/thruster |
| Rogue Master | any | T0848 | Address claim / NAME spoof, SA theft |
| PGN flood | any | T0814 | High-rate flood; sample ONNX `throughput-lstm` is trained to fire on this pattern |
| Gateway bypass | cross-segment | T1692 + isolation failure | Engine or command PGN on nav; nav-only PGN forced onto propulsion outside allowlist |

Off-bus RF GNSS spoofing is **not** simulated at RF. `gps-spoof-underway` reproduces the **on-bus consequence** (unauthorized reporting PGNs) so the sensor’s N2K path is exercised. Scenario `GNSS-degraded` remains the benign counterpart: poor quality, position still on the DR track.

## GPS spoofing scenario

`scenario_id: gps-spoof-underway`. Overlay on **Underway**. The injector never touches RF; GNSS twins (or a colliding SA) publish a false track on `vcan_nav`.

Goal: look like a healthy GPS fix that slowly walks the ship off dead-reckoning, so models must not confuse it with `GNSS-degraded`.

### Variants

| `attack_id` | What is spoofed | Why it exists |
| --- | --- | --- |
| `gps-spoof-primary` | GNSS-1 only (SA 16) | Dual-receiver split: GNSS-2 stays on true kinematics |
| `gps-spoof-both` | GNSS-1 and GNSS-2 | Correlated spoof (both antennas / both talkers follow the lie) |
| `gps-spoof-sa-collision` | Rogue talker claims SA 16 | Bus injection without owning the receiver; may also present as T0848 |

Default lab run is `gps-spoof-primary`. AIS own-ship PGNs (129038) **follow GNSS-1**, as on a typical OPV where the transponder is slaved to the primary fix.

### Timeline

Times are offsets from overlay start. Base underway traffic continues throughout.

| Phase | Duration | Bus behavior |
| --- | --- | --- |
| `baseline` | 30 s | Both GNSS agree with gyro + SOG integration. DOPs healthy. |
| `ramp` | 60 s | Spoofed track starts at true position and pulls off at a bounded rate (meaconing-style). Satellite count and 129539 DOPs stay **good**. |
| `hold` | 90 s | Offset lat/lon and COG held. Heading, ROT, RPM, depth remain **true**. |
| `recover` | 20 s | Spoof stops; GNSS-1 snaps back to kinematic truth (or ramps, configurable). |

### PGNs mutated vs left true

| PGN | Twin | During spoof |
| --- | --- | --- |
| 129025 Position Rapid | GNSS-1 (and GNSS-2 if `gps-spoof-both`) | False lat/lon |
| 129026 COG/SOG | same | False COG; SOG kept near plant-consistent unless the variant requests a speed lie |
| 129029 GNSS Position Data | same | False position; method/satellite count stay “valid” |
| 129539 GNSS DOPs | same | Stay low (healthy) — opposite of `GNSS-degraded` |
| 126992 System time | GNSS | Unchanged (time-spoof is a different overlay) |
| 127250 / 127251 | Gyro | True |
| 127488 | Engines | True |
| 128267 | Echo sounder | True |
| 129038 AIS Class A position | AIS | Follows GNSS-1 (contaminated view) |

### Contrast with `GNSS-degraded`

| Signal | GPS spoof | GNSS-degraded (benign) |
| --- | --- | --- |
| 129539 DOP | Healthy | High / invalid |
| Satellite count | Stable, high | Drops |
| Position vs dead-reckoning | Walks off | Noisy but on-track |
| GNSS-1 vs GNSS-2 (`primary`) | Diverges | Both degrade together |
| `fault_likelihood` target | Low | High |

### Label records (`dev` only)

One label per mutated PGN emit during `ramp` and `hold`:

```
{
  "t": "...",
  "scenario_id": "gps-spoof-underway",
  "attack_id": "gps-spoof-primary",
  "technique": "T1692.002",
  "victim_sa": 16,
  "pgn": 129029,
  "segment": "nav",
  "phase": "ramp"
}
```

`baseline` and `recover` are unlabeled (or `attack_id: none`) so training can learn the edges. `prod` emits the same CAN with **no** label topic.

### Expected sensor / co-pilot outcome

Physics residuals: GNSS vs DR, GNSS-1 vs GNSS-2, COG vs heading, healthy-DOP-but-jump. Multi-head: `attack_family` ≈ reporting spoof, `fault_likelihood` low. Rule `gps-spoof-nav` fires on the same `event_id`. Alert correlation folds ONNX scores and the rule hit into **one incident** before the local SLM writes alert text.

SLM techniques: [T1692.002](https://attack.mitre.org/techniques/T1692/002/) (and T0856 if that alias is on the incident), impacts [T0832](https://attack.mitre.org/techniques/T0832/) Manipulation of View and [T0829](https://attack.mitre.org/techniques/T0829/) Loss of View. Example title: *GNSS-1 walked off dead-reckoning; distrust position and AIS*. Recommend: distrust GNSS-1 (and AIS derived from it), prefer gyro + DR / GNSS-2, do not let autopilot follow spoofed COG. No actuation.

### Label stream (`dev` only)

```
{ t, attack_id, technique, victim_sa, pgn, segment, scenario_id }
```

Published only when `SIM_MODE=dev`. Used to train ONNX heads and to score co-pilot technique IDs **after** inference — labels are not placed on the CAN bus and are not fed into the LLM prompt.

`SIM_MODE=prod` does not start the publisher. There is no empty topic and no heartbeat of “no attack”: the channel does not exist.

## Safety

- Simulator processes must not open a physical CAN interface that is cabled to a vessel backbone.
- TAP is one-way into the sensor.
- Attack injector is disabled unless a scenario explicitly enables it.
- `SIM_MODE=prod` on a process that still has `LABEL_TOPIC` set must exit before opening any CAN iface.

## Coupling to the OT sensor

| Channel | Simulator `dev` + sensor `dev` | Simulator `prod` + sensor `prod` | Ship (`prod` sensor) |
| --- | --- | --- | --- |
| CAN frames + `segment` | `vcan_*` (lab) | `vcan_*` (unlabeled) | Hardware TAP |
| Label topic | Present | **Absent** | **Absent** |
| Ground truth in LLM / SIEM | No (eval join only) | No | No |

Byte-level frames on the CAN channel are interchangeable. The sensor must not require simulator-specific headers on the bus and must not require a label topic in `prod`.

## Lab implementation

Code and tests: [ot-lab.md](./ot-lab.md). CI uses `InMemoryCanBus`; `vcan_*` is still the ship TAP contract. `uv run pytest` covers scenario, twins, gateways, injector, and labels. The lab binary is NMEA 2000 only.
