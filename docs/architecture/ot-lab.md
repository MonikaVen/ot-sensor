# OT lab implementation

Runnable **simulator** and **sensor** for the OPV architecture. Specs remain [nmea2000-opv-simulator.md](./nmea2000-opv-simulator.md) and [ot-sensor-nmea2000.md](./ot-sensor-nmea2000.md).

```
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev,onnx]'
.venv/bin/pytest tests -q
```

CI uses an **in-memory CAN bus** (`InMemoryCanBus`), not SocketCAN. Frame bytes and `segment` tags are the same contract as `vcan_*`. SocketCAN remains the ship TAP; it is not required to test services.

## Layout

```
src/otlab/          CanFrame, PGN pack, geo, in-memory bus
src/opv_sim/        scenario, N2K twins, gateways, injector, labels
src/ot_sensor/      adapters → honeypot, assets, graph, features, onnx, rules,
                    incidents, slm, stix, eval
tests/              one module per concern + end-to-end spoof
docs/architecture/  specs and sample maps / models
```

Feature windows match the Bytewax contract (`FeatureWindow` + `event_id`). The lab operator is `FeatureStage` in-process. A later Bytewax worker can replace it without changing ONNX/rules/incidents.

Ingest in this tree is in-process lists. Compose still targets NATS `4222` / Redpanda `can.raw.*` when the TAP reader exists; tests do not start a broker.

## Simulator services (`SIM_MODE=dev|prod`)

NMEA 2000 only: `PlantState` → device twins → `InMemoryCanBus` / `vcan_*`. No Modbus slave, no 0183 talker.

| Service | Module | Test | Notes |
| --- | --- | --- | --- |
| Scenario engine | `opv_sim.ScenarioEngine` | `test_simulator.py` | Underway kinematics; GNSS-degraded vs spoof phases |
| Device twins | `opv_sim.twins.DeviceTwins` | split GNSS-1/2 on spoof | PGNs 129025/026/029/539, 127250, 127488, 60928 |
| Isolating gateways | `IsolatingGateway` | RPM onto nav denied; `force_bypass` | Allowlist nav→prop: heading, COG/SOG |
| Attack injector | `AttackInjector` | overlay on twins | Labels only if `dev` |
| Label topic | `LabelTopic` | prod + `LABEL_TOPIC` fatal | No publisher in `prod`; CAN still flows |

CLI: `SIM_MODE=dev opv-sim --attack gps-spoof-primary --ticks 8`

## Sensor services (`SENSOR_MODE=dev|prod`)

| Service | Module | Test | Notes |
| --- | --- | --- | --- |
| N2K adapter | `ot_sensor.adapters.Nmea2000Adapter` | `OTEvent`; `writes` fatal in prod | Listen-only |
| NMEA 0183 adapter | `Nmea0183Adapter` | talker id + HDT | |
| Modbus adapter | `ModbusAdapter` | reads only | |
| Honeypot | `Honeypot` | rotate + retain cap | Async gzip; never unlink `open-{pid}` |
| Asset detector | `AssetDetector` | criticality 5, dependents | Loads `asset-criticality.yaml` |
| Comms graph | `CommsGraph` | `new_edge` for SA 44 | Expected vs live |
| Features (Bytewax 1–5) | `FeatureStage` | GNSS split / DR residual | No ONNX inside |
| ONNX enrich | `OnnxEnrich` | `throughput-lstm` or `model_unavailable` | Extra `otlab[onnx]` |
| Rules enrich | `RulesEnrich.gps_spoof_nav` | fires on healthy-DOP walk-off | Parallel to ONNX |
| Incidents | `IncidentCorrelator` | risk + NIS2; hop dedup | Does not wait on SLM |
| Local SLM | `LocalSlm` | `llm_unavailable` without GGUF; `LLM_ENDPOINT` fatal in prod | Template fallback |
| STIX 2.1 | `StixExporter` | local file, `taxii_shared=False` | |
| Eval join | `EvalJoin` | prod + label topic fatal | After emit; not in prompt |
| Dashboard | `ot_sensor.app` | `test_dashboard.py` | Asset map snapshot, `/api/snapshot` |

End-to-end: `test_pipeline.py` runs `gps-spoof-primary` ticks → `gps-spoof-nav` fire → `nis2_significant` → SLM fallback → STIX file. `dev` scores labels; `prod` has no label records.

CLI: `SENSOR_MODE=dev ot-sensor --ticks 10`

Operator UI: `ot-dashboard` (build `frontend/` first) on `:8443`.

## Dataflow (lab)

```
ScenarioEngine → DeviceTwins → InMemoryCanBus
                      ↓
              Nmea2000Adapter → OTEvent
                      ├→ Honeypot (rotate/retain)
                      ├→ AssetDetector
                      ├→ CommsGraph
                      └→ FeatureStage → ONNX ∥ rules → Incidents → LocalSlm → STIX
dev: LabelTopic ──→ EvalJoin (after SLM)
```

## Still not in this tree

- Linux `vcan_*` / SocketCAN TAP reader (needed before Redpanda/NATS on the hot path)
- GGUF `watchstander-slm` weights (fail closed)
- TAXII listener `:8444`, operator HTTPS `:8443`
- Full PGN catalog `pgn-2026.03.json` (lab codec covers the spoof/flood PGNs only)
