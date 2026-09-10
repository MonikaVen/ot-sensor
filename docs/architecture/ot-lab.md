# OT lab implementation

Runnable **simulator** and **sensor** for the OPV architecture. Specs remain [nmea2000-opv-simulator.md](./nmea2000-opv-simulator.md) and [ot-sensor-nmea2000.md](./ot-sensor-nmea2000.md).

```
uv python install 3.12
uv sync
uv run pytest -q
```

uv is the Python package manager (`uv sync`, `uv run`). Do not use `pip` or `python -m venv`.

CI uses an **in-memory CAN bus** (`InMemoryCanBus`), not SocketCAN. Frame bytes and `segment` tags are the same contract as `vcan_*`. SocketCAN remains the ship TAP; it is not required to test services.

## Layout

```
simulator/src/otlab/       CanFrame, PGN pack, geo, in-memory bus
simulator/src/opv_sim/     scenario, N2K twins, gateways, injector, labels
ot-sensor/src/ot_sensor/   adapters → honeypot, assets, graph, features, onnx, rules,
                           incidents, slm, stix, eval, dashboard
ot-sensor/frontend/        Vite + TypeScript operator UI
docs/architecture/         specs and sample maps / models
```

uv workspace: `simulator/` (`opv-sim`) and `ot-sensor/` (`ot-sensor`). The sensor depends on the simulator package for codecs and the batch lab. Live dashboard ingest is listen-only `GET /api/tap`. The **attack injector** is only on `opv-sim` (CLI `--attack` / `--serve` UI on `:8444`).

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

CLI: `SIM_MODE=dev uv run opv-sim --attack gps-spoof-primary --ticks 8`

Injector UI: `uv run opv-sim --serve --port 8444`

## Sensor services (`SENSOR_MODE=dev|prod`)

| Service | Module | Test | Notes |
| --- | --- | --- | --- |
| N2K adapter | `ot_sensor.adapters.Nmea2000Adapter` | `OTEvent`; `writes` fatal in prod | Listen-only |
| NMEA 0183 adapter | `Nmea0183Adapter` | talker id + HDT | |
| Modbus adapter | `ModbusAdapter` | reads only | |
| Honeypot | `Honeypot` | rotate + retain cap | Async gzip; never unlink `open-{pid}` |
| Asset detector | `AssetDetector` | live TAP talkers + YAML join | Autodetect SA/PGN/NAME; silent catalog not shown |
| Comms graph | `CommsGraph` | `new_edge` for SA 44 | Expected vs live |
| Features (Bytewax 1–5) | `FeatureStage` | GNSS split / DR residual | No ONNX inside |
| ONNX enrich | `OnnxEnrich` | `throughput-lstm` or `model_unavailable` | Extra `otlab[onnx]` |
| Rules enrich | `RulesEnrich.gps_spoof_nav` | fires on healthy-DOP walk-off | Parallel to ONNX |
| Incidents | `IncidentCorrelator` | risk + NIS2; hop dedup | Does not wait on SLM |
| Local SLM | `LocalSlm` | `ok` when Ollama has the configured tag; `llm_unavailable` otherwise | Template titles if Ollama is down; `LLM_ENDPOINT` fatal in prod |
| CyberPal assistant | `CyberPalAssistant` | one session per incident; `/api/assistant` | Correlation JSON only; not a detector |
| STIX 2.1 | `StixExporter` | local file, `taxii_shared=False` | |
| Eval join | `EvalJoin` | prod + label topic fatal | After emit; not in prompt |
| Dashboard | `ot_sensor.app` | `test_dashboard.py` | Asset map snapshot, `/api/snapshot` |

End-to-end: `test_pipeline.py` runs `gps-spoof-primary` ticks → `gps-spoof-nav` fire → `nis2_significant` → SLM fallback → STIX file. `dev` scores labels; `prod` has no label records.

CLI: `SENSOR_MODE=dev uv run ot-sensor --ticks 10`

Operator UI: `uv run ot-dashboard` (build `ot-sensor/frontend/` first) on `:8443`. Injector stays on `:8444`. Dashboard polls `OPV_SIM_URL` / `--sim-url` (`GET /api/tap`); it does not tick the plant.

Local language models: start Ollama (`ollama serve`), `ollama pull qwen2:1.5b`, then `OTLAB_SLM_MODEL=qwen2:1.5b uv run python -m ot_sensor.cyberpal`. Health pills **Local SLM** and **CyberPal** show that tag. See [ot-sensor/README.md](../../ot-sensor/README.md).

## Dataflow (lab)

```
ScenarioEngine → DeviceTwins → InMemoryCanBus → GET /api/tap
                                                     ↓
                                             Nmea2000Adapter → OTEvent
                                                     ├→ Honeypot (rotate/retain)
                                                     ├→ AssetDetector
                                                     ├→ CommsGraph
                                                     └→ FeatureStage → ONNX ∥ rules → Incidents → LocalSlm → STIX
                                                     dashboard GET/POST /api/assistant ← CyberPal (per-incident)
dev: LabelTopic ──→ EvalJoin (after SLM)
```

## Still not in this tree

- Linux `vcan_*` / SocketCAN TAP reader (needed before Redpanda/NATS on the hot path)
- TAXII listener `:8444`, operator HTTPS `:8443`
- Full PGN catalog `pgn-2026.03.json` (lab codec covers the spoof/flood PGNs only)
