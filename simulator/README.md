# opv-sim

OPV NMEA 2000 simulator. Lab only. It never opens a physical ship CAN interface.

Package: `simulator/` in the uv workspace (`opv-sim` + `otlab` codecs). Spec: [docs/architecture/nmea2000-opv-simulator.md](../docs/architecture/nmea2000-opv-simulator.md). Interactive canvas: [canvases/nmea2000-opv-simulator-architecture.canvas.tsx](../canvases/nmea2000-opv-simulator-architecture.canvas.tsx).

The **attack injector lives here**, not on the sensor dashboard.

## Services

| Service | Module | Input | Output |
| --- | --- | --- | --- |
| Scenario engine | `opv_sim.ScenarioEngine` | `scenario_id`, `SIM_MODE` | `PlantState` |
| Device twins | `opv_sim.twins.DeviceTwins` | plant + overlays | `CanFrame` on four trunks |
| Isolating gateways | `IsolatingGateway` | `CanFrame` | allowlisted forward |
| Attack injector | `AttackInjector` | `POST /api/control` | mutated PGN + dev labels |
| Runtime / TAP API | `opv_sim.runtime` + `app` | tick loop | `GET /api/tap`, injector UI |
| Label topic | `LabelTopic` | injector (dev) | in-memory records; never on CAN |

NMEA 2000 only. No Modbus slave, no 0183 talker.

`SIM_MODE=prod` is unlabeled CAN for certifying a prod sensor. `LABEL_TOPIC` set in prod is fatal. The overlay can still mutate PGN for a blind test.

## Install

Python **3.12**. From the **repo root**:

```bash
uv sync --package opv-sim
```

Injector UI extra (FastAPI / uvicorn) is included when you `uv sync` the workspace (`opv-sim[ui]`). Isolated install:

```bash
uv sync --package opv-sim --extra ui
```

## Run

Batch ticks (prints plant phase and frame counts):

```bash
uv run opv-sim --mode dev --attack gps-spoof-primary --ticks 8
```

Benign underway (no injector):

```bash
uv run opv-sim --mode dev --attack '' --ticks 8
```

Injector UI + TAP API:

```bash
uv run opv-sim --serve --mode dev --port 8444
```

Open http://127.0.0.1:8444

| Route | Role |
| --- | --- |
| `GET /` | Injector UI (MITRE overlays + frequency slider) |
| `GET /api/tap` | Listen-only frames for `ot-dashboard` |
| `POST /api/control` | `toggle_attack`, `frequency`, `frequency_random`, `reset`, `start`, `pause` |
| `GET /api/health` | `mode` + `attack_id` |

Frequency (1–32 Hz) sizes flood bursts and repeats spoofed talker rows in the attack log. Check **Randomize** to pick a new Hz each tick; moving the slider turns randomize off and locks that rate. Each log line keeps the ATT&CK id (`T1692.002`, `T0848`, …).

The right rail is the live message log. **Plots** is a header tab beside Start/Pause. One collective live chart shows benign plus each named attack (samples/tick). Filter by overlay and device, then **Export CSV** (header and Plots toolbar) to save the series and filtered frames.

Attach the sensor:

```bash
uv run ot-dashboard --mode dev --port 8443 --sim-url http://127.0.0.1:8444
```

CI uses `InMemoryCanBus`. Linux `vcan_*` is the ship TAP contract; it is not required to run this lab.

## Tests

```bash
uv run pytest simulator/tests -q
```
