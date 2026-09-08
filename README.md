# ot-sensor

NMEA 2000 **simulator** (`opv-sim`) and **sensor** (`ot-sensor`) for an OPV backbone.

Architecture: [docs/architecture/ot-lab.md](docs/architecture/ot-lab.md). Specs: [simulator](docs/architecture/nmea2000-opv-simulator.md), [sensor](docs/architecture/ot-sensor-nmea2000.md).

The simulator is **NMEA 2000 only** (in-memory CAN in this tree; Linux `vcan_*` later). It does not start Modbus or NMEA 0183.

Packages live in two folders, managed with **uv**:

```
simulator/    opv-sim CLI, otlab CAN/PGN types, in-memory bus
ot-sensor/    ot-sensor + ot-dashboard, Vite TypeScript UI
```

## Install

Python **3.12** (ONNX Runtime has no 3.14 wheel). From the repo root:

```bash
uv sync
```

That creates `.venv`, installs both workspace packages (sensor extras `onnx` and `ui` included), and pytest.

Check the tools:

```bash
uv run opv-sim --help
uv run ot-sensor --help
```

Install only one package:

```bash
uv sync --package opv-sim
uv sync --package ot-sensor --extra onnx --extra ui
```

## Run the simulator

Lab-only. Never opens a physical ship CAN interface.

```bash
uv run opv-sim --mode dev --attack gps-spoof-primary --ticks 8
```

Same thing with env vars:

```bash
SIM_MODE=dev uv run opv-sim --attack gps-spoof-primary --ticks 8
```

| Flag / env | Default | Meaning |
| --- | --- | --- |
| `--mode` / `SIM_MODE` | `dev` | `dev` publishes off-bus labels. `prod` is unlabeled CAN (certify a prod sensor). |
| `--attack` | `gps-spoof-primary` | Overlay on CAN. Use `--attack ''` for benign underway (no injector). |
| `--ticks` | `8` | Scenario steps. Spoof ramp starts after 5 s of elapsed scenario time. |

Example output:

```
2026-09-08T19:00:00+00:00 phase=baseline frames=18 labels=0
2026-09-08T19:00:06+00:00 phase=ramp frames=18 labels=4
```

`prod` refuses a configured label topic:

```bash
SIM_MODE=prod LABEL_TOPIC=nats://labels:4223 uv run opv-sim   # exits non-zero
SIM_MODE=prod uv run opv-sim --ticks 8                        # CAN still flows; labels=0
```

This CLI prints ticks. It does not bind SocketCAN yet. Frames stay in process (`InMemoryCanBus`).

## Run the sensor

The sensor CLI runs the **spoof lab pipeline**: simulator ticks → listen-only N2K adapter → honeypot / assets / graph / features → ONNX ∥ rules → incident → local SLM → STIX.

It does **not** attach to a separate `opv-sim` process. Start it on its own:

```bash
uv run ot-sensor --mode dev --ticks 10
```

Or:

```bash
SENSOR_MODE=dev uv run ot-sensor --ticks 10
```

`--ticks 10` is enough for the default CLI (ticks start at t=6, which is spoof ramp).

| Flag / env | Default | Meaning |
| --- | --- | --- |
| `--mode` / `SENSOR_MODE` | `dev` | `dev` scores labels after emit. `prod` has no label topic. |
| `--ticks` | `10` | Simulator hops ingested before one feature window. |

Example output:

```
frames_ingested 180 labels 40
incident inc-0001 critical risk 86 nis2 True
slm llm_unavailable
```

Artifacts under `./otlab-work/` (created in the current working directory):

- `hp/` — honeypot JSONL (rotated / gzipped)
- `stix/<mode>/opv1/<incident_id>.json` — local STIX bundle (`taxii_shared=false`)

`prod` refuses a remote LLM:

```bash
SENSOR_MODE=prod LLM_ENDPOINT=https://api.example.com uv run ot-sensor   # exits non-zero
SENSOR_MODE=prod uv run ot-sensor --ticks 10
```

Without `watchstander-slm` GGUF weights, SLM status is `llm_unavailable` and the incident still stands.

## Run the dashboard

Operator UI (Vite + TypeScript, no React): asset / communications map, service health, incident cases, NIS2 clocks, and a pop-up when a new incident opens. The API ticks the N2K lab into the sensor (same pipeline as `ot-sensor`).

```bash
uv sync
cd ot-sensor/frontend && npm install && npm run build && cd ../..
uv run ot-dashboard --mode dev --port 8443
```

Open http://127.0.0.1:8443

Vite live reload (API must already be on 8443):

```bash
uv run ot-dashboard --mode dev --port 8443
cd ot-sensor/frontend && npm install && npm run dev
```

Then open http://127.0.0.1:5173

| Control | Effect |
| --- | --- |
| Start / Pause | Lab ticks (GPS spoof overlay by default) |
| Reset spoof | Restart `gps-spoof-primary` |
| Reset underway | Benign kinematics, no injector |
| Communications | Live src→dst (and broadcast to the segment bus). Violations in red |
| Dependencies | `depends_on` from asset-criticality.yaml |

`SENSOR_MODE=prod uv run ot-dashboard` is unlabeled; `LLM_ENDPOINT` is still fatal.

## Tests

```bash
uv run pytest -q
```

## Modes (both processes)

| | `dev` | `prod` |
| --- | --- | --- |
| Where | Lab / CI | Lab only (unlabeled path). Never on the vessel |
| Simulator labels | Published off-bus | **Absent.** `LABEL_TOPIC` is fatal |
| Sensor eval join | After emit; not in the SLM prompt | **Absent.** Label topic bind is fatal |
| Sensor LLM | Local GGUF only | `LLM_ENDPOINT` is fatal |
