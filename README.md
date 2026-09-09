# ot-lab

NMEA 2000 **simulator** (`opv-sim`) and **sensor** (`ot-sensor`) for an OPV backbone.

| Package | Readme | Architecture canvas |
| --- | --- | --- |
| Sensor | [ot-sensor/README.md](ot-sensor/README.md) | [canvases/ot-sensor-nmea2000-architecture.canvas.tsx](canvases/ot-sensor-nmea2000-architecture.canvas.tsx) |
| Simulator | [simulator/README.md](simulator/README.md) | [canvases/nmea2000-opv-simulator-architecture.canvas.tsx](canvases/nmea2000-opv-simulator-architecture.canvas.tsx) |
| Lab (both) | [docs/architecture/ot-lab.md](docs/architecture/ot-lab.md) | [canvases/ot-lab-schema.canvas.tsx](canvases/ot-lab-schema.canvas.tsx) |

Specs: [simulator](docs/architecture/nmea2000-opv-simulator.md), [sensor](docs/architecture/ot-sensor-nmea2000.md).

The simulator is **NMEA 2000 only** (in-memory CAN in this tree; Linux `vcan_*` later). The **attack injector** is only on `opv-sim` (`:8444`). The sensor dashboard (`:8443`) is listen-only.

## Install

Python **3.12**. From the repo root:

```bash
uv sync
```

That creates `.venv` and installs both workspace packages (sensor extras `onnx` and `ui` included) plus pytest.

```bash
uv run opv-sim --help
uv run ot-sensor --help
uv run ot-dashboard --help
```

One package:

```bash
uv sync --package opv-sim --extra ui
uv sync --package ot-sensor --extra onnx --extra ui
```

Dashboard UI:

```bash
npm install --prefix ot-sensor/frontend
npm run build --prefix ot-sensor/frontend
```

## Run (typical lab)

```bash
uv run opv-sim --serve --mode dev --port 8444
uv run ot-dashboard --mode dev --port 8443 --sim-url http://127.0.0.1:8444
```

- Watchstander: http://127.0.0.1:8443
- Injector: http://127.0.0.1:8444

Service tables, flags, and CyberPal import: [ot-sensor/README.md](ot-sensor/README.md) and [simulator/README.md](simulator/README.md).

## Tests

```bash
uv run pytest -q
```

## Modes

| | `dev` | `prod` |
| --- | --- | --- |
| Where | Lab / CI | Lab only (unlabeled path). Never on the vessel |
| Simulator labels | Off-bus, in-memory | **Absent.** `LABEL_TOPIC` is fatal |
| Sensor eval join | After emit; not in SLM / CyberPal | **Absent** |
| Sensor LLM | Local GGUF only | `LLM_ENDPOINT` is fatal |
