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

## Local SLM (Ollama)

Watchstander alert text and the CyberPal assistant both use a **local Ollama** instruct model on loopback. They do not call a cloud LLM. `SENSOR_MODE=prod` still refuses `LLM_ENDPOINT`.

1. Install [Ollama](https://ollama.com) and start it (default `http://127.0.0.1:11434`):

```bash
ollama serve
```

2. Pull a small instruct tag (this lab host uses `qwen2:1.5b`):

```bash
ollama pull qwen2:1.5b
```

3. Point the sensor at that tag and create the `cyberpal` alias (system prompt + keep-alive):

```bash
export OLLAMA_HOST=http://127.0.0.1:11434   # optional; this is the default
export OTLAB_SLM_MODEL=qwen2:1.5b           # or OTLAB_CYBERPAL_MODEL
uv run python -m ot_sensor.cyberpal
```

The dashboard health pills **Local SLM** and **CyberPal** turn green and show the tag (`qwen2:1.5b`) when Ollama answers `/api/tags` with that model. If Ollama is down, both pills show `llm_unavailable` and the UI falls back to template alert text / heuristic investigation notes.

| Variable | Effect |
| --- | --- |
| `OLLAMA_HOST` | Ollama base URL (default `http://127.0.0.1:11434`) |
| `OTLAB_SLM_MODEL` | Exact Ollama tag for Local SLM + CyberPal |
| `OTLAB_CYBERPAL_MODEL` | Same as `OTLAB_SLM_MODEL` (either is enough) |

```bash
OTLAB_SLM_MODEL=qwen2:latest uv run ot-dashboard --mode dev --port 8443 --sim-url http://127.0.0.1:8444
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
| Sensor LLM | Local Ollama (or GGUF) | `LLM_ENDPOINT` is fatal |
