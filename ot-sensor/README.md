# ot-sensor

Listen-only OT sensor for an OPV NMEA 2000 backbone. It polls the simulator TAP, maps CAN to `OTEvent`, runs features / ONNX / rules, correlates incidents, and serves the watchstander dashboard. It does **not** write the bus and does **not** arm the injector.

Package: `ot-sensor/` in the uv workspace. Spec: [docs/architecture/ot-sensor-nmea2000.md](../docs/architecture/ot-sensor-nmea2000.md). Interactive canvas: [canvases/ot-sensor-nmea2000-architecture.canvas.tsx](../canvases/ot-sensor-nmea2000-architecture.canvas.tsx).

## Services

| Service | Module | Input | Output |
| --- | --- | --- | --- |
| TAP client | `ot_sensor.tap` | `GET {sim}/api/tap` | `CanFrame` |
| N2K adapter | `adapters.Nmea2000Adapter` | `CanFrame` | `OTEvent` |
| Honeypot | `honeypot.HoneypotService` | raw TAP bytes | JSONL + dashboard feed |
| Asset detector | `assets.AssetDetector` | `OTEvent` | live catalog vs YAML |
| Comms graph | `CommsGraph` | `OTEvent` | expected vs live edges |
| Feature stage | `features.FeatureStage` | `OTEvent` | `FeatureWindow` |
| ONNX enrich | `onnx_enrich.OnnxEnrich` | `FeatureWindow` | `ModelScore` (`throughput-lstm` or `model_unavailable`) |
| Rules enrich | `rules.RulesEnrich` | `FeatureWindow` | `RuleHit` (`gps-spoof-nav`) |
| Incidents | `incidents.IncidentCorrelator` | scores + hits | `Incident`, risk, NIS2 clocks |
| Watchstander SLM | `slm.LocalSlm` | incident summary | `CopilotAssessment` (Ollama `ok`, else template) |
| CyberPal assistant | `assistant.CyberPalAssistant` | correlation JSON | one session per `incident_id` |
| STIX | `stix.StixExporter` | incident + assessment | local bundle (`taxii_shared=false`) |
| Dashboard | `ot_sensor.app` | `/api/snapshot` | UI on `:8443` |

Adapters for Modbus and NMEA 0183 exist. The live TAP in this lab is **NMEA 2000 only**.

`SENSOR_MODE=prod` refuses `LLM_ENDPOINT` and a label topic. Ground truth never enters the SLM or CyberPal prompt.

## Local SLM (Ollama)

Watchstander titles and CyberPal investigation share one local Ollama process. Start Ollama, pull a tag, then point the app at it:

```bash
ollama serve
ollama pull qwen2:1.5b
export OLLAMA_HOST=http://127.0.0.1:11434          # default
export OTLAB_SLM_MODEL=qwen2:1.5b                  # or OTLAB_CYBERPAL_MODEL
uv run python -m ot_sensor.cyberpal                # alias `cyberpal` FROM that tag
```

The dashboard **Local SLM** and **CyberPal** pills show the tag when `/api/tags` lists it. Override per process:

```bash
OTLAB_SLM_MODEL=qwen2:latest uv run ot-dashboard --mode dev --port 8443 --sim-url http://127.0.0.1:8444
```

`SENSOR_MODE=prod` still refuses `LLM_ENDPOINT`. Ground truth never enters the prompt.

## Install

**[uv](https://docs.astral.sh/uv/)** from the **repo root**. Do not use `pip` or a virtualenv.

```bash
uv python install 3.12
uv sync --package ot-sensor --extra onnx --extra ui
```

Or install the whole workspace (`uv sync`). Node is required to build the dashboard:

```bash
npm install --prefix ot-sensor/frontend
npm run build --prefix ot-sensor/frontend
```

## Run

Batch lab (in-process simulator ticks, no HTTP TAP):

```bash
uv run ot-sensor --mode dev --ticks 10
```

Watchstander dashboard. Start the injector first, then follow it:

```bash
uv run opv-sim --serve --mode dev --port 8444
uv run ot-dashboard --mode dev --port 8443 --sim-url http://127.0.0.1:8444
```

Open http://127.0.0.1:8443

`ot-dashboard` without `--sim-url` also starts the injector on `:8444`. Prefer `--sim-url` when the simulator is already running.

Tabs: Map, Rules, Models, Correlation, Honeypot, Assistant. Reset clears TAP history only. On **Honeypot**, **Export CSV** downloads collector JSONL (open + rotated files); **Delete data** wipes those logs and leaves incidents in place.

## Tests

```bash
uv run pytest ot-sensor/tests -q
```

Artifacts under `./otlab-work/` (`hp/`, `stix/`, local GGUF paths). Not committed.
