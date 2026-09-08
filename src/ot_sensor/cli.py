"""ot-sensor CLI."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from ot_sensor.pipeline import run_spoof_lab


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--mode", default=os.environ.get("SENSOR_MODE", "dev"))
    p.add_argument("--ticks", type=int, default=10)
    args = p.parse_args()
    if args.mode == "prod" and os.environ.get("LLM_ENDPOINT"):
        raise SystemExit("LLM_ENDPOINT is fatal in SENSOR_MODE=prod")
    repo = Path(__file__).resolve().parents[2]
    work = Path.cwd() / "otlab-work"
    work.mkdir(exist_ok=True)
    sim, sensor, result = run_spoof_lab(repo, work, args.mode, args.ticks)
    inc = sensor.last_incident
    print("frames_ingested", len(sensor.events), "labels", len(sim.labels.records))
    if inc:
        print("incident", inc.incident_id, inc.severity, "risk", inc.risk.total, "nis2", inc.risk.nis2_significant)
        print("slm", sensor.last_copilot.status if sensor.last_copilot else None)
    else:
        print("no incident", result)


if __name__ == "__main__":
    main()
