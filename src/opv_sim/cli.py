"""opv-sim CLI. Lab only. Never opens a physical ship CAN iface.

Emits NMEA 2000 frames only (in-memory CAN in CI; vcan_* on Linux).
"""

from __future__ import annotations

import argparse
import os

from opv_sim.lab import OpvSimulator


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--mode", default=os.environ.get("SIM_MODE", "dev"))
    p.add_argument("--attack", default="gps-spoof-primary")
    p.add_argument("--ticks", type=int, default=8)
    args = p.parse_args()
    if args.mode == "prod" and os.environ.get("LABEL_TOPIC"):
        raise SystemExit("LABEL_TOPIC is fatal in SIM_MODE=prod")
    sim = OpvSimulator(
        sim_mode=args.mode,
        attack_id=args.attack,
        scenario_id="gps-spoof-underway" if args.attack else "underway",
    )
    for i in range(args.ticks):
        plant, frames = sim.tick(float(i))
        print(f"{plant.t.isoformat()} phase={plant.phase} frames={len(frames)} labels={len(sim.labels.records)}")


if __name__ == "__main__":
    main()
