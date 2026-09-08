"""ot-dashboard: operator UI + snapshot API."""

from __future__ import annotations

import argparse
import os


def main() -> None:
    p = argparse.ArgumentParser(description="OT sensor operator dashboard")
    p.add_argument("--mode", default=os.environ.get("SENSOR_MODE", "dev"))
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=int(os.environ.get("OT_DASH_PORT", "8443")))
    p.add_argument("--attack", default="gps-spoof-primary")
    args = p.parse_args()
    os.environ["SENSOR_MODE"] = args.mode
    if args.mode == "prod" and os.environ.get("LLM_ENDPOINT"):
        raise SystemExit("LLM_ENDPOINT is fatal in SENSOR_MODE=prod")
    import uvicorn
    from ot_sensor.app import app, runtime

    runtime.mode = args.mode
    runtime.reset(args.attack)
    runtime.running = True
    uvicorn.run(app, host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
