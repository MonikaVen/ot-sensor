"""ot-dashboard: operator UI + snapshot API. Listens to the simulator TAP."""

from __future__ import annotations

import argparse
import asyncio
import os


def main() -> None:
    p = argparse.ArgumentParser(description="OT sensor operator dashboard")
    p.add_argument("--mode", default=os.environ.get("SENSOR_MODE", "dev"))
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=int(os.environ.get("OT_DASH_PORT", "8443")))
    p.add_argument("--sim-port", type=int, default=int(os.environ.get("OPV_SIM_PORT", "8444")))
    p.add_argument(
        "--sim-url",
        default=os.environ.get("OPV_SIM_URL"),
        help="Follow an already-running simulator (skips starting the injector)",
    )
    args = p.parse_args()
    os.environ["SENSOR_MODE"] = args.mode
    os.environ["SIM_MODE"] = args.mode
    os.environ.pop("OPV_SIM_EMBEDDED", None)
    follow = (args.sim_url or "").rstrip("/")
    start_sim = not follow
    tap_url = follow or f"http://{args.host}:{args.sim_port}"
    os.environ["OPV_SIM_URL"] = tap_url
    if args.mode == "prod" and os.environ.get("LLM_ENDPOINT"):
        raise SystemExit("LLM_ENDPOINT is fatal in SENSOR_MODE=prod")
    import uvicorn
    from ot_sensor.app import app, runtime
    from ot_sensor.tap import TapMirror

    runtime.mode = args.mode
    runtime.tap_url = tap_url
    runtime.drive_sim = False
    runtime.sim = TapMirror()
    runtime.reset()
    runtime.running = True

    async def serve() -> None:
        sensor_cfg = uvicorn.Config(app, host=args.host, port=args.port, log_level="info")
        sensor_srv = uvicorn.Server(sensor_cfg)
        sensor_srv.install_signal_handlers = False
        tasks = [sensor_srv.serve()]
        if start_sim:
            import opv_sim.app as sim_mod

            sim_cfg = uvicorn.Config(sim_mod.app, host=args.host, port=args.sim_port, log_level="info")
            sim_srv = uvicorn.Server(sim_cfg)
            sim_srv.install_signal_handlers = False
            tasks.append(sim_srv.serve())
        await asyncio.gather(*tasks)

    asyncio.run(serve())


if __name__ == "__main__":
    main()
