"""Simulator control API and injector UI. Lab only."""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from opv_sim.runtime import SimRuntime

EMBEDDED = os.environ.get("OPV_SIM_EMBEDDED") == "1"
MODE = os.environ.get("SIM_MODE", "dev")
ATTACK = os.environ.get("SIM_ATTACK", "gps-spoof-primary")

runtime = SimRuntime(MODE, ATTACK)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not EMBEDDED:
        runtime.running = True
        task = asyncio.create_task(_tick_loop())
        yield
        runtime.running = False
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    else:
        yield


app = FastAPI(title="OPV simulator", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8443",
        "http://localhost:8443",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8445",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


async def _tick_loop() -> None:
    while True:
        if runtime.running:
            await asyncio.to_thread(runtime.tick)
        await asyncio.sleep(0.8)


class ControlBody(BaseModel):
    action: str
    attack_id: str | None = Field(default=None)
    intensity: float | None = Field(default=None)
    attack: str | None = Field(default=None)
    device: str | None = Field(default=None)
    enabled: bool | None = Field(default=None)


@app.get("/api/health")
def health():
    return {"ok": True, "mode": runtime.mode, "attack_id": runtime.attack_id or None}


@app.get("/api/snapshot")
def snapshot():
    return runtime.snapshot()


@app.get("/api/tap")
def tap():
    return runtime.tap()


@app.post("/api/control")
def control(body: ControlBody):
    if body.action == "start":
        runtime.running = True
    elif body.action == "pause":
        runtime.running = False
    elif body.action == "reset":
        runtime.running = False
        runtime.reset(body.attack_id if body.attack_id is not None else runtime.attack_id)
        runtime.running = True
    elif body.action == "step":
        runtime.tick()
    elif body.action == "intensity":
        if body.intensity is None:
            return {"ok": False, "error": "intensity required"}
        runtime.set_intensity(body.intensity)
    elif body.action == "toggle_attack":
        if not body.attack or body.enabled is None:
            return {"ok": False, "error": "attack and enabled required"}
        try:
            runtime.set_attack(body.attack, body.enabled)
        except ValueError:
            return {"ok": False, "error": "unknown attack"}
    elif body.action == "toggle_device":
        if body.device is None or body.enabled is None:
            return {"ok": False, "error": "device and enabled required"}
        try:
            runtime.set_device(body.device, body.enabled)
        except ValueError:
            return {"ok": False, "error": "unknown device"}
    else:
        return {"ok": False, "error": "unknown action"}
    return {"ok": True, "snapshot": runtime.snapshot()}


@app.get("/", response_class=HTMLResponse)
def injector_ui():
    path = Path(__file__).with_name("injector.html")
    return HTMLResponse(path.read_text(encoding="utf-8"))
