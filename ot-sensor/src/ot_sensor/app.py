"""Operator dashboard API. Listen-only TAP data; no bus writes."""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ot_sensor.lab_runtime import LabRuntime
from ot_sensor.paths import lab_root, sensor_root

REPO = lab_root()
WORK = Path(os.environ.get("OTLAB_WORK", Path.cwd() / "otlab-work"))
MODE = os.environ.get("SENSOR_MODE", "dev")

runtime = LabRuntime(REPO, WORK, MODE)


@asynccontextmanager
async def lifespan(app: FastAPI):
    WORK.mkdir(parents=True, exist_ok=True)
    task = asyncio.create_task(_tick_loop())
    yield
    runtime.running = False
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="OT sensor dashboard", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


async def _tick_loop() -> None:
    while True:
        if runtime.running:
            await asyncio.to_thread(runtime.step)
        await asyncio.sleep(0.8)


class ControlBody(BaseModel):
    action: str
    attack_id: str | None = Field(default=None)


class AckBody(BaseModel):
    incident_ids: list[str] | None = None


@app.get("/api/health")
def health():
    return {"ok": True, "mode": runtime.mode, "version": runtime.snapshot()["sensor_version"]}


@app.get("/api/snapshot")
def snapshot():
    return runtime.snapshot()


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
        runtime.step()
    else:
        return {"ok": False, "error": "unknown action"}
    return {"ok": True, "snapshot": runtime.snapshot()}


@app.post("/api/ack")
def ack(body: AckBody):
    runtime.ack_alerts(body.incident_ids)
    return {"ok": True, "new_incident_ids": runtime.new_incident_ids}


def _mount_ui() -> None:
    dist = sensor_root() / "frontend" / "dist"
    if dist.is_dir():
        app.mount("/", StaticFiles(directory=dist, html=True), name="ui")


_mount_ui()
