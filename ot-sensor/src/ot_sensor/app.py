"""Operator dashboard API. Listen-only TAP data; no bus writes."""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ot_sensor.lab_runtime import LabRuntime
from ot_sensor.paths import lab_root, sensor_root

REPO = lab_root()
WORK = Path(os.environ.get("OTLAB_WORK", Path.cwd() / "otlab-work"))
MODE = os.environ.get("SENSOR_MODE", "dev")
TAP_URL = (os.environ.get("OPV_SIM_URL") or "").rstrip("/") or None
DRIVE_SIM = os.environ.get("SENSOR_DRIVE_SIM", "1") != "0"

runtime = LabRuntime(REPO, WORK, MODE, tap_url=TAP_URL, drive_sim=DRIVE_SIM)


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
        if runtime.tap_url:
            await asyncio.to_thread(runtime.pull_remote)
            await asyncio.to_thread(runtime.ingest_from_sim)
        else:
            if runtime.drive_sim and runtime.running:
                await asyncio.to_thread(runtime.sim.tick)
            if runtime.running:
                await asyncio.to_thread(runtime.ingest_from_sim)
        await asyncio.sleep(0.8)


class ControlBody(BaseModel):
    action: str


class AckBody(BaseModel):
    incident_ids: list[str] | None = None


class AssistantBody(BaseModel):
    incident_id: str
    message: str | None = None
    refresh: bool = False


class RuleBody(BaseModel):
    rule_id: str
    enabled: bool | None = None
    severity: str | None = None
    clauses: dict[str, float | bool] | None = None


@app.get("/api/health")
def health():
    return {"ok": True, "mode": runtime.mode, "version": runtime.snapshot()["sensor_version"]}


@app.get("/api/snapshot")
def snapshot():
    return runtime.snapshot()


@app.get("/api/honeypot")
def honeypot():
    return runtime.snapshot()["honeypot"]


@app.post("/api/control")
def control(body: ControlBody):
    if body.action == "reset":
        runtime.reset()
    elif body.action == "step":
        runtime.step()
    elif body.action == "clear_honeypot":
        runtime.clear_honeypot()
    elif body.action in ("start", "pause"):
        runtime.running = body.action == "start"
    else:
        return {"ok": False, "error": "unknown action"}
    return {"ok": True, "snapshot": runtime.snapshot()}


@app.post("/api/ack")
def ack(body: AckBody):
    runtime.ack_alerts(body.incident_ids)
    return {"ok": True, "new_incident_ids": runtime.new_incident_ids}


@app.post("/api/rules")
def update_rules(body: RuleBody):
    try:
        snap = runtime.update_rule(body.rule_id, enabled=body.enabled, severity=body.severity, clauses=body.clauses)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "snapshot": snap}


@app.get("/api/assistant")
async def assistant_get(incident_id: str | None = None, refresh: bool = False):
    if not incident_id:
        return {"ok": True, **runtime.assistant.status()}
    return await asyncio.to_thread(runtime.assistant_handle, incident_id, None, refresh)


@app.post("/api/assistant")
async def assistant_post(body: AssistantBody):
    return await asyncio.to_thread(runtime.assistant_handle, body.incident_id, body.message, body.refresh)


def _mount_ui() -> None:
    dist = sensor_root() / "frontend" / "dist"
    if dist.is_dir():
        app.mount("/", StaticFiles(directory=dist, html=True), name="ui")


_mount_ui()
