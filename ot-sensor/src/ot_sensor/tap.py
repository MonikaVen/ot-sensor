"""Listen-only TAP client: pull live CAN from the simulator HTTP API."""

from __future__ import annotations

import json
from datetime import datetime
from types import SimpleNamespace
from urllib.request import Request, urlopen

from otlab import CanFrame


def parse_iso(raw) -> datetime:
    if isinstance(raw, datetime):
        return raw
    if isinstance(raw, str) and raw:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    return datetime.now().astimezone()


def frame_to_wire(frame: CanFrame | dict) -> dict:
    """TAP port shape: raw CAN before NMEA 2000 convert."""
    if isinstance(frame, dict):
        data_hex = str(frame.get("data_hex") or "")
        return {
            "t": frame.get("t"),
            "segment": str(frame.get("segment") or "nav"),
            "can_id": int(frame.get("can_id") or 0),
            "data_hex": data_hex,
            "error": bool(frame.get("error")),
        }
    t = frame.t.isoformat() if hasattr(frame.t, "isoformat") else str(frame.t)
    return {
        "t": t,
        "segment": frame.segment,
        "can_id": int(frame.can_id),
        "data_hex": frame.data.hex(),
        "error": bool(frame.error),
    }


def wire_to_frame(row: dict) -> CanFrame:
    return CanFrame(
        t=parse_iso(row.get("t")),
        segment=str(row.get("segment") or "nav"),
        can_id=int(row.get("can_id") or 0),
        data=bytes.fromhex(str(row.get("data_hex") or "")),
        error=bool(row.get("error")),
    )


def plant_from_tap(row: dict | None):
    if not row:
        return None
    plant = SimpleNamespace(**row)
    if getattr(plant, "t", None):
        plant.t = parse_iso(plant.t)
    return plant


def pull_tap(base_url: str, timeout_s: float = 2.0) -> dict:
    url = base_url.rstrip("/") + "/api/tap"
    req = Request(url, headers={"Accept": "application/json"})
    with urlopen(req, timeout=timeout_s) as resp:
        return json.loads(resp.read().decode("utf-8"))


class TapMirror:
    """Duck-types SimRuntime fields the sensor ingest path needs."""

    def __init__(self) -> None:
        self.ticks = 0
        self.elapsed = 0.0
        self.running = False
        self.attack_id = ""
        self.plant = None
        self.last_frames: list[CanFrame] = []
        self.last_raw: list[dict] = []
        self.attacks: dict = {}
        self.histograms: list = []

    def apply(self, payload: dict) -> None:
        self.ticks = int(payload.get("ticks") or 0)
        self.elapsed = float(payload.get("elapsed_s") or 0)
        self.running = bool(payload.get("running"))
        self.attack_id = payload.get("attack_id") or ""
        self.plant = plant_from_tap(payload.get("plant"))
        self.last_raw = [frame_to_wire(row) for row in payload.get("frames") or []]
        self.last_frames = [wire_to_frame(row) for row in self.last_raw]
        self.attacks = dict(payload.get("attacks") or {})
        self.histograms = list(payload.get("histograms") or [])

    def tick(self):
        return self.plant, self.last_frames

    def reset(self, _attack_id: str | None = None) -> None:
        self.ticks = 0
        self.elapsed = 0.0
        self.running = False
        self.plant = None
        self.last_frames = []
        self.last_raw = []
        self.attack_id = ""
        self.attacks = {}
        self.histograms = []
