"""Incremental simulator session. Owns the attack injector."""

from __future__ import annotations

from collections import deque
from datetime import datetime

from otlab.pgn import decode_fields
from opv_sim.lab import OpvSimulator
from opv_sim.twins import ATTACK_IDS, ATTACK_KEYS, DEVICE_CATALOG, attacks_for, default_devices

PGN_NAME = {
    59904: "ISO request",
    60928: "ISO address claim",
    127237: "Heading/track control",
    127250: "Vessel heading",
    127488: "Engine rapid",
    129025: "Position rapid",
    129026: "COG/SOG",
    129029: "GNSS position data",
    129539: "GNSS DOPs",
}

SA_NAME = {
    "0": "engine-port",
    "1": "engine-stbd",
    "12": "thruster",
    "16": "GNSS-1",
    "17": "GNSS-2",
    "20": "genset-1",
    "24": "AIS",
    "35": "gyro",
    "44": "rogue",
    "52": "rudder",
    "56": "autopilot",
    "60": "MFD",
    "99": "decoy",
}

TRACK_MAX = 180


def _iso(v):
    if isinstance(v, datetime):
        return v.isoformat()
    return v


def _summary(fields: dict) -> str:
    if "lat_deg" in fields and "lon_deg" in fields:
        return f"lat {fields['lat_deg']:.5f}  lon {fields['lon_deg']:.5f}"
    if "cog_deg" in fields:
        return f"COG {fields['cog_deg']:.1f}°  SOG {fields.get('sog_kn', 0):.1f} kn"
    if "hdop" in fields:
        return f"HDOP {fields['hdop']:.2f}"
    if "sat_count" in fields:
        return f"sats {fields['sat_count']}"
    if fields.get("operation_name") == "heading_control":
        return f"heading cmd {fields.get('heading_deg', 0):.1f}°"
    if "heading_deg" in fields:
        return f"heading {fields['heading_deg']:.1f}°"
    if "rpm" in fields:
        return f"{fields['rpm']:.0f} rpm"
    if fields.get("operation_name") == "address_claim":
        return "ISO NAME claim"
    if fields.get("operation_name") == "iso_request":
        return f"request PGN {fields.get('requested_pgn', 0)}"
    return fields.get("operation_name") or "frame"


def emission_row(frame, plant, attacks: dict | None = None) -> dict:
    fields = decode_fields(frame)
    sa = str(fields.get("sa", ""))
    pgn = int(fields.get("pgn") or 0)
    attack_id = getattr(plant, "attack_id", None) if plant else None
    on = attacks or {}
    spoofed = bool(
        (on.get("spoof") or attack_id == "gps-spoof-primary")
        and sa == "16"
        and pgn in (129025, 129026, 129029, 129539)
    )
    gyro_spoof = bool(
        (on.get("gyro") or attack_id == "heading-spoof")
        and sa == "35"
        and pgn == 127250
        and not on.get("pgn_flood")
    )
    vel_spoof = bool(
        (on.get("velocity") or attack_id == "sog-spoof")
        and sa == "16"
        and pgn == 129026
        and not spoofed
    )
    pgn_flood = bool(on.get("pgn_flood") or attack_id == "pgn-flood")
    if spoofed:
        kind = "spoof"
    elif gyro_spoof:
        kind = "gyro"
        spoofed = True
    elif vel_spoof:
        kind = "velocity"
        spoofed = True
    elif pgn == 59904:
        kind = "read"
    elif pgn == 127237:
        kind = "write"
    elif pgn_flood and sa == "35" and pgn == 127250:
        kind = "flood"
    else:
        kind = "ok"
    return {
        "sa": sa,
        "name": SA_NAME.get(sa, f"SA {sa}"),
        "pgn": pgn,
        "pgn_name": PGN_NAME.get(pgn, f"PGN {pgn}"),
        "segment": frame.segment,
        "summary": _summary(fields),
        "hex": frame.data.hex(),
        "spoofed": spoofed,
        "kind": kind,
    }


class SimRuntime:
    """Plant + injector. The sensor never chooses an attack_id."""

    def __init__(self, mode: str = "dev", attack_id: str = "gps-spoof-primary") -> None:
        self.mode = mode
        self.attack_id = attack_id or ""
        self.elapsed = 0.0
        self.running = False
        self.ticks = 0
        self.plant = None
        self.last_frames = []
        self.track: deque[dict] = deque(maxlen=TRACK_MAX)
        self.attacks = attacks_for(self.attack_id)
        self.devices = default_devices()
        self.intensity = 1.0 if self.attacks.get("spoof") else 0.0
        self._build()

    def _build(self) -> None:
        scenario = "gps-spoof-underway" if self.attacks.get("spoof") else "underway"
        if self.attacks.get("spoof"):
            aid: str | None = "gps-spoof-primary"
        elif self.attacks.get("gyro"):
            aid = "heading-spoof"
        elif self.attacks.get("velocity"):
            aid = "sog-spoof"
        else:
            aid = None
        self.sim = OpvSimulator(
            sim_mode=self.mode,
            attack_id=aid,
            scenario_id=scenario,
        )
        self.sim.twins.enabled = dict(self.devices)
        self.sim.injector.attacks = dict(self.attacks)
        self.sim.injector.intensity = self.intensity

    def reset(self, attack_id: str | None = None) -> None:
        if attack_id is not None:
            self.attack_id = attack_id
        self.elapsed = 0.0
        self.ticks = 0
        self.plant = None
        self.last_frames = []
        self.track.clear()
        self.attacks = attacks_for(self.attack_id)
        self.devices = default_devices()
        self.intensity = 1.0 if self.attacks.get("spoof") else 0.0
        self._build()

    def set_intensity(self, intensity: float) -> None:
        self.set_attack("spoof", float(intensity) > 0)

    def set_attack(self, kind: str, enabled: bool) -> None:
        if kind not in ATTACK_KEYS:
            raise ValueError(kind)
        self.attacks[kind] = bool(enabled)
        self.intensity = 1.0 if self.attacks.get("spoof") else 0.0
        self.sim.injector.attacks = dict(self.attacks)
        self.sim.injector.intensity = self.intensity
        if self.attacks.get("spoof"):
            self.attack_id = "gps-spoof-primary"
            self.sim.engine.attack_id = "gps-spoof-primary"
            self.sim.engine.scenario_id = "gps-spoof-underway"
        else:
            active = [k for k, v in self.attacks.items() if v]
            self.attack_id = ATTACK_IDS.get(active[0], active[0]) if active else ""
            self.sim.engine.attack_id = self.attack_id or None
            if not self.attacks.get("spoof"):
                self.sim.engine.scenario_id = "underway"

    def set_device(self, sa: str, enabled: bool) -> None:
        sa = str(sa)
        if sa not in self.devices:
            raise ValueError(sa)
        self.devices[sa] = bool(enabled)
        self.sim.twins.set_device(sa, enabled)

    def tick(self):
        plant, frames = self.sim.tick(self.elapsed, attacks=self.attacks)
        self.plant = plant
        self.last_frames = frames
        self.elapsed += 1.0
        self.ticks += 1
        if plant is not None:
            self.track.append(
                {
                    "lat_deg": plant.lat_deg,
                    "lon_deg": plant.lon_deg,
                    "heading_deg": plant.heading_deg,
                    "cog_deg": plant.cog_deg,
                    "sog_kn": plant.sog_kn,
                }
            )
        return plant, frames

    def tap(self) -> dict:
        """Listen-only wire dump for ot-sensor. Raw frames, not injector controls."""
        snap = self.snapshot()
        return {
            "ticks": self.ticks,
            "running": self.running,
            "attack_id": snap["attack_id"],
            "elapsed_s": self.elapsed,
            "plant": snap["plant"],
            "attacks": dict(self.attacks),
            "frames": [
                {
                    "t": _iso(f.t),
                    "segment": f.segment,
                    "can_id": f.can_id,
                    "data_hex": f.data.hex(),
                    "error": bool(f.error),
                }
                for f in self.last_frames
            ],
        }

    def snapshot(self) -> dict:
        plant = self.plant
        active = [k for k, v in self.attacks.items() if v]
        if self.attacks.get("spoof"):
            attack_id = "gps-spoof-primary"
        elif active:
            attack_id = ATTACK_IDS.get(active[0], active[0])
        else:
            attack_id = None
        return {
            "sim_mode": self.mode,
            "running": self.running,
            "attack_id": attack_id,
            "attacks": dict(self.attacks),
            "devices": dict(self.devices),
            "device_catalog": [
                {"sa": str(sa), "name": name, "segment": seg, "enabled": self.devices[str(sa)]}
                for sa, seg, name, _ in DEVICE_CATALOG
            ],
            "intensity": round(self.intensity, 3),
            "elapsed_s": self.elapsed,
            "ticks": self.ticks,
            "frames_this_tick": len(self.last_frames),
            "labels": len(self.sim.labels.records),
            "emissions": [emission_row(f, plant, self.attacks) for f in self.last_frames],
            "plant": {
                "t": _iso(plant.t) if plant else None,
                "lat_deg": plant.lat_deg if plant else None,
                "lon_deg": plant.lon_deg if plant else None,
                "heading_deg": plant.heading_deg if plant else None,
                "cog_deg": plant.cog_deg if plant else None,
                "sog_kn": plant.sog_kn if plant else None,
                "sog_ms": (plant.sog_kn * 0.514444) if plant else None,
                "phase": plant.phase if plant else "idle",
                "attack_id": plant.attack_id if plant else None,
            }
            if plant
            else None,
            "ownship": self.sim.injector.reported(plant),
            "track": list(self.track),
        }
