"""Incremental simulator session. Owns the attack injector."""

from __future__ import annotations

from collections import deque
from datetime import datetime

from otlab.pgn import decode_fields
from opv_sim.lab import OpvSimulator
from opv_sim.twins import (
    ATTACK_CATALOG,
    ATTACK_IDS,
    ATTACK_KEYS,
    ATTACK_TECHNIQUES,
    DEVICE_CATALOG,
    FREQ_DEFAULT,
    attacks_for,
    clamp_frequency,
    default_devices,
)

PGN_NAME = {
    59904: "ISO request",
    60928: "ISO address claim",
    126208: "Engine/thruster command",
    127237: "Heading/track control",
    127245: "Rudder",
    127250: "Vessel heading",
    127251: "Rate of turn",
    127257: "Attitude",
    127488: "Engine rapid",
    127489: "Engine dynamic params",
    127493: "Transmission parameters",
    127501: "Binary status",
    127505: "Fluid level",
    127508: "Battery status",
    128259: "Speed, water referenced",
    128267: "Water depth",
    129025: "Position rapid",
    129026: "COG/SOG",
    129029: "GNSS position data",
    129038: "AIS position",
    129539: "GNSS DOPs",
    129794: "AIS class A static/voyage",
    130306: "Wind data",
    130311: "Environmental parameters",
}

SA_NAME = {
    "0": "engine-port",
    "1": "engine-stbd",
    "4": "gear-port",
    "5": "gear-stbd",
    "8": "fuel",
    "12": "thruster",
    "16": "GNSS-1",
    "17": "GNSS-2",
    "20": "genset-1",
    "21": "genset-2",
    "24": "AIS",
    "28": "battery",
    "32": "switchbank",
    "35": "gyro",
    "40": "echo",
    "44": "rogue",
    "48": "wind",
    "52": "rudder",
    "56": "autopilot",
    "60": "MFD",
    "80": "environment",
    "84": "tanks",
    "88": "bilge-fire",
    "99": "decoy",
}

TRACK_MAX = 180


def _iso(v):
    if isinstance(v, datetime):
        return v.isoformat()
    return v


def _summary(fields: dict) -> str:
    if fields.get("error"):
        return "CAN error frame"
    if "lat_deg" in fields and "lon_deg" in fields:
        prefix = "AIS " if fields.get("operation_name") == "ais_position" else ""
        return f"{prefix}lat {fields['lat_deg']:.5f}  lon {fields['lon_deg']:.5f}"
    if "cog_deg" in fields:
        return f"COG {fields['cog_deg']:.1f}°  SOG {fields.get('sog_kn', 0):.1f} kn"
    if "hdop" in fields:
        return f"HDOP {fields['hdop']:.2f}"
    if "sat_count" in fields:
        return f"sats {fields['sat_count']}"
    if fields.get("operation_name") == "heading_control":
        return f"heading cmd {fields.get('heading_deg', 0):.1f}°"
    if fields.get("operation_name") == "heading_control_status":
        return f"heading-control status {fields.get('heading_deg', 0):.1f}° (engaged)"
    if fields.get("operation_name") == "engine_control":
        return f"engine cmd {fields.get('rpm', 0):.0f} rpm → SA {fields.get('engine_da', 0)}"
    if fields.get("operation_name") == "rate_of_turn":
        return f"ROT {fields.get('rot_deg_s', 0):.1f}°/s"
    if fields.get("operation_name") == "attitude":
        return (
            f"yaw {fields.get('yaw_deg', 0):.1f}° "
            f"pitch {fields.get('pitch_deg', 0):.1f}° "
            f"roll {fields.get('roll_deg', 0):.1f}°"
        )
    if fields.get("operation_name") == "rudder":
        return f"rudder {fields.get('rudder_deg', 0):.1f}°"
    if fields.get("operation_name") == "engine_dynamic":
        return (
            f"oil {fields.get('oil_kpa', 0):.0f} kPa "
            f"{fields.get('oil_temp_c', 0):.0f} °C  "
            f"load {fields.get('load_pct', 0):.0f}%"
        )
    if fields.get("operation_name") == "ais_static":
        return f"AIS static {fields.get('ship_name', '')}"
    if fields.get("operation_name") == "speed_water":
        return f"STW {fields.get('stw_kn', 0):.1f} kn"
    if fields.get("operation_name") == "wind":
        return f"wind {fields.get('wind_kn', 0):.1f} kn @ {fields.get('wind_deg', 0):.0f}°"
    if fields.get("operation_name") == "transmission":
        return f"gear {fields.get('gear', 0)}"
    if fields.get("operation_name") == "fluid_level":
        return f"fluid {fields.get('fluid_pct', 0):.0f}%"
    if fields.get("operation_name") == "binary_status":
        return f"binary {int(fields.get('bits', 0))}"
    if fields.get("operation_name") == "environment":
        return f"{fields.get('temp_c', 0):.1f} °C  {fields.get('humidity_pct', 0):.0f}% RH"
    if fields.get("operation_name") == "water_depth":
        return f"depth {fields.get('depth_m', 0):.1f} m"
    if fields.get("operation_name") == "battery_status":
        return f"{fields.get('volts', 0):.1f} V"
    if "heading_deg" in fields:
        return f"heading {fields['heading_deg']:.1f}°"
    if "rpm" in fields:
        return f"{fields['rpm']:.0f} rpm"
    if fields.get("operation_name") == "address_claim":
        name = fields.get("iso_name") or "claim"
        return f"ISO NAME claim {name}"
    if fields.get("operation_name") == "iso_request":
        return f"request PGN {fields.get('requested_pgn', 0)}"
    return fields.get("operation_name") or "frame"


def emission_row(frame, plant, attacks: dict | None = None, frequency: int = FREQ_DEFAULT) -> dict:
    fields = decode_fields(frame)
    sa = str(fields.get("sa", ""))
    pgn = int(fields.get("pgn") or 0)
    attack_id = getattr(plant, "attack_id", None) if plant else None
    on = attacks or {}
    spoofed = False
    kind = "ok"
    technique = None
    burst = False
    if fields.get("error") or on.get("error_flood") and sa == "44" and frame.error:
        kind = "error"
        spoofed = True
        technique = "T0814"
        burst = True
    elif (on.get("spoof") or on.get("spoof_both") or attack_id in ("gps-spoof-primary", "gps-spoof-both")) and sa in (
        "16",
        "17",
    ) and pgn in (129025, 129026, 129029, 129539) and (sa == "16" or on.get("spoof_both")):
        kind = "spoof"
        spoofed = True
        technique = "T1692.002"
    elif (on.get("ais") or attack_id == "ais-spoof") and sa == "24" and pgn == 129038:
        kind = "ais"
        spoofed = True
        technique = "T1692.002"
    elif (on.get("gyro") or attack_id == "heading-spoof") and sa == "35" and pgn == 127250 and not on.get("pgn_flood"):
        kind = "gyro"
        spoofed = True
        technique = "T1692.002"
    elif (on.get("rot") or attack_id == "rot-spoof") and sa == "35" and pgn == 127251:
        kind = "rot"
        spoofed = True
        technique = "T1692.002"
    elif (on.get("velocity") or attack_id == "sog-spoof") and sa == "16" and pgn == 129026 and kind == "ok":
        kind = "velocity"
        spoofed = True
        technique = "T1692.002"
    elif (on.get("rpm") or attack_id == "rpm-spoof") and sa in ("0", "1") and pgn == 127488 and frame.segment == "propulsion":
        kind = "rpm"
        spoofed = True
        technique = "T1692.002"
    elif (on.get("depth") or attack_id == "depth-spoof") and pgn == 128267:
        kind = "depth"
        spoofed = True
        technique = "T1692.002"
    elif (on.get("battery") or attack_id == "battery-spoof") and pgn == 127508:
        kind = "battery"
        spoofed = True
        technique = "T1692.002"
    elif (on.get("gateway_bypass") or attack_id == "gateway-bypass") and sa == "0" and pgn == 127488 and frame.segment == "nav":
        kind = "bypass"
        spoofed = True
        technique = "T1692"
        burst = True
    elif pgn == 59904:
        kind = "read"
        technique = "T0814" if on.get("read_flood") else "T0801"
        burst = bool(on.get("read_flood"))
    elif pgn == 126208:
        kind = "engine"
        technique = "T1692.001"
        burst = True
    elif pgn == 127237 and (fields.get("privileged") or sa == "44"):
        kind = "write"
        technique = "T0814" if on.get("write_flood") else "T1692.001"
        burst = bool(on.get("write_flood"))
    elif (on.get("pgn_flood") or attack_id == "pgn-flood") and sa == "35" and pgn == 127250:
        kind = "flood"
        technique = "T0814"
        burst = True
    elif (on.get("fast_packet") or attack_id == "fast-packet") and sa == "44" and pgn == 129029:
        kind = "flood"
        technique = "T0814"
        burst = True
    elif (on.get("rogue_master") or attack_id == "rogue-master") and pgn == 60928 and (
        sa == "44" or (sa == "16" and (fields.get("iso_name") or "").startswith("ROGUE"))
    ):
        kind = "rogue"
        technique = "T0848"
        burst = True
    if technique is None and kind != "ok":
        technique = ATTACK_TECHNIQUES.get(kind)
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
        "technique": technique,
        "hz": frequency,
        "burst": burst,
        "error": bool(frame.error),
    }


def attack_log_rows(frames, plant, attacks: dict | None, frequency: int) -> list[dict]:
    """Build the injector attack log. Non-burst attack frames are repeated `frequency` times."""
    hz = clamp_frequency(frequency)
    rows: list[dict] = []
    for frame in frames:
        row = emission_row(frame, plant, attacks, hz)
        copies = hz if row["kind"] != "ok" and not row["burst"] else 1
        for _ in range(copies):
            rows.append(dict(row))
    return rows


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
        gnss = self.attacks.get("spoof") or self.attacks.get("spoof_both")
        self.intensity = 1.0 if gnss else 0.0
        self.frequency = FREQ_DEFAULT
        self._build()

    def _build(self) -> None:
        scenario = "gps-spoof-underway" if (self.attacks.get("spoof") or self.attacks.get("spoof_both")) else "underway"
        aid = None
        for key in ATTACK_KEYS:
            if self.attacks.get(key):
                aid = ATTACK_IDS.get(key, key)
                break
        self.sim = OpvSimulator(
            sim_mode=self.mode,
            attack_id=aid,
            scenario_id=scenario,
            frequency=self.frequency,
        )
        self.sim.twins.enabled = dict(self.devices)
        self.sim.injector.attacks = dict(self.attacks)
        self.sim.injector.intensity = self.intensity
        self.sim.injector.frequency = self.frequency

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
        gnss = self.attacks.get("spoof") or self.attacks.get("spoof_both")
        self.intensity = 1.0 if gnss else 0.0
        self.frequency = FREQ_DEFAULT
        self._build()

    def set_intensity(self, intensity: float) -> None:
        self.set_attack("spoof", float(intensity) > 0)

    def set_frequency(self, hz: float | int) -> None:
        self.frequency = clamp_frequency(hz)
        self.sim.injector.frequency = self.frequency

    def set_attack(self, kind: str, enabled: bool) -> None:
        if kind not in ATTACK_KEYS:
            raise ValueError(kind)
        self.attacks[kind] = bool(enabled)
        gnss = self.attacks.get("spoof") or self.attacks.get("spoof_both")
        self.intensity = 1.0 if gnss else 0.0
        self.sim.injector.attacks = dict(self.attacks)
        self.sim.injector.intensity = self.intensity
        self.sim.injector.frequency = self.frequency
        active = [k for k, v in self.attacks.items() if v]
        if self.attacks.get("spoof_both"):
            self.attack_id = "gps-spoof-both"
            self.sim.engine.attack_id = "gps-spoof-both"
            self.sim.engine.scenario_id = "gps-spoof-underway"
        elif self.attacks.get("spoof"):
            self.attack_id = "gps-spoof-primary"
            self.sim.engine.attack_id = "gps-spoof-primary"
            self.sim.engine.scenario_id = "gps-spoof-underway"
        else:
            self.attack_id = ATTACK_IDS.get(active[0], active[0]) if active else ""
            self.sim.engine.attack_id = self.attack_id or None
            self.sim.engine.scenario_id = "underway"

    def set_device(self, sa: str, enabled: bool) -> None:
        sa = str(sa)
        if sa not in self.devices:
            raise ValueError(sa)
        self.devices[sa] = bool(enabled)
        self.sim.twins.set_device(sa, enabled)

    def tick(self):
        plant, frames = self.sim.tick(self.elapsed, attacks=self.attacks, frequency=self.frequency)
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
            "frequency": self.frequency,
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
        if self.attacks.get("spoof_both"):
            attack_id = "gps-spoof-both"
        elif self.attacks.get("spoof"):
            attack_id = "gps-spoof-primary"
        elif active:
            attack_id = ATTACK_IDS.get(active[0], active[0])
        else:
            attack_id = None
        hz = self.frequency
        return {
            "sim_mode": self.mode,
            "running": self.running,
            "attack_id": attack_id,
            "attacks": dict(self.attacks),
            "attack_catalog": [
                {"key": k, "label": label, "technique": tech, "detail": detail}
                for k, label, tech, detail in ATTACK_CATALOG
            ],
            "devices": dict(self.devices),
            "device_catalog": [
                {"sa": str(sa), "name": name, "segment": seg, "enabled": self.devices[str(sa)]}
                for sa, seg, name, _ in DEVICE_CATALOG
            ],
            "intensity": round(self.intensity, 3),
            "frequency": hz,
            "elapsed_s": self.elapsed,
            "ticks": self.ticks,
            "frames_this_tick": len(self.last_frames),
            "labels": len(self.sim.labels.records),
            "emissions": attack_log_rows(self.last_frames, plant, self.attacks, hz),
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
