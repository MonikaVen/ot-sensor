"""Device twins + isolating gateways + attack injector."""

from __future__ import annotations

from otlab import CanFrame, LabelRecord, PlantState
from otlab.bus import InMemoryCanBus
from otlab.geo import dest_point
from otlab.pgn import (
    encode_claim,
    encode_cog_sog,
    encode_dops,
    encode_heading,
    encode_heading_control,
    encode_iso_request,
    encode_position,
    encode_rpm,
    encode_sats,
    decode_fields,
)
from otlab.can import unpack_id

NAV_TO_PROP = {127250, 129026, 126992}
ROGUE_SA = 44
FLOOD_N = 16
GYRO_HEADING_OFFSET_DEG = 40.0
VEL_SOG_OFFSET_KN = 8.0
ATTACK_KEYS = ("spoof", "gyro", "velocity", "read", "write", "read_flood", "write_flood", "pgn_flood")
ATTACK_IDS = {
    "spoof": "gps-spoof-primary",
    "gyro": "heading-spoof",
    "velocity": "sog-spoof",
    "read": "read",
    "write": "write",
    "read_flood": "read-flood",
    "write_flood": "write-flood",
    "pgn_flood": "pgn-flood",
}

# sa, segment, name, default_on
DEVICE_CATALOG = [
    (16, "nav", "GNSS-1", True),
    (17, "nav", "GNSS-2", True),
    (35, "nav", "gyro", True),
    (24, "nav", "AIS", False),
    (56, "nav", "autopilot", False),
    (52, "nav", "rudder", False),
    (60, "nav", "MFD", False),
    (99, "nav", "decoy", False),
    (0, "propulsion", "engine-port", True),
    (1, "propulsion", "engine-stbd", True),
    (12, "propulsion", "thruster", False),
    (20, "power", "genset-1", False),
]


def default_devices() -> dict[str, bool]:
    return {str(sa): on for sa, _seg, _name, on in DEVICE_CATALOG}


def default_attacks(spoof_on: bool = False) -> dict[str, bool]:
    return {k: (k == "spoof" and spoof_on) for k in ATTACK_KEYS}


def attacks_for(attack_id: str | None) -> dict[str, bool]:
    on = default_attacks(False)
    aid = attack_id or ""
    if aid in ("gps-spoof-primary", "gps-spoof-underway"):
        on["spoof"] = True
    elif aid in ("heading-spoof", "gyro"):
        on["gyro"] = True
    elif aid in ("sog-spoof", "velocity"):
        on["velocity"] = True
    elif aid == "pgn-flood":
        on["pgn_flood"] = True
    elif aid in ATTACK_KEYS:
        on[aid] = True
    elif aid:
        on["spoof"] = True
    return on


class IsolatingGateway:
    def __init__(self, bus: InMemoryCanBus) -> None:
        self.bus = bus

    def forward(self, frame: CanFrame, dest_segment: str) -> CanFrame | None:
        pgn = unpack_id(frame.can_id)["pgn"]
        if frame.segment == "nav" and dest_segment == "propulsion":
            if pgn not in NAV_TO_PROP:
                return None
        if frame.segment == "propulsion" and dest_segment == "nav":
            return None
        forwarded = CanFrame(frame.t, dest_segment, frame.can_id, frame.data, frame.error)
        self.bus.send(forwarded)
        return forwarded

    def force_bypass(self, frame: CanFrame, dest_segment: str) -> CanFrame:
        forwarded = CanFrame(frame.t, dest_segment, frame.can_id, frame.data, frame.error)
        self.bus.send(forwarded)
        return forwarded


class AttackInjector:
    def __init__(self, sim_mode: str = "dev") -> None:
        self.sim_mode = sim_mode
        self.intensity = 1.0
        self.attacks = default_attacks(False)
        self.labels: list[LabelRecord] = []

    def spoof_gnss1(self, plant: PlantState) -> tuple[float, float, float]:
        if not self.attacks.get("spoof") or self.intensity <= 0:
            return plant.lat_deg, plant.lon_deg, plant.cog_deg
        offset_m = 120.0 * self.intensity
        cog_off = 25.0 * self.intensity
        lat, lon = dest_point(plant.lat_deg, plant.lon_deg, plant.heading_deg + 90.0, offset_m)
        return lat, lon, (plant.cog_deg + cog_off) % 360.0

    def spoof_heading(self, plant: PlantState) -> float:
        if not self.attacks.get("gyro"):
            return plant.heading_deg
        return (plant.heading_deg + GYRO_HEADING_OFFSET_DEG) % 360.0

    def spoof_sog(self, plant: PlantState) -> float:
        if not self.attacks.get("velocity"):
            return plant.sog_kn
        return max(0.0, plant.sog_kn + VEL_SOG_OFFSET_KN)

    def reported(self, plant: PlantState | None) -> dict | None:
        if plant is None:
            return None
        lat, lon, cog = self.spoof_gnss1(plant)
        sog = self.spoof_sog(plant)
        hdg = self.spoof_heading(plant)
        return {
            "lat_deg": lat,
            "lon_deg": lon,
            "cog_deg": cog,
            "sog_kn": sog,
            "sog_ms": sog * 0.514444,
            "heading_deg": hdg,
        }

    def record_label(
        self,
        plant: PlantState,
        pgn: int,
        sa: int,
        *,
        technique: str = "T1692.002",
        attack_id: str | None = None,
        scenario_id: str | None = None,
    ) -> LabelRecord | None:
        if self.sim_mode != "dev":
            return None
        rec = LabelRecord(
            t=plant.t,
            scenario_id=scenario_id or plant.scenario_id or "underway",
            attack_id=attack_id or plant.attack_id or "gps-spoof-primary",
            technique=technique,
            victim_sa=sa,
            pgn=pgn,
            segment="nav",
            phase=plant.phase,
        )
        self.labels.append(rec)
        return rec


class DeviceTwins:
    def __init__(self, bus: InMemoryCanBus, injector: AttackInjector) -> None:
        self.bus = bus
        self.injector = injector
        self.enabled = default_devices()
        self.claimed: set[int] = set()

    def _on(self, sa: int) -> bool:
        return bool(self.enabled.get(str(sa), False))

    def set_device(self, sa: str, enabled: bool) -> None:
        if sa not in self.enabled:
            return
        self.enabled[str(sa)] = bool(enabled)

    def _emit(self, frames: list[CanFrame], enc: CanFrame) -> None:
        self.bus.send(enc)
        frames.append(enc)

    def publish(self, plant: PlantState) -> list[CanFrame]:
        frames: list[CanFrame] = []
        for sa, seg, name, _on in DEVICE_CATALOG:
            if self._on(sa) and sa not in self.claimed:
                self._emit(frames, encode_claim(plant.t, seg, sa, name[:8]))
                self.claimed.add(sa)
            if not self._on(sa):
                self.claimed.discard(sa)

        lat1, lon1, cog1 = self.injector.spoof_gnss1(plant)
        sog1 = self.injector.spoof_sog(plant)
        if self._on(16):
            for enc in (
                encode_position(plant.t, "nav", 16, lat1, lon1),
                encode_cog_sog(plant.t, "nav", 16, cog1, sog1),
                encode_dops(plant.t, "nav", 16, plant.hdop),
                encode_sats(plant.t, "nav", 16, plant.sat_count, lat1, lon1),
            ):
                self._emit(frames, enc)
                pgn = decode_fields(enc)["pgn"]
                if self.injector.attacks.get("spoof") and self.injector.intensity > 0:
                    self.injector.record_label(
                        plant,
                        pgn,
                        16,
                        attack_id="gps-spoof-primary",
                        scenario_id="gps-spoof-underway",
                    )
                elif self.injector.attacks.get("velocity") and pgn == 129026:
                    self.injector.record_label(
                        plant,
                        129026,
                        16,
                        attack_id="sog-spoof",
                        scenario_id="underway",
                    )
        if self._on(17):
            for enc in (
                encode_position(plant.t, "nav", 17, plant.lat_deg, plant.lon_deg),
                encode_cog_sog(plant.t, "nav", 17, plant.cog_deg, plant.sog_kn),
                encode_dops(plant.t, "nav", 17, plant.hdop),
                encode_sats(plant.t, "nav", 17, plant.sat_count, plant.lat_deg, plant.lon_deg),
            ):
                self._emit(frames, enc)
        heading = self.injector.spoof_heading(plant)
        if self._on(35):
            self._emit(frames, encode_heading(plant.t, "nav", 35, heading))
            if self.injector.attacks.get("gyro"):
                self.injector.record_label(
                    plant,
                    127250,
                    35,
                    attack_id="heading-spoof",
                    scenario_id="underway",
                )
        if self._on(0):
            self._emit(frames, encode_rpm(plant.t, "propulsion", 0, plant.rpm_port))
        if self._on(1):
            self._emit(frames, encode_rpm(plant.t, "propulsion", 1, plant.rpm_stbd))
        if self._on(24):
            self._emit(frames, encode_position(plant.t, "nav", 24, plant.lat_deg, plant.lon_deg))
        if self._on(56):
            self._emit(frames, encode_heading(plant.t, "nav", 56, plant.heading_deg))
        if self._on(52):
            self._emit(frames, encode_heading(plant.t, "nav", 52, plant.heading_deg))
        if self._on(12):
            self._emit(frames, encode_rpm(plant.t, "propulsion", 12, 900.0))
        if self._on(20):
            self._emit(frames, encode_rpm(plant.t, "power", 20, 1800.0))

        attacks = self.injector.attacks
        if attacks.get("pgn_flood") and self._on(35):
            for _ in range(FLOOD_N):
                self._emit(frames, encode_heading(plant.t, "nav", 35, heading))
        if attacks.get("read") or attacks.get("read_flood"):
            n = FLOOD_N if attacks.get("read_flood") else 1
            for _ in range(n):
                self._emit(frames, encode_iso_request(plant.t, "nav", ROGUE_SA, 16, 129025))
                self._emit(frames, encode_iso_request(plant.t, "propulsion", ROGUE_SA, 0, 127488))
                self._emit(frames, encode_iso_request(plant.t, "propulsion", ROGUE_SA, 1, 127488))
        if attacks.get("write") or attacks.get("write_flood"):
            n = FLOOD_N if attacks.get("write_flood") else 1
            for _ in range(n):
                self._emit(frames, encode_heading_control(plant.t, "nav", ROGUE_SA, plant.heading_deg))
        return frames
