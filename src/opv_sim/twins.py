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
    encode_position,
    encode_rpm,
    encode_sats,
    decode_fields,
)
from otlab.can import unpack_id

# nav → propulsion allowlist
NAV_TO_PROP = {127250, 129026, 126992}


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
        """Attack path: ignore allowlist."""
        forwarded = CanFrame(frame.t, dest_segment, frame.can_id, frame.data, frame.error)
        self.bus.send(forwarded)
        return forwarded


class AttackInjector:
    def __init__(self, sim_mode: str = "dev") -> None:
        self.sim_mode = sim_mode
        self.labels: list[LabelRecord] = []

    def spoof_gnss1(self, plant: PlantState) -> tuple[float, float, float]:
        """Walk GNSS-1 off DR. Returns lat, lon, cog for SA 16."""
        if plant.attack_id != "gps-spoof-primary":
            return plant.lat_deg, plant.lon_deg, plant.cog_deg
        offset_m = 90.0 if plant.phase == "ramp" else 120.0
        lat, lon = dest_point(plant.lat_deg, plant.lon_deg, plant.heading_deg + 90.0, offset_m)
        return lat, lon, (plant.cog_deg + 25.0) % 360.0

    def record_label(self, plant: PlantState, pgn: int, sa: int) -> LabelRecord | None:
        if self.sim_mode != "dev":
            return None
        if not plant.attack_id or plant.phase in ("baseline", "recover"):
            return None
        rec = LabelRecord(
            t=plant.t,
            scenario_id="gps-spoof-underway",
            attack_id=plant.attack_id,
            technique="T1692.002",
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
        self.claimed = False

    def claim(self, plant: PlantState) -> None:
        for sa, seg in ((16, "nav"), (17, "nav"), (35, "nav"), (24, "nav"), (0, "propulsion"), (1, "propulsion")):
            self.bus.send(encode_claim(plant.t, seg, sa))
        self.claimed = True

    def publish(self, plant: PlantState) -> list[CanFrame]:
        if not self.claimed:
            self.claim(plant)
        frames: list[CanFrame] = []
        lat1, lon1, cog1 = self.injector.spoof_gnss1(plant)
        # GNSS-1 (possibly spoofed)
        for enc in (
            encode_position(plant.t, "nav", 16, lat1, lon1),
            encode_cog_sog(plant.t, "nav", 16, cog1, plant.sog_kn),
            encode_dops(plant.t, "nav", 16, plant.hdop),
            encode_sats(plant.t, "nav", 16, plant.sat_count, lat1, lon1),
        ):
            self.bus.send(enc)
            frames.append(enc)
            self.injector.record_label(plant, decode_fields(enc)["pgn"], 16)
        # GNSS-2 true
        for enc in (
            encode_position(plant.t, "nav", 17, plant.lat_deg, plant.lon_deg),
            encode_cog_sog(plant.t, "nav", 17, plant.cog_deg, plant.sog_kn),
            encode_dops(plant.t, "nav", 17, plant.hdop),
            encode_sats(plant.t, "nav", 17, plant.sat_count, plant.lat_deg, plant.lon_deg),
        ):
            self.bus.send(enc)
            frames.append(enc)
        # gyro + engines true
        for enc in (
            encode_heading(plant.t, "nav", 35, plant.heading_deg),
            encode_rpm(plant.t, "propulsion", 0, plant.rpm_port),
            encode_rpm(plant.t, "propulsion", 1, plant.rpm_stbd),
        ):
            self.bus.send(enc)
            frames.append(enc)
        if plant.attack_id == "pgn-flood":
            for i in range(40):
                f = encode_heading(plant.t, "nav", 35, plant.heading_deg)
                self.bus.send(f)
                frames.append(f)
        return frames
