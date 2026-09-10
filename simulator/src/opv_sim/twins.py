"""Device twins + isolating gateways + attack injector."""

from __future__ import annotations

from otlab import CanFrame, LabelRecord, PlantState
from otlab.bus import InMemoryCanBus
from otlab.geo import dest_point
from otlab.pgn import (
    encode_ais_position,
    encode_ais_static,
    encode_attitude,
    encode_battery,
    encode_binary_status,
    encode_claim,
    encode_cog_sog,
    encode_depth,
    encode_dops,
    encode_engine_control,
    encode_engine_dynamic,
    encode_environment,
    encode_error_frame,
    encode_fluid_level,
    encode_heading,
    encode_heading_control,
    encode_iso_request,
    encode_position,
    encode_rate_of_turn,
    encode_rpm,
    encode_rudder,
    encode_sats,
    encode_speed_water,
    encode_transmission,
    encode_wind,
    decode_fields,
)
from otlab.can import unpack_id

NAV_TO_PROP = {127250, 129026, 126992}
ROGUE_SA = 44
FREQ_MIN = 1
FREQ_MAX = 32
FREQ_DEFAULT = 16
GYRO_HEADING_OFFSET_DEG = 40.0
ROT_OFFSET_DEG_S = 8.0
VEL_SOG_OFFSET_KN = 8.0
RPM_OFFSET = 420.0
DEPTH_OFFSET_M = 12.0
BATTERY_VOLTS = 11.2
TRUE_BATTERY_VOLTS = 28.0

ATTACK_KEYS = (
    "spoof",
    "spoof_both",
    "ais",
    "gyro",
    "rot",
    "velocity",
    "rpm",
    "depth",
    "battery",
    "read",
    "write",
    "engine_cmd",
    "read_flood",
    "write_flood",
    "pgn_flood",
    "error_flood",
    "fast_packet",
    "rogue_master",
    "gateway_bypass",
)

ATTACK_IDS = {
    "spoof": "gps-spoof-primary",
    "spoof_both": "gps-spoof-both",
    "ais": "ais-spoof",
    "gyro": "heading-spoof",
    "rot": "rot-spoof",
    "velocity": "sog-spoof",
    "rpm": "rpm-spoof",
    "depth": "depth-spoof",
    "battery": "battery-spoof",
    "read": "read",
    "write": "write",
    "engine_cmd": "engine-cmd",
    "read_flood": "read-flood",
    "write_flood": "write-flood",
    "pgn_flood": "pgn-flood",
    "error_flood": "error-flood",
    "fast_packet": "fast-packet",
    "rogue_master": "rogue-master",
    "gateway_bypass": "gateway-bypass",
}

ATTACK_TECHNIQUES = {
    "spoof": "T1692.002",
    "spoof_both": "T1692.002",
    "ais": "T1692.002",
    "gyro": "T1692.002",
    "rot": "T1692.002",
    "velocity": "T1692.002",
    "rpm": "T1692.002",
    "depth": "T1692.002",
    "battery": "T1692.002",
    "read": "T0801",
    "write": "T1692.001",
    "engine_cmd": "T1692.001",
    "read_flood": "T0814",
    "write_flood": "T0814",
    "pgn_flood": "T0814",
    "error_flood": "T0814",
    "fast_packet": "T0814",
    "rogue_master": "T0848",
    "gateway_bypass": "T1692",
}

ATTACK_CATALOG = [
    ("spoof", "GNSS-1 spoof", "T1692.002", "129025"),
    ("spoof_both", "GNSS-1+2 spoof", "T1692.002", "gps-spoof-both"),
    ("ais", "AIS spoof", "T1692.002", "129038"),
    ("gyro", "Gyro spoof", "T1692.002", "127250"),
    ("rot", "ROT spoof", "T1692.002", "127251"),
    ("velocity", "Velocity spoof", "T1692.002", "129026 SOG"),
    ("rpm", "RPM spoof", "T1692.002", "127488"),
    ("depth", "Depth spoof", "T1692.002", "128267"),
    ("battery", "Battery spoof", "T1692.002", "127508"),
    ("read", "Read", "T0801", "ISO Request 59904"),
    ("write", "Write", "T1692.001 · T0855", "127237"),
    ("engine_cmd", "Engine command", "T1692.001", "126208"),
    ("read_flood", "Read flood", "T0814", "ISO Request burst"),
    ("write_flood", "Write flood", "T0814", "127237 burst"),
    ("pgn_flood", "PGN flood", "T0814", "heading burst"),
    ("error_flood", "Error flood", "T0814", "error frames"),
    ("fast_packet", "Fast Packet flood", "T0814", "129029 exhaustion"),
    ("rogue_master", "Rogue Master", "T0848", "SA 16 NAME theft"),
    ("gateway_bypass", "Gateway bypass", "T1692", "RPM onto nav"),
]

# sa, segment, name, default_on
DEVICE_CATALOG = [
    (16, "nav", "GNSS-1", True),
    (17, "nav", "GNSS-2", True),
    (35, "nav", "gyro", True),
    (40, "nav", "echo", True),
    (48, "nav", "wind", True),
    (24, "nav", "AIS", False),
    (56, "nav", "autopilot", False),
    (52, "nav", "rudder", False),
    (60, "nav", "MFD", False),
    (99, "nav", "decoy", False),
    (0, "propulsion", "engine-port", True),
    (1, "propulsion", "engine-stbd", True),
    (4, "propulsion", "gear-port", True),
    (5, "propulsion", "gear-stbd", True),
    (8, "propulsion", "fuel", True),
    (12, "propulsion", "thruster", False),
    (20, "power", "genset-1", False),
    (21, "power", "genset-2", False),
    (28, "power", "battery", True),
    (32, "power", "switchbank", False),
    (80, "aux", "environment", True),
    (84, "aux", "tanks", True),
    (88, "aux", "bilge-fire", True),
]


def clamp_frequency(hz: float | int | None) -> int:
    try:
        value = int(round(float(hz)))
    except (TypeError, ValueError):
        return FREQ_DEFAULT
    return max(FREQ_MIN, min(FREQ_MAX, value))


def default_devices() -> dict[str, bool]:
    return {str(sa): on for sa, _seg, _name, on in DEVICE_CATALOG}


def default_attacks(spoof_on: bool = False) -> dict[str, bool]:
    return {k: (k == "spoof" and spoof_on) for k in ATTACK_KEYS}


def attacks_for(attack_id: str | None) -> dict[str, bool]:
    on = default_attacks(False)
    aid = attack_id or ""
    if aid in ("gps-spoof-primary", "gps-spoof-underway"):
        on["spoof"] = True
    elif aid in ("gps-spoof-both", "spoof_both"):
        on["spoof_both"] = True
    elif aid in ("heading-spoof", "gyro"):
        on["gyro"] = True
    elif aid in ("sog-spoof", "velocity"):
        on["velocity"] = True
    elif aid in ("ais-spoof", "ais"):
        on["ais"] = True
    elif aid in ("rot-spoof", "rot"):
        on["rot"] = True
    elif aid in ("rpm-spoof", "rpm"):
        on["rpm"] = True
    elif aid in ("depth-spoof", "depth"):
        on["depth"] = True
    elif aid in ("battery-spoof", "battery"):
        on["battery"] = True
    elif aid in ("engine-cmd", "engine_cmd"):
        on["engine_cmd"] = True
    elif aid in ("rogue-master", "rogue_master", "gps-spoof-sa-collision"):
        on["rogue_master"] = True
    elif aid in ("gateway-bypass", "gateway_bypass"):
        on["gateway_bypass"] = True
    elif aid in ("error-flood", "error_flood"):
        on["error_flood"] = True
    elif aid in ("fast-packet", "fast_packet"):
        on["fast_packet"] = True
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
        self.frequency = FREQ_DEFAULT
        self.attacks = default_attacks(False)
        self.labels: list[LabelRecord] = []

    def burst_n(self) -> int:
        return clamp_frequency(self.frequency)

    def gnss_spoof_on(self) -> bool:
        return bool((self.attacks.get("spoof") or self.attacks.get("spoof_both")) and self.intensity > 0)

    def spoof_gnss1(self, plant: PlantState) -> tuple[float, float, float]:
        if not self.gnss_spoof_on():
            return plant.lat_deg, plant.lon_deg, plant.cog_deg
        offset_m = 120.0 * self.intensity
        cog_off = 25.0 * self.intensity
        lat, lon = dest_point(plant.lat_deg, plant.lon_deg, plant.heading_deg + 90.0, offset_m)
        return lat, lon, (plant.cog_deg + cog_off) % 360.0

    def spoof_ais(self, plant: PlantState) -> tuple[float, float]:
        if not self.attacks.get("ais"):
            return plant.lat_deg, plant.lon_deg
        return dest_point(plant.lat_deg, plant.lon_deg, plant.heading_deg + 45.0, 80.0)

    def spoof_heading(self, plant: PlantState) -> float:
        if not self.attacks.get("gyro"):
            return plant.heading_deg
        return (plant.heading_deg + GYRO_HEADING_OFFSET_DEG) % 360.0

    def spoof_rot(self, plant: PlantState) -> float:
        if not self.attacks.get("rot"):
            return plant.rot_deg_s
        return plant.rot_deg_s + ROT_OFFSET_DEG_S

    def spoof_sog(self, plant: PlantState) -> float:
        if not self.attacks.get("velocity"):
            return plant.sog_kn
        return max(0.0, plant.sog_kn + VEL_SOG_OFFSET_KN)

    def spoof_rpm(self, plant: PlantState, which: str = "port") -> float:
        base = plant.rpm_port if which == "port" else plant.rpm_stbd
        if not self.attacks.get("rpm"):
            return base
        return base + RPM_OFFSET

    def spoof_depth(self, plant: PlantState) -> float:
        if not self.attacks.get("depth"):
            return plant.depth_m
        return plant.depth_m + DEPTH_OFFSET_M

    def spoof_battery(self) -> float:
        if not self.attacks.get("battery"):
            return TRUE_BATTERY_VOLTS
        return BATTERY_VOLTS

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
        segment: str = "nav",
        copies: int | None = None,
    ) -> LabelRecord | None:
        if self.sim_mode != "dev":
            return None
        n = max(1, copies if copies is not None else 1)
        rec = None
        for _ in range(n):
            rec = LabelRecord(
                t=plant.t,
                scenario_id=scenario_id or plant.scenario_id or "underway",
                attack_id=attack_id or plant.attack_id or "gps-spoof-primary",
                technique=technique,
                victim_sa=sa,
                pgn=pgn,
                segment=segment,
                phase=plant.phase,
                frequency_hz=self.burst_n(),
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

    def _burst(self, frames: list[CanFrame], make) -> None:
        for _ in range(self.injector.burst_n()):
            self._emit(frames, make())

    def publish(self, plant: PlantState) -> list[CanFrame]:
        frames: list[CanFrame] = []
        n = self.injector.burst_n()
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
                if self.injector.gnss_spoof_on():
                    self.injector.record_label(
                        plant,
                        pgn,
                        16,
                        technique="T1692.002",
                        attack_id="gps-spoof-both" if self.injector.attacks.get("spoof_both") else "gps-spoof-primary",
                        scenario_id="gps-spoof-underway",
                        copies=n,
                    )
                elif self.injector.attacks.get("velocity") and pgn == 129026:
                    self.injector.record_label(
                        plant,
                        129026,
                        16,
                        technique="T1692.002",
                        attack_id="sog-spoof",
                        scenario_id="underway",
                        copies=n,
                    )
        lat2, lon2, cog2 = (lat1, lon1, cog1) if self.injector.attacks.get("spoof_both") and self.injector.intensity > 0 else (
            plant.lat_deg,
            plant.lon_deg,
            plant.cog_deg,
        )
        sog2 = sog1 if self.injector.attacks.get("spoof_both") else plant.sog_kn
        if self._on(17):
            for enc in (
                encode_position(plant.t, "nav", 17, lat2, lon2),
                encode_cog_sog(plant.t, "nav", 17, cog2, sog2),
                encode_dops(plant.t, "nav", 17, plant.hdop),
                encode_sats(plant.t, "nav", 17, plant.sat_count, lat2, lon2),
            ):
                self._emit(frames, enc)
                if self.injector.attacks.get("spoof_both") and self.injector.intensity > 0:
                    self.injector.record_label(
                        plant,
                        decode_fields(enc)["pgn"],
                        17,
                        technique="T1692.002",
                        attack_id="gps-spoof-both",
                        scenario_id="gps-spoof-underway",
                        copies=n,
                    )
        heading = self.injector.spoof_heading(plant)
        rot = self.injector.spoof_rot(plant)
        if self._on(35):
            pitch = 0.4
            roll = rot * 0.35
            self._emit(frames, encode_heading(plant.t, "nav", 35, heading))
            self._emit(frames, encode_rate_of_turn(plant.t, "nav", 35, rot))
            self._emit(frames, encode_attitude(plant.t, "nav", 35, heading, pitch, roll))
            if self.injector.attacks.get("gyro"):
                self.injector.record_label(
                    plant,
                    127250,
                    35,
                    technique="T1692.002",
                    attack_id="heading-spoof",
                    scenario_id="underway",
                    copies=n,
                )
            if self.injector.attacks.get("rot"):
                self.injector.record_label(
                    plant,
                    127251,
                    35,
                    technique="T1692.002",
                    attack_id="rot-spoof",
                    scenario_id="underway",
                    copies=n,
                )
        rpm_port = self.injector.spoof_rpm(plant, "port")
        rpm_stbd = self.injector.spoof_rpm(plant, "stbd")
        load = 55.0 if plant.sog_kn > 1 else 12.0
        oil_kpa = 420.0
        if self._on(0):
            self._emit(frames, encode_rpm(plant.t, "propulsion", 0, rpm_port))
            self._emit(frames, encode_engine_dynamic(plant.t, "propulsion", 0, plant.oil_temp_c, oil_kpa, load))
            if self.injector.attacks.get("rpm"):
                self.injector.record_label(
                    plant,
                    127488,
                    0,
                    technique="T1692.002",
                    attack_id="rpm-spoof",
                    scenario_id="underway",
                    segment="propulsion",
                    copies=n,
                )
        if self._on(1):
            self._emit(frames, encode_rpm(plant.t, "propulsion", 1, rpm_stbd))
            self._emit(frames, encode_engine_dynamic(plant.t, "propulsion", 1, plant.oil_temp_c, oil_kpa, load))
        gear = 1 if plant.sog_kn > 1 else 0
        if self._on(4):
            self._emit(frames, encode_transmission(plant.t, "propulsion", 4, gear))
        if self._on(5):
            self._emit(frames, encode_transmission(plant.t, "propulsion", 5, gear))
        if self._on(8):
            self._emit(frames, encode_fluid_level(plant.t, "propulsion", 8, 68.0, instance=0))
        echo_on = self._on(40) or self.injector.attacks.get("depth")
        if echo_on:
            depth = self.injector.spoof_depth(plant)
            stw = max(0.0, plant.sog_kn * 0.96)
            self._emit(frames, encode_depth(plant.t, "nav", 40, depth))
            self._emit(frames, encode_speed_water(plant.t, "nav", 40, stw))
            if self.injector.attacks.get("depth"):
                self.injector.record_label(
                    plant,
                    128267,
                    40,
                    technique="T1692.002",
                    attack_id="depth-spoof",
                    scenario_id="underway",
                    copies=n,
                )
        if self._on(48):
            self._emit(frames, encode_wind(plant.t, "nav", 48, 12.0, 40.0))
        ais_on = self._on(24) or self.injector.attacks.get("ais")
        if ais_on:
            alat, alon = self.injector.spoof_ais(plant)
            self._emit(frames, encode_ais_position(plant.t, "nav", 24, alat, alon))
            self._emit(frames, encode_ais_static(plant.t, "nav", 24, "OPV-LAB1"))
            if self.injector.attacks.get("ais"):
                self.injector.record_label(
                    plant,
                    129038,
                    24,
                    technique="T1692.002",
                    attack_id="ais-spoof",
                    scenario_id="underway",
                    copies=n,
                )
        if self._on(56):
            self._emit(frames, encode_heading_control(plant.t, "nav", 56, plant.heading_deg, status=True))
        if self._on(52):
            angle = max(-35.0, min(35.0, rot * 2.5))
            self._emit(frames, encode_rudder(plant.t, "nav", 52, angle))
        if self._on(12):
            self._emit(frames, encode_rpm(plant.t, "propulsion", 12, 900.0))
        if self._on(20):
            self._emit(frames, encode_rpm(plant.t, "power", 20, 1800.0))
        if self._on(21):
            self._emit(frames, encode_rpm(plant.t, "power", 21, 1800.0))
        batt_on = self._on(28) or self.injector.attacks.get("battery")
        if batt_on:
            self._emit(frames, encode_battery(plant.t, "power", 28, self.injector.spoof_battery()))
            if self.injector.attacks.get("battery"):
                self.injector.record_label(
                    plant,
                    127508,
                    28,
                    technique="T1692.002",
                    attack_id="battery-spoof",
                    scenario_id="underway",
                    segment="power",
                    copies=n,
                )
        if self._on(32):
            bits = 0x01 if plant.breaker_closed else 0x00
            self._emit(frames, encode_binary_status(plant.t, "power", 32, bits))
        if self._on(80):
            self._emit(frames, encode_environment(plant.t, "aux", 80, 16.0, 78.0))
        if self._on(84):
            self._emit(frames, encode_fluid_level(plant.t, "aux", 84, 41.0, instance=1))
        if self._on(88):
            self._emit(frames, encode_binary_status(plant.t, "aux", 88, 0))

        attacks = self.injector.attacks
        if attacks.get("pgn_flood") and self._on(35):
            self._burst(frames, lambda: encode_heading(plant.t, "nav", 35, heading))
            self.injector.record_label(
                plant, 127250, 35, technique="T0814", attack_id="pgn-flood", scenario_id="underway", copies=n
            )
        if attacks.get("error_flood"):
            self._burst(frames, lambda: encode_error_frame(plant.t, "nav", ROGUE_SA, 127250))
            self.injector.record_label(
                plant, 127250, ROGUE_SA, technique="T0814", attack_id="error-flood", scenario_id="underway", copies=n
            )
        if attacks.get("fast_packet"):
            self._burst(
                frames,
                lambda: encode_sats(plant.t, "nav", ROGUE_SA, plant.sat_count, plant.lat_deg, plant.lon_deg),
            )
            self.injector.record_label(
                plant, 129029, ROGUE_SA, technique="T0814", attack_id="fast-packet", scenario_id="underway", copies=n
            )
        if attacks.get("read") or attacks.get("read_flood"):
            count = n if attacks.get("read_flood") else 1
            for _ in range(count):
                self._emit(frames, encode_iso_request(plant.t, "nav", ROGUE_SA, 16, 129025))
                self._emit(frames, encode_iso_request(plant.t, "propulsion", ROGUE_SA, 0, 127488))
                self._emit(frames, encode_iso_request(plant.t, "propulsion", ROGUE_SA, 1, 127488))
            self.injector.record_label(
                plant,
                59904,
                ROGUE_SA,
                technique="T0814" if attacks.get("read_flood") else "T0801",
                attack_id="read-flood" if attacks.get("read_flood") else "read",
                scenario_id="underway",
                copies=n if attacks.get("read_flood") else 1,
            )
        if attacks.get("write") or attacks.get("write_flood"):
            count = n if attacks.get("write_flood") else 1
            for _ in range(count):
                self._emit(frames, encode_heading_control(plant.t, "nav", ROGUE_SA, plant.heading_deg))
            self.injector.record_label(
                plant,
                127237,
                ROGUE_SA,
                technique="T0814" if attacks.get("write_flood") else "T1692.001",
                attack_id="write-flood" if attacks.get("write_flood") else "write",
                scenario_id="underway",
                copies=n if attacks.get("write_flood") else 1,
            )
        if attacks.get("engine_cmd"):
            self._burst(frames, lambda: encode_engine_control(plant.t, "propulsion", ROGUE_SA, 0, 1800.0))
            self.injector.record_label(
                plant,
                126208,
                ROGUE_SA,
                technique="T1692.001",
                attack_id="engine-cmd",
                scenario_id="underway",
                segment="propulsion",
                copies=n,
            )
        if attacks.get("rogue_master"):
            self._burst(frames, lambda: encode_claim(plant.t, "nav", 16, "ROGUE16"))
            self._burst(frames, lambda: encode_claim(plant.t, "nav", ROGUE_SA, "ROGUE"))
            self.injector.record_label(
                plant, 60928, 16, technique="T0848", attack_id="rogue-master", scenario_id="underway", copies=n
            )
        if attacks.get("gateway_bypass") and self._on(0):
            self._burst(frames, lambda: encode_rpm(plant.t, "nav", 0, rpm_port))
            self.injector.record_label(
                plant,
                127488,
                0,
                technique="T1692",
                attack_id="gateway-bypass",
                scenario_id="underway",
                segment="nav",
                copies=n,
            )
        return frames
