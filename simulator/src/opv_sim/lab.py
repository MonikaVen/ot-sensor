"""Lab simulator facade: scenario → N2K twins → CAN bus."""

from __future__ import annotations

from otlab.bus import InMemoryCanBus
from opv_sim import ScenarioEngine
from opv_sim.labels import LabelTopic
from opv_sim.twins import (
    AttackInjector,
    DeviceTwins,
    IsolatingGateway,
    attacks_for,
    clamp_frequency,
    default_attacks,
)


_STAMP = (
    ("spoof_both", "gps-spoof-both", "inject"),
    ("spoof", "gps-spoof-primary", "inject"),
    ("ais", "ais-spoof", "inject"),
    ("gyro", "heading-spoof", "inject"),
    ("rot", "rot-spoof", "inject"),
    ("velocity", "sog-spoof", "inject"),
    ("rpm", "rpm-spoof", "inject"),
    ("depth", "depth-spoof", "inject"),
    ("battery", "battery-spoof", "inject"),
    ("engine_cmd", "engine-cmd", "inject"),
    ("rogue_master", "rogue-master", "inject"),
    ("gateway_bypass", "gateway-bypass", "inject"),
    ("write_flood", "write-flood", "flood"),
    ("read_flood", "read-flood", "flood"),
    ("error_flood", "error-flood", "flood"),
    ("fast_packet", "fast-packet", "flood"),
    ("pgn_flood", "pgn-flood", "flood"),
    ("write", "write", "inject"),
    ("read", "read", "inject"),
)


class OpvSimulator:
    """NMEA 2000 only. No Modbus slave, no 0183 talker."""

    def __init__(
        self,
        sim_mode: str = "dev",
        attack_id: str | None = None,
        scenario_id: str = "underway",
        label_topic_configured: bool = False,
        frequency: int | None = None,
    ) -> None:
        self.sim_mode = sim_mode
        self.engine = ScenarioEngine(scenario_id, attack_id, sim_mode)
        self.bus = InMemoryCanBus()
        self.injector = AttackInjector(sim_mode)
        self.injector.attacks = attacks_for(attack_id)
        gnss = self.injector.attacks.get("spoof") or self.injector.attacks.get("spoof_both")
        self.injector.intensity = 1.0 if gnss else 0.0
        self.injector.frequency = clamp_frequency(frequency)
        self.twins = DeviceTwins(self.bus, self.injector)
        self.gw = IsolatingGateway(self.bus)
        self.labels = LabelTopic(sim_mode, label_topic_configured)

    def _stamp_plant(self, plant) -> None:
        a = self.injector.attacks
        for key, attack_id, phase in _STAMP:
            if a.get(key):
                plant.attack_id = attack_id
                plant.phase = phase
                return
        if self.injector.extra_spoof_sas:
            plant.attack_id = "device-spoof"
            plant.phase = "inject"
            return
        plant.attack_id = None
        plant.phase = "underway"

    def tick(
        self,
        elapsed_s: float,
        intensity: float | None = None,
        attacks: dict | None = None,
        frequency: int | None = None,
    ):
        plant = self.engine.state_at(elapsed_s)
        if frequency is not None:
            self.injector.frequency = clamp_frequency(frequency)
        if attacks is not None:
            merged = default_attacks()
            merged.update({k: bool(v) for k, v in attacks.items() if k in merged})
            self.injector.attacks = merged
            gnss = merged.get("spoof") or merged.get("spoof_both")
            self.injector.intensity = 1.0 if gnss else 0.0
            self._stamp_plant(plant)
        elif intensity is not None:
            self.injector.attacks["spoof"] = intensity > 0
            self.injector.intensity = max(0.0, min(1.0, intensity))
            self._stamp_plant(plant)
        else:
            aid = plant.attack_id
            if aid:
                self.injector.attacks = attacks_for(aid)
                gnss = self.injector.attacks.get("spoof") or self.injector.attacks.get("spoof_both")
                self.injector.intensity = 1.0 if gnss else 0.0
            elif aid is None:
                self.injector.attacks["spoof"] = False
                self.injector.attacks["spoof_both"] = False
                self.injector.attacks["gyro"] = False
                self.injector.attacks["velocity"] = False
            self._stamp_plant(plant)
        frames = self.twins.publish(plant)
        for rec in self.injector.labels:
            self.labels.publish(rec)
        self.injector.labels.clear()
        return plant, frames
