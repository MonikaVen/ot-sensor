"""Lab simulator facade: scenario → N2K twins → CAN bus."""

from __future__ import annotations

from otlab.bus import InMemoryCanBus
from opv_sim import ScenarioEngine
from opv_sim.labels import LabelTopic
from opv_sim.twins import AttackInjector, DeviceTwins, IsolatingGateway, attacks_for, default_attacks


class OpvSimulator:
    """NMEA 2000 only. No Modbus slave, no 0183 talker."""

    def __init__(
        self,
        sim_mode: str = "dev",
        attack_id: str | None = None,
        scenario_id: str = "underway",
        label_topic_configured: bool = False,
    ) -> None:
        self.sim_mode = sim_mode
        self.engine = ScenarioEngine(scenario_id, attack_id, sim_mode)
        self.bus = InMemoryCanBus()
        self.injector = AttackInjector(sim_mode)
        self.injector.attacks = attacks_for(attack_id)
        self.injector.intensity = 1.0 if self.injector.attacks.get("spoof") else 0.0
        self.twins = DeviceTwins(self.bus, self.injector)
        self.gw = IsolatingGateway(self.bus)
        self.labels = LabelTopic(sim_mode, label_topic_configured)

    def _stamp_plant(self, plant) -> None:
        a = self.injector.attacks
        if a.get("spoof"):
            plant.attack_id = "gps-spoof-primary"
            plant.phase = "inject"
        elif a.get("gyro"):
            plant.attack_id = "heading-spoof"
            plant.phase = "inject"
        elif a.get("velocity"):
            plant.attack_id = "sog-spoof"
            plant.phase = "inject"
        elif a.get("write_flood"):
            plant.attack_id = "write-flood"
            plant.phase = "inject"
        elif a.get("read_flood"):
            plant.attack_id = "read-flood"
            plant.phase = "inject"
        elif a.get("write"):
            plant.attack_id = "write"
            plant.phase = "inject"
        elif a.get("read"):
            plant.attack_id = "read"
            plant.phase = "inject"
        elif a.get("pgn_flood"):
            plant.attack_id = "pgn-flood"
            plant.phase = "flood"
        else:
            plant.attack_id = None
            plant.phase = "underway"

    def tick(self, elapsed_s: float, intensity: float | None = None, attacks: dict | None = None):
        plant = self.engine.state_at(elapsed_s)
        if attacks is not None:
            merged = default_attacks()
            merged.update({k: bool(v) for k, v in attacks.items() if k in merged})
            self.injector.attacks = merged
            self.injector.intensity = 1.0 if merged.get("spoof") else 0.0
            self._stamp_plant(plant)
        elif intensity is not None:
            self.injector.attacks["spoof"] = intensity > 0
            self.injector.intensity = max(0.0, min(1.0, intensity))
            self._stamp_plant(plant)
        else:
            if plant.attack_id == "gps-spoof-primary":
                self.injector.attacks["spoof"] = True
                self.injector.intensity = 1.0
            elif plant.attack_id in ("heading-spoof", "gyro"):
                self.injector.attacks["gyro"] = True
            elif plant.attack_id in ("sog-spoof", "velocity"):
                self.injector.attacks["velocity"] = True
            elif plant.attack_id == "pgn-flood":
                self.injector.attacks["pgn_flood"] = True
            elif plant.attack_id is None:
                self.injector.attacks["spoof"] = False
                self.injector.attacks["gyro"] = False
                self.injector.attacks["velocity"] = False
        frames = self.twins.publish(plant)
        for rec in self.injector.labels:
            self.labels.publish(rec)
        self.injector.labels.clear()
        return plant, frames
