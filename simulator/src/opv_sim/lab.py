"""Lab simulator facade: scenario → N2K twins → CAN bus."""

from __future__ import annotations

from otlab.bus import InMemoryCanBus
from opv_sim import ScenarioEngine
from opv_sim.labels import LabelTopic
from opv_sim.twins import AttackInjector, DeviceTwins, IsolatingGateway


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
        self.twins = DeviceTwins(self.bus, self.injector)
        self.gw = IsolatingGateway(self.bus)
        self.labels = LabelTopic(sim_mode, label_topic_configured)

    def tick(self, elapsed_s: float):
        plant = self.engine.state_at(elapsed_s)
        frames = self.twins.publish(plant)
        for rec in self.injector.labels:
            self.labels.publish(rec)
        self.injector.labels.clear()
        return plant, frames
