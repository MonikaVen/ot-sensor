"""OPV scenario engine: kinematics + overlays. Labels never on CAN."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from otlab import PlantState
from otlab.geo import dest_point


class ScenarioEngine:
    def __init__(
        self,
        scenario_id: str = "underway",
        attack_id: str | None = None,
        sim_mode: str = "dev",
    ) -> None:
        if sim_mode not in ("dev", "prod"):
            raise ValueError(sim_mode)
        self.scenario_id = scenario_id
        self.attack_id = attack_id
        self.sim_mode = sim_mode
        self.t0 = datetime(2026, 9, 8, 19, 0, tzinfo=timezone.utc)
        self.lat0, self.lon0 = 54.5, 18.7
        self.heading = 90.0
        self.sog_kn = 12.0

    def state_at(self, elapsed_s: float) -> PlantState:
        dist_m = self.sog_kn * 0.514444 * elapsed_s
        lat, lon = dest_point(self.lat0, self.lon0, self.heading, dist_m)
        phase = "baseline"
        attack = None
        hdop, sats = 0.8, 12
        if self.scenario_id == "GNSS-degraded":
            hdop, sats = 8.0, 4
            phase = "degraded"
        if self.attack_id == "gps-spoof-primary":
            # overlay timeline: 0-5 baseline, 5-25 ramp, 25-40 hold
            if elapsed_s < 5:
                phase = "baseline"
            elif elapsed_s < 25:
                phase = "ramp"
                attack = "gps-spoof-primary"
            else:
                phase = "hold"
                attack = "gps-spoof-primary"
        elif self.attack_id in ("heading-spoof", "gyro"):
            phase = "inject"
            attack = "heading-spoof"
        elif self.attack_id in ("sog-spoof", "velocity"):
            phase = "inject"
            attack = "sog-spoof"
        elif self.attack_id in ("ais-spoof", "ais"):
            phase = "inject"
            attack = "ais-spoof"
        elif self.attack_id in ("rot-spoof", "rot"):
            phase = "inject"
            attack = "rot-spoof"
        elif self.attack_id in ("rpm-spoof", "rpm"):
            phase = "inject"
            attack = "rpm-spoof"
        elif self.attack_id in ("depth-spoof", "depth"):
            phase = "inject"
            attack = "depth-spoof"
        elif self.attack_id in ("battery-spoof", "battery"):
            phase = "inject"
            attack = "battery-spoof"
        elif self.attack_id in ("engine-cmd", "engine_cmd"):
            phase = "inject"
            attack = "engine-cmd"
        elif self.attack_id in ("rogue-master", "rogue_master", "gps-spoof-sa-collision"):
            phase = "inject"
            attack = "rogue-master"
        elif self.attack_id in ("gateway-bypass", "gateway_bypass"):
            phase = "inject"
            attack = "gateway-bypass"
        elif self.attack_id in ("error-flood", "error_flood"):
            phase = "flood"
            attack = "error-flood"
        elif self.attack_id in ("fast-packet", "fast_packet"):
            phase = "flood"
            attack = "fast-packet"
        elif self.attack_id == "pgn-flood":
            phase = "flood"
            attack = "pgn-flood"
        elif self.attack_id in ("gps-spoof-both", "spoof_both"):
            if elapsed_s < 5:
                phase = "baseline"
            elif elapsed_s < 25:
                phase = "ramp"
                attack = "gps-spoof-both"
            else:
                phase = "hold"
                attack = "gps-spoof-both"
        t = self.t0 + timedelta(seconds=elapsed_s)
        return PlantState(
            t=t,
            lat_deg=lat,
            lon_deg=lon,
            sog_kn=self.sog_kn,
            cog_deg=self.heading,
            heading_deg=self.heading,
            rot_deg_s=0.0,
            depth_m=18.0,
            hdop=hdop,
            sat_count=sats,
            rpm_port=1400.0,
            rpm_stbd=1400.0,
            oil_temp_c=78.0,
            breaker_closed=True,
            phase=phase,
            scenario_id=self.scenario_id,
            attack_id=attack,
        )
