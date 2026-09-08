"""Incremental lab session: simulator ticks into the sensor for the dashboard."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from opv_sim.lab import OpvSimulator
from ot_sensor import SENSOR_VERSION
from ot_sensor.pipeline import SensorPipeline


def _iso(v):
    if isinstance(v, datetime):
        return v.isoformat()
    return v


class LabRuntime:
    def __init__(
        self,
        repo: Path,
        work: Path,
        mode: str = "dev",
        attack_id: str = "gps-spoof-primary",
    ) -> None:
        self.repo = Path(repo)
        self.work = Path(work)
        self.mode = mode
        self.attack_id = attack_id or ""
        self.elapsed = 0.0
        self.running = False
        self.ticks = 0
        self.frames_this_tick = 0
        self.plant = None
        self.last_hit = None
        self.last_score = None
        self.seen_incident_ids: set[str] = set()
        self.new_incident_ids: list[str] = []
        self._reset_pipeline()

    def _reset_pipeline(self) -> None:
        scenario = "gps-spoof-underway" if self.attack_id else "underway"
        self.sim = OpvSimulator(
            sim_mode=self.mode,
            attack_id=self.attack_id or None,
            scenario_id=scenario,
        )
        self.sensor = SensorPipeline(self.mode, self.repo, self.work)

    def reset(self, attack_id: str | None = None) -> None:
        if attack_id is not None:
            self.attack_id = attack_id
        self.elapsed = 0.0
        self.ticks = 0
        self.frames_this_tick = 0
        self.plant = None
        self.last_hit = None
        self.last_score = None
        self.seen_incident_ids.clear()
        self.new_incident_ids.clear()
        self._reset_pipeline()

    def step(self) -> dict:
        plant, frames = self.sim.tick(self.elapsed)
        self.plant = plant
        self.frames_this_tick = len(frames)
        new_events = self.sensor.ingest_frames(frames)
        result = self.sensor.detect() if new_events else None
        if result:
            _, score, hit, inc = result
            self.last_score = score
            self.last_hit = hit
            if inc and inc.incident_id not in self.seen_incident_ids:
                self.seen_incident_ids.add(inc.incident_id)
                self.new_incident_ids.append(inc.incident_id)
        self.elapsed += 1.0
        self.ticks += 1
        return self.snapshot()

    def ack_alerts(self, incident_ids: list[str] | None = None) -> None:
        if incident_ids is None:
            self.new_incident_ids.clear()
            return
        drop = set(incident_ids)
        self.new_incident_ids = [i for i in self.new_incident_ids if i not in drop]

    def snapshot(self) -> dict:
        sensor = self.sensor
        plant = self.plant
        live = sensor.assets.live
        catalog = sensor.assets.by_id
        incident_by_asset: dict[str, list[str]] = {}
        incidents = []
        for inc in sensor.incidents.open.values():
            row = _incident_row(inc, sensor)
            incidents.append(row)
            for aid in inc.asset_ids:
                incident_by_asset.setdefault(aid, []).append(inc.incident_id)

        assets = []
        ordered = list(catalog.keys()) + [i for i in live if i not in catalog]
        for aid in ordered:
            meta = catalog.get(aid, {})
            rec = live.get(aid)
            assets.append(
                {
                    "asset_id": aid,
                    "name": (rec.name if rec else None) or meta.get("name") or f"SA-{aid}",
                    "segment": (rec.segment if rec else None) or meta.get("segment") or "aux",
                    "criticality": rec.criticality if rec else meta.get("criticality", 2),
                    "nis2_service": rec.nis2_service if rec else meta.get("nis2_service", "none"),
                    "expected": rec.expected if rec else aid in catalog,
                    "live": rec is not None,
                    "last_seen": _iso(rec.last_seen) if rec else None,
                    "channels_seen": list(rec.channels_seen) if rec else [],
                    "depends_on": list(rec.depends_on if rec else meta.get("depends_on", [])),
                    "dependents": list(rec.dependents if rec else meta.get("dependents", [])),
                    "incident_ids": incident_by_asset.get(aid, []),
                }
            )

        live_edges = []
        for edge in sensor.graph.edges.values():
            live_edges.append(
                {
                    "src": edge.src,
                    "dst": edge.dst,
                    "segment": edge.segment,
                    "expected": edge.expected,
                    "live": True,
                    "kind": "violation" if not edge.expected else ("broadcast" if edge.dst is None else "unicast"),
                    "last_seen": _iso(edge.last_seen),
                }
            )
        dep_edges = []
        for a in assets:
            for parent in a["depends_on"]:
                dep_edges.append(
                    {
                        "src": parent,
                        "dst": a["asset_id"],
                        "segment": a["segment"],
                        "kind": "depends_on",
                    }
                )

        score = self.last_score
        hit = self.last_hit
        cop = sensor.last_copilot
        services = [
            {"id": "tap", "label": "N2K TAP", "status": "ok" if self.frames_this_tick else "idle"},
            {"id": "honeypot", "label": "Honeypot", "status": "ok" if sensor.honeypot.seq or sensor.honeypot.closed else "idle"},
            {"id": "assets", "label": "Asset detector", "status": "ok" if live else "idle"},
            {"id": "graph", "label": "Comms graph", "status": "ok" if sensor.graph.edges else "idle"},
            {"id": "features", "label": "Features", "status": "ok" if self.ticks else "idle"},
            {
                "id": "onnx",
                "label": "ONNX",
                "status": score.status if score else "idle",
            },
            {"id": "rules", "label": "Rules", "status": "fired" if hit and hit.fired else ("ok" if hit else "idle")},
            {"id": "incidents", "label": "Correlator", "status": "alert" if incidents else "ok"},
            {
                "id": "slm",
                "label": "Local SLM",
                "status": cop.status if cop else "idle",
            },
            {"id": "stix", "label": "STIX", "status": "ok" if sensor.last_stix else "idle"},
        ]

        return {
            "sensor_version": SENSOR_VERSION,
            "mode": self.mode,
            "hull": "opv1",
            "running": self.running,
            "attack_id": self.attack_id or None,
            "elapsed_s": self.elapsed,
            "ticks": self.ticks,
            "t": datetime.now(timezone.utc).isoformat(),
            "plant": {
                "t": _iso(plant.t) if plant else None,
                "lat_deg": plant.lat_deg if plant else None,
                "lon_deg": plant.lon_deg if plant else None,
                "heading_deg": plant.heading_deg if plant else None,
                "sog_kn": plant.sog_kn if plant else None,
                "phase": plant.phase if plant else "idle",
                "attack_id": plant.attack_id if plant else None,
            } if plant else None,
            "stats": {
                "frames_this_tick": self.frames_this_tick,
                "events": len(sensor.events),
                "open_incidents": len(incidents),
                "honeypot_seq": sensor.honeypot.seq,
            },
            "services": services,
            "assets": assets,
            "comms": live_edges,
            "dependencies": dep_edges,
            "graph_changes": list(sensor.graph.changes[-20:]),
            "incidents": incidents,
            "new_incident_ids": list(self.new_incident_ids),
            "copilot": asdict(cop) if cop else None,
            "stix_path": sensor.last_stix.path if sensor.last_stix else None,
        }


def _incident_row(inc, sensor) -> dict:
    cop = sensor.last_copilot if sensor.last_copilot and sensor.last_copilot.incident_id == inc.incident_id else None
    nis2 = None
    if inc.nis2:
        nis2 = {
            "incident_id": inc.nis2.incident_id,
            "t_aware": _iso(inc.nis2.t_aware),
            "early_warning_due": _iso(inc.nis2.early_warning_due),
            "notification_due": _iso(inc.nis2.notification_due),
            "stage": inc.nis2.stage,
            "essential_service": inc.nis2.essential_service,
            "human_confirm": inc.nis2.human_confirm,
        }
    return {
        "incident_id": inc.incident_id,
        "state": inc.state,
        "t_open": _iso(inc.t_open),
        "t_last": _iso(inc.t_last),
        "severity": inc.severity,
        "title": cop.alert_title if cop else f"{inc.severity} {inc.segment}",
        "body": cop.alert_body if cop else "",
        "protocol": inc.protocol,
        "source": inc.source,
        "segment": inc.segment,
        "asset_ids": list(inc.asset_ids),
        "techniques": list(inc.techniques),
        "impacts": list(inc.impacts),
        "alert_count": inc.alert_count,
        "evidence_summary": dict(inc.evidence_summary),
        "risk": {
            "total": inc.risk.total,
            "impact": inc.risk.impact,
            "likelihood": inc.risk.likelihood,
            "blast_radius": inc.risk.blast_radius,
            "control_plane": inc.risk.control_plane,
            "max_criticality": inc.risk.max_criticality,
            "dependent_asset_ids": list(inc.risk.dependent_asset_ids),
            "nis2_significant": inc.risk.nis2_significant,
        },
        "nis2": nis2,
    }
