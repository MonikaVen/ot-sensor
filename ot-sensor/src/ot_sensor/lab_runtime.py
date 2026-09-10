"""Incremental lab session: simulator ticks into the sensor for the dashboard."""

from __future__ import annotations

from collections import deque
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import shutil

from otlab.pgn import decode_fields
from opv_sim.runtime import SimRuntime, emission_row
from ot_sensor import SENSOR_VERSION
from ot_sensor.assistant import CyberPalAssistant
from ot_sensor.onnx_enrich import list_onnx_models
from ot_sensor.pipeline import SensorPipeline
from ot_sensor.tap import TapMirror, pull_tap

GNSS_READING_KEYS = (
    "gnss1_lat_deg",
    "gnss1_lon_deg",
    "gnss2_lat_deg",
    "gnss2_lon_deg",
    "hdop",
    "sat_count",
    "cog_deg",
    "heading_deg",
    "cog_heading_residual_deg",
    "gnss1_gnss2_split_m",
    "gnss_dr_residual_m",
)

SPOOF_SA = "16"
FLOW_MAX = 100
MONITOR_MAX = 90
HP_HIST_MAX = 90


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
        sim: SimRuntime | None = None,
        tap_url: str | None = None,
        drive_sim: bool = True,
    ) -> None:
        self.repo = Path(repo)
        self.work = Path(work)
        self.mode = mode
        self.tap_url = (tap_url or "").rstrip("/") or None
        self.drive_sim = drive_sim and not self.tap_url
        self.tap_error: str | None = None
        self.sim = TapMirror() if self.tap_url else (sim or SimRuntime(mode))
        self.running = False
        self.ticks = 0
        self.frames_this_tick = 0
        self.plant = None
        self.last_hit = None
        self.last_score = None
        self.last_features: dict = {}
        self.seen_incident_ids: set[str] = set()
        self.new_incident_ids: list[str] = []
        self.message_flow: deque[dict] = deque(maxlen=FLOW_MAX)
        self.monitor: deque[dict] = deque(maxlen=MONITOR_MAX)
        self.hp_history: deque[dict] = deque(maxlen=HP_HIST_MAX)
        self.last_lstm: dict | None = None
        self.attack_started_at: str | None = None
        self.traffic_talkers: set[str] = set()
        self.traffic_attacked: set[str] = set()
        self._ingested_ticks = -1
        self.assistant = CyberPalAssistant(self.repo, self.work)
        self._reset_pipeline()

    def _reset_pipeline(self) -> None:
        prev = getattr(self, "sensor", None)
        keep = prev.rules if prev else None
        if prev is not None:
            prev.honeypot.close()
        self.sensor = SensorPipeline(self.mode, self.repo, self.work)
        if keep is not None:
            keep.last_hits = []
            self.sensor.rules = keep

    def reset(self) -> None:
        self.ticks = 0
        self.frames_this_tick = 0
        self.plant = None
        self.last_hit = None
        self.last_score = None
        self.last_features = {}
        self.seen_incident_ids.clear()
        self.new_incident_ids.clear()
        self.message_flow.clear()
        self.monitor.clear()
        self.hp_history.clear()
        self.last_lstm = None
        self.attack_started_at = None
        self.traffic_talkers.clear()
        self.traffic_attacked.clear()
        self._ingested_ticks = -1
        self.assistant.clear()
        self._reset_pipeline()
        inv = self.work / "assets" / self.mode / "opv1" / "inventory.json"
        if inv.exists():
            inv.unlink()
        hp = self.work / "hp"
        if hp.exists():
            shutil.rmtree(hp)

    def pull_remote(self) -> None:
        if not self.tap_url:
            return
        try:
            payload = pull_tap(self.tap_url)
            self.sim.apply(payload)
            self.tap_error = None
        except Exception as exc:
            self.tap_error = str(exc)

    def ingest_from_sim(self) -> dict:
        if self.tap_error:
            return self.snapshot()
        if self.sim.ticks == self._ingested_ticks:
            return self.snapshot()
        self._ingested_ticks = self.sim.ticks
        plant = self.sim.plant
        frames = self.sim.last_frames
        self.plant = plant
        self.frames_this_tick = len(frames)
        new_events = self.sensor.ingest_frames(frames) if frames else []
        self._record_honeypot()
        result = self.sensor.detect() if new_events else None
        if result:
            win, score, hit, inc = result
            self.last_score = score
            self.last_hit = hit
            self.last_features = dict(win.features)
            self.last_lstm = getattr(self.sensor, "last_lstm", None)
            self._record_monitor()
            for case in list(self.sensor.incidents.open.values()) + list(self.sensor.incidents.closed):
                if case.incident_id not in self.seen_incident_ids:
                    self.seen_incident_ids.add(case.incident_id)
                    self.new_incident_ids.append(case.incident_id)
        self._record_flow(frames, plant)
        self._classify_traffic(frames, plant)
        self.ticks += 1
        return self.snapshot()

    def step(self) -> dict:
        if self.tap_url:
            self.pull_remote()
        elif self.drive_sim:
            self.sim.tick()
        return self.ingest_from_sim()

    def _record_honeypot(self) -> None:
        usage = self.sensor.honeypot.usage()
        self.hp_history.append(
            {
                "t": float(getattr(self.sim, "elapsed", 0) or 0),
                "bytes": int(usage.get("bytes") or 0),
                "files": int(usage.get("files") or 0),
                "written": int(usage.get("written") or 0),
            }
        )

    def clear_honeypot(self) -> dict:
        self.sensor.honeypot.wipe()
        self.hp_history.clear()
        return self.snapshot()

    def _attacks(self) -> dict:
        return dict(getattr(self.sim, "attacks", None) or {})

    def _classify_traffic(self, frames, plant) -> None:
        talkers: set[str] = set()
        attacked: set[str] = set()
        attacks = self._attacks()
        for fr in frames or []:
            row = emission_row(fr, plant, attacks)
            sa = row.get("sa") or ""
            if sa:
                talkers.add(sa)
            if row.get("spoofed") or row.get("kind") not in (None, "ok"):
                if sa:
                    attacked.add(sa)
                da = decode_fields(fr).get("da")
                if da not in (None, 255):
                    attacked.add(str(da))
        self.traffic_talkers = talkers
        self.traffic_attacked = attacked

    def _record_flow(self, frames, plant) -> None:
        if not frames:
            return
        attacks = self._attacks()
        for fr in frames:
            row = emission_row(fr, plant, attacks)
            is_attack = bool(row.get("spoofed") or row.get("kind") not in (None, "ok"))
            if row["sa"] != SPOOF_SA and not is_attack:
                continue
            row["t"] = _iso(fr.t)
            self.message_flow.append(row)
            if is_attack and self.attack_started_at is None:
                self.attack_started_at = row["t"]

    def _record_monitor(self) -> None:
        packs = self.sensor.rules.snapshot(self.last_features).get("packs") or []
        rules = {}
        for pack in packs:
            values: dict[str, float] = {}
            thresholds: dict[str, float] = {}
            for group in pack.get("groups") or []:
                for clause in group.get("clauses") or []:
                    if clause.get("type") != "number":
                        continue
                    live = clause.get("live")
                    if live is None:
                        continue
                    cid = str(clause["id"])
                    feat = str(clause.get("feature") or cid)
                    values[cid] = float(live)
                    values[feat] = float(live)
                    thresholds[cid] = float(clause.get("value") or 0)
                    thresholds[feat] = float(clause.get("value") or 0)
            f = self.last_features or {}
            readings = {k: float(f[k]) for k in GNSS_READING_KEYS if k in f and f[k] is not None}
            rules[pack["rule_id"]] = {
                "fired": bool(pack.get("fired")),
                "values": values,
                "thresholds": thresholds,
                "readings": readings,
            }
        lstm = dict(self.last_lstm or getattr(self.sensor, "last_lstm", None) or {})
        self.monitor.append(
            {
                "t": float(getattr(self.sim, "elapsed", 0) or 0),
                "rules": rules,
                "lstm": lstm,
            }
        )

    def ack_alerts(self, incident_ids: list[str] | None = None) -> None:
        if incident_ids is None:
            self.new_incident_ids.clear()
            return
        drop = set(incident_ids)
        self.new_incident_ids = [i for i in self.new_incident_ids if i not in drop]

    def _histograms(self) -> list:
        fn = getattr(self.sim, "histogram_payload", None)
        if callable(fn):
            return fn()
        return list(getattr(self.sim, "histograms", None) or [])

    def snapshot(self) -> dict:
        sensor = self.sensor
        plant = self.plant
        live = sensor.assets.live
        incident_by_asset: dict[str, list[str]] = {}
        incidents = []
        for inc in list(sensor.incidents.open.values()) + list(reversed(sensor.incidents.closed[-12:])):
            row = _incident_row(inc, sensor)
            incidents.append(row)
            for aid in inc.asset_ids:
                incident_by_asset.setdefault(aid, []).append(inc.incident_id)
        alerts = [_alert_row(a) for a in reversed(sensor.incidents.recent[-40:])]

        assets = []
        for row in sensor.assets.inventory_rows():
            aid = row["asset_id"]
            rec = live.get(aid)
            if aid in self.traffic_attacked:
                traffic = "attack"
            elif aid in self.traffic_talkers:
                traffic = "benign"
            else:
                traffic = "silent"
            assets.append(
                {
                    **row,
                    "live": rec is not None and rec.last_seen is not None,
                    "talking": aid in self.traffic_talkers,
                    "traffic": traffic,
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
        honeypot = _honeypot_snapshot(sensor.honeypot, list(self.hp_history))
        tap_status = "down" if self.tap_error else ("ok" if self.frames_this_tick else "idle")
        hp_status = "ok" if honeypot["bytes"] or honeypot["seq"] else "idle"
        services = [
            {"id": "tap", "label": "N2K TAP", "status": tap_status},
            {"id": "honeypot", "label": "Honeypot", "status": hp_status},
            {"id": "assets", "label": "Asset detector", "status": "ok" if live else "idle"},
            {"id": "graph", "label": "Comms graph", "status": "ok" if sensor.graph.edges else "idle"},
            {"id": "features", "label": "Features", "status": "ok" if self.ticks else "idle"},
            {
                "id": "onnx",
                "label": "ONNX",
                "status": score.status if score else "idle",
            },
            {"id": "rules", "label": "Rules", "status": _rules_status(sensor.rules, hit)},
            {"id": "incidents", "label": "Correlator", "status": "alert" if any(i["state"] != "closed" for i in incidents) else "ok"},
            {
                "id": "slm",
                "label": "Local SLM",
                "status": "ok" if self.sensor.slm.ready() else "llm_unavailable",
                "detail": self.sensor.slm.runtime(),
            },
            {
                "id": "assistant",
                "label": "CyberPal",
                "status": "ok" if self.assistant.ready() else "llm_unavailable",
                "detail": self.assistant.status().get("base_model"),
            },
            {"id": "stix", "label": "STIX", "status": "ok" if sensor.last_stix else "idle"},
        ]

        return {
            "sensor_version": SENSOR_VERSION,
            "mode": self.mode,
            "hull": "opv1",
            "running": self.running,
            "tap_url": self.tap_url,
            "tap_error": self.tap_error,
            "attack_id": self.sim.attack_id or None,
            "elapsed_s": self.sim.elapsed,
            "ticks": self.ticks,
            "t": datetime.now(timezone.utc).isoformat(),
            "plant": {
                "t": _iso(getattr(plant, "t", None)) if plant else None,
                "lat_deg": getattr(plant, "lat_deg", None) if plant else None,
                "lon_deg": getattr(plant, "lon_deg", None) if plant else None,
                "heading_deg": getattr(plant, "heading_deg", None) if plant else None,
                "sog_kn": getattr(plant, "sog_kn", None) if plant else None,
                "phase": getattr(plant, "phase", "idle") if plant else "idle",
                "attack_id": getattr(plant, "attack_id", None) if plant else None,
            } if plant else None,
            "stats": {
                "frames_this_tick": self.frames_this_tick,
                "events": len(sensor.events),
                "open_incidents": sum(1 for i in incidents if i["state"] != "closed"),
                "alerts": len(alerts),
                "honeypot_seq": honeypot["seq"],
                "honeypot_bytes": honeypot["bytes"],
            },
            "services": services,
            "assets": assets,
            "comms": live_edges,
            "dependencies": dep_edges,
            "graph_changes": list(sensor.graph.changes[-20:]),
            "incidents": incidents,
            "alerts": alerts,
            "new_incident_ids": list(self.new_incident_ids),
            "copilot": asdict(cop) if cop else None,
            "stix_path": sensor.last_stix.path if sensor.last_stix else None,
            "rules": _rules_snapshot(sensor, self.last_features, hit, list(self.monitor), self.ticks > 0),
            "models": _models_snapshot(self.repo, sensor, list(self.monitor), self.last_lstm or getattr(sensor, "last_lstm", None), self.ticks > 0),
            "attack_started_at": self.attack_started_at,
            "message_flow": list(reversed(self.message_flow)),
            "flow_asset": {"asset_id": SPOOF_SA, "name": "GNSS-1"},
            "histograms": self._histograms(),
            "honeypot": honeypot,
            "assistant": self.assistant.status(),
        }

    def assistant_handle(self, incident_id: str, message: str | None = None, refresh: bool = False) -> dict:
        snap = self.snapshot()
        inc = next((i for i in snap["incidents"] if i["incident_id"] == incident_id), None)
        if inc is None:
            return {"ok": False, "error": "unknown incident", "incident_id": incident_id}
        if message:
            sess = self.assistant.ask(incident_id, message, inc, snap["assets"])
        else:
            sess = self.assistant.get(incident_id, inc, snap["assets"], refresh=refresh)
        return {"ok": True, **sess}

    def update_rule(self, rule_id: str, enabled: bool | None = None, severity: str | None = None, clauses: dict | None = None) -> dict:
        self.sensor.rules.apply(rule_id, enabled=enabled, severity=severity, clauses=clauses)
        return self.snapshot()


def _rules_status(rules, hit) -> str:
    hits = getattr(rules, "last_hits", None) or ([hit] if hit else [])
    if any(h.fired for h in hits):
        return "fired"
    if hits and all(h.status == "disabled" for h in hits):
        return "disabled"
    if hit or hits:
        return "ok"
    return "idle"


def _rules_snapshot(sensor, features, hit, hist: list, ticking: bool) -> dict:
    snap = sensor.rules.snapshot(features, hit)
    for pack in snap.get("packs") or []:
        rid = pack["rule_id"]
        pack["live"] = bool(pack.get("enabled") and ticking)
        pack["series"] = [
            {
                "t": row["t"],
                "values": (row.get("rules") or {}).get(rid, {}).get("values") or {},
                "thresholds": (row.get("rules") or {}).get(rid, {}).get("thresholds") or {},
                "readings": (row.get("rules") or {}).get(rid, {}).get("readings") or {},
                "fired": bool((row.get("rules") or {}).get(rid, {}).get("fired")),
            }
            for row in hist
        ]
    return snap


def _models_snapshot(repo, sensor, hist: list, last_lstm, ticking: bool) -> dict:
    lstm = last_lstm or {}
    onnx_loaded = getattr(getattr(sensor, "onnx", None), "sess", None) is not None
    deployed = list_onnx_models(repo)
    by_id = {p["model_id"]: p for p in deployed}
    live = bool(ticking and (lstm.get("steps") or onnx_loaded))
    fired = bool(lstm.get("fired"))
    series = [
        {
            "t": row["t"],
            "actual_fps": (row.get("lstm") or {}).get("actual_fps"),
            "predicted_fps": (row.get("lstm") or {}).get("predicted_fps"),
            "threshold_fps": (row.get("lstm") or {}).get("threshold_fps"),
            "flood_score": (row.get("lstm") or {}).get("flood_score"),
            "residual_fps": (row.get("lstm") or {}).get("residual_fps"),
            "fired": bool((row.get("lstm") or {}).get("fired")),
            "crossed": bool((row.get("lstm") or {}).get("crossed")),
        }
        for row in hist
        if row.get("lstm")
    ]
    meta = by_id.get("throughput-lstm") or {}
    packs = [
        {
            "model_id": "throughput-lstm",
            "version": meta.get("version") or "1.0.0",
            "title": "Throughput LSTM",
            "blurb": "One-step frames/s prediction is the live threshold. Detection when actual flow crosses above it.",
            "live": live,
            "onnx_loaded": bool(meta.get("onnx_loaded") or onnx_loaded),
            "status": "fired" if fired else ("ok" if live else "idle"),
            "detected": fired,
            "scores": {
                "actual_fps": lstm.get("actual_fps"),
                "predicted_fps": lstm.get("predicted_fps"),
                "threshold_fps": lstm.get("threshold_fps"),
                "residual_fps": lstm.get("residual_fps"),
                "flood_score": lstm.get("flood_score"),
            },
            "thresholds": {
                "threshold_fps": float(lstm.get("threshold_fps") or lstm.get("predicted_fps") or 0.0),
                "flood_score": 0.80,
            },
            "techniques": meta.get("techniques") or ["T0814"],
            "impacts": meta.get("impacts") or ["T0826"],
            "series": series,
        }
    ]
    for extra in deployed:
        if extra["model_id"] == "throughput-lstm":
            continue
        packs.append(
            {
                "model_id": extra["model_id"],
                "version": extra["version"],
                "title": extra["title"],
                "blurb": extra["blurb"],
                "live": bool(extra.get("onnx_loaded") and ticking),
                "onnx_loaded": bool(extra.get("onnx_loaded")),
                "status": "ok" if extra.get("onnx_loaded") and ticking else "idle",
                "detected": False,
                "scores": {},
                "thresholds": {"flood_score": extra.get("fire") or 0.8},
                "techniques": extra.get("techniques") or [],
                "impacts": extra.get("impacts") or [],
                "series": [],
            }
        )
    return {"packs": packs}


def _honeypot_snapshot(honeypot, hist: list | None = None) -> dict:
    return {
        **honeypot.snapshot(),
        "series": list(hist or []),
    }


def _alert_row(alert) -> dict:
    models = []
    for m in alert.models:
        scores = {k: v for k, v in (m.scores or {}).items() if v is not None}
        models.append(
            {
                "event_id": m.event_id,
                "model_id": m.model_id,
                "version": m.version,
                "scores": scores,
                "status": m.status,
                "fired": float(scores.get("flood_score") or 0) >= 0.8,
            }
        )
    rules = []
    for r in alert.rules:
        rules.append(
            {
                "event_id": getattr(r, "event_id", alert.event_id),
                "rule_id": r.rule_id,
                "version": r.version,
                "fired": bool(r.fired),
                "severity": r.severity,
                "status": r.status,
                "techniques": list(r.techniques),
                "impacts": list(r.impacts),
                "clauses_fired": list(r.clauses_fired),
                "clauses_suppressed": list(r.clauses_suppressed),
            }
        )
    return {
        "event_id": alert.event_id,
        "timestamp": _iso(alert.timestamp),
        "join_incomplete": bool(alert.join_incomplete),
        "source": alert.source,
        "segment": alert.segment,
        "protocol": alert.protocol,
        "asset_ids": list(alert.asset_ids),
        "models": models,
        "rules": rules,
        "graph": list(alert.graph or []),
        "evidence_summary": dict(alert.evidence_summary or {}),
        "fired_rules": [r["rule_id"] for r in rules if r["fired"]],
        "fired_models": [m["model_id"] for m in models if m["fired"]],
    }


def _incident_row(inc, sensor) -> dict:
    copilots = getattr(sensor, "copilots", None) or {}
    cop = copilots.get(inc.incident_id)
    if cop is None and sensor.last_copilot and sensor.last_copilot.incident_id == inc.incident_id:
        cop = sensor.last_copilot
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
    member_alerts = [_alert_row(a) for a in reversed(inc.alerts[-16:])]
    return {
        "incident_id": inc.incident_id,
        "state": inc.state,
        "t_open": _iso(inc.t_open),
        "t_last": _iso(inc.t_last),
        "severity": inc.severity,
        "families": list(getattr(inc, "families", []) or []),
        "title": cop.alert_title if cop else f"{inc.severity} {inc.segment}",
        "body": cop.alert_body if cop else "",
        "protocol": inc.protocol,
        "source": inc.source,
        "segment": inc.segment,
        "asset_ids": list(inc.asset_ids),
        "techniques": list(inc.techniques),
        "impacts": list(inc.impacts),
        "alert_count": inc.alert_count,
        "alerts": member_alerts,
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
        "copilot": {
            "status": cop.status,
            "runtime": cop.runtime,
            "alert_title": cop.alert_title,
            "alert_body": cop.alert_body,
            "recommend": list(cop.recommend),
        }
        if cop
        else None,
    }
