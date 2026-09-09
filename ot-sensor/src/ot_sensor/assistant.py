"""Per-incident CyberPal investigation sessions.

Uses correlated incident JSON only: no raw CAN, honeypot blobs, or labels.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ot_sensor.cyberpal import chat, gguf_path, ollama_ready


def briefing_payload(incident: dict, assets: list[dict] | None = None) -> dict:
    """Compact correlation record for the model. Strips GT and raw frames."""
    related_ids = set(incident.get("asset_ids") or [])
    related_ids.update(incident.get("risk", {}).get("dependent_asset_ids") or [])
    related = []
    for a in assets or []:
        if a.get("asset_id") not in related_ids:
            continue
        related.append(
            {
                "asset_id": a.get("asset_id"),
                "name": a.get("name"),
                "segment": a.get("segment"),
                "criticality": a.get("criticality"),
                "nis2_service": a.get("nis2_service"),
                "dependents": a.get("dependents") or [],
                "depends_on": a.get("depends_on") or [],
                "traffic": a.get("traffic"),
            }
        )
    rules_by_id: dict = {}
    models_by_id: dict = {}
    graph: list = []
    seen_edge: set[str] = set()
    timeline: list = []
    for al in incident.get("alerts") or []:
        timeline.append(
            {
                "event_id": al.get("event_id"),
                "timestamp": al.get("timestamp"),
                "segment": al.get("segment"),
                "asset_ids": al.get("asset_ids") or [],
                "fired_rules": al.get("fired_rules") or [],
                "fired_models": al.get("fired_models") or [],
            }
        )
        for r in al.get("rules") or []:
            if not r.get("fired"):
                continue
            rid = r.get("rule_id")
            rules_by_id[rid] = {
                "rule_id": rid,
                "severity": r.get("severity"),
                "techniques": r.get("techniques") or [],
                "impacts": r.get("impacts") or [],
                "clauses_fired": r.get("clauses_fired") or [],
            }
        for m in al.get("models") or []:
            mid = m.get("model_id")
            models_by_id[mid] = {
                "model_id": mid,
                "scores": m.get("scores") or {},
                "fired": m.get("fired"),
                "status": m.get("status"),
            }
        for e in al.get("graph") or []:
            compact = _edge(e)
            key = _json(compact)
            if key in seen_edge:
                continue
            seen_edge.add(key)
            graph.append(compact)
    for e in incident.get("graph") or []:
        compact = _edge(e)
        key = _json(compact)
        if key in seen_edge:
            continue
        seen_edge.add(key)
        graph.append(compact)
    risk = incident.get("risk") or {}
    ev = incident.get("evidence_summary") or {}
    nis2 = incident.get("nis2") or {}
    cop = incident.get("copilot") or {}
    return {
        "incident_id": incident.get("incident_id"),
        "state": incident.get("state"),
        "severity": incident.get("severity"),
        "families": incident.get("families") or [],
        "title": incident.get("title"),
        "segment": incident.get("segment"),
        "protocol": incident.get("protocol"),
        "t_open": incident.get("t_open"),
        "t_last": incident.get("t_last"),
        "asset_ids": incident.get("asset_ids") or [],
        "techniques": incident.get("techniques") or [],
        "impacts": incident.get("impacts") or [],
        "alert_count": incident.get("alert_count") or len(timeline),
        "risk": {
            "total": risk.get("total"),
            "impact": risk.get("impact"),
            "likelihood": risk.get("likelihood"),
            "blast_radius": risk.get("blast_radius"),
            "nis2_significant": risk.get("nis2_significant"),
            "dependent_asset_ids": risk.get("dependent_asset_ids") or [],
        },
        "nis2": {
            "early_warning_due": nis2.get("early_warning_due"),
            "notification_due": nis2.get("notification_due"),
        }
        if nis2
        else None,
        "evidence_summary": {
            "top_features": (ev.get("top_features") or [])[:10],
            "rules_fired": ev.get("rules_fired") or [],
        },
        "fired_rules": list(rules_by_id.values()),
        "fired_models": list(models_by_id.values()),
        "graph": graph[:16],
        "watchstander_recommend": cop.get("recommend") or [],
        "alerts": timeline[-4:],
        "assets": related,
    }


def heuristic_interpretation(payload: dict) -> str:
    inc = payload.get("incident_id") or "unknown"
    sev = payload.get("severity") or "info"
    fam = ", ".join(payload.get("families") or []) or "uncategorized"
    assets = ", ".join(payload.get("asset_ids") or []) or "none"
    techs = " ".join(payload.get("techniques") or []) or "—"
    risk = payload.get("risk") or {}
    fired = []
    for al in payload.get("alerts") or []:
        fired.extend(al.get("fired_rules") or [])
    rules = ", ".join(dict.fromkeys(fired)) or "none"
    feats = payload.get("evidence_summary") or {}
    top = ", ".join((feats.get("top_features") or [])[:8]) or "—"
    nis2 = payload.get("nis2")
    lines = [
        f"Incident {inc} is {payload.get('state') or 'open'} · {sev} · family {fam} on {payload.get('segment') or '—'}.",
        f"Risk {risk.get('total', 0)} (impact {risk.get('impact', 0)} · likelihood {risk.get('likelihood', 0)} · blast {risk.get('blast_radius', 0)} · control {risk.get('control_plane', 0)})."
        + (" NIS2 significant — early warning and 72h clocks apply." if risk.get("nis2_significant") else ""),
        f"Assets {assets}. ATT&CK {techs}. Rules fired: {rules}. Features: {top}.",
        "This is a listen-only TAP case. Distrust the implicated talkers; do not actuate from spoofed PGN. Compare redundant sensors (GNSS-2, gyro) and review gateway allowlists.",
    ]
    if nis2:
        lines.append(
            f"NIS2 clocks: early warning {nis2.get('early_warning_due')}, notification {nis2.get('notification_due')}. Human confirm is required before CSIRT."
        )
    rec = payload.get("watchstander_recommend") or (payload.get("watchstander_alert") or {}).get("recommend") or []
    if rec:
        lines.append("Existing watchstander recommend: " + "; ".join(rec) + ".")
    return "\n".join(lines)


def heuristic_answer(payload: dict, question: str) -> str:
    q = (question or "").lower()
    assets = ", ".join(payload.get("asset_ids") or []) or "none"
    techs = " ".join(payload.get("techniques") or []) or "none listed"
    fired = []
    clauses = []
    for al in payload.get("alerts") or []:
        fired.extend(al.get("fired_rules") or [])
        for r in al.get("rules") or []:
            clauses.extend(r.get("clauses_fired") or [])
    if "asset" in q or "who" in q or "which" in q and "affect" in q:
        deps = (payload.get("risk") or {}).get("dependent_asset_ids") or []
        extra = f" Dependents: {', '.join(deps)}." if deps else ""
        return f"Implicated assets: {assets}.{extra} Stay listen-only; do not write the bus."
    if "attack" in q or "fault" in q or "spoof" in q:
        return (
            f"Correlation treats this as {payload.get('families') or ['unknown']}. Techniques {techs}. "
            "If GNSS residuals walk off with healthy HDOP, prefer attack over sensor fault. Confirm against gyro and GNSS-2."
        )
    if "next" in q or "check" in q or "investigat" in q or "what should" in q:
        return (
            f"1. Compare {assets} against redundant talkers. 2. Review clauses {', '.join(dict.fromkeys(clauses)) or 'fired rules'}. "
            "3. Do not steer from the suspected source. 4. Keep TAP health and honeypot logs; do not TX."
        )
    if "why" in q or "fire" in q or "rule" in q:
        return f"Joined alerts fired rules: {', '.join(dict.fromkeys(fired)) or 'none'}. Clauses: {', '.join(dict.fromkeys(clauses)) or '—'}. Techniques {techs}."
    return heuristic_interpretation(payload) + f"\n\nQuestion was: {question}"


@dataclass
class AssistantSession:
    incident_id: str
    interpretation: str = ""
    alert_count: int = 0
    messages: list[dict] = field(default_factory=list)
    status: str = "idle"
    source: str = "heuristic"


class CyberPalAssistant:
    def __init__(self, repo: Path, work: Path) -> None:
        self.repo = Path(repo)
        self.work = Path(work)
        self.sessions: dict[str, AssistantSession] = {}
        self._ready: bool | None = None

    def status(self) -> dict:
        ready = self.ready()
        path = gguf_path(self.work, self.repo)
        return {
            "model": "cyberpal-2.0-4b",
            "version": "1.0.0",
            "status": "ok" if ready else "llm_unavailable",
            "loaded": ready,
            "gguf": str(path) if path else None,
            "sessions": list(self.sessions),
        }

    def ready(self) -> bool:
        if not self._ready:
            self._ready = ollama_ready()
        return bool(self._ready)

    def clear(self) -> None:
        self.sessions.clear()

    def session_view(self, sess: AssistantSession) -> dict:
        st = self.status()
        return {
            "incident_id": sess.incident_id,
            "interpretation": sess.interpretation,
            "messages": list(sess.messages),
            "status": sess.status,
            "source": sess.source,
            "model": st["model"],
            "loaded": st["loaded"],
            "alert_count": sess.alert_count,
        }

    def get(self, incident_id: str, incident: dict, assets: list[dict] | None = None, refresh: bool = False) -> dict:
        payload = briefing_payload(incident, assets)
        sess = self.sessions.get(incident_id)
        count = int(incident.get("alert_count") or 0)
        if sess is None:
            sess = AssistantSession(incident_id=incident_id)
            self.sessions[incident_id] = sess
        if refresh or not sess.interpretation:
            sess.interpretation, sess.status, sess.source = self._interpret(payload)
            sess.alert_count = count
        else:
            sess.alert_count = count
        return self.session_view(sess)

    def ask(self, incident_id: str, question: str, incident: dict, assets: list[dict] | None = None) -> dict:
        q = (question or "").strip()
        if not q:
            return self.get(incident_id, incident, assets)
        payload = briefing_payload(incident, assets)
        sess = self.sessions.get(incident_id)
        if sess is None or not sess.interpretation:
            self.get(incident_id, incident, assets)
            sess = self.sessions[incident_id]
        sess.messages.append({"role": "user", "content": q})
        answer, status, source = self._answer(payload, sess)
        sess.messages.append({"role": "assistant", "content": answer})
        sess.status = status
        sess.source = source
        return self.session_view(sess)

    def _interpret(self, payload: dict) -> tuple[str, str, str]:
        fallback = heuristic_interpretation(payload)
        if not self.ready():
            return fallback, "llm_unavailable", "heuristic"
        prompt = (
            "Write a watchstander briefing in at most 8 short sentences. "
            "Cover what fired, assets, ATT&CK, risk/NIS2, and next observe-only checks. "
            "No bus writes.\n\nINCIDENT JSON:\n" + _json(payload)
        )
        try:
            text = chat([{"role": "user", "content": prompt}])
            return text, "ok", "cyberpal"
        except Exception:
            if not ollama_ready():
                self._ready = False
            return fallback, "llm_unavailable", "heuristic"

    def _answer(self, payload: dict, sess: AssistantSession) -> tuple[str, str, str]:
        q = sess.messages[-1]["content"]
        fallback = heuristic_answer(payload, q)
        if not self.ready():
            return fallback, "llm_unavailable", "heuristic"
        history = [
            {
                "role": "user",
                "content": "Incident JSON (investigation only). Answer later questions in at most 6 sentences.\n" + _json(payload),
            }
        ]
        history.append({"role": "assistant", "content": sess.interpretation or fallback})
        for m in sess.messages[-8:]:
            history.append({"role": m["role"], "content": m["content"]})
        try:
            text = chat(history)
            return text, "ok", "cyberpal"
        except Exception:
            if not ollama_ready():
                self._ready = False
            return fallback, "llm_unavailable", "heuristic"


def _edge(e):
    if not isinstance(e, dict):
        return e
    return {k: e[k] for k in ("src", "dst", "segment", "kind", "pgn", "expected") if k in e}


def _json(obj) -> str:
    import json

    return json.dumps(obj, default=str, separators=(",", ":"))
