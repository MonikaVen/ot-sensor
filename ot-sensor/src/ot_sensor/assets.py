"""Listen-only asset detector: talkers on the TAP, joined to the OPV model."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import yaml

from otlab import OTEvent

# Operator labels inferred from observed PGNs. Criticality still comes from the
# vessel model — unknown SAs stay at default 2 (spec: do not invent criticality).
FUNCTION_BY_PGN = {
    129025: "GNSS",
    129026: "GNSS",
    129029: "GNSS",
    129539: "GNSS",
    127245: "rudder",
    127250: "heading sensor",
    127251: "heading sensor",
    127257: "attitude sensor",
    127488: "engine",
    127489: "engine",
    127493: "transmission",
    127501: "binary status",
    127505: "fluid level",
    127508: "battery",
    127237: "heading/track controller",
    128259: "speed log",
    128267: "echo sounder",
    129038: "AIS",
    129794: "AIS",
    130306: "wind",
    130311: "environment",
    59904: "ISO requestor",
    60928: "NMEA 2000 node",
}
GENERIC_ISO_NAMES = {"", "LABTWIN"}
EXPECTED_PGNS = {
    "0": {"127488", "127489", "60928"},
    "1": {"127488", "127489", "60928"},
    "4": {"127493", "60928"},
    "5": {"127493", "60928"},
    "8": {"127505", "60928"},
    "12": {"60928", "127488"},
    "16": {"129025", "129026", "129029", "129539", "60928"},
    "17": {"129025", "129026", "129029", "129539", "60928"},
    "20": {"60928", "127488"},
    "21": {"60928", "127488"},
    "24": {"60928", "129038", "129794"},
    "28": {"60928", "127508"},
    "32": {"60928", "127501"},
    "35": {"127250", "127251", "127257", "60928"},
    "40": {"128267", "128259", "60928"},
    "48": {"130306", "60928"},
    "52": {"60928", "127245"},
    "56": {"60928", "127237"},
    "60": {"60928"},
    "80": {"130311", "60928"},
    "84": {"127505", "60928"},
    "88": {"127501", "60928"},
    "99": {"60928"},
}


@dataclass
class AssetRecord:
    asset_id: str
    segment: str
    name: str | None
    expected: bool
    criticality: int
    nis2_service: str | None
    depends_on: list[str] = field(default_factory=list)
    dependents: list[str] = field(default_factory=list)
    channels_seen: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    role: str | None = None
    identity: dict = field(default_factory=dict)
    detected_via: list[str] = field(default_factory=list)


def _function_from_pgn(pgn: int | None) -> str | None:
    if pgn is None:
        return None
    return FUNCTION_BY_PGN.get(pgn)


def _iso_name(ev: OTEvent) -> str | None:
    raw = ev.parser_fields.get("iso_name")
    if not raw and isinstance(ev.value_after, dict):
        raw = ev.value_after.get("iso_name")
    if not raw:
        return None
    name = str(raw).strip()
    if name.upper() in GENERIC_ISO_NAMES:
        return None
    return name


def _pgn_int(ev: OTEvent) -> int | None:
    addr = ev.object_address
    if addr and str(addr).isdigit():
        return int(addr)
    return None


class AssetDetector:
    def __init__(self, criticality_path: Path) -> None:
        raw = yaml.safe_load(Path(criticality_path).read_text())
        self.by_id: dict[str, dict] = {}
        names = raw["criticality"]
        deps = {d["asset"]: d["depends_on"] for d in raw.get("dependencies", [])}
        dependents: dict[str, list[str]] = {k: [] for k in names}
        for child, parents in deps.items():
            for p in parents:
                dependents.setdefault(p, []).append(child)
        for name, row in names.items():
            aid = str(row["asset_id"])
            parent_ids = [str(names[p]["asset_id"]) for p in deps.get(name, [])]
            child_ids = [str(names[c]["asset_id"]) for c in dependents.get(name, [])]
            self.by_id[aid] = {
                "name": name,
                "segment": row["segment"],
                "criticality": row["criticality"],
                "nis2_service": row["nis2_service"],
                "depends_on": parent_ids,
                "dependents": child_ids,
                "role": "decoy" if aid == "99" else "expected",
            }
        self.live: dict[str, AssetRecord] = {}
        self.changes: list[dict] = []

    def _note(self, event_id: str, change: str, asset_id: str, **extra) -> None:
        self.changes.append({"event_id": event_id, "change": change, "asset_id": asset_id, **extra})

    def _new_record(self, aid: str, segment: str, ev: OTEvent, talker: bool) -> AssetRecord:
        model = self.by_id.get(aid)
        expected = aid in self.by_id
        iso = _iso_name(ev) if talker else None
        fn = _function_from_pgn(_pgn_int(ev)) if talker else None
        return AssetRecord(
            asset_id=aid,
            segment=segment,
            name=(model or {}).get("name") or iso or fn or f"SA {aid}",
            expected=expected,
            criticality=(model or {}).get("criticality", 2),
            nis2_service=(model or {}).get("nis2_service", "none"),
            depends_on=list((model or {}).get("depends_on", [])),
            dependents=list((model or {}).get("dependents", [])),
            first_seen=ev.timestamp,
            role=(model or {}).get("role") or ("unexpected" if not expected else "expected"),
        )

    def observe(self, ev: OTEvent) -> AssetRecord | None:
        if ev.source_asset_id is None:
            return None
        rec = self._observe_id(ev, ev.source_asset_id, talker=True)
        dest = ev.destination_asset_id
        if dest:
            self._observe_id(ev, dest, talker=False)
            if dest == "99" and rec.identity.get("decoy_contact") != dest:
                rec.identity["decoy_contact"] = dest
                self._note(ev.event_id, "decoy_contact", dest, src=ev.source_asset_id)
        return rec

    def _observe_id(self, ev: OTEvent, aid: str, talker: bool) -> AssetRecord:
        model = self.by_id.get(aid)
        observed_seg = ev.parser_fields.get("segment") or (model or {}).get("segment") or "aux"
        rec = self.live.get(aid)
        if rec is None:
            rec = self._new_record(aid, observed_seg, ev, talker)
            self.live[aid] = rec
            self._note(ev.event_id, "new_asset" if not rec.expected else "seen", aid)
        if not talker:
            return rec

        rec.last_seen = ev.timestamp
        rec.segment = observed_seg
        pgn_i = _pgn_int(ev)
        pgn = str(pgn_i) if pgn_i is not None else None
        iso = _iso_name(ev) if pgn == "60928" else None
        fn = _function_from_pgn(pgn_i)

        if iso:
            prev = rec.identity.get("iso_name")
            rec.identity["iso_name"] = iso
            if not rec.expected and rec.name in {f"SA {aid}", "NMEA 2000 node", "ISO requestor"}:
                rec.name = iso
            if prev and prev != iso:
                self._note(ev.event_id, "name_change", aid)
        if fn and not rec.expected:
            generic = rec.name in {f"SA {aid}", "NMEA 2000 node", "ISO requestor"} or rec.name is None
            if generic and fn not in {"NMEA 2000 node", "ISO requestor"}:
                rec.name = fn

        via = "address_claim" if pgn == "60928" else (f"pgn:{pgn}" if pgn else None)
        if via and via not in rec.detected_via:
            rec.detected_via.append(via)
        if pgn and pgn not in rec.channels_seen:
            rec.channels_seen.append(pgn)
            allowed = EXPECTED_PGNS.get(aid)
            if rec.expected and allowed and pgn not in allowed:
                self._note(ev.event_id, "pgn_set_drift", aid, pgn=pgn)

        model_seg = (model or {}).get("segment")
        if rec.expected and model_seg and observed_seg != model_seg:
            if rec.identity.get("segment_mismatch") != observed_seg:
                rec.identity["segment_mismatch"] = observed_seg
                self._note(ev.event_id, "unexpected_segment", aid, segment=observed_seg)
        return rec

    def inventory_rows(self) -> list[dict]:
        def key(rec: AssetRecord):
            aid = rec.asset_id
            sa = int(aid) if aid.isdigit() else aid
            return rec.segment, sa

        rows = []
        for rec in sorted(self.live.values(), key=key):
            rows.append(
                {
                    "asset_id": rec.asset_id,
                    "segment": rec.segment,
                    "name": rec.name,
                    "channels_seen": list(rec.channels_seen),
                    "first_seen": rec.first_seen.isoformat() if rec.first_seen else None,
                    "last_seen": rec.last_seen.isoformat() if rec.last_seen else None,
                    "expected": rec.expected,
                    "role": rec.role,
                    "criticality": rec.criticality,
                    "nis2_service": rec.nis2_service,
                    "depends_on": list(rec.depends_on),
                    "dependents": list(rec.dependents),
                    "detected_via": list(rec.detected_via),
                    "identity": dict(rec.identity),
                }
            )
        return rows

    def write_inventory(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.inventory_rows(), indent=2) + "\n", encoding="utf-8")
