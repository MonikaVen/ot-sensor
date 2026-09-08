"""Asset detector: inventory + criticality + depends_on."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import yaml

from otlab import OTEvent


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
    last_seen: datetime | None = None


class AssetDetector:
    def __init__(self, criticality_path: Path) -> None:
        raw = yaml.safe_load(Path(criticality_path).read_text())
        self.by_id: dict[str, dict] = {}
        names = raw["criticality"]
        deps = {d["asset"]: d["depends_on"] for d in raw.get("dependencies", [])}
        name_of = {v["asset_id"]: k for k, v in names.items()}
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
            }
        self.live: dict[str, AssetRecord] = {}
        self.changes: list[dict] = []

    def observe(self, ev: OTEvent) -> AssetRecord | None:
        if ev.source_asset_id is None:
            return None
        aid = ev.source_asset_id
        meta = self.by_id.get(aid, {"name": None, "segment": ev.parser_fields.get("segment"), "criticality": 2, "nis2_service": "none", "depends_on": [], "dependents": []})
        rec = self.live.get(aid)
        change = None
        if rec is None:
            rec = AssetRecord(
                asset_id=aid,
                segment=meta["segment"],
                name=meta["name"],
                expected=aid in self.by_id,
                criticality=meta["criticality"],
                nis2_service=meta["nis2_service"],
                depends_on=list(meta["depends_on"]),
                dependents=list(meta["dependents"]),
            )
            self.live[aid] = rec
            change = "new_asset" if not rec.expected else "seen"
        rec.last_seen = ev.timestamp
        ch = ev.object_address
        if ch and ch not in rec.channels_seen:
            rec.channels_seen.append(ch)
        if change:
            self.changes.append({"event_id": ev.event_id, "change": change, "asset_id": aid})
        return rec
