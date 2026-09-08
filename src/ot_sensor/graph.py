"""Communication graph: who talks to whom vs expected edges."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from otlab import OTEvent

EXPECTED = {
    ("16", "56", "nav"),
    ("16", None, "nav"),
    ("17", None, "nav"),
    ("35", "56", "nav"),
    ("35", None, "nav"),
    ("0", None, "propulsion"),
}


@dataclass
class GraphEdge:
    src: str
    dst: str | None
    segment: str
    expected: bool
    last_seen: datetime


class CommsGraph:
    def __init__(self) -> None:
        self.edges: dict[tuple, GraphEdge] = {}
        self.changes: list[dict] = []

    def observe(self, ev: OTEvent) -> GraphEdge | None:
        if ev.source_asset_id is None:
            return None
        src, dst = ev.source_asset_id, ev.destination_asset_id
        seg = ev.parser_fields.get("segment", "")
        key = (src, dst, seg)
        expected = (src, dst, seg) in EXPECTED or (src, None, seg) in EXPECTED
        edge = self.edges.get(key)
        if edge is None:
            edge = GraphEdge(src, dst, seg, expected, ev.timestamp)
            self.edges[key] = edge
            if not expected:
                change = "gateway_bypass" if src in {"0", "1"} and seg == "nav" else "new_edge"
                self.changes.append({"event_id": ev.event_id, "change": change, "src": src, "dst": dst})
        else:
            edge.last_seen = ev.timestamp
        return edge
