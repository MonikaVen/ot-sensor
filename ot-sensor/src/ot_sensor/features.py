"""Feature windows (Bytewax contract). Does not run ONNX."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from otlab import OTEvent
from otlab.geo import haversine_m

# Vessel model SAs from asset-criticality.yaml. Anything else is unexpected.
EXPECTED_SAS = frozenset(
    {
        "0",
        "1",
        "4",
        "5",
        "8",
        "12",
        "16",
        "17",
        "20",
        "21",
        "24",
        "28",
        "32",
        "35",
        "40",
        "48",
        "52",
        "56",
        "60",
        "80",
        "84",
        "88",
        "99",
    }
)
RECENT_S = 5.0


@dataclass
class FeatureWindow:
    event_id: str
    t_start: datetime
    t_end: datetime
    source: str
    protocol: str
    segment: str
    asset_ids: list[str]
    member_event_ids: list[str]
    features: dict[str, float] = field(default_factory=dict)
    parser_snapshot: dict = field(default_factory=dict)


class FeatureStage:
    """Bytewax stages 1–5 as an in-process operator."""

    def window(self, events: list[OTEvent], source: str = "n2k-nav") -> FeatureWindow:
        if not events:
            raise ValueError("empty window")
        t0, t1 = events[0].timestamp, events[-1].timestamp
        dt = max(0.001, (t1 - t0).total_seconds())
        assets = sorted({e.source_asset_id for e in events if e.source_asset_id})
        pgns = {e.object_address for e in events}
        nbytes = sum(8 for _ in events)
        lat1 = lon1 = lat2 = lon2 = hdg = cog = hdop = sats = None
        for e in events:
            v = e.value_after or {}
            pf = e.parser_fields
            if e.source_asset_id == "16":
                lat1 = v.get("lat_deg", pf.get("lat_deg", lat1))
                lon1 = v.get("lon_deg", pf.get("lon_deg", lon1))
                cog = v.get("cog_deg", pf.get("cog_deg", cog))
                hdop = v.get("hdop", pf.get("hdop", hdop))
                sats = v.get("sat_count", pf.get("sat_count", sats))
            if e.source_asset_id == "17":
                lat2 = v.get("lat_deg", pf.get("lat_deg", lat2))
                lon2 = v.get("lon_deg", pf.get("lon_deg", lon2))
            if e.source_asset_id == "35":
                hdg = v.get("heading_deg", pf.get("heading_deg", hdg))
        split = 0.0
        if None not in (lat1, lon1, lat2, lon2):
            split = haversine_m(lat1, lon1, lat2, lon2)
        # DR ≈ GNSS-2 (true twin) vs GNSS-1
        dr = split
        cog_hdg = 0.0
        if cog is not None and hdg is not None:
            cog_hdg = abs((cog - hdg + 180) % 360 - 180)
        frames_per_s = len(events) / dt
        cutoff = t1 - timedelta(seconds=RECENT_S)
        recent = [e for e in events if e.timestamp >= cutoff] or events[-20:]
        dt_r = 0.2
        if len(recent) > 1:
            dt_r = max(0.2, (recent[-1].timestamp - recent[0].timestamp).total_seconds())
        iso_n = sum(1 for e in recent if e.object_address == "59904")
        ctrl_n = sum(
            1
            for e in recent
            if e.object_address == "127237" and (e.is_write or e.privileged)
        )
        hdg_n = sum(1 for e in recent if e.object_address == "127250")
        unexpected = {e.source_asset_id for e in recent if e.source_asset_id and e.source_asset_id not in EXPECTED_SAS}
        feat = {
            "bus_load_pct": min(100.0, frames_per_s / 1500.0 * 100.0),
            "frames_per_s_norm": frames_per_s / 1500.0,
            "bytes_per_s_norm": (nbytes / dt) / 25000.0,
            "mean_interarrival_norm": (dt / max(1, len(events) - 1) * 1000 / 50) if len(events) > 1 else 1.0,
            "unique_sa_norm": len(assets) / 50.0,
            "unique_pgn_norm": len(pgns) / 50.0,
            "error_frame_rate": 0.0,
            "high_prio_share": 0.1,
            "gnss_dr_residual_m": dr,
            "gnss1_gnss2_split_m": split,
            "hdop": float(hdop or 99),
            "sat_count": float(sats or 0),
            "cog_heading_residual_deg": cog_hdg,
            "heading_rot_consistent": 1.0,
            "sat_count_drop": 0.0,
            "iso_request_count": float(iso_n),
            "iso_request_per_s": iso_n / dt_r,
            "heading_control_count": float(ctrl_n),
            "heading_pgn_per_s": hdg_n / dt_r,
            "unexpected_talker_count": float(len(unexpected)),
            "recent_frames_per_s": len(recent) / dt_r,
        }
        if lat1 is not None:
            feat["gnss1_lat_deg"] = float(lat1)
        if lon1 is not None:
            feat["gnss1_lon_deg"] = float(lon1)
        if lat2 is not None:
            feat["gnss2_lat_deg"] = float(lat2)
        if lon2 is not None:
            feat["gnss2_lon_deg"] = float(lon2)
        if cog is not None:
            feat["cog_deg"] = float(cog)
        if hdg is not None:
            feat["heading_deg"] = float(hdg)
        return FeatureWindow(
            event_id=str(uuid.uuid4()),
            t_start=t0,
            t_end=t1,
            source=source,
            protocol=events[0].protocol,
            segment=events[0].parser_fields.get("segment", "nav"),
            asset_ids=[a for a in assets if a],
            member_event_ids=[e.event_id for e in events],
            features=feat,
            parser_snapshot={"lat1": lat1, "lon1": lon1, "hdop": hdop, "sats": sats},
        )

    def lstm_seq(self, windows: list[FeatureWindow]) -> list[list[float]]:
        keys = [
            "bus_load_pct",
            "frames_per_s_norm",
            "bytes_per_s_norm",
            "mean_interarrival_norm",
            "unique_sa_norm",
            "unique_pgn_norm",
            "error_frame_rate",
            "high_prio_share",
        ]
        seq = []
        for w in windows[-20:]:
            seq.append([float(w.features.get(k, 0.0)) for k in keys])
        while len(seq) < 20:
            seq.insert(0, seq[0] if seq else [0.0] * 8)
        return seq
