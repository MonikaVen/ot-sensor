"""Shared lab types. Mirrors docs/architecture/samples/schemas/ot_events.py."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any


def dump(obj: Any) -> dict:
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    return obj


@dataclass
class CanFrame:
    t: datetime
    segment: str
    can_id: int
    data: bytes
    error: bool = False


@dataclass
class OTEvent:
    event_id: str
    timestamp: datetime
    protocol: str
    source_asset_id: str | None
    destination_asset_id: str | None
    operation_category: str
    operation_name: str
    object_type: str | None
    object_address: str | None
    value_before: object | None
    value_after: object | None
    is_write: bool
    is_control: bool
    is_configuration: bool
    privileged: bool
    parser_fields: dict = field(default_factory=dict)


@dataclass
class LabelRecord:
    t: datetime
    scenario_id: str
    attack_id: str
    technique: str
    victim_sa: int
    pgn: int
    segment: str
    phase: str


@dataclass
class PlantState:
    t: datetime
    lat_deg: float
    lon_deg: float
    sog_kn: float
    cog_deg: float
    heading_deg: float
    rot_deg_s: float
    depth_m: float
    hdop: float
    sat_count: int
    rpm_port: float
    rpm_stbd: float
    oil_temp_c: float
    breaker_closed: bool
    phase: str = "baseline"
    scenario_id: str = "underway"
    attack_id: str | None = None
