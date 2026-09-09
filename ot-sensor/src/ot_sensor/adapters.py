"""Protocol adapters → OTEvent. Listen-only."""

from __future__ import annotations

import uuid
from datetime import datetime

from otlab import CanFrame, OTEvent
from otlab.pgn import decode_fields


def _eid() -> str:
    return str(uuid.uuid4())


class Nmea2000Adapter:
    def __init__(self, source_id: str = "n2k-nav", writes: bool = False, mode: str = "prod") -> None:
        if mode == "prod" and writes:
            raise RuntimeError("writes:true is fatal in SENSOR_MODE=prod")
        self.source_id = source_id
        self.mode = mode

    def convert(self, frame: CanFrame) -> OTEvent:
        fields = decode_fields(frame)
        pgn = fields["pgn"]
        sa = str(fields["sa"])
        da = None if fields["da"] == 255 else str(fields["da"])
        privileged = bool(fields.get("privileged"))
        is_control = pgn in (127237,)
        is_write = pgn in (127237,)
        category = "identity" if pgn == 60928 else "read" if pgn == 59904 else "control" if is_write else "report"
        value = {
            k: v
            for k, v in fields.items()
            if k in (
                "lat_deg",
                "lon_deg",
                "cog_deg",
                "sog_kn",
                "heading_deg",
                "hdop",
                "sat_count",
                "rpm",
                "iso_name",
                "requested_pgn",
            )
        }
        return OTEvent(
            event_id=_eid(),
            timestamp=frame.t,
            protocol="nmea2000",
            source_asset_id=sa,
            destination_asset_id=da,
            operation_category=category,
            operation_name=fields.get("operation_name", "pgn"),
            object_type="pgn",
            object_address=str(pgn),
            value_before=None,
            value_after=value or None,
            is_write=is_write,
            is_control=is_control,
            is_configuration=pgn == 60928,
            privileged=privileged,
            parser_fields={
                "source": self.source_id,
                "segment": frame.segment,
                "catalog": "pgn-2026.03",
                **{
                    k: fields[k]
                    for k in fields
                    if k not in ("pgn", "sa", "da", "prio", "segment", "operation_name", "privileged")
                },
            },
        )


class Nmea0183Adapter:
    def convert(self, sentence: str, t: datetime, segment: str = "nav") -> OTEvent:
        body = sentence[1:].split("*")[0]
        parts = body.split(",")
        talker = parts[0][:2]
        kind = parts[0][2:]
        fields: dict = {}
        if kind == "HDT" and len(parts) > 1:
            fields["heading_deg"] = float(parts[1])
        return OTEvent(
            event_id=_eid(),
            timestamp=t,
            protocol="nmea0183",
            source_asset_id=talker,
            destination_asset_id=None,
            operation_category="report",
            operation_name=kind.lower(),
            object_type="nmea_sentence",
            object_address=kind,
            value_before=None,
            value_after=fields or None,
            is_write=False,
            is_control=False,
            is_configuration=False,
            privileged=False,
            parser_fields={"source": "n0183-nav", "segment": segment, **fields},
        )


class ModbusAdapter:
    def convert(self, plant_or_regs: dict, t: datetime) -> list[OTEvent]:
        events = []
        for name, val in plant_or_regs.items():
            events.append(
                OTEvent(
                    event_id=_eid(),
                    timestamp=t,
                    protocol="modbus",
                    source_asset_id="1",
                    destination_asset_id=None,
                    operation_category="read",
                    operation_name="read_holding_register" if name.startswith("rpm") else "read",
                    object_type="modbus_reg",
                    object_address=name,
                    value_before=None,
                    value_after=val,
                    is_write=False,
                    is_control=False,
                    is_configuration=False,
                    privileged=False,
                    parser_fields={"source": "mb-prop", "segment": "propulsion", name: val},
                )
            )
        return events
