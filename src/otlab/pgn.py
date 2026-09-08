"""Encode/decode the lab PGN set (not a full catalog)."""

from __future__ import annotations

import math
import struct

from otlab.can import pack_id, unpack_id
from otlab import CanFrame


def _i32(x: float, scale: float) -> bytes:
    return struct.pack("<i", int(round(x / scale)))


def _u16(x: float, scale: float) -> bytes:
    v = max(0, min(65535, int(round(x / scale))))
    return struct.pack("<H", v)


def encode_position(t, segment: str, sa: int, lat: float, lon: float) -> CanFrame:
    data = _i32(lat, 1e-7) + _i32(lon, 1e-7)
    return CanFrame(t, segment, pack_id(129025, sa), data)


def encode_cog_sog(t, segment: str, sa: int, cog_deg: float, sog_kn: float) -> CanFrame:
    cog_rad = math.radians(cog_deg)
    sog_ms = sog_kn * 0.514444
    data = b"\x00\xff" + _u16(cog_rad, 1e-4) + _u16(sog_ms, 0.01) + b"\xff\xff"
    return CanFrame(t, segment, pack_id(129026, sa), data[:8])


def encode_dops(t, segment: str, sa: int, hdop: float) -> CanFrame:
    data = b"\x00\x00" + _u16(hdop, 0.01) + b"\xff\xff\xff\xff"
    return CanFrame(t, segment, pack_id(129539, sa), data[:8])


def encode_sats(t, segment: str, sa: int, sat_count: int, lat: float, lon: float) -> CanFrame:
    # Lab stand-in for 129029 first frame: sat count + quality flag.
    data = bytes([sat_count & 0xFF, 1]) + _i32(lat, 1e-7)[:6]
    return CanFrame(t, segment, pack_id(129029, sa), data[:8])


def encode_heading(t, segment: str, sa: int, heading_deg: float) -> CanFrame:
    data = b"\x00" + _u16(math.radians(heading_deg), 1e-4) + b"\xff\xff\xff\xff"
    return CanFrame(t, segment, pack_id(127250, sa), data[:8])


def encode_rpm(t, segment: str, sa: int, rpm: float) -> CanFrame:
    data = b"\x00" + _u16(rpm, 0.25) + b"\xff\xff\xff\xff"
    return CanFrame(t, segment, pack_id(127488, sa), data[:8])


def encode_claim(t, segment: str, sa: int, name: bytes = b"LABTWIN\x00") -> CanFrame:
    data = (name + b"\x00" * 8)[:8]
    return CanFrame(t, segment, pack_id(60928, sa, da=255), data)


def decode_fields(frame: CanFrame) -> dict:
    ids = unpack_id(frame.can_id)
    pgn, data = ids["pgn"], frame.data
    out = {**ids, "segment": frame.segment}
    if pgn == 129025 and len(data) >= 8:
        lat, lon = struct.unpack("<ii", data[:8])
        out.update(lat_deg=lat * 1e-7, lon_deg=lon * 1e-7, operation_name="gnss_position")
    elif pgn == 129026 and len(data) >= 6:
        cog = struct.unpack("<H", data[2:4])[0] * 1e-4
        sog = struct.unpack("<H", data[4:6])[0] * 0.01
        out.update(cog_deg=math.degrees(cog), sog_kn=sog / 0.514444, operation_name="cog_sog")
    elif pgn == 129539 and len(data) >= 4:
        hdop = struct.unpack("<H", data[2:4])[0] * 0.01
        out.update(hdop=hdop, operation_name="gnss_dops")
    elif pgn == 129029 and len(data) >= 2:
        out.update(sat_count=data[0], operation_name="gnss_position_data")
        if data[1] == 1:
            out["fix_valid"] = True
    elif pgn == 127250 and len(data) >= 3:
        hdg = struct.unpack("<H", data[1:3])[0] * 1e-4
        out.update(heading_deg=math.degrees(hdg), operation_name="heading")
    elif pgn == 127488 and len(data) >= 3:
        rpm = struct.unpack("<H", data[1:3])[0] * 0.25
        out.update(rpm=rpm, operation_name="engine_rapid")
    elif pgn == 60928:
        out.update(operation_name="address_claim", privileged=True)
    else:
        out["operation_name"] = f"pgn_{pgn}"
    return out
