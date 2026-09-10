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


def encode_rate_of_turn(t, segment: str, sa: int, rot_deg_s: float) -> CanFrame:
    raw = int(round(math.radians(rot_deg_s) / 3.125e-5))
    raw = max(-32767, min(32767, raw))
    data = b"\x00" + struct.pack("<h", raw) + b"\xff\xff\xff\xff"
    return CanFrame(t, segment, pack_id(127251, sa), data[:8])


def encode_ais_position(t, segment: str, sa: int, lat: float, lon: float) -> CanFrame:
    data = _i32(lat, 1e-7) + _i32(lon, 1e-7)
    return CanFrame(t, segment, pack_id(129038, sa), data)


def encode_depth(t, segment: str, sa: int, depth_m: float) -> CanFrame:
    data = b"\x00" + _u16(depth_m, 0.01) + b"\xff\xff\xff\xff"
    return CanFrame(t, segment, pack_id(128267, sa), data[:8])


def encode_battery(t, segment: str, sa: int, volts: float) -> CanFrame:
    data = b"\x00" + _u16(volts, 0.01) + b"\xff\xff\xff\xff"
    return CanFrame(t, segment, pack_id(127508, sa), data[:8])


def encode_engine_control(t, segment: str, sa: int, da: int, rpm: float) -> CanFrame:
    data = b"\x01" + _u16(rpm, 0.25) + bytes([da & 0xFF]) + b"\xff\xff\xff"
    return CanFrame(t, segment, pack_id(126208, sa, da=da), data[:8])


def encode_error_frame(t, segment: str, sa: int, pgn: int = 127250) -> CanFrame:
    data = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    return CanFrame(t, segment, pack_id(pgn, sa), data, error=True)


def encode_rpm(t, segment: str, sa: int, rpm: float) -> CanFrame:
    data = b"\x00" + _u16(rpm, 0.25) + b"\xff\xff\xff\xff"
    return CanFrame(t, segment, pack_id(127488, sa), data[:8])


def encode_claim(t, segment: str, sa: int, name: str | bytes = "LABTWIN") -> CanFrame:
    raw = name.encode("ascii", "replace") if isinstance(name, str) else name
    data = (raw + b"\x00" * 8)[:8]
    return CanFrame(t, segment, pack_id(60928, sa, da=255), data)


def encode_iso_request(t, segment: str, sa: int, da: int, requested_pgn: int) -> CanFrame:
    data = bytes(
        [requested_pgn & 0xFF, (requested_pgn >> 8) & 0xFF, (requested_pgn >> 16) & 0xFF]
    ) + b"\xff\xff\xff\xff\xff"
    return CanFrame(t, segment, pack_id(59904, sa, da=da), data[:8])


def encode_heading_control(t, segment: str, sa: int, heading_deg: float) -> CanFrame:
    data = b"\x00" + _u16(math.radians(heading_deg), 1e-4) + b"\xff\xff\xff\xff"
    return CanFrame(t, segment, pack_id(127237, sa), data[:8])


def decode_fields(frame: CanFrame) -> dict:
    ids = unpack_id(frame.can_id)
    pgn, data = ids["pgn"], frame.data
    out = {**ids, "segment": frame.segment, "error": bool(frame.error)}
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
    elif pgn == 127251 and len(data) >= 3:
        rot = struct.unpack("<h", data[1:3])[0] * 3.125e-5
        out.update(rot_deg_s=math.degrees(rot), operation_name="rate_of_turn")
    elif pgn == 129038 and len(data) >= 8:
        lat, lon = struct.unpack("<ii", data[:8])
        out.update(lat_deg=lat * 1e-7, lon_deg=lon * 1e-7, operation_name="ais_position")
    elif pgn == 128267 and len(data) >= 3:
        depth = struct.unpack("<H", data[1:3])[0] * 0.01
        out.update(depth_m=depth, operation_name="water_depth")
    elif pgn == 127508 and len(data) >= 3:
        volts = struct.unpack("<H", data[1:3])[0] * 0.01
        out.update(volts=volts, operation_name="battery_status")
    elif pgn == 126208 and len(data) >= 4:
        rpm = struct.unpack("<H", data[1:3])[0] * 0.25
        out.update(rpm=rpm, engine_da=data[3], operation_name="engine_control", privileged=True)
    elif pgn == 127488 and len(data) >= 3:
        rpm = struct.unpack("<H", data[1:3])[0] * 0.25
        out.update(rpm=rpm, operation_name="engine_rapid")
    elif pgn == 127237 and len(data) >= 3:
        hdg = struct.unpack("<H", data[1:3])[0] * 1e-4
        out.update(heading_deg=math.degrees(hdg), operation_name="heading_control", privileged=True)
    elif pgn == 59904:
        req = data[0] | (data[1] << 8) | (data[2] << 16) if len(data) >= 3 else 0
        out.update(requested_pgn=req, operation_name="iso_request", privileged=True)
    elif pgn == 60928:
        iso_name = data.split(b"\x00", 1)[0].decode("ascii", "replace").strip()
        out.update(operation_name="address_claim", privileged=True, iso_name=iso_name)
    else:
        out["operation_name"] = f"pgn_{pgn}"
    return out
