"""NMEA 2000 29-bit CAN ID pack/unpack."""

from __future__ import annotations


def pack_id(pgn: int, sa: int, da: int = 255, prio: int = 6) -> int:
    pf = (pgn >> 8) & 0xFF
    dp = (pgn >> 16) & 0x01
    if pf < 240:
        ps = da & 0xFF
    else:
        ps = pgn & 0xFF
    return ((prio & 0x7) << 26) | (dp << 24) | (pf << 16) | (ps << 8) | (sa & 0xFF)


def unpack_id(can_id: int) -> dict:
    sa = can_id & 0xFF
    ps = (can_id >> 8) & 0xFF
    pf = (can_id >> 16) & 0xFF
    dp = (can_id >> 24) & 0x01
    prio = (can_id >> 26) & 0x7
    if pf < 240:
        pgn = (dp << 16) | (pf << 8)
        da = ps
    else:
        pgn = (dp << 16) | (pf << 8) | ps
        da = 255
    return {"pgn": pgn, "sa": sa, "da": da, "prio": prio}
