from datetime import datetime, timezone

from otlab.can import pack_id, unpack_id
from otlab.pgn import decode_fields, encode_heading, encode_position


def test_pack_unpack_pdu2():
    cid = pack_id(129025, sa=16)
    ids = unpack_id(cid)
    assert ids["pgn"] == 129025
    assert ids["sa"] == 16
    assert ids["da"] == 255


def test_pack_unpack_address_claim():
    cid = pack_id(60928, sa=16, da=255)
    ids = unpack_id(cid)
    assert ids["pgn"] == 60928
    assert ids["sa"] == 16


def test_position_roundtrip():
    t = datetime(2026, 9, 8, tzinfo=timezone.utc)
    fr = encode_position(t, "nav", 16, 54.5, 18.7)
    d = decode_fields(fr)
    assert abs(d["lat_deg"] - 54.5) < 1e-5
    assert abs(d["lon_deg"] - 18.7) < 1e-5


def test_heading_roundtrip():
    t = datetime(2026, 9, 8, tzinfo=timezone.utc)
    fr = encode_heading(t, "nav", 35, 90.0)
    d = decode_fields(fr)
    assert abs(d["heading_deg"] - 90.0) < 0.5
