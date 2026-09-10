from datetime import datetime, timezone

from otlab.can import pack_id, unpack_id
from otlab.pgn import (
    decode_fields,
    encode_ais_static,
    encode_attitude,
    encode_engine_dynamic,
    encode_heading,
    encode_heading_control,
    encode_position,
    encode_rudder,
)


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


def test_attitude_rudder_engine_ais_control_roundtrip():
    t = datetime(2026, 9, 8, tzinfo=timezone.utc)
    att = decode_fields(encode_attitude(t, "nav", 35, 90.0, 1.5, -2.0))
    assert att["pgn"] == 127257
    assert abs(att["yaw_deg"] - 90.0) < 0.5
    assert abs(att["pitch_deg"] - 1.5) < 0.2
    assert att["operation_name"] == "attitude"
    rud = decode_fields(encode_rudder(t, "nav", 52, -12.0))
    assert rud["pgn"] == 127245
    assert abs(rud["rudder_deg"] + 12.0) < 0.5
    dyn = decode_fields(encode_engine_dynamic(t, "propulsion", 0, 95.0, 420.0, 55.0))
    assert dyn["pgn"] == 127489
    assert abs(dyn["oil_temp_c"] - 95.0) < 1.0
    assert dyn["oil_kpa"] == 400 or abs(dyn["oil_kpa"] - 400) <= 100
    ais = decode_fields(encode_ais_static(t, "nav", 24, "OPV-LAB1"))
    assert ais["pgn"] == 129794
    assert ais["ship_name"] == "OPV-LAB1"
    status = decode_fields(encode_heading_control(t, "nav", 56, 90.0, status=True))
    assert status["pgn"] == 127237
    assert status["operation_name"] == "heading_control_status"
    assert status.get("privileged") is False
    cmd = decode_fields(encode_heading_control(t, "nav", 44, 90.0))
    assert cmd["operation_name"] == "heading_control"
    assert cmd.get("privileged") is True
