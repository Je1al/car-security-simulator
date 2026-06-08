"""CAN frame model tests."""

import pytest

from carsec.can.identifiers import MSG_ID, decode_rpm, encode_rpm
from carsec.can.message import WIRE_SIZE, CANMessage


def test_dlc_and_name():
    m = CANMessage(arbitration_id=MSG_ID["ENGINE_RPM"], data=encode_rpm(1234))
    assert m.dlc == 2
    assert m.name == "ENGINE_RPM"
    assert decode_rpm(m.data) == 1234


def test_unknown_id_name_is_hex():
    assert CANMessage(arbitration_id=0x123, data=b"").name == "0x123"


def test_wire_roundtrip_preserves_fields():
    m = CANMessage(
        arbitration_id=MSG_ID["BRAKE_PRESS"],
        data=b"\x12\x34",
        freshness=7,
        mac=b"\xaa" * 8,
    )
    raw = m.to_bytes()
    assert len(raw) == WIRE_SIZE
    back = CANMessage.from_bytes(raw)
    assert back.arbitration_id == m.arbitration_id
    assert back.data == m.data
    assert back.freshness == 7
    assert back.mac == b"\xaa" * 8


def test_clone_is_independent():
    m = CANMessage(arbitration_id=1, data=b"\x01", is_attack=True, attack_type="replay")
    c = m.clone()
    assert c.is_attack and c.attack_type == "replay"
    assert c is not m


def test_payload_too_long_rejected():
    with pytest.raises(ValueError):
        CANMessage(arbitration_id=1, data=b"\x00" * 9)


def test_is_secured_flag():
    assert not CANMessage(arbitration_id=1, data=b"").is_secured
    assert CANMessage(arbitration_id=1, data=b"", mac=b"\x01" * 8).is_secured
