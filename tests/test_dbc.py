"""DBC decoding (works with cantools or the stdlib fallback)."""

from carsec.can.dbc import DbcDatabase
from carsec.can.identifiers import (
    MSG_ID,
    encode_brake_pressure,
    encode_rpm,
    encode_temperature,
)
from carsec.can.message import CANMessage


def test_decode_matches_encoders():
    db = DbcDatabase()
    cases = [
        (MSG_ID["ENGINE_RPM"], encode_rpm(2500), "EngineRPM", 2500),
        (MSG_ID["ENGINE_TEMP"], encode_temperature(87.5), "EngineTemp", 87.5),
        (MSG_ID["BRAKE_PRESS"], encode_brake_pressure(42.25), "BrakePressure", 42.25),
    ]
    for arb, data, signal, expected in cases:
        decoded = db.decode(CANMessage(arbitration_id=arb, data=data))
        assert abs(float(decoded[signal]) - expected) < 1e-6


def test_unknown_id_decodes_empty():
    assert DbcDatabase().decode(CANMessage(arbitration_id=0x000, data=b"\x00")) == {}
