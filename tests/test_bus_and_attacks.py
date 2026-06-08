"""Bus broadcast semantics and attacker mechanics (no threads, deterministic)."""

from carsec.attacks.base import Attacker
from carsec.attacks.dos import BusFlooder
from carsec.attacks.fuzz import CANFuzzer
from carsec.can.bus import VirtualCANBus
from carsec.can.identifiers import MSG_ID, encode_rpm
from carsec.can.message import CANMessage
from carsec.telemetry.logger import EventLogger


def _logger():
    return EventLogger(console=False, to_file=False)


def test_send_excludes_sender_reaches_others():
    bus = VirtualCANBus()
    a = bus.register_node("A")
    b = bus.register_node("B")
    bus.send(CANMessage(arbitration_id=1, data=b"\x01"), sender="A")
    assert a.empty()  # sender does not receive its own frame
    assert not b.empty()


def test_tap_sees_every_frame():
    bus = VirtualCANBus()
    bus.register_node("A")
    seen = []
    bus.add_tap(seen.append)
    bus.send(CANMessage(arbitration_id=1, data=b"\x01"), sender="A")
    bus.inject(CANMessage(arbitration_id=2, data=b"\x02"), injector="X")
    assert len(seen) == 2


def test_attacker_captures_then_replays():
    bus = VirtualCANBus()
    log = _logger()
    atk = Attacker("ATTACKER", bus, log)
    bus.register_node("victim")
    # legitimate frame on the bus → attacker sniffs it
    bus.send(CANMessage(arbitration_id=MSG_ID["ENGINE_RPM"], data=encode_rpm(1500), sender="ECU_Engine"), "ECU_Engine")
    assert atk.captured_count() == 1
    assert atk.replay("ENGINE_RPM") is True
    assert atk.replays == 1


def test_attacker_inject_marks_attack():
    bus = VirtualCANBus()
    seen = []
    bus.add_tap(seen.append)
    atk = Attacker("ATTACKER", bus, _logger())
    atk.inject(MSG_ID["BRAKE_PRESS"])
    assert seen and seen[-1].is_attack and seen[-1].attack_type == "injection"


def test_dos_flood_counts_frames():
    bus = VirtualCANBus()
    seen = []
    bus.add_tap(seen.append)
    flooder = BusFlooder("ATTACKER", bus, _logger())
    n = flooder.flood(duration=0.05, rate_hz=0)  # rate_hz=0 → no sleep, tight loop
    assert n > 0 and flooder.frames_sent == n
    assert all(f.attack_type == "dos" for f in seen if f.is_attack)


def test_fuzzer_emits_frames():
    bus = VirtualCANBus()
    seen = []
    bus.add_tap(seen.append)
    fz = CANFuzzer("ATTACKER", bus, _logger())
    assert fz.fuzz_random(count=10) == 10
    assert fz.frames_sent == 10
    assert all(f.attack_type == "fuzz" for f in seen)
