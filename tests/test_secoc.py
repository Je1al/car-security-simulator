"""SecOC: crypto, freshness, and the layered verifier."""

from carsec.can.identifiers import MSG_ID, encode_rpm
from carsec.can.message import CANMessage
from carsec.security.crypto import compute_mac, derive_key, verify_mac
from carsec.security.freshness import FreshnessManager
from carsec.security.secoc import SecOCLayer


def _frame(rpm=1000):
    return CANMessage(arbitration_id=MSG_ID["ENGINE_RPM"], data=encode_rpm(rpm))


# ── crypto ────────────────────────────────────────────────────────────────────

def test_mac_verifies_and_detects_change():
    key = derive_key()
    tag = compute_mac(b"hello", key)
    assert verify_mac(b"hello", tag, key)
    assert not verify_mac(b"hellp", tag, key)


def test_mac_truncated_to_8_bytes():
    assert len(compute_mac(b"x")) == 8


# ── freshness ─────────────────────────────────────────────────────────────────

def test_freshness_monotonic_and_replay_rejected():
    fm = FreshnessManager()
    assert fm.next_value(0xA0) == 1
    assert fm.next_value(0xA0) == 2
    assert fm.is_fresh(0xA0, 5)
    fm.commit(0xA0, 5)
    assert not fm.is_fresh(0xA0, 5)  # equal → replay
    assert not fm.is_fresh(0xA0, 4)  # older → replay
    assert fm.is_fresh(0xA0, 6)


def test_freshness_window_bounds_jump():
    fm = FreshnessManager(accept_window=8)
    assert not fm.is_fresh(1, 100)  # too far ahead
    assert fm.is_fresh(1, 8)


# ── SecOC verifier ────────────────────────────────────────────────────────────

def test_authenticated_frame_accepted():
    tx = SecOCLayer("ECU_Engine", secure=True)
    rx = SecOCLayer("ECU_Brake", secure=True)
    msg = tx.authenticate(_frame())
    assert msg.mac and msg.freshness == 1
    assert rx.verify(msg).accepted


def test_tampered_frame_rejected():
    tx = SecOCLayer("ECU_Engine", secure=True)
    rx = SecOCLayer("ECU_Brake", secure=True)
    msg = tx.authenticate(_frame(1000))
    msg.data = encode_rpm(9999)  # tamper after signing
    result = rx.verify(msg)
    assert not result.accepted and not result.mac_valid


def test_replayed_frame_rejected_by_freshness():
    tx = SecOCLayer("ECU_Engine", secure=True)
    rx = SecOCLayer("ECU_Brake", secure=True)
    msg = tx.authenticate(_frame())
    assert rx.verify(msg).accepted
    replay = msg.clone()  # identical frame, same freshness
    result = rx.verify(replay)
    assert not result.accepted and not result.freshness_ok


def test_injected_frame_without_mac_rejected():
    rx = SecOCLayer("ECU_Brake", secure=True)
    forged = _frame(9999)  # no MAC, attacker doesn't know the key
    assert not rx.verify(forged).accepted


def test_insecure_mode_accepts_everything():
    rx = SecOCLayer("ECU_Brake", secure=False)
    assert rx.verify(_frame()).accepted
    forged = CANMessage(arbitration_id=0x666, data=b"\xff")
    assert rx.verify(forged).accepted
