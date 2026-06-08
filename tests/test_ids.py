"""IDS detector and metrics tests (deterministic via explicit arrival times)."""

from carsec.can.identifiers import MSG_ID, encode_brake_pressure, encode_rpm
from carsec.can.message import CANMessage
from carsec.ids.detector import IDS, DetectionMetrics
from carsec.ids.entropy import EntropyDetector, shannon_entropy
from carsec.ids.frequency import FrequencyDetector
from carsec.ids.rules import RuleDetector


def test_rule_flags_unknown_id():
    assert RuleDetector().inspect(CANMessage(arbitration_id=0x000, data=b"\x00"), 0.0)


def test_rule_flags_implausible_rpm():
    msg = CANMessage(arbitration_id=MSG_ID["ENGINE_RPM"], data=encode_rpm(9999))
    assert RuleDetector().inspect(msg, 0.0)


def test_rule_accepts_normal_frame():
    msg = CANMessage(arbitration_id=MSG_ID["BRAKE_PRESS"], data=encode_brake_pressure(30))
    assert RuleDetector().inspect(msg, 0.0) is None


def test_frequency_flags_fast_frame_after_warmup():
    d = FrequencyDetector(warmup_frames=4, tolerance=0.4)
    arb = MSG_ID["ENGINE_RPM"]
    t = 0.0
    for _ in range(8):  # establish a 100 ms baseline
        assert d.inspect(CANMessage(arbitration_id=arb, data=encode_rpm(1000)), t) is None
        t += 0.1
    # a frame arriving 20 ms later is anomalous
    assert d.inspect(CANMessage(arbitration_id=arb, data=encode_rpm(1000)), t - 0.08)


def test_entropy_high_payload_flagged():
    d = EntropyDetector(warmup_frames=2, abs_threshold=2.5, margin=1.0)
    arb = MSG_ID["GATEWAY_FWD"]
    for _ in range(4):  # low-entropy baseline
        d.inspect(CANMessage(arbitration_id=arb, data=b"\x00\x01"), 0.0)
    flagged = d.inspect(CANMessage(arbitration_id=arb, data=bytes(range(8))), 0.0)
    assert flagged


def test_shannon_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 8) == 0.0
    assert abs(shannon_entropy(bytes(range(256))) - 8.0) < 1e-9


def test_metrics_math():
    m = DetectionMetrics(true_positives=8, false_positives=2, true_negatives=90, false_negatives=0)
    assert abs(m.precision - 0.8) < 1e-9
    assert m.recall == 1.0
    assert abs(m.f1 - (2 * 0.8 * 1.0 / 1.8)) < 1e-9


def test_ids_detects_injection_not_normal():
    ids = IDS(logger=None, alert=False)
    # normal frame is benign
    ids.observe(CANMessage(arbitration_id=MSG_ID["BRAKE_PRESS"], data=encode_brake_pressure(20)), now=0.0)
    # injected implausible RPM is flagged + scored as a true positive
    flagged = ids.observe(
        CANMessage(arbitration_id=MSG_ID["ENGINE_RPM"], data=encode_rpm(9999), is_attack=True),
        now=0.01,
    )
    assert flagged
    assert ids.metrics.true_positives == 1
    assert ids.metrics.false_positives == 0
