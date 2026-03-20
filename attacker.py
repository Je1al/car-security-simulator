"""
attacker.py
────────────────────────────────────────────────────────────────────────────────
Automotive attack simulation module.

Real-world attack context
──────────────────────────
In 2015 Charlie Miller and Chris Valasek demonstrated remote CAN bus attacks
on a Jeep Cherokee via the Uconnect telematics unit.  Their toolkit could:
  • Kill the engine at highway speed (via CAN injection to ECM)
  • Disable brakes (ABS/ESC module injection)
  • Control steering at low speed

These attacks work because:
  1. CAN has no authentication — any message with the right ID is accepted
  2. ECUs inside the vehicle trust the bus implicitly
  3. Once one ECU is compromised, the entire bus is compromised

We simulate three attack techniques:
──────────────────────────────────
  1. REPLAY ATTACK
     The attacker passively listens (sniffs) legitimate messages and later
     re-transmits a captured message.  The goal is to re-trigger an action
     the victim ECU performed when it first received the message.
     
     Example: capture "BRAKE_PRESS=0" (no braking) and replay it when the
     driver presses the brake pedal — the brake ECU discards the braking
     command, vehicle fails to decelerate.

     Detection (secure mode):
       • Nonce counter mismatch — replayed nonce is ≤ last accepted nonce
       • Timestamp too old (beyond TIMESTAMP_WINDOW_SEC)

  2. TAMPERING ATTACK
     The attacker modifies the payload of a captured message before re-sending.
     Example: change ENGINE_RPM from 1200 to 9999 to confuse the dashboard
     or trigger false over-rev protection.
     
     Detection (secure mode):
       • HMAC mismatch — any single-bit change to payload invalidates the MAC

  3. INJECTION ATTACK
     The attacker fabricates an entirely new message with a chosen payload.
     Most dangerous form — equivalent to impersonating a trusted ECU.
     In insecure mode this is completely undetected.
     
     Detection (secure mode):
       • No valid HMAC (attacker does not know the shared key)
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import random
import struct
import time
import threading
from typing import Dict, List, Optional

from can_protocol import CANMessage, MSG_ID, encode_brake_pressure, encode_rpm, encode_status
from network      import CANBus
from logger       import EventLogger


# ─── Attacker ─────────────────────────────────────────────────────────────────

class Attacker:
    """
    Passive sniffer + active attacker.

    The attacker registers as a sniffer on the bus (passive — receives copies
    of all messages without appearing in the listener list).
    When attack methods are called it injects crafted messages via bus.inject().
    """

    def __init__(
        self,
        name:   str,
        bus:    CANBus,
        logger: EventLogger,
    ) -> None:
        self.name    = name
        self._bus    = bus
        self._logger = logger

        # Packet capture buffer: msg_name → list of captured CANMessages
        self._capture: Dict[str, List[CANMessage]] = {}
        self._lock    = threading.Lock()

        # Statistics
        self.replays_attempted   = 0
        self.tampers_attempted   = 0
        self.injections_attempted= 0

        # Register as passive sniffer
        bus.set_sniffer(self._sniff)

    # ── Passive sniffing ──────────────────────────────────────────────────────

    def _sniff(self, msg: CANMessage) -> None:
        """Called by the bus for every transmitted frame (passive copy)."""
        with self._lock:
            key = msg.msg_name
            if key not in self._capture:
                self._capture[key] = []
            self._capture[key].append(msg.clone())
            # Keep only last 20 captures per type to limit memory
            if len(self._capture[key]) > 20:
                self._capture[key].pop(0)

    def captured_count(self) -> int:
        with self._lock:
            return sum(len(v) for v in self._capture.values())

    def list_captured(self) -> Dict[str, int]:
        with self._lock:
            return {k: len(v) for k, v in self._capture.items()}

    # ── Attack 1: Replay ──────────────────────────────────────────────────────

    def replay_attack(self, msg_name: str = "ENGINE_RPM") -> bool:
        """
        Replay a previously captured message exactly as captured.
        
        Why dangerous:
          In insecure mode the receiving ECU accepts the old message without
          question.  If the attacker captured "BRAKE_PRESS=0.0" (no braking)
          they can replay it while the driver is braking — defeating ABS.
        
        How we detect it (secure mode):
          • The nonce in the replayed message was already seen → REJECTED
          • The timestamp is stale (> TIMESTAMP_WINDOW_SEC old) → REJECTED
        """
        with self._lock:
            msgs = self._capture.get(msg_name, [])
            if not msgs:
                self._logger.log_event(
                    "WARN", self.name,
                    f"No captured {msg_name} messages available for replay",
                )
                return False
            target = random.choice(msgs).clone()

        target.is_replay = True
        self.replays_attempted += 1

        self._logger.log_event(
            "REPLAY", self.name,
            f"REPLAY ATTACK → replaying captured {msg_name} "
            f"(nonce={target.nonce}, age={time.time()-target.timestamp:.2f}s)",
            target,
        )
        self._bus.inject(target, injector_name=self.name)
        return True

    # ── Attack 2: Tampering ───────────────────────────────────────────────────

    def tamper_attack(
        self,
        msg_name:     str   = "ENGINE_RPM",
        new_payload:  Optional[bytes] = None,
    ) -> bool:
        """
        Capture a legitimate message, modify its payload, and re-transmit.
        The HMAC tag still belongs to the ORIGINAL payload → mismatch.
        
        Why dangerous:
          An attacker who captures a brake command can change the brake
          pressure field from 80 bar (hard braking) to 0 bar (no braking).
          In insecure mode this is accepted silently.
        
        How we detect it (secure mode):
          • HMAC of (msg_id | NEW_payload | ts | nonce) ≠ stored hmac_tag
          → REJECTED with "HMAC verification FAILED"
        """
        with self._lock:
            msgs = self._capture.get(msg_name, [])
            if not msgs:
                self._logger.log_event(
                    "WARN", self.name,
                    f"No captured {msg_name} messages available for tampering",
                )
                return False
            target = msgs[-1].clone()   # take most recent

        # Modify the payload (if not specified, flip all bits in first byte)
        original_payload = target.payload
        if new_payload:
            target.payload = new_payload[:len(target.payload)]
        else:
            # Flip bits in the first byte — simulates data manipulation
            ba = bytearray(target.payload)
            ba[0] = ba[0] ^ 0xFF
            target.payload = bytes(ba)

        target.is_tampered = True
        self.tampers_attempted += 1

        self._logger.log_event(
            "TAMPER", self.name,
            f"TAMPER ATTACK → {msg_name} payload changed "
            f"{original_payload.hex()} → {target.payload.hex()} "
            f"(HMAC still references original)",
            target,
        )
        self._bus.inject(target, injector_name=self.name)
        return True

    # ── Attack 3: Injection ───────────────────────────────────────────────────

    def inject_attack(
        self,
        msg_id:  int   = None,
        payload: bytes = None,
    ) -> bool:
        """
        Fabricate a completely new message and inject it onto the bus.
        The message has no valid HMAC (attacker does not know the key).
        
        Why dangerous:
          In insecure mode this allows arbitrary ECU impersonation.
          Example: inject BRAKE_STATUS=0xFF to trigger false ABS activation,
          or inject ENGINE_RPM=9999 to trigger false over-rev protection.
        
        How we detect it (secure mode):
          • hmac_tag = b'\\x00'*8 does not match computed HMAC → REJECTED
        """
        if msg_id is None:
            msg_id = random.choice([
                MSG_ID["BRAKE_PRESS"],
                MSG_ID["ENGINE_RPM"],
                MSG_ID["BRAKE_STATUS"],
            ])

        if payload is None:
            # Choose a dangerously wrong value
            if msg_id == MSG_ID["BRAKE_PRESS"]:
                payload = encode_brake_pressure(0.0)   # no braking!
                desc    = "brake_pressure=0.0 bar (DISABLE BRAKES)"
            elif msg_id == MSG_ID["ENGINE_RPM"]:
                payload = encode_rpm(9999)
                desc    = "rpm=9999 (FALSE OVER-REV)"
            elif msg_id == MSG_ID["BRAKE_STATUS"]:
                payload = encode_status(0xFF)
                desc    = "brake_status=0xFF (FAKE FAULT)"
            else:
                payload = os.urandom(2)
                desc    = "random payload"
        else:
            desc = f"payload={payload.hex()}"

        fake_msg = CANMessage(
            msg_id=msg_id,
            payload=payload,
            nonce=random.randint(0, 2**32 - 1),   # random nonce, no valid MAC
        )
        fake_msg.hmac_tag = b"\x00" * 8  # no valid HMAC

        self.injections_attempted += 1

        self._logger.log_event(
            "INJECT", self.name,
            f"INJECTION ATTACK → fabricated {fake_msg.msg_name}: {desc}",
            fake_msg,
        )
        self._bus.inject(fake_msg, injector_name=self.name)
        return True

    # ── Wait and collect ──────────────────────────────────────────────────────

    def wait_for_capture(self, count: int = 5, timeout: float = 10.0) -> bool:
        """Block until at least `count` messages have been captured."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.captured_count() >= count:
                return True
            time.sleep(0.05)
        return False

    def summary(self) -> Dict[str, int]:
        return {
            "captured":   self.captured_count(),
            "replays":    self.replays_attempted,
            "tampers":    self.tampers_attempted,
            "injections": self.injections_attempted,
        }


import os  # needed for os.urandom fallback above
