"""
ISO-TP (ISO 15765-2) transport-layer segmentation.

A classic CAN frame carries at most 8 data bytes, but a UDS message can be far
larger (e.g. a firmware block).  ISO-TP segments a message across multiple CAN
frames using a one-nibble Protocol Control Information (PCI) tag in the first
byte(s):

    Single Frame (SF)      0x0L           up to 7 bytes in one frame
    First Frame  (FF)      0x1LLL ...      starts a multi-frame message (len up to 4095)
    Consecutive  (CF)      0x2N ...        carries the remaining bytes, N = sequence
    Flow Control (FC)      0x3S BS STmin   receiver → sender pacing

This module implements the segmentation/reassembly that matters for the security
demonstrations.  Following a valid configuration, the receiver advertises Block
Size = 0 and STmin = 0 in its Flow Control frame (send everything, no inter-frame
delay), so no per-block FC round-trips are needed after the first; the transport
layer in :mod:`carsec.uds.transport` performs that single FF→FC→CF* handshake.
"""

from __future__ import annotations

# PCI type nibbles (high nibble of the first byte).
SF = 0x0
FF = 0x1
CF = 0x2
FC = 0x3

# Flow Control flow-status values.
FC_CTS = 0x0  # Clear To Send
FC_WAIT = 0x1
FC_OVFL = 0x2

MAX_SF_LEN = 7
MAX_MESSAGE_LEN = 0xFFF  # 4095, classic ISO-TP 12-bit length


class IsoTpError(Exception):
    """Malformed ISO-TP frame sequence."""


def segment(payload: bytes) -> list[bytes]:
    """
    Split a UDS message into a list of ISO-TP CAN data fields (each ≤ 8 bytes).

    Returns a single Single Frame for short messages, or a First Frame followed
    by Consecutive Frames for longer ones.
    """
    n = len(payload)
    if n > MAX_MESSAGE_LEN:
        raise IsoTpError(f"message too long for ISO-TP: {n} > {MAX_MESSAGE_LEN}")

    if n <= MAX_SF_LEN:
        return [bytes([(SF << 4) | n]) + payload]

    frames: list[bytes] = []
    # First Frame: 0x1L LL  + first 6 data bytes.
    first = bytes([(FF << 4) | ((n >> 8) & 0x0F), n & 0xFF]) + payload[:6]
    frames.append(first)

    rest = payload[6:]
    seq = 1
    for i in range(0, len(rest), 7):
        chunk = rest[i : i + 7]
        frames.append(bytes([(CF << 4) | (seq & 0x0F)]) + chunk)
        seq = (seq + 1) & 0x0F
    return frames


def flow_control(flow_status: int = FC_CTS, block_size: int = 0, st_min: int = 0) -> bytes:
    """Build a Flow Control frame data field."""
    return bytes([(FC << 4) | (flow_status & 0x0F), block_size & 0xFF, st_min & 0xFF])


class Reassembler:
    """Streaming reassembly of an ISO-TP message from successive frames."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._expected = 0
        self._seq = 0
        self._active = False

    @property
    def done(self) -> bool:
        return self._active is False and len(self._buf) > 0

    def push(self, frame: bytes) -> bytes | None:
        """
        Feed one frame.  Returns the full message once complete, else ``None``.
        """
        if not frame:
            raise IsoTpError("empty frame")
        pci = frame[0] >> 4

        if pci == SF:
            length = frame[0] & 0x0F
            return bytes(frame[1 : 1 + length])

        if pci == FF:
            self._expected = ((frame[0] & 0x0F) << 8) | frame[1]
            self._buf = bytearray(frame[2:8])
            self._seq = 1
            self._active = True
            return None

        if pci == CF:
            if not self._active:
                raise IsoTpError("consecutive frame without first frame")
            seq = frame[0] & 0x0F
            if seq != (self._seq & 0x0F):
                raise IsoTpError(f"out-of-order CF: got {seq}, want {self._seq & 0x0F}")
            self._seq += 1
            self._buf.extend(frame[1:8])
            if len(self._buf) >= self._expected:
                self._active = False
                return bytes(self._buf[: self._expected])
            return None

        raise IsoTpError(f"unexpected PCI type 0x{pci:X}")


def reassemble(frames: list[bytes]) -> bytes:
    """Convenience: reassemble a complete list of frames into the message."""
    r = Reassembler()
    for f in frames:
        result = r.push(f)
        if result is not None:
            return result
    raise IsoTpError("incomplete ISO-TP frame sequence")
