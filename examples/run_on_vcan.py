#!/usr/bin/env python3
"""
Run the simulation on a real (or virtual) CAN interface via python-can.

The simulated ECUs transmit SecOC-protected frames that are mirrored onto the
bus, and any frame arriving from the bus is injected back into the simulation —
so external tools see and can interact with the traffic.

Examples
--------
Cross-platform (works on macOS/Windows/Linux, no kernel module needed)::

    pip install "carsec[hardware]"
    python examples/run_on_vcan.py --interface virtual

On Linux against a real virtual-CAN device, in another terminal run
``candump vcan0`` to watch, or ``cansend vcan0 000#DEADBEEF`` to inject::

    sudo scripts/setup_vcan.sh            # one-time: create vcan0
    python examples/run_on_vcan.py --interface socketcan --channel vcan0

Requires the ``hardware`` extra.  SocketCAN is Linux-only; ``virtual`` is not.
"""

from __future__ import annotations

import argparse
import time

from carsec.can.dbc import DbcDatabase
from carsec.can.socketcan import SocketCANBus
from carsec.scenarios.runner import SimulationRunner
from carsec.telemetry.logger import EventLogger


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--interface", default="virtual", help="python-can interface (virtual|socketcan)")
    ap.add_argument("--channel", default="vcan0", help="CAN channel name")
    ap.add_argument("--seconds", type=float, default=3.0, help="run duration")
    args = ap.parse_args()

    logger = EventLogger(prefix="vcan", console=True, verbose=True)
    bus = SocketCANBus(channel=args.channel, interface=args.interface, logger=logger)
    dbc = DbcDatabase()

    # Decode every frame seen on the wire into named signals.
    def decode_tap(msg):
        signals = dbc.decode(msg)
        if signals:
            print(f"    [dbc] {msg.name:14} {signals}")

    bus.add_tap(decode_tap)

    runner = SimulationRunner(secure=True, bus=bus, logger=logger)
    print(f"Running on interface={args.interface} channel={args.channel} for {args.seconds}s ...")
    runner.start()
    time.sleep(args.seconds)
    runner.stop()
    bus.close()
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
