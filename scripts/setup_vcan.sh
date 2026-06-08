#!/usr/bin/env bash
# Create a Linux virtual-CAN interface (vcan0) for testing without hardware.
# Usage:  sudo scripts/setup_vcan.sh [iface]
# Then:   candump vcan0      (watch)   /   cansend vcan0 000#DEADBEEF   (inject)
set -euo pipefail

IFACE="${1:-vcan0}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "SocketCAN/vcan is Linux-only. On macOS/Windows use the python-can"
  echo "'virtual' interface instead:  python examples/run_on_vcan.py --interface virtual"
  exit 1
fi

modprobe vcan
if ! ip link show "$IFACE" >/dev/null 2>&1; then
  ip link add dev "$IFACE" type vcan
fi
ip link set up "$IFACE"
echo "Interface '$IFACE' is up. Watch it with:  candump $IFACE"
