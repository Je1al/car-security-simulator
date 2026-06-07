#!/usr/bin/env python3
"""
Convenience launcher so the simulator runs from a fresh checkout without an
install step:

    python main.py                 # interactive menu
    python main.py -s all          # full demo
    python main.py -s replay-secure

The packaged entry points (``carsec`` console script and ``python -m carsec``)
are the preferred way once installed with ``pip install -e .``.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from carsec.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
