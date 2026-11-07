"""Launcher: ``python3 -I civ4dbg.py <command> ...`` (works under isolated mode).

``-I`` drops the working directory and ``PYTHONPATH`` from ``sys.path``, so this
trusted launcher adds the directory it lives in, then runs the package.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from civ4dbg.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
