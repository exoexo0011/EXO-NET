#!/usr/bin/env python3
"""EXO NET CLI entry point.

EXO NET is an advanced (educational) network reconnaissance toolkit.
The actual scanner lives in the :mod:`safescan` package next to this file.
Keeping a top-level shim means ``python network_scanner.py ...`` still works
without requiring the package to be installed.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the sibling `safescan/` package importable when this script is run
# directly (e.g. `python network_scanner.py ...`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from safescan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
