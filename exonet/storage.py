"""Output directory management for ``--save``.

We create one timestamped subdirectory per scan invocation so re-running the
same scanner against the same target never overwrites previous results.
"""

from __future__ import annotations

import time
from pathlib import Path


def make_session_dir(base: str, target: str) -> Path:
    """Create ``<base>/<timestamp>_<target>/`` and return the path."""
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_").replace("\\", "_")
    out = Path(base) / f"{ts}_{safe_target}"
    out.mkdir(parents=True, exist_ok=True)
    return out
