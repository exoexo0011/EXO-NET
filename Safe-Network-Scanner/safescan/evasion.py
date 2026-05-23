"""Evasion policy: random inter-probe jitter and random source ports.

Mirrors what nmap calls ``--scan-delay`` (with jitter) plus ``--source-port``.
Both knobs are stealth aids; neither bypasses authentication or any other
control. They are useful in environments where IDS rate-thresholds are tuned
for predictable scan patterns.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class EvasionPolicy:
    enabled: bool = False
    jitter_max_s: float = 0.0       # extra random sleep, 0..jitter_max_s, per probe
    randomize_sport: bool = False   # bind connections to a random source port

    def jitter(self) -> None:
        """Sleep a random fraction of `jitter_max_s` if jitter is enabled."""
        if self.enabled and self.jitter_max_s > 0:
            time.sleep(random.uniform(0.0, self.jitter_max_s))

    def random_sport(self) -> Optional[int]:
        """Return a random ephemeral source port, or None if disabled."""
        if not self.enabled or not self.randomize_sport:
            return None
        return random.randint(1024, 65535)


def from_args(enabled: bool, jitter_max_s: float = 0.5) -> EvasionPolicy:
    """Build a policy from CLI args. Defaults are intentionally mild."""
    if not enabled:
        return EvasionPolicy()
    return EvasionPolicy(
        enabled=True,
        jitter_max_s=max(0.0, jitter_max_s),
        randomize_sport=True,
    )
