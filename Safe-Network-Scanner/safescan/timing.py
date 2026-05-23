"""nmap-style timing profiles T0..T5."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class TimingProfile:
    name: str
    timeout: float            # per-probe socket / scapy timeout (s)
    threads: int              # max concurrent workers
    delay: float              # inter-probe delay per worker (s)
    discovery_timeout: float  # ICMP / ARP / TCP-ping timeout (s)


PROFILES: Dict[int, TimingProfile] = {
    0: TimingProfile("paranoid",   5.0,    1, 5.0, 5.0),
    1: TimingProfile("sneaky",     2.0,    5, 1.0, 3.0),
    2: TimingProfile("polite",     1.5,   20, 0.4, 2.0),
    3: TimingProfile("normal",     1.0,  100, 0.0, 1.0),
    4: TimingProfile("aggressive", 0.5,  300, 0.0, 0.5),
    5: TimingProfile("insane",     0.25, 600, 0.0, 0.3),
}


def get(level: int) -> TimingProfile:
    if level not in PROFILES:
        raise ValueError(f"--timing must be 0..5 (got {level})")
    return PROFILES[level]
