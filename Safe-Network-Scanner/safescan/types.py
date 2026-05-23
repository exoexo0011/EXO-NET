"""Shared data classes used across the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class PortResult:
    """One TCP/UDP port probe result."""
    port: int
    proto: str = "tcp"               # 'tcp' or 'udp'
    state: str = "closed"            # open, closed, filtered, open|filtered
    service: Optional[str] = None    # /etc/services name (best-effort)
    banner: Optional[str] = None     # protocol-specific banner / version string
    latency_ms: Optional[float] = None


@dataclass
class HostResult:
    """All information gathered about a single host."""
    ip: str
    alive: bool = False
    discovered_via: List[str] = field(default_factory=list)  # ["arp", "icmp", "tcp"]
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    ttl: Optional[int] = None
    os_guess: Optional[str] = None
    ports: List[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state.startswith("open")]
