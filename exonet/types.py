"""Shared data classes used across the scanner.

EXO NET Pro additions: per-port ``cves`` and ``ssl_info``, per-host
``whois_data``, ``dns_records``, ``subdomains``, ``firewall_info``, and
risk-scoring fields. All new fields have safe defaults so the original
unprivileged scan paths keep working unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PortResult:
    """One TCP/UDP port probe result."""
    port: int
    proto: str = "tcp"               # 'tcp' or 'udp'
    state: str = "closed"            # open, closed, filtered, open|filtered
    service: Optional[str] = None    # /etc/services name (best-effort)
    banner: Optional[str] = None     # protocol-specific banner / version string
    details: Dict[str, str] = field(default_factory=dict)  # structured fingerprint data
    latency_ms: Optional[float] = None

    # ---- EXO NET Pro fields -------------------------------------------------
    # CVEs matched for this service/version. Each entry is a small dict, e.g.
    # {"id": "CVE-2021-44228", "cvss": 10.0, "summary": "..."}.
    cves: List[Dict[str, Any]] = field(default_factory=list)

    # SSL/TLS findings if we ran an SSL probe against this port.
    # Schema: {"checked": bool, "expired": bool, "self_signed": bool,
    #          "weak_protocols": [str], "weak_ciphers": [str], "subject": str,
    #          "issuer": str, "not_after": str, "days_remaining": int,
    #          "error": str|None}
    ssl_info: Optional[Dict[str, Any]] = None

    # True when our heuristic version comparison flagged this banner as old.
    outdated: bool = False


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

    # ---- EXO NET Pro fields -------------------------------------------------
    # Raw WHOIS dict (registrar, dates, country, etc.) - shape depends on
    # whether we used python-whois or the system `whois` binary.
    whois_data: Optional[Dict[str, Any]] = None

    # DNS records keyed by type, e.g. {"A": ["1.2.3.4"], "MX": [...]}.
    dns_records: Dict[str, List[str]] = field(default_factory=dict)

    # Hostnames found by the wordlist subdomain scanner.
    subdomains: List[str] = field(default_factory=list)

    # Firewall detection summary.
    # Schema: {"detected": bool, "confidence": "low|medium|high",
    #          "filtered_count": int, "closed_count": int, "open_count": int,
    #          "ttl_anomaly": bool, "notes": [str]}
    firewall_info: Optional[Dict[str, Any]] = None

    # Risk scoring output.
    risk_score: Optional[int] = None        # 0..100
    risk_level: Optional[str] = None        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    risk_factors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state.startswith("open")]
