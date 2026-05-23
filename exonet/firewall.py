"""Firewall / packet-filter detection (EXO NET Pro).

Heuristic, non-invasive checks that look at the *patterns* in our existing
port-scan results plus an optional TTL probe. We never send extra traffic
beyond what the user already authorized via the normal scan flow.

Public surface:
    classify_state(state)             -> 'open'|'filtered'|'closed'|'unknown'
    detect(host)                      -> Dict (also stored on host.firewall_info)
    expected_ttl(observed)            -> int or None  (initial-TTL bucket)
    ttl_anomaly(host)                 -> bool
    proper_state(p, host_alive)       -> str  (refines 'closed' vs 'filtered')

The result dict has this shape::

    {
        "detected": bool,
        "confidence": "low" | "medium" | "high",
        "filtered_count": int,
        "closed_count": int,
        "open_count": int,
        "ttl_anomaly": bool,
        "notes": [str, ...],
    }

Decision rules (calibrated to be conservative):
- 0 filtered + sane TTL -> no firewall (most home networks).
- A few filtered ports OR all 'open|filtered' on UDP -> low confidence FW.
- Mostly filtered + mixed open/closed -> medium confidence FW.
- 'No response on most TCP ports' + alive host -> high confidence FW.
- Anomalous TTL (e.g. observed 247 vs expected 255) bumps confidence.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .types import HostResult, PortResult


# ---- state classification ---------------------------------------------------

# Common initial TTLs by OS family. Hops between us and the target
# typically subtract <30 from these, so we bucket by "what was the
# nearest plausible starting TTL".
_TTL_BUCKETS = (32, 64, 128, 255)


def classify_state(state: str) -> str:
    """Reduce a raw port state to one of: open / filtered / closed / unknown."""
    if not state:
        return "unknown"
    s = state.lower()
    if s == "open":
        return "open"
    if s.startswith("open|"):
        # 'open|filtered' is UDP's "didn't get an ICMP unreachable" state -
        # treat as filtered for counting purposes.
        return "filtered"
    if "filtered" in s:
        return "filtered"
    if s == "closed":
        return "closed"
    return "unknown"


def proper_state(p: PortResult, host_alive: bool) -> str:
    """Refine ``p.state`` using firewall-aware rules.

    - A 'closed' result on a host we never proved alive is really 'unknown'.
    - 'open|filtered' on UDP keeps its label (kernel didn't speak up).
    - Everything else is returned unchanged.
    """
    if not host_alive and p.state == "closed":
        return "unknown"
    return p.state


# ---- TTL fingerprinting -----------------------------------------------------

def expected_ttl(observed: Optional[int]) -> Optional[int]:
    """Return the closest plausible *initial* TTL for ``observed``.

    Example: TTL 56 -> 64 bucket. None if we have nothing to work with.
    """
    if observed is None or observed <= 0:
        return None
    return min(_TTL_BUCKETS, key=lambda t: abs(t - observed) if t >= observed else 1000)


def ttl_anomaly(host: HostResult) -> bool:
    """True when the observed TTL doesn't fit any normal initial-TTL bucket.

    Firewalls / NAT boxes sometimes rewrite TTLs to obscure topology. We
    treat *anything more than 30 hops away from the nearest standard
    bucket* as suspicious.
    """
    if not host.ttl:
        return False
    bucket = expected_ttl(host.ttl)
    if bucket is None:
        return False
    # Anything >30 hops away from the bucket is unusual on the public
    # internet, never mind a LAN. Treat as anomalous.
    return abs(bucket - host.ttl) > 30


# ---- main detection ---------------------------------------------------------

def detect(host: HostResult) -> Dict[str, Any]:
    """Compute the firewall summary for ``host`` and stash it on the host."""
    counts = {"open": 0, "filtered": 0, "closed": 0, "unknown": 0}
    for p in host.ports:
        counts[classify_state(p.state)] += 1

    total = sum(counts.values())
    notes: List[str] = []

    # Default = no firewall, low confidence (we always emit *some* signal).
    detected = False
    confidence = "low"

    if total == 0:
        notes.append("No ports were scanned for this host")
    else:
        f, c, o = counts["filtered"], counts["closed"], counts["open"]
        if f == 0 and c > 0:
            # Plenty of clean rejects -> stack speaking, no upstream filter.
            notes.append("All non-open ports returned RST (no upstream filter)")
        elif f > 0 and c > 0:
            detected = True
            ratio = f / (f + c) if (f + c) else 0.0
            if ratio >= 0.66:
                confidence = "high"
                notes.append(f"{ratio:.0%} of probed ports were filtered "
                             f"(no response) - looks like a stateful filter")
            else:
                confidence = "medium"
                notes.append(f"Mixed RST + drop pattern ({f}/{f+c} filtered)")
        elif f > 0 and c == 0 and o == 0:
            detected = True
            confidence = "high"
            notes.append("All probed ports silently dropped - default-deny "
                         "firewall likely")
        elif f > 0 and o > 0 and c == 0:
            detected = True
            confidence = "medium"
            notes.append("Open ports allowed, others dropped - selective "
                         "firewall policy")

    anomaly = ttl_anomaly(host)
    if anomaly:
        notes.append(f"Anomalous TTL {host.ttl} (closest bucket "
                     f"{expected_ttl(host.ttl)}); probable middle-box rewrite")
        # Bump confidence one level when we also see an unusual TTL.
        if confidence == "low":
            confidence = "medium"
        elif confidence == "medium":
            confidence = "high"
        detected = True

    summary: Dict[str, Any] = {
        "detected": detected,
        "confidence": confidence,
        "filtered_count": counts["filtered"],
        "closed_count": counts["closed"],
        "open_count": counts["open"],
        "unknown_count": counts["unknown"],
        "ttl_anomaly": anomaly,
        "notes": notes,
    }
    host.firewall_info = summary
    return summary
