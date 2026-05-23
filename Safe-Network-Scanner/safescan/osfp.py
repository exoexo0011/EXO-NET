"""Very basic OS fingerprinting.

We use two cheap signals:
  * Initial TTL of an ICMP echo reply. Most OSes default to 64, 128, or 255.
  * (When available) TCP window size from a SYN/ACK reply.

This is intentionally simple. Real OS fingerprinting (nmap -O, p0f) uses
many more features and a large database. The goal here is "Linux vs
Windows vs network gear", not a full fingerprint.
"""

from __future__ import annotations

from typing import Optional


def _round_initial_ttl(observed: int) -> int:
    """Round a received TTL up to the nearest plausible initial value."""
    for initial in (64, 128, 255):
        if observed <= initial:
            return initial
    return 255


def guess_from_ttl(ttl: Optional[int]) -> Optional[str]:
    if ttl is None or ttl <= 0:
        return None
    initial = _round_initial_ttl(ttl)
    if initial == 64:
        return "Linux/Unix/macOS"
    if initial == 128:
        return "Windows"
    if initial == 255:
        return "Network device / legacy Unix"
    return None


def refine_with_window(os_guess: Optional[str], window: Optional[int]) -> Optional[str]:
    """Optionally narrow the guess using the TCP window size."""
    if window is None:
        return os_guess
    # Common defaults observed in the wild:
    #   Linux:    ~5840, 14600, 29200, 64240
    #   Windows:  ~8192, 65535
    #   macOS:    ~65535
    if os_guess is None:
        if window in (5840, 14600, 29200, 64240):
            return "Linux"
        if window in (8192, 65535):
            return "Windows/macOS"
    elif os_guess.startswith("Linux") and window in (8192,):
        return "Windows (TTL spoofed?)"
    return os_guess
