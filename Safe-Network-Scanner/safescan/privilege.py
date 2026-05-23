"""Privilege detection and Scapy capability probes.

Scapy can be *imported* on Windows even without Npcap, but raw L3/L2 socket
operations will then fail at runtime. We probe up-front so we can transparently
fall back to stdlib (subprocess ping / TCP connect) instead of crashing
mid-scan with cryptic errors.
"""

from __future__ import annotations

import logging
import os
import platform
from typing import Optional

# Suppress Scapy's import-time banner / runtime warnings.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import conf as _scapy_conf  # type: ignore
    _scapy_conf.verb = 0
    SCAPY_INSTALLED = True
except Exception:  # pragma: no cover
    SCAPY_INSTALLED = False


# Cached probe results so we only pay the cost once per process.
_l3_usable: Optional[bool] = None
_l2_usable: Optional[bool] = None


def is_admin() -> bool:
    """True if we have privileges to send raw packets."""
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def scapy_l3_usable() -> bool:
    """True if Scapy can open a raw L3 socket (sr1 will work)."""
    global _l3_usable
    if _l3_usable is not None:
        return _l3_usable
    if not SCAPY_INSTALLED or not is_admin():
        _l3_usable = False
        return False
    try:
        sock = _scapy_conf.L3socket()
        try:
            sock.close()
        except Exception:
            pass
        _l3_usable = True
    except Exception:
        # Most common failure mode on Windows: Npcap not installed.
        _l3_usable = False
    return _l3_usable


def scapy_l2_usable() -> bool:
    """True if Scapy can do L2 (ARP) operations."""
    global _l2_usable
    if _l2_usable is not None:
        return _l2_usable
    if not SCAPY_INSTALLED or not is_admin():
        _l2_usable = False
        return False
    try:
        sock = _scapy_conf.L2socket()
        try:
            sock.close()
        except Exception:
            pass
        _l2_usable = True
    except Exception:
        _l2_usable = False
    return _l2_usable


def describe_capabilities() -> str:
    """One-line summary of what we can do, useful for the startup info line."""
    parts = []
    parts.append("admin" if is_admin() else "unprivileged")
    parts.append("scapy-L3:on" if scapy_l3_usable() else "scapy-L3:off")
    parts.append("scapy-L2:on" if scapy_l2_usable() else "scapy-L2:off")
    return " ".join(parts)
