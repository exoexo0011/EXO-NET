"""Tiny OUI (MAC vendor) lookup table.

This is a hand-curated subset of common vendors, not a full IEEE OUI dump.
Good enough to label most household / lab / VM MACs without bundling a
multi-megabyte database.
"""

from __future__ import annotations

from typing import Optional


# Keys are lowercase 6-hex-char OUI prefixes (e.g. "001122").
COMMON_OUI = {
    # Virtualization
    "005056": "VMware",
    "000c29": "VMware",
    "001c14": "VMware",
    "080027": "VirtualBox",
    "00155d": "Microsoft Hyper-V",
    "525400": "QEMU/KVM",
    "00163e": "Xen",
    # SBCs
    "b827eb": "Raspberry Pi Foundation",
    "dca632": "Raspberry Pi Trading",
    "e45f01": "Raspberry Pi Trading",
    "28cdc1": "Raspberry Pi Trading",
    "d83add": "Raspberry Pi Trading",
    # Apple
    "f01898": "Apple",
    "acde48": "Apple",
    "88665a": "Apple",
    "3c22fb": "Apple",
    "f45c89": "Apple",
    "a45e60": "Apple",
    "002500": "Apple",
    "f81edf": "Apple",
    # Intel / Dell / HP
    "001b21": "Intel",
    "8c1645": "Intel",
    "a0369f": "Intel",
    "001422": "Dell",
    "0024e8": "Dell",
    "f8b156": "Dell",
    "0023ae": "Dell",
    "ecf4bb": "Dell",
    "0050b6": "Hewlett-Packard",
    "0025b3": "Hewlett-Packard",
    "001f29": "Hewlett-Packard",
    # Networking
    "001cc0": "Cisco",
    "001b0d": "Cisco",
    "0024f7": "Cisco",
    "fcecda": "Ubiquiti",
    "245a4c": "Ubiquiti",
    "00095b": "Netgear",
    "20e52a": "Netgear",
    "94103e": "Belkin",
    "001d7e": "Cisco-Linksys",
    # NAS / IoT
    "001132": "Synology",
    "001a11": "Google",
    "f4f5d8": "Google",
    "3c5ab4": "Google",
    "ec71db": "Amazon Tech",
    "fc65de": "Amazon",
    "44650d": "Amazon",
    "b0fc0d": "Amazon",
    "ac63be": "Amazon",
    "f0272d": "Amazon",
    "78e103": "Samsung",
    "002399": "Samsung",
    "5c0a5b": "Samsung",
    "f025b7": "Samsung",
}


def _normalize(mac: str) -> str:
    """Strip separators and lowercase. Returns '' if input looks bad."""
    if not mac:
        return ""
    cleaned = mac.lower().replace(":", "").replace("-", "").replace(".", "")
    return cleaned if len(cleaned) >= 6 and all(ch in "0123456789abcdef" for ch in cleaned) else ""


def lookup(mac: str, extra: Optional[dict] = None) -> Optional[str]:
    """Return a human-readable vendor for `mac`, or None if unknown.

    `extra` is an optional supplementary OUI map (e.g. loaded from a file via
    :func:`load_from_file`). It takes precedence over the bundled table.
    """
    n = _normalize(mac)
    if not n:
        return None
    prefix = n[:6]
    if extra and prefix in extra:
        return extra[prefix]
    return COMMON_OUI.get(prefix)


def load_from_file(path: str) -> dict:
    """Load an OUI map from a file. Returns ``{6-hex-prefix: vendor}``.

    Supports several common formats (mixed in the same file is fine):
      * ``AABBCC<whitespace>Vendor name``      (Wireshark ``manuf``)
      * ``AA:BB:CC<whitespace>Vendor name``
      * ``AA-BB-CC<whitespace>Vendor name``    (IEEE oui.txt)
      * ``aabbcc,Vendor name``                  (CSV-ish)
    Lines starting with ``#`` are treated as comments. Unrecognized lines are
    silently ignored.
    """
    out: dict = {}
    try:
        f = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return out
    with f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            # split on whitespace OR comma; first field is the OUI candidate
            if "," in line and "\t" not in line:
                parts = [p.strip() for p in line.split(",", 1)]
            else:
                parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            prefix = _normalize(parts[0])
            if len(prefix) >= 6:
                out[prefix[:6]] = parts[1].strip()
    return out
