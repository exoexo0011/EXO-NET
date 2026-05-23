"""Reference table of historically common default credentials.

This module is for AWARENESS / AUDIT purposes only. The scanner NEVER
attempts to authenticate with these credentials. If you discover a
service in your OWN environment that still ships with one of these
pairs, rotate the credentials immediately.

Sources: vendor manuals, distro install guides, public-domain default
password compendia. Nothing here is a secret; it's all in the original
product documentation.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

# Maps a service name (matching `PortResult.service` or one of its aliases)
# to a list of well-known (username, password) defaults.
DEFAULTS: Dict[str, List[Tuple[str, str]]] = {
    "ssh": [
        ("root",  "root"),
        ("root",  "toor"),
        ("admin", "admin"),
        ("pi",    "raspberry"),       # Raspberry Pi OS pre-2022
        ("ubnt",  "ubnt"),            # older Ubiquiti gear
    ],
    "ftp": [
        ("anonymous", ""),
        ("ftp",       "ftp"),
        ("admin",     "admin"),
    ],
    "telnet": [
        ("admin", "admin"),
        ("root",  ""),
        ("cisco", "cisco"),
    ],
    "smtp": [
        ("admin", "admin"),
    ],
    "smb":            [("guest",         ""), ("administrator", "")],
    "microsoft-ds":   [("guest",         ""), ("administrator", "")],
    "rdp":            [("administrator", "administrator")],
    "ms-wbt-server":  [("administrator", "administrator")],
    "mysql":          [("root",          ""), ("root",          "root")],
    "postgresql":     [("postgres",      "postgres"), ("postgres", "")],
    "mssql":          [("sa",            ""), ("sa",            "sa")],
    "ms-sql-s":       [("sa",            ""), ("sa",            "sa")],
    "vnc":            [("",              "password")],
    "http":           [("admin",         "admin"), ("admin", "password")],
    "https":          [("admin",         "admin")],
    "webcache":       [("admin",         "admin")],
    "http-proxy":     [("admin",         "admin")],
    "snmp":           [("",              "public"), ("", "private")],
    "redis":          [("",              "")],         # default = no auth
    "mongodb":        [("",              "")],
    "elasticsearch":  [("",              "")],
}


def lookup(service: str) -> List[Tuple[str, str]]:
    """Return defaults for `service`, or [] if none recorded."""
    return DEFAULTS.get((service or "").lower(), [])
