"""Public-IP safety guard.

We refuse to scan anything outside RFC1918 / loopback / link-local unless the
user explicitly opts in with ``--allow-public``. This is a guardrail against
accidentally scanning the open internet from a misconfigured target.
"""

from __future__ import annotations

import ipaddress
import sys

from . import ui


def is_private(network: ipaddress.IPv4Network) -> bool:
    return network.is_private or network.is_loopback or network.is_link_local


def enforce(network: ipaddress.IPv4Network, allow_public: bool) -> None:
    """Exit if `network` is public and the user did not pass --allow-public."""
    if is_private(network):
        return
    if not allow_public:
        ui.bad(f"Refusing to scan non-private range {network}.")
        ui.bad("Pass --allow-public to override (only on networks you own).")
        sys.exit(2)
    ui.warn(f"Scanning PUBLIC range {network} because --allow-public was given.")
    ui.warn("Make sure you have explicit written permission for this target.\n")
