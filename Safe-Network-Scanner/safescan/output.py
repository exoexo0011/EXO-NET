"""Output renderers: colored ASCII table, plain table, and JSON."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from typing import List

from . import ui
from .types import HostResult


# ---- shared helpers ---------------------------------------------------------
def _state_color(state: str) -> str:
    from colorama import Fore  # local import to honor ui's color-disabled fallback
    return {
        "open": Fore.GREEN,
        "open|filtered": Fore.YELLOW,
        "filtered": Fore.YELLOW,
        "closed": Fore.RED,
    }.get(state, "")


def _pad(s: str, n: int) -> str:
    """Pad a string to width `n`, accounting for the fact that ANSI escapes
    don't take screen columns."""
    import re
    visible = re.sub(r"\x1b\[[0-9;]*m", "", s)
    return s + " " * max(0, n - len(visible))


# ---- table renderer ---------------------------------------------------------
def render_table(hosts: List[HostResult]) -> None:
    if not hosts:
        print(ui.c("[!] ", "\x1b[33m") + "No live hosts to report.")
        return

    for host in hosts:
        # ---- per-host header (printed to stdout so the whole table stays together) ----
        header_bits = [ui.c(host.ip, "\x1b[1;36m") if sys.stdout.isatty() else host.ip]
        if host.hostname:
            header_bits.append(f"({host.hostname})")
        if host.mac:
            mac_bit = host.mac
            if host.vendor:
                mac_bit = f"{mac_bit} [{host.vendor}]"
            header_bits.append(f"mac={mac_bit}")
        if host.ttl:
            header_bits.append(f"ttl={host.ttl}")
        if host.os_guess:
            header_bits.append(f"os={host.os_guess}")
        if host.discovered_via:
            header_bits.append("via=" + ",".join(host.discovered_via))

        print()
        print(ui.c("[+] ", "\x1b[32m") + "Host: " + "  ".join(header_bits))

        # ---- port table ----
        if not host.ports:
            print("  (no ports scanned)")
            continue

        open_ports = [p for p in host.ports if p.state.startswith("open")]
        if not open_ports:
            print("  No open ports in the scanned set.")
            continue

        rows = [("PORT", "PROTO", "STATE", "SERVICE", "BANNER")]
        for p in open_ports:
            rows.append((
                str(p.port),
                p.proto,
                p.state,
                p.service or "-",
                p.banner or "-",
            ))

        widths = [max(len(r[i]) for r in rows) for i in range(5)]
        widths = [min(w, 80) for w in widths]  # cap banner width
        for idx, row in enumerate(rows):
            cells = []
            for i, cell in enumerate(row):
                truncated = cell if len(cell) <= widths[i] else cell[:widths[i] - 1] + "."
                if idx == 0:
                    cells.append(_pad(truncated, widths[i]))
                elif i == 2:  # state column gets color
                    color = _state_color(open_ports[idx - 1].state)
                    colored = ui.c(truncated, color) if color else truncated
                    cells.append(_pad(colored, widths[i]))
                else:
                    cells.append(_pad(truncated, widths[i]))
            print("  " + "  ".join(cells))


# ---- JSON renderer ----------------------------------------------------------
def render_json(hosts: List[HostResult]) -> None:
    payload = {
        "version": 1,
        "host_count": len(hosts),
        "hosts": [asdict(h) for h in hosts],
    }
    json.dump(payload, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
