"""HTML and CSV report writers.

JSON exports go through :func:`safescan.output.render_json`. This module
focuses on file-based, human-friendly tabular formats.
"""

from __future__ import annotations

import csv
import html as html_lib
import json
from dataclasses import asdict
from pathlib import Path
from typing import List

from .types import HostResult


# ---- CSV --------------------------------------------------------------------
def write_csv(hosts: List[HostResult], dest: Path) -> None:
    """One row per (host, port). Hosts with no scanned ports get a single row."""
    with dest.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ip", "hostname", "mac", "vendor", "ttl", "os_guess",
            "discovered_via", "port", "proto", "state", "service",
            "banner", "details", "latency_ms",
        ])
        for h in hosts:
            if not h.ports:
                writer.writerow([
                    h.ip, h.hostname or "", h.mac or "", h.vendor or "",
                    h.ttl or "", h.os_guess or "",
                    ",".join(h.discovered_via),
                    "", "", "", "", "", "", "",
                ])
                continue
            for p in h.ports:
                detail_str = "; ".join(f"{k}={v}" for k, v in (p.details or {}).items())
                writer.writerow([
                    h.ip, h.hostname or "", h.mac or "", h.vendor or "",
                    h.ttl or "", h.os_guess or "",
                    ",".join(h.discovered_via),
                    p.port, p.proto, p.state, p.service or "",
                    p.banner or "", detail_str, p.latency_ms or "",
                ])


# ---- JSON (file) -----------------------------------------------------------
def write_json(hosts: List[HostResult], dest: Path) -> None:
    payload = {
        "version": 1,
        "host_count": len(hosts),
        "hosts": [asdict(h) for h in hosts],
    }
    dest.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


# ---- HTML -------------------------------------------------------------------
_HTML_CSS = """
:root { color-scheme: dark; }
body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
       background: #0e0f12; color: #e6e8eb; padding: 18px; line-height: 1.4; }
h1   { color: #6ddcff; margin: 0 0 8px 0; }
h2   { color: #a8e890; margin-top: 28px; border-bottom: 1px solid #303339;
       padding-bottom: 4px; }
.meta { color: #9aa0a6; font-size: 0.92em; margin: 4px 0 10px; }
table { border-collapse: collapse; margin-top: 6px; min-width: 60%; }
th, td { padding: 5px 12px; border: 1px solid #303339; text-align: left;
         vertical-align: top; }
th { background: #1a1c20; color: #6ddcff; font-weight: 600; }
.open    { color: #a8e890; font-weight: 600; }
.openf   { color: #f0c674; }
.closed  { color: #cc6666; }
.muted   { color: #888; }
.warn-box { background: #2a1d12; color: #f0c674; padding: 10px 14px;
            border-left: 3px solid #f0c674; margin: 10px 0 18px; }
.details { color: #9aa0a6; font-size: 0.9em; }
"""


def _state_class(state: str) -> str:
    if state == "open":
        return "open"
    if state.startswith("open"):
        return "openf"
    return "closed"


def _details_html(details: dict) -> str:
    if not details:
        return "<span class='muted'>-</span>"
    return "<br>".join(
        f"<span class='details'>{html_lib.escape(k)}: {html_lib.escape(str(v))}</span>"
        for k, v in details.items()
    )


def write_html(hosts: List[HostResult], dest: Path, generated_at: str,
               target: str = "") -> None:
    parts: list[str] = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    parts.append("<title>Safe-Network-Scanner Report</title>")
    parts.append(f"<style>{_HTML_CSS}</style></head><body>")

    parts.append("<h1>Safe-Network-Scanner Report</h1>")
    parts.append(
        f"<p class='meta'>Generated {html_lib.escape(generated_at)} - "
        f"target {html_lib.escape(target)} - "
        f"{len(hosts)} host(s) reported.</p>"
    )
    parts.append(
        "<div class='warn-box'>Educational use only. Use only on networks "
        "you own or have explicit written permission to scan.</div>"
    )

    if not hosts:
        parts.append("<p class='muted'>No live hosts to report.</p>")
        parts.append("</body></html>")
        dest.write_text("".join(parts), encoding="utf-8")
        return

    for h in hosts:
        parts.append(f"<h2>{html_lib.escape(h.ip)}</h2>")

        meta_bits = []
        if h.hostname:        meta_bits.append(f"hostname=<b>{html_lib.escape(h.hostname)}</b>")
        if h.mac:             meta_bits.append(f"mac={html_lib.escape(h.mac)}")
        if h.vendor:          meta_bits.append(f"vendor={html_lib.escape(h.vendor)}")
        if h.ttl:             meta_bits.append(f"ttl={h.ttl}")
        if h.os_guess:        meta_bits.append(f"os={html_lib.escape(h.os_guess)}")
        if h.discovered_via:  meta_bits.append("via=" + html_lib.escape(",".join(h.discovered_via)))
        if meta_bits:
            parts.append("<p class='meta'>" + " &middot; ".join(meta_bits) + "</p>")

        if not h.ports:
            parts.append("<p class='muted'>No ports scanned.</p>")
            continue

        parts.append("<table><thead><tr>"
                     "<th>port</th><th>proto</th><th>state</th>"
                     "<th>service</th><th>banner</th>"
                     "<th>details</th><th>ms</th>"
                     "</tr></thead><tbody>")
        for p in h.ports:
            cls = _state_class(p.state)
            parts.append(
                "<tr>"
                f"<td>{p.port}</td>"
                f"<td>{html_lib.escape(p.proto)}</td>"
                f"<td class='{cls}'>{html_lib.escape(p.state)}</td>"
                f"<td>{html_lib.escape(p.service or '')}</td>"
                f"<td>{html_lib.escape(p.banner or '')}</td>"
                f"<td>{_details_html(p.details or {})}</td>"
                f"<td>{p.latency_ms if p.latency_ms is not None else ''}</td>"
                "</tr>"
            )
        parts.append("</tbody></table>")

    parts.append("</body></html>")
    dest.write_text("".join(parts), encoding="utf-8")
