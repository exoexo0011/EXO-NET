"""HTML and CSV report writers (EXO NET themed).

JSON exports go through :func:`exonet.output.render_json`. This module
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


# ---- HTML (EXO NET theme) ---------------------------------------------------
_HTML_FONT_LINK = (
    "<link rel='preconnect' href='https://fonts.googleapis.com'>"
    "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>"
    "<link href='https://fonts.googleapis.com/css2?family=Share+Tech+Mono"
    "&display=swap' rel='stylesheet'>"
)

_HTML_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  font-family: 'Share Tech Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
  background: #000;
  color: #00ff41;
  text-shadow: 0 0 8px #00ff41;
  padding: 24px;
  line-height: 1.5;
  margin: 0;
}
h1 {
  color: #00cfff;
  text-shadow: 0 0 8px #00cfff;
  margin: 0 0 6px 0;
  letter-spacing: 2px;
  font-weight: normal;
}
h2 {
  color: #00cfff;
  text-shadow: 0 0 8px #00cfff;
  margin-top: 32px;
  border-bottom: 1px solid #ff003c44;
  padding-bottom: 6px;
  letter-spacing: 1px;
  font-weight: normal;
}
.tag {
  color: #00ff41;
  text-shadow: 0 0 8px #00ff41;
  letter-spacing: 1px;
}
.meta {
  color: #00cfff;
  text-shadow: none;
  font-size: 0.92em;
  margin: 4px 0 10px;
}
.meta b { color: #00ff41; text-shadow: 0 0 8px #00ff41; }
.stats {
  margin: 8px 0 12px;
  font-size: 0.95em;
  letter-spacing: 1px;
}
.stats .pill {
  display: inline-block;
  padding: 2px 10px;
  margin-right: 8px;
  border: 1px solid #1a1a1a;
  background: #0d0d0d;
}
.stats .pill.open    { color: #00ff41; text-shadow: 0 0 8px #00ff41; font-weight: bold; }
.stats .pill.openf   { color: #ffe600; text-shadow: 0 0 8px #ffe600; }
.stats .pill.closed  { color: #ff003c; text-shadow: 0 0 8px #ff003c; }
table {
  border-collapse: collapse;
  margin-top: 6px;
  min-width: 60%;
  background: #000;
}
th, td {
  padding: 6px 12px;
  border: 1px solid #1a1a1a;
  text-align: left;
  vertical-align: top;
}
th {
  background: #0d0d0d;
  color: #00cfff;
  text-shadow: 0 0 8px #00cfff;
  font-weight: bold;
  letter-spacing: 1px;
}
td { color: #00ff41; }
.open    { color: #00ff41; text-shadow: 0 0 8px #00ff41; font-weight: bold; }
.openf   { color: #ffe600; text-shadow: 0 0 8px #ffe600; }
.closed  { color: #ff003c; text-shadow: 0 0 8px #ff003c; }
.muted   { color: #4d6650; text-shadow: none; }
.warn-box {
  background: #0d0000;
  color: #ff003c;
  text-shadow: 0 0 8px #ff003c;
  padding: 12px 16px;
  border-left: 3px solid #ff003c;
  margin: 14px 0 22px;
  letter-spacing: 1px;
}
.details {
  color: #00cfff;
  text-shadow: none;
  font-size: 0.9em;
}
a { color: #00cfff; }
"""


def _state_class(state: str) -> str:
    if state == "open":
        return "open"
    if state.startswith("open"):
        return "openf"
    return "closed"


def _state_bucket(state: str) -> str:
    """Bucket a port state into one of: open, filtered, closed."""
    if state == "open":
        return "open"
    if state.startswith("open"):
        # 'open|filtered' -> filtered bucket (UDP best-effort)
        return "filtered"
    if "filtered" in state:
        return "filtered"
    return "closed"


def _details_html(details: dict) -> str:
    if not details:
        return "<span class='muted'>-</span>"
    return "<br>".join(
        f"<span class='details'>{html_lib.escape(k)}: {html_lib.escape(str(v))}</span>"
        for k, v in details.items()
    )


def _stats_row_html(host: HostResult) -> str:
    """Render an open / filtered / closed counts pill row for a host."""
    counts = {"open": 0, "filtered": 0, "closed": 0}
    for p in host.ports:
        counts[_state_bucket(p.state)] += 1
    return (
        "<div class='stats'>"
        f"<span class='pill open'>open: {counts['open']}</span>"
        f"<span class='pill openf'>filtered: {counts['filtered']}</span>"
        f"<span class='pill closed'>closed: {counts['closed']}</span>"
        "</div>"
    )


def write_html(hosts: List[HostResult], dest: Path, generated_at: str,
               target: str = "") -> None:
    parts: list[str] = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    parts.append("<title>EXO NET &mdash; Reconnaissance Report</title>")
    parts.append(_HTML_FONT_LINK)
    parts.append(f"<style>{_HTML_CSS}</style></head><body>")

    parts.append("<h1>EXO NET &mdash; Reconnaissance Report</h1>")
    parts.append(
        "<div class='tag'>[ Advanced Network Reconnaissance ]</div>"
    )
    parts.append(
        f"<p class='meta'>Generated {html_lib.escape(generated_at)} &middot; "
        f"target {html_lib.escape(target)} &middot; "
        f"{len(hosts)} host(s) reported.</p>"
    )
    parts.append(
        "<div class='warn-box'>// Educational use only. Only scan networks "
        "you own or have explicit written permission to scan.</div>"
    )

    if not hosts:
        parts.append("<p class='muted'>No live hosts to report.</p>")
        parts.append("</body></html>")
        dest.write_text("".join(parts), encoding="utf-8")
        return

    for h in hosts:
        parts.append(f"<h2>&gt; {html_lib.escape(h.ip)}</h2>")

        meta_bits = []
        if h.hostname:        meta_bits.append(f"hostname=<b>{html_lib.escape(h.hostname)}</b>")
        if h.mac:             meta_bits.append(f"mac={html_lib.escape(h.mac)}")
        if h.vendor:          meta_bits.append(f"vendor={html_lib.escape(h.vendor)}")
        if h.ttl:             meta_bits.append(f"ttl={h.ttl}")
        if h.os_guess:        meta_bits.append(f"os={html_lib.escape(h.os_guess)}")
        if h.discovered_via:  meta_bits.append("via=" + html_lib.escape(",".join(h.discovered_via)))
        if meta_bits:
            parts.append("<p class='meta'>" + " &middot; ".join(meta_bits) + "</p>")

        # Per-host stats row (open / filtered / closed)
        parts.append(_stats_row_html(h))

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
