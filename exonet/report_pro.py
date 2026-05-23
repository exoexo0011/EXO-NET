"""EXO NET Pro — full pentest-style HTML/PDF report.

Renders an executive-summary-first report with per-host risk badges, CVE
tables, SSL findings, WHOIS / DNS recon, firewall detection, and
prioritized recommendations. Theme is the same cyberpunk palette as the
basic report (black bg, neon green primary, red accent, cyan info).

Optional PDF export via ``weasyprint`` (lazy import, never breaks the
HTML path).

Usage::

    from . import report_pro
    report_pro.write_html(hosts, dest_html, generated_at="...", target="...")
    report_pro.write_pdf(hosts, dest_pdf, generated_at="...", target="...")
"""

from __future__ import annotations

import html as html_lib
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import ui
from .risk import LEVEL_COLOR
from .types import HostResult, PortResult


# -------------------------------------------------------------------------
# Theme
# -------------------------------------------------------------------------

_FONT_LINK = (
    "<link rel='preconnect' href='https://fonts.googleapis.com'>"
    "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>"
    "<link href='https://fonts.googleapis.com/css2?"
    "family=Share+Tech+Mono&family=Orbitron:wght@600;800&display=swap' "
    "rel='stylesheet'>"
)

_CSS = """
:root {
  color-scheme: dark;
  --bg:        #000000;
  --bg-2:      #0a0a0a;
  --bg-3:      #111111;
  --bg-4:      #1a1a1a;
  --neon:      #00ff41;
  --red:       #ff003c;
  --orange:    #ff7700;
  --yellow:    #ffe600;
  --cyan:      #00cfff;
  --muted:     #4d6650;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: var(--bg); }
body {
  font-family: 'Share Tech Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
  color: var(--neon);
  text-shadow: 0 0 8px var(--neon);
  line-height: 1.55;
  padding: 32px;
}

/* ---- Header ---- */
.header { border-bottom: 1px solid var(--red); padding-bottom: 18px; margin-bottom: 22px; }
.header h1 {
  font-family: 'Orbitron', 'Share Tech Mono', monospace;
  color: var(--cyan);
  text-shadow: 0 0 10px var(--cyan);
  font-size: 30px; font-weight: 800; letter-spacing: 4px;
  margin: 0 0 6px 0;
}
.header .tag {
  color: var(--neon); text-shadow: 0 0 8px var(--neon);
  letter-spacing: 1px; font-size: 14px;
}
.header .meta {
  color: var(--cyan); text-shadow: none;
  margin-top: 8px; font-size: 13px;
}
.header .meta b { color: var(--neon); text-shadow: 0 0 8px var(--neon); }

/* ---- Sections ---- */
section { margin: 28px 0; }
section > h2 {
  font-family: 'Orbitron', 'Share Tech Mono', monospace;
  color: var(--cyan); text-shadow: 0 0 10px var(--cyan);
  letter-spacing: 2px; font-weight: 600;
  border-bottom: 1px solid #ff003c44;
  padding-bottom: 6px; margin: 0 0 12px 0;
}
section h3 {
  color: var(--cyan); text-shadow: 0 0 8px var(--cyan);
  letter-spacing: 1px; margin: 18px 0 8px 0;
  font-weight: normal; font-size: 16px;
}
section h4 {
  color: var(--neon); text-shadow: 0 0 6px var(--neon);
  margin: 12px 0 4px 0; font-weight: normal; font-size: 14px;
}

/* ---- Executive summary cards ---- */
.exec-grid {
  display: grid; gap: 12px;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  margin-top: 6px;
}
.card {
  background: var(--bg-2);
  border: 1px solid var(--bg-4);
  padding: 14px 16px;
}
.card .num {
  font-family: 'Orbitron', monospace; font-size: 28px;
  color: var(--neon); text-shadow: 0 0 12px var(--neon);
  display: block;
}
.card .lbl { color: var(--cyan); text-shadow: none; font-size: 12px; letter-spacing: 1px; }
.card.crit .num { color: var(--red); text-shadow: 0 0 12px var(--red); }
.card.high .num { color: var(--orange); text-shadow: 0 0 12px var(--orange); }
.card.med  .num { color: var(--yellow); text-shadow: 0 0 12px var(--yellow); }
.card.low  .num { color: var(--neon); text-shadow: 0 0 12px var(--neon); }
.card.info .num { color: var(--cyan); text-shadow: 0 0 12px var(--cyan); }

/* ---- Risk badges (glow) ---- */
.badge {
  display: inline-block; padding: 4px 12px;
  border: 1px solid currentColor; font-weight: bold;
  letter-spacing: 2px; font-size: 12px;
  text-shadow: 0 0 8px currentColor;
  box-shadow: 0 0 12px currentColor, inset 0 0 6px currentColor;
  border-radius: 1px;
}
.badge.CRITICAL { color: #ff003c; }
.badge.HIGH     { color: #ff7700; }
.badge.MEDIUM   { color: #ffe600; }
.badge.LOW      { color: #00ff41; }
.badge.INFO     { color: #00cfff; }

/* ---- Per-host blocks ---- */
.host {
  background: var(--bg-2);
  border-left: 3px solid var(--red);
  padding: 14px 18px; margin: 14px 0;
}
.host header {
  display: flex; flex-wrap: wrap; align-items: center; gap: 12px;
  border-bottom: 1px dashed #003a14; padding-bottom: 8px; margin-bottom: 8px;
}
.host header .ip {
  font-family: 'Orbitron', monospace; font-size: 18px;
  color: var(--cyan); text-shadow: 0 0 10px var(--cyan);
  letter-spacing: 2px;
}
.host header .score {
  margin-left: auto; font-family: 'Orbitron', monospace;
  color: var(--neon); text-shadow: 0 0 8px var(--neon);
}
.host .meta-line { color: var(--cyan); text-shadow: none; font-size: 12px; }
.host .meta-line b { color: var(--neon); text-shadow: 0 0 6px var(--neon); }

/* ---- Tables ---- */
table { border-collapse: collapse; width: 100%; margin-top: 6px; background: var(--bg); }
th, td { padding: 6px 10px; border: 1px solid var(--bg-4); text-align: left; vertical-align: top; font-size: 12px; }
th {
  background: var(--bg-3);
  color: var(--cyan); text-shadow: 0 0 6px var(--cyan);
  font-weight: bold; letter-spacing: 1px;
}
td { color: var(--neon); }
td.open    { color: var(--neon); text-shadow: 0 0 6px var(--neon); font-weight: bold; }
td.openf   { color: var(--yellow); text-shadow: 0 0 6px var(--yellow); }
td.closed  { color: var(--red); text-shadow: 0 0 6px var(--red); }
.cvss-crit { color: var(--red); text-shadow: 0 0 6px var(--red); font-weight: bold; }
.cvss-high { color: var(--orange); text-shadow: 0 0 6px var(--orange); font-weight: bold; }
.cvss-med  { color: var(--yellow); text-shadow: 0 0 6px var(--yellow); }
.cvss-low  { color: var(--cyan); text-shadow: 0 0 6px var(--cyan); }

/* ---- Lists ---- */
ul.findings, ul.recs {
  list-style: none; padding: 0; margin: 6px 0;
}
ul.findings li, ul.recs li {
  padding: 4px 8px 4px 22px; position: relative;
  border-left: 2px solid var(--bg-4); margin-bottom: 3px;
}
ul.findings li::before {
  content: "[!]"; position: absolute; left: 4px;
  color: var(--red); text-shadow: 0 0 6px var(--red);
}
ul.recs li::before {
  content: "[+]"; position: absolute; left: 4px;
  color: var(--neon); text-shadow: 0 0 6px var(--neon);
}

/* ---- Disclaimer / footer ---- */
.disclaimer {
  background: #0d0000; color: var(--red); text-shadow: 0 0 8px var(--red);
  border-left: 3px solid var(--red); padding: 12px 16px;
  margin: 14px 0 22px; letter-spacing: 1px;
}
footer {
  border-top: 1px solid var(--bg-4); padding-top: 16px; margin-top: 28px;
  color: var(--muted); text-shadow: none; font-size: 11px;
  letter-spacing: 1px;
}

.muted { color: var(--muted); text-shadow: none; }
.kv { display: grid; grid-template-columns: 140px 1fr; gap: 4px 12px; font-size: 12px; }
.kv .k { color: var(--cyan); text-shadow: none; }
.kv .v { color: var(--neon); }
"""


# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

def _esc(text: Any) -> str:
    """HTML-escape any value (None -> empty, list -> comma-joined)."""
    if text is None:
        return ""
    if isinstance(text, (list, tuple)):
        return ", ".join(_esc(t) for t in text)
    return html_lib.escape(str(text))


def _state_class(state: str) -> str:
    if state == "open":
        return "open"
    if state.startswith("open"):
        return "openf"
    return "closed"


def _cvss_class(cvss: Optional[float]) -> str:
    if cvss is None:
        return "cvss-low"
    if cvss >= 9.0:
        return "cvss-crit"
    if cvss >= 7.0:
        return "cvss-high"
    if cvss >= 4.0:
        return "cvss-med"
    return "cvss-low"


def _risk_distribution(hosts: List[HostResult]) -> Dict[str, int]:
    counts = Counter()
    for h in hosts:
        counts[h.risk_level or "INFO"] += 1
    return dict(counts)


def _exec_summary_cards(hosts: List[HostResult]) -> str:
    if not hosts:
        return ""
    total_hosts = len(hosts)
    total_open  = sum(len(h.open_ports) for h in hosts)
    total_cves  = sum(len(p.cves or []) for h in hosts for p in h.open_ports)
    fw_detected = sum(1 for h in hosts if (h.firewall_info or {}).get("detected"))

    dist = _risk_distribution(hosts)
    cards = [
        ("info",  total_hosts, "HOSTS"),
        ("info",  total_open,  "OPEN PORTS"),
        ("med",   total_cves,  "CVES"),
        ("info",  fw_detected, "FIREWALLS DETECTED"),
        ("crit",  dist.get("CRITICAL", 0), "CRITICAL"),
        ("high",  dist.get("HIGH", 0),     "HIGH"),
        ("med",   dist.get("MEDIUM", 0),   "MEDIUM"),
        ("low",   dist.get("LOW", 0),      "LOW"),
        ("info",  dist.get("INFO", 0),     "INFO"),
    ]

    parts = ["<div class='exec-grid'>"]
    for klass, num, lbl in cards:
        parts.append(
            f"<div class='card {klass}'>"
            f"<span class='num'>{_esc(num)}</span>"
            f"<span class='lbl'>{_esc(lbl)}</span>"
            f"</div>"
        )
    parts.append("</div>")
    return "".join(parts)


def _badge(level: Optional[str]) -> str:
    lvl = (level or "INFO").upper()
    return f"<span class='badge {lvl}'>{_esc(lvl)}</span>"


# -------------------------------------------------------------------------
# Per-host rendering
# -------------------------------------------------------------------------

def _render_meta(host: HostResult) -> str:
    bits: List[str] = []
    if host.hostname:        bits.append(f"hostname=<b>{_esc(host.hostname)}</b>")
    if host.mac:             bits.append(f"mac={_esc(host.mac)}")
    if host.vendor:          bits.append(f"vendor={_esc(host.vendor)}")
    if host.ttl:             bits.append(f"ttl={host.ttl}")
    if host.os_guess:        bits.append(f"os={_esc(host.os_guess)}")
    if host.discovered_via:  bits.append("via=" + _esc(",".join(host.discovered_via)))
    return " &middot; ".join(bits) if bits else ""


def _render_ports_table(host: HostResult) -> str:
    if not host.ports:
        return "<p class='muted'>No ports scanned.</p>"
    rows = ["<table><thead><tr>"
            "<th>port</th><th>proto</th><th>state</th><th>service</th>"
            "<th>banner</th><th>CVEs</th><th>SSL</th><th>ms</th>"
            "</tr></thead><tbody>"]
    for p in host.ports:
        cls = _state_class(p.state)
        cves = ", ".join(c.get("id", "") for c in (p.cves or [])[:3])
        if (p.cves or []) and len(p.cves) > 3:
            cves += f" (+{len(p.cves) - 3})"
        si = p.ssl_info or {}
        ssl_bits = []
        if si.get("checked"):
            if si.get("expired"):     ssl_bits.append("expired")
            if si.get("self_signed"): ssl_bits.append("self-signed")
            if si.get("weak_protocols"): ssl_bits.append("weak-proto")
            if si.get("weak_ciphers"):   ssl_bits.append("weak-cipher")
            if not ssl_bits:             ssl_bits.append("ok")
        rows.append(
            "<tr>"
            f"<td>{p.port}</td>"
            f"<td>{_esc(p.proto)}</td>"
            f"<td class='{cls}'>{_esc(p.state)}</td>"
            f"<td>{_esc(p.service or '')}</td>"
            f"<td>{_esc(p.banner or '')}</td>"
            f"<td>{_esc(cves)}</td>"
            f"<td>{_esc(', '.join(ssl_bits))}</td>"
            f"<td>{p.latency_ms if p.latency_ms is not None else ''}</td>"
            "</tr>"
        )
    rows.append("</tbody></table>")
    return "".join(rows)


def _render_cve_table(host: HostResult) -> str:
    """Build a per-host CVE table (one row per CVE finding)."""
    rows = []
    for p in host.open_ports:
        for cve in (p.cves or []):
            cvss = cve.get("cvss")
            cls = _cvss_class(cvss)
            rows.append(
                "<tr>"
                f"<td>{p.proto}/{p.port}</td>"
                f"<td>{_esc(p.service or p.banner or '')}</td>"
                f"<td><a href='https://nvd.nist.gov/vuln/detail/{_esc(cve['id'])}'"
                f" target='_blank' rel='noreferrer'>{_esc(cve['id'])}</a></td>"
                f"<td class='{cls}'>{_esc(cvss if cvss is not None else 'n/a')}</td>"
                f"<td>{_esc(cve.get('summary', ''))}</td>"
                "</tr>"
            )
    if not rows:
        return ""
    return ("<h3>CVE findings</h3>"
            "<table><thead><tr>"
            "<th>port</th><th>service</th><th>CVE</th><th>CVSS</th><th>summary</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def _render_ssl_block(host: HostResult) -> str:
    bits = []
    for p in host.open_ports:
        si = p.ssl_info or {}
        if not si.get("checked"):
            continue
        rows = [
            ("subject",         si.get("subject")),
            ("issuer",          si.get("issuer")),
            ("not_after",       si.get("not_after")),
            ("days_remaining",  si.get("days_remaining")),
            ("expired",         si.get("expired")),
            ("self_signed",     si.get("self_signed")),
            ("weak_protocols",  si.get("weak_protocols")),
            ("weak_ciphers",    si.get("weak_ciphers")),
            ("error",           si.get("error")),
        ]
        kv = "".join(f"<div class='k'>{_esc(k)}</div>"
                     f"<div class='v'>{_esc(v)}</div>"
                     for k, v in rows if v not in (None, "", []))
        if kv:
            bits.append(f"<h4>TLS on {p.proto}/{p.port}</h4>"
                        f"<div class='kv'>{kv}</div>")
    if not bits:
        return ""
    return "<h3>SSL / TLS findings</h3>" + "".join(bits)


def _render_recon_block(host: HostResult) -> str:
    parts = []
    if host.whois_data:
        keep = [k for k in ("registrar", "creation_date", "expiration_date",
                            "country", "org", "netname", "asn", "asn_description",
                            "name_servers")
                if k in host.whois_data]
        if keep:
            kv = "".join(f"<div class='k'>{_esc(k)}</div>"
                         f"<div class='v'>{_esc(host.whois_data[k])}</div>"
                         for k in keep)
            parts.append("<h3>WHOIS</h3>"
                         f"<div class='kv'>{kv}</div>")
    if host.dns_records:
        rows = "".join(
            f"<tr><td>{_esc(rtype)}</td><td>{_esc(values)}</td></tr>"
            for rtype, values in sorted(host.dns_records.items())
        )
        parts.append("<h3>DNS records</h3>"
                     "<table><thead><tr><th>type</th><th>values</th></tr></thead>"
                     f"<tbody>{rows}</tbody></table>")
    if host.subdomains:
        items = "".join(f"<li>{_esc(s)}</li>" for s in host.subdomains)
        parts.append(f"<h3>Subdomains ({len(host.subdomains)})</h3>"
                     f"<ul class='findings'>{items}</ul>")
    return "".join(parts)


def _render_firewall_block(host: HostResult) -> str:
    fw = host.firewall_info or {}
    if not fw:
        return ""
    detected = "yes" if fw.get("detected") else "no"
    rows = [
        ("detected",        detected),
        ("confidence",      fw.get("confidence")),
        ("open_count",      fw.get("open_count")),
        ("filtered_count",  fw.get("filtered_count")),
        ("closed_count",    fw.get("closed_count")),
        ("ttl_anomaly",     "yes" if fw.get("ttl_anomaly") else "no"),
    ]
    kv = "".join(f"<div class='k'>{_esc(k)}</div>"
                 f"<div class='v'>{_esc(v)}</div>"
                 for k, v in rows if v not in (None, ""))
    notes = ""
    if fw.get("notes"):
        items = "".join(f"<li>{_esc(n)}</li>" for n in fw["notes"])
        notes = f"<ul class='findings'>{items}</ul>"
    return ("<h3>Firewall analysis</h3>"
            f"<div class='kv'>{kv}</div>{notes}")


def _render_factors(host: HostResult) -> str:
    if not host.risk_factors:
        return ""
    items = "".join(f"<li>{_esc(f)}</li>" for f in host.risk_factors)
    return f"<h3>Risk factors</h3><ul class='findings'>{items}</ul>"


def _render_recs(host: HostResult) -> str:
    if not host.recommendations:
        return ""
    items = "".join(f"<li>{_esc(r)}</li>" for r in host.recommendations)
    return f"<h3>Recommendations</h3><ul class='recs'>{items}</ul>"


def _render_host(host: HostResult) -> str:
    score = host.risk_score if host.risk_score is not None else "-"
    color = LEVEL_COLOR.get(host.risk_level or "INFO", LEVEL_COLOR["INFO"])
    return (
        f"<article class='host' style='border-left-color:{color}'>"
        "<header>"
        f"<span class='ip'>{_esc(host.ip)}</span>"
        f"{_badge(host.risk_level)}"
        f"<span class='score'>score {_esc(score)}/100</span>"
        "</header>"
        f"<div class='meta-line'>{_render_meta(host)}</div>"
        f"{_render_ports_table(host)}"
        f"{_render_cve_table(host)}"
        f"{_render_ssl_block(host)}"
        f"{_render_recon_block(host)}"
        f"{_render_firewall_block(host)}"
        f"{_render_factors(host)}"
        f"{_render_recs(host)}"
        "</article>"
    )


# -------------------------------------------------------------------------
# Public render entry points
# -------------------------------------------------------------------------

def render_html(hosts: List[HostResult],
                generated_at: str = "",
                target: str = "",
                version: str = "") -> str:
    """Return the full HTML document as a string."""
    if not generated_at:
        generated_at = time.strftime("%Y-%m-%d %H:%M:%S %z").strip()

    # Sort hosts: most-risky first, then by IP.
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_hosts = sorted(
        hosts,
        key=lambda h: (severity_rank.get(h.risk_level or "INFO", 9),
                       -(h.risk_score or 0),
                       h.ip),
    )

    parts: List[str] = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    parts.append("<title>EXO NET Pro &mdash; Penetration Test Report</title>")
    parts.append(_FONT_LINK)
    parts.append(f"<style>{_CSS}</style></head><body>")

    # Header
    parts.append("<div class='header'>"
                 "<h1>EXO NET PRO</h1>"
                 "<div class='tag'>[ Professional Ethical Hacking Toolkit ]</div>"
                 f"<div class='meta'>Report generated <b>{_esc(generated_at)}</b>"
                 f" &middot; target <b>{_esc(target)}</b>"
                 f" &middot; <b>{len(hosts)}</b> host(s) reported"
                 + (f" &middot; engine v{_esc(version)}" if version else "")
                 + "</div></div>")

    # Disclaimer
    parts.append(
        "<div class='disclaimer'>"
        "// AUTHORIZATION REQUIRED. EXO NET Pro is intended exclusively for "
        "authorized security assessments. Use only on assets you own or have "
        "explicit, written permission to test. Unauthorized scanning may "
        "violate computer misuse laws."
        "</div>"
    )

    # Executive summary
    parts.append("<section><h2>Executive summary</h2>"
                 + _exec_summary_cards(sorted_hosts) + "</section>")

    # Findings (per host)
    parts.append("<section><h2>Findings</h2>")
    if sorted_hosts:
        parts.extend(_render_host(h) for h in sorted_hosts)
    else:
        parts.append("<p class='muted'>No live hosts to report.</p>")
    parts.append("</section>")

    # Footer
    parts.append(
        "<footer>"
        "EXO NET Pro // generated " + _esc(generated_at) + " // "
        "Risk badges follow CVSS-inspired bands (CRITICAL >= 80, HIGH >= 60, "
        "MEDIUM >= 40, LOW >= 20, else INFO). "
        "This report is informational; verify findings before acting."
        "</footer>"
    )

    parts.append("</body></html>")
    return "".join(parts)


def write_html(hosts: List[HostResult], dest: Path,
               generated_at: str = "", target: str = "",
               version: str = "") -> None:
    html = render_html(hosts, generated_at=generated_at, target=target,
                       version=version)
    dest.write_text(html, encoding="utf-8")


def write_pdf(hosts: List[HostResult], dest: Path,
              generated_at: str = "", target: str = "",
              version: str = "") -> bool:
    """Render the HTML and convert to PDF via weasyprint.

    Returns True on success. On any failure (missing weasyprint, system
    libs missing, etc.) we log a warning and return False without raising.
    """
    try:
        from weasyprint import HTML  # type: ignore
    except Exception as exc:
        ui.warn(f"PDF export skipped: weasyprint unavailable "
                f"({exc.__class__.__name__}: {exc}). "
                "Install with: pip install weasyprint")
        return False

    try:
        html_str = render_html(hosts, generated_at=generated_at,
                               target=target, version=version)
        HTML(string=html_str).write_pdf(str(dest))
        return True
    except Exception as exc:
        ui.warn(f"PDF export failed: {exc.__class__.__name__}: {exc}")
        return False
