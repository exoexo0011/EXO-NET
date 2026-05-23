"""Risk scoring engine (EXO NET Pro).

Combines per-host signals into a single 0..100 score and a categorical
level (CRITICAL / HIGH / MEDIUM / LOW / INFO). The score is intended to
be *interpretable*: the ``risk_factors`` list explains every point we
added, and ``recommendations`` gives the operator something concrete to
do about each finding.

This module is pure-Python and has no external dependencies. It reads
fields populated by other modules:

- ``host.ports``          (always present)
- ``host.firewall_info``  from :mod:`exonet.firewall`  (optional)
- ``port.cves``           from :mod:`exonet.vuln`      (optional)
- ``port.ssl_info``       from :mod:`exonet.vuln`      (optional)
- ``port.outdated``       from :mod:`exonet.vuln`      (optional)
- :mod:`exonet.credentials`  for default-creds awareness
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from . import credentials
from .types import HostResult, PortResult


# ---- service sensitivity ----------------------------------------------------

# Higher = more dangerous if exposed. Tuned so that exposing a single
# very-risky service is enough to cross into HIGH on its own.
SENSITIVE_SERVICES: Dict[str, int] = {
    "telnet":         25,    # cleartext admin
    "rsh":            25,
    "rlogin":         25,
    "ftp":            10,    # cleartext, often anonymous
    "tftp":           15,
    "smb":            18,
    "microsoft-ds":   18,
    "netbios-ssn":    14,
    "rdp":            18,
    "ms-wbt-server":  18,
    "vnc":            15,
    "x11":            14,
    "snmp":           14,    # often v1/v2c "public"
    "ldap":           10,
    "mssql":          14,
    "ms-sql-s":       14,
    "mysql":          12,
    "postgresql":     12,
    "redis":          14,    # default = no auth
    "mongodb":        14,
    "elasticsearch":  14,
    "memcached":      10,
    "ipmi":           14,
    "modbus":         15,
    "s7":             15,
    "dnp3":           15,
    "ssh":            4,     # exposed SSH is normal but not free
    "http":           2,
    "https":          1,
    "smtp":           4,
    "pop3":           3,
    "imap":           3,
}


# ---- level thresholds ------------------------------------------------------

# Score boundaries (inclusive lower bound).
_LEVEL_THRESHOLDS: Tuple[Tuple[int, str], ...] = (
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0,  "INFO"),
)


def level_for(score: int) -> str:
    for lower, label in _LEVEL_THRESHOLDS:
        if score >= lower:
            return label
    return "INFO"


# ---- recommendation strings -----------------------------------------------

_REC_BY_SERVICE: Dict[str, str] = {
    "telnet":   "Disable Telnet entirely; replace with SSH and key-based auth.",
    "rsh":      "Disable rsh/rlogin; use SSH instead.",
    "rlogin":   "Disable rsh/rlogin; use SSH instead.",
    "ftp":      "Replace FTP with SFTP/FTPS and disable anonymous access.",
    "tftp":     "Restrict TFTP to a management VLAN or remove it.",
    "smb":      "Restrict SMB to trusted networks; disable SMBv1; enforce SMB signing.",
    "microsoft-ds": "Restrict SMB to trusted networks; disable SMBv1; enforce SMB signing.",
    "netbios-ssn":  "Block NetBIOS at the firewall on untrusted segments.",
    "rdp":      "Place RDP behind a VPN or RD Gateway and require MFA.",
    "ms-wbt-server": "Place RDP behind a VPN or RD Gateway and require MFA.",
    "vnc":      "Tunnel VNC over SSH or replace with a managed remote-desktop product.",
    "snmp":     "Move SNMP to v3 with auth+priv and rotate community strings.",
    "redis":    "Bind Redis to localhost; require AUTH; never expose to the internet.",
    "mongodb":  "Enable authentication on MongoDB; bind to internal interfaces only.",
    "elasticsearch": "Enable security features on Elasticsearch; disable HTTP for end-users.",
    "mysql":    "Restrict MySQL to application subnets; require TLS on the wire.",
    "postgresql": "Restrict PostgreSQL to application subnets; require TLS; review pg_hba.conf.",
    "mssql":    "Restrict MSSQL to application subnets; enforce strong sa policy or disable sa.",
    "ms-sql-s": "Restrict MSSQL to application subnets; enforce strong sa policy or disable sa.",
    "ipmi":     "Move IPMI/iDRAC/iLO to an isolated management VLAN.",
    "ssh":      "Disable password auth on SSH; require keys + fail2ban / sshguard.",
    "ldap":     "Use LDAPS only; disable anonymous binds.",
    "http":     "Redirect HTTP to HTTPS and serve HSTS.",
    "https":    "Keep TLS healthy: renew before expiry, disable TLS 1.0/1.1, drop weak ciphers.",
    "smtp":     "Require STARTTLS and authentication; rate-limit relays.",
}


# ---- scoring engine --------------------------------------------------------

def _service_key(p: PortResult) -> str:
    return (p.service or "").lower()


def score_host(host: HostResult) -> Tuple[int, str, List[str], List[str]]:
    """Compute (score, level, factors, recommendations) for one host."""
    score = 0
    factors: List[str] = []
    recs: List[str] = []
    rec_seen = set()  # de-dupe recommendations

    def _add_rec(text: str) -> None:
        if text not in rec_seen:
            rec_seen.add(text)
            recs.append(text)

    open_ports = host.open_ports
    n_open = len(open_ports)

    # --- 1. Open-port volume --------------------------------------------------
    # Mild base risk that grows with attack surface, capped to keep the
    # signal from any one factor under control.
    if n_open >= 1:
        port_pts = min(20, 2 + n_open * 2)
        score += port_pts
        factors.append(f"+{port_pts} for {n_open} open port(s) (attack surface)")

    # --- 2. Sensitive services -----------------------------------------------
    for p in open_ports:
        key = _service_key(p)
        weight = SENSITIVE_SERVICES.get(key)
        if weight:
            score += weight
            factors.append(f"+{weight} sensitive service {key.upper()} on "
                           f"{p.proto}/{p.port}")
            rec = _REC_BY_SERVICE.get(key)
            if rec:
                _add_rec(rec)

    # --- 3. Default-credentials reference matches ----------------------------
    # We *don't* try the credentials, but if a service has well-known defaults
    # we treat its exposure as worse.
    for p in open_ports:
        key = _service_key(p)
        if not key:
            continue
        if credentials.lookup(key):
            score += 6
            factors.append(f"+6 well-known default creds exist for "
                           f"{key.upper()} (rotate if unchanged)")
            _add_rec(f"Verify {key.upper()} on {p.proto}/{p.port} is not "
                     f"using vendor default credentials.")

    # --- 4. CVE findings ------------------------------------------------------
    # Cap CVE contribution per host so a noisy product doesn't dominate the score.
    cve_pts_total = 0
    for p in open_ports:
        for cve in (p.cves or [])[:5]:
            cvss = cve.get("cvss") or 0.0
            if cvss >= 9.0:
                pts = 12
            elif cvss >= 7.0:
                pts = 7
            elif cvss >= 4.0:
                pts = 4
            else:
                pts = 2
            cve_pts_total += pts
            factors.append(
                f"+{pts} CVE {cve['id']} (CVSS {cvss or 'n/a'}) on "
                f"{p.proto}/{p.port}"
            )
    if cve_pts_total:
        # Cap at +30 per host total.
        capped = min(30, cve_pts_total)
        if capped < cve_pts_total:
            score += capped
            factors.append(f"  (CVE contribution capped at +{capped})")
        else:
            score += capped
        _add_rec("Patch services flagged with CVEs to current vendor releases.")

    # --- 5. Outdated software heuristic --------------------------------------
    for p in open_ports:
        if p.outdated:
            score += 6
            label = (p.banner or p.service or "").strip() or f"{p.proto}/{p.port}"
            factors.append(f"+6 outdated software detected: {label[:60]}")
            _add_rec("Schedule a maintenance window to upgrade outdated services.")

    # --- 6. SSL/TLS health ---------------------------------------------------
    for p in open_ports:
        si = p.ssl_info or {}
        if not si.get("checked"):
            continue
        if si.get("expired"):
            score += 8
            factors.append(f"+8 expired TLS certificate on {p.proto}/{p.port}")
            _add_rec(f"Renew the TLS certificate for {p.proto}/{p.port} immediately.")
        elif (si.get("days_remaining") or 999) < 30:
            score += 3
            factors.append(f"+3 TLS cert near expiry "
                           f"({si.get('days_remaining')} days) on "
                           f"{p.proto}/{p.port}")
            _add_rec(f"Renew the TLS certificate for {p.proto}/{p.port} soon.")
        if si.get("self_signed"):
            score += 4
            factors.append(f"+4 self-signed TLS cert on {p.proto}/{p.port}")
            _add_rec("Replace self-signed certificates with a trusted CA-issued "
                     "cert (or document the trust path explicitly).")
        if si.get("weak_protocols"):
            score += 5
            factors.append(f"+5 weak TLS protocols on {p.proto}/{p.port}: "
                           f"{', '.join(si['weak_protocols'])}")
            _add_rec("Disable TLS 1.0 / 1.1 (and SSLv2/v3 if present); "
                     "require TLS 1.2+.")
        if si.get("weak_ciphers"):
            score += 4
            factors.append(f"+4 weak ciphers on {p.proto}/{p.port}: "
                           f"{', '.join(si['weak_ciphers'])}")
            _add_rec("Restrict cipher suites to modern AEAD ciphers only.")

    # --- 7. No firewall detected ---------------------------------------------
    fw = host.firewall_info or {}
    if fw and not fw.get("detected") and n_open >= 1:
        # Only "no firewall" is risk-relevant; a *detected* firewall is good.
        score += 6
        factors.append("+6 host appears to have no upstream packet filter")
        _add_rec("Place the host behind a stateful firewall and only "
                 "allow-list the services that need to be reachable.")

    # --- final clamp ---------------------------------------------------------
    score = max(0, min(100, score))
    return score, level_for(score), factors, recs


def annotate(host: HostResult) -> None:
    """Compute and store risk fields on ``host``."""
    score, level, factors, recs = score_host(host)
    host.risk_score = score
    host.risk_level = level
    host.risk_factors = factors
    if recs:
        # Extend rather than overwrite, in case the caller seeded recommendations.
        existing = set(host.recommendations)
        host.recommendations = host.recommendations + [r for r in recs
                                                       if r not in existing]
    elif not host.recommendations:
        host.recommendations = ["No specific actions identified - keep monitoring."]


def annotate_all(hosts) -> None:
    for h in hosts:
        annotate(h)


# ---- color/badge mapping for the report ------------------------------------

# Hex colors are kept identical to the existing cyberpunk palette so the
# pro report renders consistently. Each level gets a glow color too.
LEVEL_COLOR = {
    "CRITICAL": "#ff003c",   # red
    "HIGH":     "#ff7700",   # orange
    "MEDIUM":   "#ffe600",   # yellow
    "LOW":      "#00ff41",   # neon green
    "INFO":     "#00cfff",   # cyan
}
