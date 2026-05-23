"""Vulnerability detection (EXO NET Pro).

Three responsibilities:

1. **CVE lookup** - takes a service banner / version string and queries
   ``https://cve.circl.lu`` for matching CVEs. The endpoint is rate-limited
   so we cap the query count and apply per-call timeouts. Network failures
   are downgraded to warnings.

2. **SSL/TLS health check** - probes a host:port with the stdlib ``ssl``
   module, parses the leaf certificate (with ``cryptography`` if present,
   else a stdlib best-effort), and reports: expired / about-to-expire,
   self-signed, weak protocols (SSLv2/3, TLS 1.0/1.1), and weak ciphers.

3. **Outdated-version heuristic** - very small built-in table of "anything
   below this is a known-bad version". Used as a coarse signal for the
   risk engine when the CVE API is unreachable.

Every public function is ``never raises`` - any exception is caught and
turned into a warning + degraded result.
"""

from __future__ import annotations

import datetime as _dt
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from . import ui
from .types import HostResult, PortResult


# ---- dependency probes ------------------------------------------------------

def _try_import_requests():
    try:
        import requests  # type: ignore
        return requests
    except Exception:
        return None


def _try_import_cryptography():
    try:
        from cryptography import x509  # type: ignore
        from cryptography.hazmat.backends import default_backend  # type: ignore
        return x509, default_backend
    except Exception:
        return None, None


# ---- CVE lookup -------------------------------------------------------------

CIRCL_API = "https://cve.circl.lu/api/search"

# Map common service tokens -> (vendor, product) pair used by circl's API.
# Many entries map to "*" vendor on circl which is fine; we only really need
# the product slug to be correct.
_SERVICE_PRODUCT: Dict[str, Tuple[str, str]] = {
    "ssh":          ("openbsd",   "openssh"),
    "openssh":      ("openbsd",   "openssh"),
    "http":         ("apache",    "http_server"),
    "apache":       ("apache",    "http_server"),
    "nginx":        ("nginx",     "nginx"),
    "iis":          ("microsoft", "internet_information_services"),
    "smb":          ("microsoft", "windows"),
    "microsoft-ds": ("microsoft", "windows"),
    "rdp":          ("microsoft", "windows"),
    "mysql":        ("mysql",     "mysql"),
    "mariadb":      ("mariadb",   "mariadb"),
    "postgresql":   ("postgresql", "postgresql"),
    "ftp":          ("vsftpd",    "vsftpd"),
    "vsftpd":       ("vsftpd",    "vsftpd"),
    "proftpd":      ("proftpd",   "proftpd"),
    "smtp":         ("postfix",   "postfix"),
    "exim":         ("exim",      "exim"),
    "dovecot":      ("dovecot",   "dovecot"),
    "redis":        ("redis",     "redis"),
    "mongodb":      ("mongodb",   "mongodb"),
    "elasticsearch": ("elastic",  "elasticsearch"),
}

# Tokens that look like a software name in a banner -> normalized service key.
_BANNER_PRODUCT_PATTERNS = (
    (re.compile(r"\bopenssh[_/-]?(\d+\.\d+(?:\.\d+)?(?:p\d+)?)?", re.I), "openssh"),
    (re.compile(r"\bapache[/ ]?(\d+\.\d+(?:\.\d+)?)?",          re.I), "apache"),
    (re.compile(r"\bnginx[/ ]?(\d+\.\d+(?:\.\d+)?)?",           re.I), "nginx"),
    (re.compile(r"\bmicrosoft-iis[/ ]?(\d+\.\d+)?",             re.I), "iis"),
    (re.compile(r"\b(?:vsftpd|proftpd|pure-ftpd)[/ ]?(\d+\.\d+(?:\.\d+)?)?", re.I), "ftp"),
    (re.compile(r"\bmysql[/ ]?(\d+\.\d+(?:\.\d+)?)?",           re.I), "mysql"),
    (re.compile(r"\bmariadb[/ ]?(\d+\.\d+(?:\.\d+)?)?",         re.I), "mariadb"),
    (re.compile(r"\bpostgres(?:ql)?[/ ]?(\d+\.\d+(?:\.\d+)?)?", re.I), "postgresql"),
    (re.compile(r"\bexim[/ ]?(\d+\.\d+(?:\.\d+)?)?",            re.I), "exim"),
    (re.compile(r"\bdovecot[/ ]?(\d+\.\d+(?:\.\d+)?)?",         re.I), "dovecot"),
    (re.compile(r"\bredis[/ ]?(\d+\.\d+(?:\.\d+)?)?",           re.I), "redis"),
)


def parse_banner(service: Optional[str], banner: Optional[str]
                 ) -> Tuple[Optional[str], Optional[str]]:
    """Return (product_key, version) parsed from a banner string.

    ``product_key`` is the lookup key into ``_SERVICE_PRODUCT``.
    """
    text = " ".join(filter(None, [service or "", banner or ""])).strip()
    if not text:
        return (service or None, None)
    for pat, key in _BANNER_PRODUCT_PATTERNS:
        m = pat.search(text)
        if m:
            ver = m.group(1) if m.groups() else None
            return (key, ver)
    # Fallback: use the service tag and try to find a "x.y[.z]" version anywhere.
    ver_m = re.search(r"\b(\d+\.\d+(?:\.\d+)?(?:p\d+)?)\b", text)
    return ((service or "").lower() or None, ver_m.group(1) if ver_m else None)


def _circl_search(vendor: str, product: str, timeout: float
                  ) -> List[Dict[str, Any]]:
    """Query circl's /api/search/<vendor>/<product> endpoint."""
    requests = _try_import_requests()
    if requests is None:
        return []
    url = f"{CIRCL_API}/{quote(vendor)}/{quote(product)}"
    try:
        resp = requests.get(url, timeout=timeout,
                            headers={"User-Agent": "EXO-NET-Pro/2.0"})
    except Exception as exc:
        ui.warn(f"CVE API unreachable for {vendor}/{product}: "
                f"{exc.__class__.__name__}")
        return []
    if resp.status_code != 200:
        return []
    try:
        data = resp.json()
    except Exception:
        return []
    # circl returns either a dict with "results" or a flat list depending
    # on its API version; tolerate both.
    if isinstance(data, dict) and "results" in data:
        items = data.get("results") or []
    elif isinstance(data, dict) and "data" in data:
        items = data.get("data") or []
    elif isinstance(data, list):
        items = data
    else:
        items = []
    return items if isinstance(items, list) else []


def _normalize_cve(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Reduce a circl CVE record to a small, report-friendly dict."""
    if not isinstance(item, dict):
        return None
    cve_id = item.get("id") or item.get("cveMetadata", {}).get("cveId")
    if not cve_id:
        return None
    summary = (item.get("summary")
               or item.get("description")
               or "")
    if isinstance(summary, list):  # newer schema
        try:
            summary = summary[0].get("value") if summary else ""
        except Exception:
            summary = str(summary)
    cvss = (item.get("cvss")
            or item.get("cvss3")
            or (item.get("metrics") or {}).get("cvssMetricV31", [{}])[0]
            .get("cvssData", {}).get("baseScore"))
    try:
        cvss = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        cvss = None
    return {
        "id": str(cve_id),
        "cvss": cvss,
        "summary": (summary or "")[:280],
    }


def _version_in_range(version: Optional[str], record: Dict[str, Any]) -> bool:
    """Coarse check: keep CVEs whose ``vulnerable_configuration`` mentions
    a version that starts with our parsed version's "major.minor" prefix.
    Without a version we keep everything (caller can cap the count)."""
    if not version:
        return True
    needle = ".".join(version.split(".")[:2])
    cfg = record.get("vulnerable_configuration") or record.get("vulnerable_product") or []
    if not isinstance(cfg, list):
        return True  # don't filter on schemas we don't recognize
    for entry in cfg:
        try:
            if needle in str(entry):
                return True
        except Exception:
            continue
    return False


def lookup_cves(product_key: Optional[str],
                version: Optional[str],
                timeout: float = 6.0,
                max_results: int = 8) -> List[Dict[str, Any]]:
    """Return up to ``max_results`` CVE summaries for the given product."""
    if not product_key:
        return []
    mapped = _SERVICE_PRODUCT.get(product_key.lower())
    if not mapped:
        return []
    vendor, product = mapped
    raw = _circl_search(vendor, product, timeout=timeout)
    if not raw:
        return []
    out: List[Dict[str, Any]] = []
    for item in raw:
        if not _version_in_range(version, item):
            continue
        cve = _normalize_cve(item)
        if cve:
            out.append(cve)
        if len(out) >= max_results:
            break
    # Sort by CVSS desc so the worst show first.
    out.sort(key=lambda d: (d.get("cvss") or 0.0), reverse=True)
    return out


# ---- Outdated-version heuristic --------------------------------------------

# Minimum version that is *not* known-old. Anything strictly below is flagged.
# These are conservative thresholds picked from headline CVEs; they will not
# replace a real CVE feed, but they let the risk engine work offline.
_MIN_SAFE_VERSION: Dict[str, Tuple[int, int, int]] = {
    "openssh":    (8, 0, 0),
    "apache":     (2, 4, 50),
    "nginx":      (1, 22, 0),
    "iis":        (10, 0, 0),
    "mysql":      (8, 0, 0),
    "mariadb":    (10, 5, 0),
    "postgresql": (13, 0, 0),
    "vsftpd":     (3, 0, 0),
    "ftp":        (3, 0, 0),
    "exim":       (4, 95, 0),
    "dovecot":    (2, 3, 0),
    "redis":      (6, 2, 0),
}


def _parse_semver(version: Optional[str]) -> Optional[Tuple[int, int, int]]:
    if not version:
        return None
    m = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", version)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))


def is_outdated(product_key: Optional[str], version: Optional[str]) -> bool:
    if not product_key or not version:
        return False
    threshold = _MIN_SAFE_VERSION.get(product_key.lower())
    parsed = _parse_semver(version)
    if not threshold or not parsed:
        return False
    return parsed < threshold


# ---- SSL / TLS health check -------------------------------------------------

# SSL ports we'll probe by default if the user requests --vuln. (We still
# probe any port whose service banner suggests SSL/TLS.)
SSL_DEFAULT_PORTS = {443, 8443, 465, 993, 995, 8883, 4433, 5986}

# Protocols we consider weak. (Stdlib's `ssl` won't expose SSLv2/SSLv3 by
# default on modern Python, but we still flag TLS 1.0/1.1 if the server
# negotiates them.)
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}

# Small list of cipher substrings that flag a connection as weak.
WEAK_CIPHER_TOKENS = (
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON", "PSK",
)


def _parse_cert_with_cryptography(der: bytes) -> Dict[str, Any]:
    x509, default_backend = _try_import_cryptography()
    if x509 is None:
        return {}
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
    except Exception:
        return {}
    try:
        subject = cert.subject.rfc4514_string()
    except Exception:
        subject = ""
    try:
        issuer = cert.issuer.rfc4514_string()
    except Exception:
        issuer = ""
    try:
        not_after = cert.not_valid_after
    except Exception:
        not_after = None
    self_signed = bool(subject) and (subject == issuer)
    days_remaining: Optional[int] = None
    expired = False
    if not_after:
        days_remaining = (not_after - _dt.datetime.utcnow()).days
        expired = days_remaining < 0
    return {
        "subject": subject,
        "issuer": issuer,
        "not_after": not_after.isoformat() if not_after else None,
        "days_remaining": days_remaining,
        "expired": expired,
        "self_signed": self_signed,
    }


def _parse_cert_stdlib(cert: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Best-effort cert info from ``ssl.SSLSocket.getpeercert()`` output."""
    if not cert:
        return {}
    def _flatten(name):
        try:
            return ", ".join(f"{k}={v}" for tpl in name for (k, v) in tpl)
        except Exception:
            return ""
    subject = _flatten(cert.get("subject", []))
    issuer = _flatten(cert.get("issuer", []))
    not_after_str = cert.get("notAfter")
    days_remaining: Optional[int] = None
    expired = False
    not_after_iso: Optional[str] = None
    if not_after_str:
        try:
            ts = _dt.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            not_after_iso = ts.isoformat()
            days_remaining = (ts - _dt.datetime.utcnow()).days
            expired = days_remaining < 0
        except Exception:
            pass
    return {
        "subject": subject,
        "issuer": issuer,
        "not_after": not_after_iso,
        "days_remaining": days_remaining,
        "expired": expired,
        "self_signed": bool(subject) and subject == issuer,
    }


def check_ssl(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    """Open a TLS socket and report cert + protocol/cipher health."""
    info: Dict[str, Any] = {
        "checked": True,
        "expired": False,
        "self_signed": False,
        "weak_protocols": [],
        "weak_ciphers": [],
        "subject": "",
        "issuer": "",
        "not_after": None,
        "days_remaining": None,
        "error": None,
    }

    # Permissive context: lab gear often uses self-signed certs and we
    # must still be able to inspect them.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                proto = tls.version() or ""
                cipher = tls.cipher()  # tuple: (name, protocol, bits) or None
                der = tls.getpeercert(binary_form=True)
                cert_dict = tls.getpeercert(binary_form=False)
    except (ssl.SSLError, OSError, socket.timeout) as exc:
        info["error"] = f"{exc.__class__.__name__}: {exc}"
        return info

    cert_info = _parse_cert_with_cryptography(der) if der else {}
    if not cert_info:
        cert_info = _parse_cert_stdlib(cert_dict)
    info.update({k: v for k, v in cert_info.items() if v is not None})

    # Protocol weakness check.
    if proto and any(proto.upper().startswith(w.upper().split(".")[0])
                     for w in WEAK_PROTOCOLS):
        info["weak_protocols"].append(proto)
    elif proto in WEAK_PROTOCOLS:
        info["weak_protocols"].append(proto)

    # Cipher weakness check.
    if cipher:
        cipher_name = cipher[0] or ""
        if any(tok in cipher_name.upper() for tok in WEAK_CIPHER_TOKENS):
            info["weak_ciphers"].append(cipher_name)

    return info


# ---- High-level orchestration ----------------------------------------------

def _looks_like_ssl_port(port: int, banner: Optional[str]) -> bool:
    if port in SSL_DEFAULT_PORTS:
        return True
    if banner and re.search(r"\b(?:tls|ssl|https)\b", banner, re.I):
        return True
    return False


def run(host: HostResult,
        do_cves: bool = True,
        do_ssl: bool = True,
        cve_timeout: float = 6.0,
        ssl_timeout: float = 5.0,
        max_cves_per_port: int = 5,
        threads: int = 6) -> None:
    """Annotate every open port on ``host`` with CVE + SSL findings."""
    open_ports = host.open_ports
    if not open_ports:
        return

    def _work(p: PortResult):
        # CVE lookup
        if do_cves:
            try:
                product, version = parse_banner(p.service, p.banner)
                p.outdated = is_outdated(product, version)
                cves = lookup_cves(product, version,
                                   timeout=cve_timeout,
                                   max_results=max_cves_per_port)
                if cves:
                    p.cves = cves
                    ui.good(f"{host.ip}:{p.port} {product or '?'} -> "
                            f"{len(cves)} CVE(s)")
            except Exception as exc:
                ui.warn(f"CVE lookup error for {host.ip}:{p.port}: "
                        f"{exc.__class__.__name__}: {exc}")
        # SSL probe
        if do_ssl and _looks_like_ssl_port(p.port, p.banner):
            try:
                p.ssl_info = check_ssl(host.ip, p.port, timeout=ssl_timeout)
                if p.ssl_info.get("expired"):
                    ui.warn(f"{host.ip}:{p.port} TLS cert expired")
                elif p.ssl_info.get("self_signed"):
                    ui.bad(f"{host.ip}:{p.port} TLS cert self-signed")
                if p.ssl_info.get("weak_ciphers") or p.ssl_info.get("weak_protocols"):
                    ui.warn(f"{host.ip}:{p.port} weak TLS detected")
            except Exception as exc:
                ui.warn(f"SSL probe error for {host.ip}:{p.port}: "
                        f"{exc.__class__.__name__}: {exc}")

    workers = max(1, min(threads, len(open_ports)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_work, p) for p in open_ports]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception:
                pass
            # Light rate-limit so we don't hammer circl.
            time.sleep(0.05)
