"""WHOIS + DNS reconnaissance (EXO NET Pro).

This module never crashes the scan. Every external dependency is lazy-
imported inside ``try/except`` blocks; if a library is missing, the
corresponding feature is skipped and a one-line warning is emitted. All
public helpers return Python primitives (dicts/lists), never raise.

Public surface:
    lookup_whois(target)          -> Optional[dict]
    enumerate_dns(domain, types)  -> Dict[str, List[str]]
    subdomain_scan(domain, words) -> List[str]
    reverse_dns(ip)               -> Optional[str]
    run(host, ...)                -> populate HostResult.whois_data /
                                     dns_records / subdomains in-place

WHOIS coverage:
- ``python-whois`` if available (works for IPs and domains, no daemon).
- Else system ``whois`` binary if present.
- Else empty result.

DNS coverage:
- ``dnspython`` if available (default; supports A/AAAA/MX/TXT/NS/CNAME/SOA).
- Else stdlib ``socket.getaddrinfo`` for A only.

Subdomain scanner:
- Pure-Python concurrent DNS resolution against a wordlist.
- Bundled minimal wordlist (~60 entries) used when caller passes none.
"""

from __future__ import annotations

import ipaddress
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Iterable, List, Optional

from . import ui
from .types import HostResult


# ---- dependency probes ------------------------------------------------------

def _try_import_whois():
    try:
        import whois  # type: ignore
        return whois
    except Exception:
        return None


def _try_import_dnspython():
    try:
        import dns.resolver  # type: ignore
        import dns.exception  # type: ignore
        return dns
    except Exception:
        return None


# ---- target classification --------------------------------------------------

def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def looks_like_domain(target: str) -> bool:
    if not target or is_ip(target):
        return False
    return "." in target and all(c.isalnum() or c in "-._" for c in target)


# ---- WHOIS ------------------------------------------------------------------

def _whois_python(target: str, timeout: float) -> Optional[Dict[str, Any]]:
    """Use the python-whois package. Returns a flat dict or None."""
    whois = _try_import_whois()
    if whois is None:
        return None
    try:
        # python-whois has a global socket timeout via the `timeout` kwarg
        # on some versions; we set it defensively and also rely on the
        # caller's deadline.
        try:
            data = whois.whois(target, timeout=timeout)  # type: ignore[arg-type]
        except TypeError:
            data = whois.whois(target)
        if not data:
            return None
        # `data` is a WhoisEntry (dict-like). Coerce to plain dict and
        # stringify dates/lists so it's safe to JSON-serialize later.
        out: Dict[str, Any] = {}
        for key, value in dict(data).items():
            if value is None:
                continue
            if isinstance(value, (list, tuple, set)):
                out[key] = [str(v) for v in value if v is not None]
            else:
                out[key] = str(value)
        return out or None
    except Exception as exc:
        ui.warn(f"python-whois lookup failed for {target}: "
                f"{exc.__class__.__name__}: {exc}")
        return None


def _whois_subprocess(target: str, timeout: float) -> Optional[Dict[str, Any]]:
    """Fallback: shell out to the system ``whois`` binary."""
    try:
        proc = subprocess.run(
            ["whois", target],
            capture_output=True, text=True,
            timeout=max(5.0, timeout * 5),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    text = (proc.stdout or "").strip()
    if not text:
        return None
    # Parse "Key: Value" lines; collapse duplicates by keeping first.
    parsed: Dict[str, Any] = {}
    for line in text.splitlines():
        if ":" not in line or line.strip().startswith("%"):
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key or not value or key in parsed:
            continue
        parsed[key] = value
    parsed["_raw"] = text[:4000]  # cap raw block to keep reports light
    return parsed or {"_raw": text[:4000]}


def lookup_whois(target: str, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
    """Run a best-effort WHOIS query for an IP or domain. Never raises."""
    if not target:
        return None
    target = target.strip()
    data = _whois_python(target, timeout)
    if data:
        return data
    return _whois_subprocess(target, timeout)


# ---- DNS enumeration --------------------------------------------------------

DEFAULT_DNS_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA")


def _dns_dnspython(domain: str, types: Iterable[str],
                   timeout: float) -> Dict[str, List[str]]:
    dns_mod = _try_import_dnspython()
    if dns_mod is None:
        return {}
    try:
        resolver = dns_mod.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
    except Exception:
        return {}

    out: Dict[str, List[str]] = {}
    for rtype in types:
        try:
            answers = resolver.resolve(domain, rtype)  # type: ignore[attr-defined]
        except Exception:
            continue
        values: List[str] = []
        for rr in answers:
            try:
                if rtype == "MX":
                    values.append(f"{rr.preference} {rr.exchange.to_text().rstrip('.')}")
                elif rtype == "TXT":
                    chunks = [b.decode("utf-8", "replace")
                              for b in getattr(rr, "strings", [])]
                    values.append("".join(chunks) if chunks else rr.to_text())
                elif rtype == "SOA":
                    values.append(
                        f"{rr.mname.to_text().rstrip('.')} "
                        f"{rr.rname.to_text().rstrip('.')} "
                        f"{rr.serial}"
                    )
                else:
                    values.append(rr.to_text().rstrip("."))
            except Exception:
                values.append(str(rr))
        if values:
            out[rtype] = values
    return out


def _dns_stdlib(domain: str) -> Dict[str, List[str]]:
    """Last-resort A-record lookup via the stdlib resolver."""
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET)
        addrs = sorted({info[4][0] for info in infos})
        return {"A": addrs} if addrs else {}
    except (socket.gaierror, socket.herror, OSError):
        return {}


def enumerate_dns(domain: str,
                  types: Iterable[str] = DEFAULT_DNS_TYPES,
                  timeout: float = 5.0) -> Dict[str, List[str]]:
    """Return a {record_type: [values]} dict. Never raises."""
    if not looks_like_domain(domain):
        return {}
    out = _dns_dnspython(domain, types, timeout)
    if out:
        return out
    return _dns_stdlib(domain)


# ---- Subdomain scanner ------------------------------------------------------

# Compact, focused wordlist. Users wanting full coverage should pass their own.
DEFAULT_SUBDOMAINS: tuple = (
    "www", "mail", "smtp", "imap", "pop", "pop3", "ns1", "ns2", "dns",
    "dns1", "dns2", "ftp", "sftp", "vpn", "remote", "portal", "api",
    "dev", "staging", "test", "qa", "uat", "preprod", "beta", "demo",
    "admin", "administrator", "secure", "ssl", "shop", "store", "blog",
    "forum", "wiki", "docs", "support", "help", "kb", "status",
    "monitor", "metrics", "grafana", "kibana", "jenkins", "git",
    "gitlab", "gitea", "jira", "confluence", "intranet", "internal",
    "owa", "exchange", "autodiscover", "cdn", "static", "assets",
    "files", "media", "img", "images", "downloads", "upload",
    "webmail", "mx", "mx1", "mx2", "mta", "relay",
    "db", "mysql", "postgres", "redis", "elasticsearch",
)


def _resolve_one(host: str, timeout: float) -> Optional[str]:
    """Resolve a single hostname to an A record. Returns None on failure."""
    dns_mod = _try_import_dnspython()
    if dns_mod is not None:
        try:
            resolver = dns_mod.resolver.Resolver()
            resolver.lifetime = timeout
            resolver.timeout = timeout
            answers = resolver.resolve(host, "A")  # type: ignore[attr-defined]
            for rr in answers:
                return rr.to_text()
        except Exception:
            return None
    # stdlib fallback
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, socket.herror, OSError):
        return None


def subdomain_scan(domain: str,
                   wordlist: Optional[Iterable[str]] = None,
                   threads: int = 32,
                   timeout: float = 3.0) -> List[Dict[str, str]]:
    """Brute-force common subdomain names against ``domain``.

    Returns a list of {"name": fqdn, "ip": addr} dicts (sorted), or [].
    """
    if not looks_like_domain(domain):
        return []
    words = list(wordlist) if wordlist is not None else list(DEFAULT_SUBDOMAINS)
    if not words:
        return []

    candidates = [f"{w.strip()}.{domain}" for w in words if w and w.strip()]
    found: List[Dict[str, str]] = []

    workers = max(1, min(threads, len(candidates)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_resolve_one, c, timeout): c for c in candidates}
        for fut in as_completed(futs):
            try:
                ip = fut.result()
            except Exception:
                ip = None
            if ip:
                found.append({"name": futs[fut], "ip": ip})

    found.sort(key=lambda d: d["name"])
    return found


# ---- Reverse DNS ------------------------------------------------------------

def reverse_dns(ip: str) -> Optional[str]:
    """Best-effort PTR lookup. Never raises."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None


# ---- High-level orchestration helper ---------------------------------------

def run(host: HostResult,
        do_whois: bool = True,
        do_dns: bool = True,
        do_subdomains: bool = False,
        wordlist: Optional[Iterable[str]] = None,
        timeout: float = 5.0) -> None:
    """Populate WHOIS / DNS / subdomain fields on a HostResult in place.

    Operates on ``host.hostname`` when present (for DNS / subdomains) and
    on ``host.ip`` for the WHOIS lookup. Reverse-DNS is also attempted if
    no hostname is set yet.
    """
    if not host.hostname:
        host.hostname = reverse_dns(host.ip)

    target_for_whois = host.hostname or host.ip

    if do_whois:
        try:
            wd = lookup_whois(target_for_whois, timeout=timeout)
            if wd:
                host.whois_data = wd
                ui.good(f"WHOIS data collected for {target_for_whois}")
            else:
                ui.bad(f"WHOIS returned nothing for {target_for_whois}")
        except Exception as exc:  # safety net - lookup_whois shouldn't raise
            ui.warn(f"WHOIS error for {target_for_whois}: "
                    f"{exc.__class__.__name__}: {exc}")

    if do_dns and host.hostname:
        try:
            recs = enumerate_dns(host.hostname, timeout=timeout)
            if recs:
                host.dns_records = recs
                kinds = ", ".join(sorted(recs.keys()))
                ui.good(f"DNS records for {host.hostname}: {kinds}")
        except Exception as exc:
            ui.warn(f"DNS enumeration error for {host.hostname}: "
                    f"{exc.__class__.__name__}: {exc}")

    if do_subdomains and host.hostname:
        # Only scan sub-domains for an apex-style domain; if hostname is
        # already a sub-domain (>2 labels), strip to the registrable parent.
        parts = host.hostname.split(".")
        apex = ".".join(parts[-2:]) if len(parts) >= 2 else host.hostname
        try:
            subs = subdomain_scan(apex, wordlist=wordlist, timeout=timeout)
            if subs:
                host.subdomains = [s["name"] for s in subs]
                ui.good(f"Subdomain scan: {len(subs)} hits on *.{apex}")
        except Exception as exc:
            ui.warn(f"Subdomain scan error for {apex}: "
                    f"{exc.__class__.__name__}: {exc}")
