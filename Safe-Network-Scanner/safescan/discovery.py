"""Layered host discovery: ARP -> ICMP -> TCP-ping.

A host is considered alive if any of these layers responds. We tag the
HostResult with the methods that succeeded so the user can see why we
think the host is up.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from . import privilege, ui
from .timing import TimingProfile
from .types import HostResult

# TCP-ping fallback ports. Ordered by likelihood of responding through firewalls.
TCP_PING_PORTS = (80, 443, 22, 445, 3389)

_MAC_RE = re.compile(r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")


# ---- ARP --------------------------------------------------------------------
def arp_scan_scapy(network: ipaddress.IPv4Network, timeout: float) -> Dict[str, str]:
    """Broadcast ARP across `network`. Returns {ip: mac}.

    Requires Scapy L2 access (root + libpcap/Npcap). Returns empty dict on any
    failure so callers can transparently fall back.
    """
    if not privilege.scapy_l2_usable():
        return {}
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered, _ = srp(pkt, timeout=timeout, verbose=0, retry=1)
        return {r.psrc: r.hwsrc.lower() for _, r in answered}
    except Exception as exc:
        ui.warn(f"ARP scan failed ({exc.__class__.__name__}: {exc}); skipping ARP layer.")
        return {}


def parse_system_arp_table() -> Dict[str, str]:
    """Parse the OS ARP cache for {ip: mac}. Works without privileges."""
    cmd = ["arp", "-a"] if platform.system().lower() == "windows" else ["arp", "-n"]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return {}

    table: Dict[str, str] = {}
    for line in out.splitlines():
        ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        mac_match = _MAC_RE.search(line)
        if ip_match and mac_match:
            mac = mac_match.group(1).lower().replace("-", ":")
            if mac == "00:00:00:00:00:00" or "incomplete" in line.lower():
                continue
            table[ip_match.group(1)] = mac
    return table


# ---- ICMP -------------------------------------------------------------------
def _icmp_scapy(ip: str, timeout: float) -> Optional[int]:
    """Send one ICMP echo via Scapy. Returns reply TTL or None."""
    if not privilege.scapy_l3_usable():
        return None
    try:
        from scapy.all import IP, ICMP, sr1  # type: ignore
        reply = sr1(IP(dst=ip) / ICMP(), timeout=timeout, verbose=0)
        if reply is not None and reply.haslayer(IP):
            return int(reply.getlayer(IP).ttl)
        return None
    except Exception:
        return None


def _icmp_subprocess(ip: str, timeout: float) -> Optional[int]:
    """Fallback ICMP via the system `ping` command. Parses TTL from output."""
    is_windows = platform.system().lower() == "windows"
    count_flag = "-n" if is_windows else "-c"
    timeout_flag = "-w" if is_windows else "-W"
    timeout_val = str(int(timeout * 1000)) if is_windows else str(max(1, int(timeout)))
    cmd = ["ping", count_flag, "1", timeout_flag, timeout_val, ip]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 2
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    if result.returncode != 0:
        return None
    # Both Linux ('ttl=64') and Windows ('TTL=64') outputs match this.
    m = re.search(r"ttl[=\s]*(\d+)", result.stdout, re.IGNORECASE)
    return int(m.group(1)) if m else 0  # 0 = alive but TTL unknown


def icmp_ping(ip: str, timeout: float) -> Optional[int]:
    """Best-available ICMP probe. Returns TTL on success, None if no reply."""
    ttl = _icmp_scapy(ip, timeout)
    if ttl is not None:
        return ttl
    return _icmp_subprocess(ip, timeout)


# ---- TCP-ping ---------------------------------------------------------------
def tcp_ping(ip: str, timeout: float, ports=TCP_PING_PORTS) -> bool:
    """Try a TCP connect on common ports. Useful when ICMP is blocked."""
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    return True
        except OSError:
            continue
    return False


# ---- Reverse DNS ------------------------------------------------------------
def reverse_dns(ip: str) -> Optional[str]:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None


# ---- Top-level discovery ----------------------------------------------------
def _probe_host(
    ip: str,
    timing: TimingProfile,
    arp_map: Dict[str, str],
    use_tcp_ping: bool,
) -> HostResult:
    """Run all enabled discovery layers against one IP, return a HostResult."""
    host = HostResult(ip=ip)

    # Layer 1: ARP (already done in batch; just look up the answer).
    if ip in arp_map:
        host.alive = True
        host.discovered_via.append("arp")
        host.mac = arp_map[ip]

    # Layer 2: ICMP echo.
    ttl = icmp_ping(ip, timing.discovery_timeout)
    if ttl is not None:
        host.alive = True
        host.discovered_via.append("icmp")
        if ttl > 0:
            host.ttl = ttl

    # Layer 3: TCP-ping fallback (skip if we already proved liveness).
    if not host.alive and use_tcp_ping:
        if tcp_ping(ip, timing.discovery_timeout):
            host.alive = True
            host.discovered_via.append("tcp")

    if host.alive:
        host.hostname = reverse_dns(ip)
    return host


def discover(
    network: ipaddress.IPv4Network,
    timing: TimingProfile,
    use_tcp_ping: bool = True,
    use_arp: bool = True,
    progress=None,
) -> List[HostResult]:
    """Discover live hosts in `network`. Returns only hosts marked alive."""
    if network.num_addresses == 1:
        targets = [str(network.network_address)]
    else:
        targets = [str(h) for h in network.hosts()]

    # Fast batch ARP first (Scapy L2). Falls back to OS arp table afterward.
    arp_map: Dict[str, str] = {}
    if use_arp:
        if privilege.scapy_l2_usable() and len(targets) > 1:
            ui.info(f"ARP sweep on {network}...")
            arp_map = arp_scan_scapy(network, timing.discovery_timeout * 2)
            if arp_map:
                ui.good(f"ARP found {len(arp_map)} host(s).")

    ui.info(
        f"Probing {len(targets)} address(es) via "
        f"{'ARP+' if arp_map else ''}ICMP{'+TCP' if use_tcp_ping else ''}..."
    )

    results: List[HostResult] = []
    workers = max(1, min(timing.threads, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {
            pool.submit(_probe_host, ip, timing, arp_map, use_tcp_ping): ip
            for ip in targets
        }
        for fut in as_completed(futs):
            try:
                host = fut.result()
            except Exception as exc:
                ui.bad(f"Discovery error for {futs[fut]}: {exc}")
                if progress: progress.tick()
                continue
            if host.alive:
                results.append(host)
            if progress:
                progress.tick(note=f"alive={len(results)}")
            if timing.delay:
                time.sleep(timing.delay)

    # Fill in MACs from system ARP cache for hosts we didn't get via Scapy.
    if use_arp and any(h.mac is None for h in results):
        os_table = parse_system_arp_table()
        for h in results:
            if h.mac is None and h.ip in os_table:
                h.mac = os_table[h.ip]
                if "arp" not in h.discovered_via:
                    h.discovered_via.append("arp-cache")

    results.sort(key=lambda h: tuple(int(o) for o in h.ip.split(".")))
    return results
