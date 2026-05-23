"""TCP connect, TCP SYN, and UDP port scanners.

Auto-selection rules:
  * On Windows or whenever Scapy L3 is unusable, we fall back to TCP connect
    even if the user asked for SYN. SYN scans require raw L3 sockets which
    fail loudly without Npcap on Windows.
  * UDP scans are best-effort: without raw sockets we cannot distinguish
    "open" from "filtered" reliably, so we report ``open|filtered`` when no
    response is received.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Optional, Tuple

from . import privilege, ui
from .timing import TimingProfile
from .types import PortResult


# Curated list of common TCP ports used when --ports is omitted.
COMMON_TCP_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 8000, 8080, 8443,
]

# Common UDP ports for --udp without an explicit list.
COMMON_UDP_PORTS: List[int] = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900, 5353]


def _service_name(port: int, proto: str = "tcp") -> Optional[str]:
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return None


# ---- TCP connect scan -------------------------------------------------------
def _tcp_connect(ip: str, port: int, timeout: float) -> Tuple[bool, float]:
    """Return (open?, latency_ms)."""
    t0 = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            rc = sock.connect_ex((ip, port))
        except (socket.gaierror, OSError):
            return False, (time.perf_counter() - t0) * 1000
    return rc == 0, (time.perf_counter() - t0) * 1000


def _probe_tcp_connect(ip: str, port: int, timeout: float) -> PortResult:
    is_open, latency = _tcp_connect(ip, port, timeout)
    return PortResult(
        port=port, proto="tcp",
        state="open" if is_open else "closed",
        service=_service_name(port, "tcp"),
        latency_ms=round(latency, 2),
    )


# ---- TCP SYN scan -----------------------------------------------------------
def _probe_tcp_syn(ip: str, port: int, timeout: float) -> PortResult:
    """SYN scan via Scapy. Caller must verify scapy_l3_usable() first."""
    from scapy.all import IP, TCP, sr1  # type: ignore
    state = "filtered"
    t0 = time.perf_counter()
    try:
        reply = sr1(IP(dst=ip) / TCP(dport=port, flags="S"),
                    timeout=timeout, verbose=0)
        if reply is None or not reply.haslayer(TCP):
            state = "filtered"
        else:
            flags = int(reply.getlayer(TCP).flags)
            if (flags & 0x12) == 0x12:        # SYN/ACK
                state = "open"
                # Be polite: send RST so we don't leave a half-open conn.
                try:
                    sr1(IP(dst=ip) / TCP(dport=port, flags="R"),
                        timeout=timeout, verbose=0)
                except Exception:
                    pass
            elif (flags & 0x14) == 0x14:      # RST/ACK
                state = "closed"
    except Exception:
        state = "filtered"
    latency = (time.perf_counter() - t0) * 1000
    return PortResult(
        port=port, proto="tcp", state=state,
        service=_service_name(port, "tcp"),
        latency_ms=round(latency, 2),
    )


# ---- UDP scan ---------------------------------------------------------------
# Protocol-specific probes that elicit responses from common UDP services.
_UDP_PROBES = {
    53:   bytes.fromhex(                       # DNS query for 'version.bind' CHAOS TXT
        "abcd01000001000000000000"
        "0776657273696f6e0462696e6400001000030000291000000000000000"
    ),
    123:  bytes(48) if False else b"\x1b" + bytes(47),  # NTP v3 client
    161:  bytes.fromhex(                       # SNMPv1 GET sysDescr.0, community 'public'
        "302902010004067075626c6963a01c020401020304020100020100"
        "300e300c06082b060102010101000500"
    ),
    137:  bytes.fromhex(                       # NetBIOS Name Service NBSTAT *
        "abcd0000000100000000000020434b4141414141414141414141414141"
        "41414141414141414141414141414141410000210001"
    ),
    1900: (b"M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\n"
           b"Man:\"ssdp:discover\"\r\nST:ssdp:all\r\nMX:1\r\n\r\n"),
}


def _probe_udp(ip: str, port: int, timeout: float) -> PortResult:
    """Best-effort UDP probe using stdlib sockets."""
    payload = _UDP_PROBES.get(port, b"\x00")
    t0 = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, (ip, port))
            try:
                data, _ = sock.recvfrom(2048)
                state = "open" if data else "open|filtered"
            except socket.timeout:
                state = "open|filtered"
            except ConnectionRefusedError:
                state = "closed"  # ICMP port unreachable surfaced by the OS
    except OSError:
        state = "open|filtered"
    latency = (time.perf_counter() - t0) * 1000
    return PortResult(
        port=port, proto="udp", state=state,
        service=_service_name(port, "udp"),
        latency_ms=round(latency, 2),
    )


# ---- scan-type resolution ---------------------------------------------------
def resolve_scan_type(requested: str) -> str:
    """Pick the actual TCP scan type given user request and runtime caps."""
    if requested == "syn":
        if privilege.scapy_l3_usable():
            return "syn"
        ui.warn("SYN scan requested but Scapy L3 socket unavailable "
                "(missing Npcap on Windows or not root). Falling back to TCP connect.")
        return "connect"
    if requested == "auto":
        return "syn" if privilege.scapy_l3_usable() else "connect"
    return "connect"  # explicit


# ---- top-level scan ---------------------------------------------------------
def scan_tcp(
    ip: str,
    ports: Iterable[int],
    timing: TimingProfile,
    scan_type: str,             # 'connect' | 'syn'
    progress=None,
) -> List[PortResult]:
    port_list = list(ports)
    probe = _probe_tcp_syn if scan_type == "syn" else _probe_tcp_connect
    results: List[PortResult] = []
    workers = max(1, min(timing.threads, len(port_list)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {
            pool.submit(probe, ip, p, timing.timeout): p for p in port_list
        }
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as exc:
                ui.bad(f"TCP probe error {ip}:{futs[fut]} - {exc}")
            if progress:
                progress.tick()
            if timing.delay:
                time.sleep(timing.delay)
    results.sort(key=lambda r: r.port)
    return results


def scan_udp(
    ip: str,
    ports: Iterable[int],
    timing: TimingProfile,
    progress=None,
) -> List[PortResult]:
    port_list = list(ports)
    results: List[PortResult] = []
    workers = max(1, min(timing.threads, len(port_list)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {
            pool.submit(_probe_udp, ip, p, timing.timeout): p for p in port_list
        }
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as exc:
                ui.bad(f"UDP probe error {ip}:{futs[fut]} - {exc}")
            if progress:
                progress.tick()
            if timing.delay:
                time.sleep(timing.delay)
    results.sort(key=lambda r: r.port)
    return results
