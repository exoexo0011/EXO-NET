#!/usr/bin/env python3
"""
Safe-Network-Scanner
====================

An educational network scanner for use on networks you OWN or have
WRITTEN PERMISSION to scan. Unauthorized scanning may be illegal in
your jurisdiction (e.g. the U.S. Computer Fraud and Abuse Act, the
UK Computer Misuse Act, etc.).

Features
--------
1. Host discovery on an IPv4 network range (CIDR) using ICMP echo.
2. TCP port scanning of common or user-supplied ports on a target.
3. Optional low-level packet crafting via Scapy when available and
   the process is privileged; otherwise falls back to safe stdlib
   implementations (subprocess `ping`, socket `connect`).
4. Colored, human-friendly CLI output via colorama.
5. argparse-based interface with sensible defaults and timeouts.

Usage examples
--------------
    # Discover live hosts on a /24:
    python network_scanner.py --target 192.168.1.0/24 --discover

    # Scan common ports on a single host:
    python network_scanner.py --target 192.168.1.1

    # Scan a port range with custom timeout and thread count:
    python network_scanner.py --target 192.168.1.1 --ports 1-1024 \
        --timeout 0.5 --threads 200

    # Discover hosts then scan each one:
    python network_scanner.py --target 192.168.1.0/24 --discover --scan
"""

from __future__ import annotations

# ---- Standard library imports ------------------------------------------------
import argparse
import ipaddress
import os
import platform
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple

# ---- Third-party imports (graceful fallback if missing) ----------------------
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _COLOR = True
except ImportError:  # pragma: no cover - colorama is listed in requirements
    _COLOR = False

    class _Dummy:
        def __getattr__(self, _name): return ""
    Fore = Style = _Dummy()  # type: ignore

# Scapy is optional: it gives us low-level ICMP/TCP packet crafting but
# requires root/Administrator. We fall back to stdlib if it is missing
# or if we lack privileges.
try:
    # Suppress the verbose Scapy import banner.
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import IP, ICMP, TCP, sr1, conf as scapy_conf  # type: ignore
    scapy_conf.verb = 0
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


# =============================================================================
# Constants
# =============================================================================

# A small curated list of "interesting" ports. Used when --ports is omitted.
COMMON_PORTS: List[int] = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    111,   # RPCbind
    135,   # MSRPC
    139,   # NetBIOS
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    993,   # IMAPS
    995,   # POP3S
    1433,  # MSSQL
    1723,  # PPTP
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    8000,  # HTTP-alt
    8080,  # HTTP-proxy
    8443,  # HTTPS-alt
]

DEFAULT_TIMEOUT = 1.0      # seconds for socket / scapy operations
DEFAULT_THREADS = 100      # concurrent workers for port scanning
DEFAULT_PING_TIMEOUT = 1.0 # seconds for host discovery


# =============================================================================
# Data classes
# =============================================================================

@dataclass
class PortResult:
    """Result of probing a single TCP port."""
    port: int
    is_open: bool
    service: Optional[str] = None  # best-effort service name from /etc/services


@dataclass
class HostResult:
    """Aggregated scan result for a single host."""
    ip: str
    is_alive: bool = False
    open_ports: List[PortResult] = field(default_factory=list)


# =============================================================================
# Pretty printing helpers
# =============================================================================

def _c(text: str, color: str) -> str:
    """Wrap `text` with `color` if colorama is available, else return as-is."""
    if not _COLOR:
        return text
    return f"{color}{text}{Style.RESET_ALL}"


def info(msg: str) -> None:
    print(_c("[*] ", Fore.CYAN) + msg)


def good(msg: str) -> None:
    print(_c("[+] ", Fore.GREEN) + msg)


def warn(msg: str) -> None:
    print(_c("[!] ", Fore.YELLOW) + msg)


def bad(msg: str) -> None:
    print(_c("[-] ", Fore.RED) + msg)


def banner() -> None:
    art = r"""
   _____        __         _   _      _      _____
  / ____|      / _|       | \ | |    | |    / ____|
 | (___   __ _| |_ ___    |  \| | ___| |_  | (___   ___ __ _ _ __
  \___ \ / _` |  _/ _ \   | . ` |/ _ \ __|  \___ \ / __/ _` | '_ \
  ____) | (_| | ||  __/   | |\  |  __/ |_   ____) | (_| (_| | | | |
 |_____/ \__,_|_| \___|   |_| \_|\___|\__| |_____/ \___\__,_|_| |_|

                Safe-Network-Scanner - Educational Use Only
"""
    print(_c(art, Fore.MAGENTA))
    warn("Only scan networks you OWN or have explicit WRITTEN permission to scan.")
    warn("Unauthorized scanning may be illegal in your jurisdiction.\n")


# =============================================================================
# Privilege detection
# =============================================================================

def _is_privileged() -> bool:
    """True if we can probably craft raw packets (root on Unix, admin on Win)."""
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


# =============================================================================
# Host discovery
# =============================================================================

def _ping_scapy(ip: str, timeout: float) -> bool:
    """Send one ICMP echo with Scapy and return True iff a reply comes back."""
    try:
        pkt = IP(dst=ip) / ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        return reply is not None
    except PermissionError:
        return False
    except Exception:
        return False


def _ping_subprocess(ip: str, timeout: float) -> bool:
    """Fallback host check using the system `ping` command."""
    # `-c` on Unix vs `-n` on Windows. Timeout flag also differs.
    is_windows = platform.system().lower() == "windows"
    count_flag = "-n" if is_windows else "-c"
    timeout_flag = "-w" if is_windows else "-W"
    # Windows expects timeout in milliseconds, Unix in seconds.
    timeout_val = str(int(timeout * 1000)) if is_windows else str(int(max(1, timeout)))
    cmd = ["ping", count_flag, "1", timeout_flag, timeout_val, ip]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def is_host_alive(ip: str, timeout: float, use_scapy: bool) -> bool:
    """Decide whether a host responds to ICMP echo."""
    if use_scapy and _SCAPY_AVAILABLE and _is_privileged():
        return _ping_scapy(ip, timeout)
    return _ping_subprocess(ip, timeout)


def discover_hosts(
    network: ipaddress.IPv4Network,
    timeout: float,
    threads: int,
    use_scapy: bool,
) -> List[str]:
    """Return a sorted list of live hosts inside `network`."""
    # `hosts()` excludes network and broadcast addresses for sized networks.
    # For /32 it yields nothing, so handle that explicitly.
    targets: List[str]
    if network.num_addresses == 1:
        targets = [str(network.network_address)]
    else:
        targets = [str(h) for h in network.hosts()]

    info(f"Discovering live hosts in {network} ({len(targets)} addresses)...")
    alive: List[str] = []

    # ThreadPoolExecutor lets us issue many pings in parallel without the
    # complexity of asyncio. Network I/O releases the GIL so this scales well.
    with ThreadPoolExecutor(max_workers=min(threads, max(1, len(targets)))) as pool:
        future_to_ip = {
            pool.submit(is_host_alive, ip, timeout, use_scapy): ip for ip in targets
        }
        for fut in as_completed(future_to_ip):
            ip = future_to_ip[fut]
            try:
                if fut.result():
                    good(f"Host up: {ip}")
                    alive.append(ip)
            except Exception as exc:
                bad(f"Error pinging {ip}: {exc}")

    # Sort numerically rather than lexicographically for nicer output.
    alive.sort(key=lambda s: tuple(int(o) for o in s.split(".")))
    return alive


# =============================================================================
# Port scanning
# =============================================================================

def _service_name(port: int) -> Optional[str]:
    """Look up a friendly service name for `port` from the OS services DB."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return None


def _probe_port_socket(ip: str, port: int, timeout: float) -> bool:
    """TCP connect scan: portable, unprivileged, but slightly noisier."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            return sock.connect_ex((ip, port)) == 0
        except (socket.gaierror, OSError):
            return False


def _probe_port_scapy_syn(ip: str, port: int, timeout: float) -> bool:
    """
    SYN ("half-open") scan via Scapy. We send SYN and look at the reply:
      - SYN/ACK (flags 0x12) -> port is open.
      - RST/ACK (flags 0x14) -> port is closed.
      - No reply             -> filtered / dropped.
    Requires root/admin to send raw packets.
    """
    try:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply is None or not reply.haslayer(TCP):
            return False
        flags = int(reply.getlayer(TCP).flags)
        is_syn_ack = (flags & 0x12) == 0x12
        if is_syn_ack:
            # Be polite: tear the half-open connection down with a RST.
            try:
                rst = IP(dst=ip) / TCP(dport=port, flags="R")
                sr1(rst, timeout=timeout, verbose=0)
            except Exception:
                pass
        return is_syn_ack
    except PermissionError:
        return False
    except Exception:
        return False


def probe_port(ip: str, port: int, timeout: float, use_scapy: bool) -> PortResult:
    """Probe a single port and return a PortResult."""
    if use_scapy and _SCAPY_AVAILABLE and _is_privileged():
        is_open = _probe_port_scapy_syn(ip, port, timeout)
    else:
        is_open = _probe_port_socket(ip, port, timeout)
    return PortResult(port=port, is_open=is_open, service=_service_name(port))


def scan_ports(
    ip: str,
    ports: Iterable[int],
    timeout: float,
    threads: int,
    use_scapy: bool,
) -> List[PortResult]:
    """Scan many ports concurrently. Returns only the open ones."""
    port_list = list(ports)
    info(f"Scanning {len(port_list)} ports on {ip}...")
    open_results: List[PortResult] = []

    with ThreadPoolExecutor(max_workers=min(threads, max(1, len(port_list)))) as pool:
        futures = {
            pool.submit(probe_port, ip, p, timeout, use_scapy): p for p in port_list
        }
        for fut in as_completed(futures):
            try:
                result = fut.result()
            except Exception as exc:
                bad(f"Error scanning port {futures[fut]} on {ip}: {exc}")
                continue
            if result.is_open:
                svc = result.service or "unknown"
                good(f"{ip}:{result.port} OPEN ({svc})")
                open_results.append(result)

    open_results.sort(key=lambda r: r.port)
    return open_results


# =============================================================================
# Argument parsing & validation
# =============================================================================

def parse_ports(spec: str) -> List[int]:
    """
    Parse a port spec. Supported forms:
        "80"             -> [80]
        "22,80,443"      -> [22, 80, 443]
        "1-1024"         -> [1, 2, ..., 1024]
        "22,80,8000-8010"-> mixed
    """
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, hi_s = chunk.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(chunk))

    # Validate range. TCP ports are 1..65535.
    for p in ports:
        if not 1 <= p <= 65535:
            raise argparse.ArgumentTypeError(f"Port out of range: {p}")
    return sorted(ports)


def parse_target(spec: str) -> ipaddress.IPv4Network:
    """
    Accept either a single IPv4 ('192.168.1.10') or CIDR ('192.168.1.0/24').
    A bare IP is treated as a /32.
    """
    try:
        # strict=False allows host bits to be set (e.g. 192.168.1.5/24).
        return ipaddress.IPv4Network(spec, strict=False)
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise argparse.ArgumentTypeError(f"Invalid target '{spec}': {exc}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network_scanner.py",
        description="Educational network scanner. Use only on networks you own.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python network_scanner.py --target 192.168.1.1\n"
            "  python network_scanner.py --target 192.168.1.0/24 --discover\n"
            "  python network_scanner.py --target 192.168.1.1 --ports 1-1024\n"
            "  python network_scanner.py --target 10.0.0.0/24 --discover --scan\n"
        ),
    )
    parser.add_argument(
        "--target", required=True, type=parse_target,
        help="Target IP or CIDR network (e.g. 192.168.1.1 or 192.168.1.0/24).",
    )
    parser.add_argument(
        "--ports", default=None,
        help="Ports to scan: '80', '22,80,443', '1-1024', or a mix. "
             "Defaults to a curated list of common ports.",
    )
    parser.add_argument(
        "--discover", action="store_true",
        help="Run host discovery (ICMP) on the target range.",
    )
    parser.add_argument(
        "--scan", action="store_true",
        help="Run port scan. Implied when --target is a single host.",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"Per-probe timeout in seconds (default {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "--threads", type=int, default=DEFAULT_THREADS,
        help=f"Concurrent workers (default {DEFAULT_THREADS}).",
    )
    parser.add_argument(
        "--no-scapy", action="store_true",
        help="Disable Scapy even if available; use stdlib only.",
    )
    parser.add_argument(
        "--allow-public", action="store_true",
        help="Required to scan non-private (public) IP ranges. Off by default "
             "as a safety guard against accidental scans of the open internet.",
    )
    parser.add_argument(
        "--no-banner", action="store_true",
        help="Suppress the startup banner.",
    )
    return parser


# =============================================================================
# Safety guard
# =============================================================================

def _is_private_network(network: ipaddress.IPv4Network) -> bool:
    """True if every address in `network` is in RFC1918 / loopback / link-local."""
    return network.is_private or network.is_loopback or network.is_link_local


def safety_check(network: ipaddress.IPv4Network, allow_public: bool) -> None:
    """Refuse to scan public ranges unless the user explicitly opted in."""
    if _is_private_network(network):
        return
    if not allow_public:
        bad(f"Refusing to scan non-private range {network}.")
        bad("Pass --allow-public to override (only do this on networks you own).")
        sys.exit(2)
    warn(f"Scanning PUBLIC range {network} because --allow-public was given.")
    warn("Make sure you have explicit written permission for this target.")


# =============================================================================
# Main orchestration
# =============================================================================

def run(args: argparse.Namespace) -> int:
    if not args.no_banner:
        banner()

    network: ipaddress.IPv4Network = args.target
    safety_check(network, args.allow_public)

    use_scapy = not args.no_scapy
    if use_scapy and _SCAPY_AVAILABLE and not _is_privileged():
        warn("Scapy is installed but you are not root/Administrator. "
             "Falling back to stdlib (subprocess ping / TCP connect).")
        use_scapy = False
    elif not _SCAPY_AVAILABLE and not args.no_scapy:
        info("Scapy not installed; using stdlib backend.")

    ports: List[int]
    if args.ports:
        try:
            ports = parse_ports(args.ports)
        except (ValueError, argparse.ArgumentTypeError) as exc:
            bad(f"Invalid --ports value: {exc}")
            return 2
    else:
        ports = COMMON_PORTS

    # Decide what to do based on flags. Single-host targets default to "scan".
    is_single_host = network.num_addresses == 1
    do_discover = args.discover or (not is_single_host and not args.scan)
    do_scan = args.scan or is_single_host

    targets: List[str]
    if do_discover and not is_single_host:
        targets = discover_hosts(
            network, timeout=DEFAULT_PING_TIMEOUT,
            threads=args.threads, use_scapy=use_scapy,
        )
        if not targets:
            warn("No live hosts found.")
            return 0
        info(f"{len(targets)} live host(s) discovered.")
    else:
        # Either a single host or the user only wants to scan a known target.
        targets = [str(network.network_address)] if is_single_host \
            else [str(h) for h in network.hosts()]

    if not do_scan:
        return 0

    # Per-host port scan with a final summary.
    summary: List[HostResult] = []
    t0 = time.time()
    for ip in targets:
        host_result = HostResult(ip=ip, is_alive=True)
        host_result.open_ports = scan_ports(
            ip, ports, timeout=args.timeout,
            threads=args.threads, use_scapy=use_scapy,
        )
        summary.append(host_result)

    elapsed = time.time() - t0
    print()
    info(f"Scan finished in {elapsed:.2f}s.")
    print(_c("=" * 60, Fore.CYAN))
    for host in summary:
        if host.open_ports:
            good(f"{host.ip} - {len(host.open_ports)} open port(s):")
            for p in host.open_ports:
                print(f"    {_c(str(p.port).rjust(5), Fore.GREEN)}/tcp  "
                      f"{p.service or 'unknown'}")
        else:
            warn(f"{host.ip} - no open ports found in the scanned set.")
    print(_c("=" * 60, Fore.CYAN))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
