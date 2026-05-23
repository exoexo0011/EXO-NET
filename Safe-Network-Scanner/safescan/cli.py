"""Command-line entry point and scan orchestration.

Run via the top-level shim::

    python network_scanner.py --target 192.168.1.0/24 --discover --scan
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from . import __version__
from . import banners as banners_mod
from . import discovery, osfp, oui, output, portscan, privilege, safety, timing, ui
from .types import HostResult, PortResult


# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------

def _parse_target(spec: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.IPv4Network(spec, strict=False)
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise argparse.ArgumentTypeError(f"Invalid target '{spec}': {exc}")


def _parse_ports(spec: str) -> List[int]:
    """Accept '80', '22,80,443', '1-1024', or any mix."""
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
    for p in ports:
        if not 1 <= p <= 65535:
            raise argparse.ArgumentTypeError(f"Port out of range: {p}")
    return sorted(ports)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network_scanner.py",
        description=(
            "Safe-Network-Scanner: an educational nmap-lite scanner. "
            "Use only on networks you own or have written permission to scan."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python network_scanner.py --target 192.168.1.1\n"
            "  python network_scanner.py --target 192.168.1.0/24 --discover\n"
            "  python network_scanner.py --target 192.168.1.0/24 --discover --scan\n"
            "  python network_scanner.py --target 192.168.1.1 --ports 1-1024 --timing 4\n"
            "  python network_scanner.py --target 192.168.1.1 --scan-type syn --os-detect\n"
            "  python network_scanner.py --target 192.168.1.0/24 --aggressive --output json\n"
            "  python network_scanner.py --target 192.168.1.0/24 --stealth\n"
            "  python network_scanner.py --target 192.168.1.10 --udp --udp-ports 53,123,161\n"
        ),
    )

    parser.add_argument("--version", action="version",
                        version=f"safescan {__version__}")

    # ---- target & ports ----
    parser.add_argument("--target", required=True, type=_parse_target,
                        help="IP or CIDR network (e.g. 192.168.1.1 or 10.0.0.0/24).")
    parser.add_argument("--ports", default=None,
                        help="TCP ports: '80', '22,80,443', '1-1024', or a mix. "
                             "Defaults to a curated common-ports list.")
    parser.add_argument("--udp", action="store_true",
                        help="Also run a UDP scan.")
    parser.add_argument("--udp-ports", default=None,
                        help="UDP ports list (same syntax as --ports). "
                             "Defaults to common UDP services.")

    # ---- phase selection ----
    parser.add_argument("--discover", action="store_true",
                        help="Run host discovery on the target range.")
    parser.add_argument("--scan", action="store_true",
                        help="Run port scan. Implied for single-host targets.")

    # ---- scan type ----
    parser.add_argument("--scan-type",
                        choices=["auto", "connect", "syn"], default="auto",
                        help="TCP scan type. 'auto' picks SYN if Scapy L3 is "
                             "available, else connect. (default: auto)")

    # ---- timing & profiles ----
    parser.add_argument("--timing", type=int, choices=range(0, 6), default=3,
                        metavar="0-5",
                        help="nmap-style timing template: 0=paranoid, 1=sneaky, "
                             "2=polite, 3=normal (default), 4=aggressive, 5=insane.")
    profile_group = parser.add_mutually_exclusive_group()
    profile_group.add_argument("--stealth", action="store_true",
                               help="Shortcut: --timing 1, no banner grabs, no OS detect.")
    profile_group.add_argument("--aggressive", action="store_true",
                               help="Shortcut: --timing 4, banners on, OS detect on, UDP top ports.")

    # ---- discovery / detection toggles ----
    parser.add_argument("--no-arp", action="store_true",
                        help="Skip ARP discovery (only ICMP and TCP-ping).")
    parser.add_argument("--no-tcp-ping", action="store_true",
                        help="Skip TCP-ping fallback during discovery.")
    parser.add_argument("--no-banners", action="store_true",
                        help="Skip banner / version grabbing on open ports.")
    parser.add_argument("--os-detect", action="store_true",
                        help="Enable basic OS fingerprinting (TTL-based).")

    # ---- output ----
    parser.add_argument("--output", choices=["table", "json"], default="table",
                        help="Output format. (default: table)")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress the startup banner.")
    parser.add_argument("--no-progress", action="store_true",
                        help="Disable the progress bar.")

    # ---- safety ----
    parser.add_argument("--allow-public", action="store_true",
                        help="Required to scan non-private IP ranges.")

    return parser


# -----------------------------------------------------------------------------
# Preset application
# -----------------------------------------------------------------------------

def _apply_presets(args: argparse.Namespace) -> None:
    """Translate --stealth / --aggressive into their underlying flags."""
    if args.stealth:
        args.timing = 1
        args.no_banners = True
        args.os_detect = False
        # Stealth implies SYN if possible (less noisy than full connect).
        if args.scan_type == "auto":
            args.scan_type = "syn"
    elif args.aggressive:
        args.timing = 4
        args.no_banners = False
        args.os_detect = True
        if not args.udp:
            args.udp = True


# -----------------------------------------------------------------------------
# Banner grabbing (parallel across hosts/ports)
# -----------------------------------------------------------------------------

def _grab_banners(hosts: List[HostResult], timeout: float, threads: int,
                  progress: Optional[ui.ProgressBar]) -> None:
    """Populate `banner` on all open ports across all hosts."""
    jobs: list[tuple[HostResult, PortResult]] = []
    for h in hosts:
        for p in h.open_ports:
            if p.proto == "tcp":
                jobs.append((h, p))
    if not jobs:
        return

    def _work(host: HostResult, pr: PortResult):
        pr.banner = banners_mod.grab(host.ip, pr.port, timeout)

    workers = max(1, min(threads, len(jobs)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_work, h, p) for h, p in jobs]
        for f in futs:
            try:
                f.result()
            except Exception:
                pass
            if progress:
                progress.tick()


# -----------------------------------------------------------------------------
# Main orchestration
# -----------------------------------------------------------------------------

def run(args: argparse.Namespace) -> int:
    if not args.no_banner:
        ui.show_banner(__version__)

    network: ipaddress.IPv4Network = args.target
    safety.enforce(network, args.allow_public)

    _apply_presets(args)
    profile = timing.get(args.timing)
    ui.info(f"Timing: T{args.timing} ({profile.name}) | "
            f"caps: {privilege.describe_capabilities()}")

    # Resolve TCP scan strategy now that capabilities are probed.
    tcp_scan = portscan.resolve_scan_type(args.scan_type)
    if tcp_scan != args.scan_type and args.scan_type != "auto":
        ui.warn(f"Scan type adjusted: {args.scan_type} -> {tcp_scan}")

    # Resolve port lists.
    try:
        tcp_ports = _parse_ports(args.ports) if args.ports else portscan.COMMON_TCP_PORTS
        udp_ports = _parse_ports(args.udp_ports) if args.udp_ports else portscan.COMMON_UDP_PORTS
    except (ValueError, argparse.ArgumentTypeError) as exc:
        ui.bad(f"Invalid port list: {exc}")
        return 2

    is_single_host = network.num_addresses == 1
    do_discover = args.discover or (not is_single_host and not args.scan)
    do_scan = args.scan or is_single_host or do_discover

    # ---- Phase 1: Discovery ------------------------------------------------
    if is_single_host:
        # Skip the broadcast layers for a single target; just probe it.
        host = HostResult(ip=str(network.network_address), alive=True,
                          discovered_via=["assumed"])
        host.hostname = discovery.reverse_dns(host.ip)
        ttl = discovery.icmp_ping(host.ip, profile.discovery_timeout)
        if ttl is not None and ttl > 0:
            host.ttl = ttl
            if "icmp" not in host.discovered_via:
                host.discovered_via.append("icmp")
        # Try to fill MAC from system ARP cache (works if the host is on-LAN).
        arp_table = discovery.parse_system_arp_table()
        if host.ip in arp_table:
            host.mac = arp_table[host.ip]
        hosts = [host]
    else:
        prog: Optional[ui.ProgressBar] = None
        if not args.no_progress:
            num = max(1, network.num_addresses - 2 if network.num_addresses > 2 else 1)
            prog = ui.ProgressBar(num, label="discover")
        hosts = discovery.discover(
            network, profile,
            use_tcp_ping=not args.no_tcp_ping,
            use_arp=not args.no_arp,
            progress=prog,
        )
        if prog: prog.close()
        if not hosts:
            ui.warn("No live hosts found.")
            if args.output == "json":
                output.render_json([])
            return 0
        ui.good(f"{len(hosts)} live host(s) discovered.")

    if not do_scan:
        # Discovery-only mode: still enrich with vendor + OS guess for reporting.
        for h in hosts:
            if h.mac:
                h.vendor = oui.lookup(h.mac)
            if args.os_detect:
                h.os_guess = osfp.guess_from_ttl(h.ttl)
        _render(hosts, args)
        return 0

    # ---- Phase 2: Port scan ------------------------------------------------
    total_ports = len(hosts) * (len(tcp_ports) + (len(udp_ports) if args.udp else 0))
    scan_prog: Optional[ui.ProgressBar] = None
    if not args.no_progress:
        scan_prog = ui.ProgressBar(total_ports, label="portscan")

    t0 = time.time()
    for host in hosts:
        host.ports.extend(
            portscan.scan_tcp(host.ip, tcp_ports, profile, tcp_scan, progress=scan_prog)
        )
        if args.udp:
            host.ports.extend(
                portscan.scan_udp(host.ip, udp_ports, profile, progress=scan_prog)
            )
    if scan_prog: scan_prog.close()

    # ---- Phase 3: Enrichment (banners, vendor, OS) -------------------------
    if not args.no_banners:
        open_count = sum(len(h.open_ports) for h in hosts)
        if open_count:
            banner_prog: Optional[ui.ProgressBar] = None
            if not args.no_progress:
                banner_prog = ui.ProgressBar(open_count, label="banners ")
            _grab_banners(hosts, profile.timeout, profile.threads, banner_prog)
            if banner_prog: banner_prog.close()

    for host in hosts:
        if host.mac:
            host.vendor = oui.lookup(host.mac)
        if args.os_detect:
            host.os_guess = osfp.guess_from_ttl(host.ttl)

    elapsed = time.time() - t0
    ui.info(f"Scan finished in {elapsed:.2f}s.")

    _render(hosts, args)
    return 0


def _render(hosts: List[HostResult], args: argparse.Namespace) -> None:
    if args.output == "json":
        output.render_json(hosts)
    else:
        output.render_table(hosts)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print()
        ui.warn("Interrupted by user.")
        return 130
