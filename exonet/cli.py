"""Command-line entry point and scan orchestration (EXO NET Pro).

Run via the top-level shim::

    python exonet.py --target 192.168.1.0/24 --discover --scan
    python exonet.py --target 192.168.1.0/24 --pro --report html --save
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List, Optional

from . import __version__
from . import banners as banners_mod
from . import (
    credentials,
    discovery,
    evasion as evasion_mod,
    firewall as firewall_mod,
    osfp,
    oui,
    output,
    portscan,
    privilege,
    report,
    report_pro,
    risk as risk_mod,
    safety,
    screenshots,
    storage,
    timing,
    ui,
    vuln,
    whois as whois_mod,
)
from .types import HostResult, PortResult


# -----------------------------------------------------------------------------
# Argument parsing helpers
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


def _parse_report(spec: str) -> List[str]:
    """Comma-separated list of {html,csv,json}. Empty -> []."""
    if not spec:
        return []
    valid = {"html", "csv", "json"}
    out: List[str] = []
    for chunk in spec.split(","):
        c = chunk.strip().lower()
        if not c:
            continue
        if c not in valid:
            raise argparse.ArgumentTypeError(
                f"Invalid --report value '{c}'. Choices: html, csv, json.")
        if c not in out:
            out.append(c)
    return out


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exonet.py",
        description=(
            "EXO NET Pro [ Professional Ethical Hacking Toolkit ] - an "
            "advanced reconnaissance and assessment scanner. Use only on "
            "networks you own or have explicit written permission to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python exonet.py --target 192.168.1.1\n"
            "  python exonet.py --target 192.168.1.0/24 --discover\n"
            "  python exonet.py --target 192.168.1.0/24 --discover --scan\n"
            "  python exonet.py --target 192.168.1.1 --ports 1-1024 --timing 4\n"
            "  python exonet.py --target 192.168.1.1 --scan-type syn --os-detect\n"
            "  python exonet.py --target 192.168.1.0/24 --aggressive --report html,csv\n"
            "\n"
            "EXO NET Pro examples:\n"
            "  python exonet.py --target 192.168.1.0/24 --pro --report html --save\n"
            "  python exonet.py --target 192.168.1.1 --whois --vuln --risk --report html --save\n"
            "  python exonet.py --target 192.168.1.1 --pro --output-pdf --save\n"
        ),
    )

    parser.add_argument("--version", action="version",
                        version=f"EXO NET Pro {__version__}")

    # ---- target & ports ----
    parser.add_argument("--target", required=True, type=_parse_target,
                        help="IP or CIDR network (e.g. 192.168.1.1 or 10.0.0.0/24).")
    parser.add_argument("--ports", default=None,
                        help="TCP ports: '80', '22,80,443', '1-1024', or a mix. "
                             "Defaults to a curated common-ports list.")
    parser.add_argument("--udp", action="store_true",
                        help="Also run a UDP scan.")
    parser.add_argument("--udp-ports", default=None,
                        help="UDP ports list (same syntax as --ports).")

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
                               help="Preset: T1, no banner grabs, no OS detect.")
    profile_group.add_argument("--aggressive", action="store_true",
                               help="Preset: T4 + UDP + banners + OS detect.")

    # ---- discovery / detection toggles ----
    parser.add_argument("--no-arp", action="store_true",
                        help="Skip ARP discovery (only ICMP and TCP-ping).")
    parser.add_argument("--no-tcp-ping", action="store_true",
                        help="Skip TCP-ping fallback during discovery.")
    parser.add_argument("--no-banners", action="store_true",
                        help="Skip banner / version grabbing on open ports.")
    parser.add_argument("--os-detect", action="store_true",
                        help="Enable basic OS fingerprinting (TTL-based).")
    parser.add_argument("--oui-file", default=None, metavar="PATH",
                        help="Load an external OUI database file for MAC vendor "
                             "lookup (Wireshark manuf or IEEE oui.txt format).")

    # ---- evasion ----
    parser.add_argument("--evasion", action="store_true",
                        help="Enable mild evasion: random inter-probe jitter "
                             "(<=0.5s) and random source ports.")

    # ---- output / save ----
    parser.add_argument("--output", choices=["table", "json"], default="table",
                        help="stdout output format. (default: table)")
    parser.add_argument("--report", type=_parse_report, default=[],
                        metavar="FORMATS",
                        help="Comma-separated report files to write (under --save). "
                             "Choices: html, csv, json. Example: --report html,csv")
    parser.add_argument("--save", nargs="?", const="./exonet_results", default=None,
                        metavar="DIR",
                        help="Save results to a timestamped subdirectory. Optional "
                             "DIR is the base path (default ./exonet_results).")
    parser.add_argument("--screenshots", action="store_true",
                        help="Capture HTML + headers from open HTTP/HTTPS ports. "
                             "Implies --save. Add 'playwright' for PNG screenshots.")
    parser.add_argument("--screenshots-png", action="store_true",
                        help="Also capture PNG screenshots (requires playwright).")

    # ---- credentials awareness ----
    parser.add_argument("--show-default-creds", action="store_true",
                        help="After the scan, print historical default credentials "
                             "for any detected services (display-only; the scanner "
                             "NEVER attempts to log in).")

    # ---- EXO NET Pro flags --------------------------------------------------
    pro_group = parser.add_argument_group("EXO NET Pro")
    pro_group.add_argument("--pro", action="store_true",
                           help="Enable ALL pro features: WHOIS + DNS + "
                                "vulnerability checks + risk scoring + "
                                "professional pentest report.")
    pro_group.add_argument("--whois", action="store_true",
                           help="Run WHOIS + DNS recon on each host's hostname/IP.")
    pro_group.add_argument("--subdomains", action="store_true",
                           help="With --whois, also brute-force common subdomains.")
    pro_group.add_argument("--vuln", action="store_true",
                           help="Look up CVEs for detected services and run "
                                "SSL/TLS health checks on TLS ports.")
    pro_group.add_argument("--risk", action="store_true",
                           help="Compute a 0-100 risk score per host.")
    pro_group.add_argument("--output-pdf", action="store_true",
                           help="Also export the pro report as a PDF (requires "
                                "weasyprint).")

    # ---- ux ----
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress the startup ASCII banner.")
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
    """Translate --stealth / --aggressive / --pro into their underlying flags."""
    if args.stealth:
        args.timing = 1
        args.no_banners = True
        args.os_detect = False
        if args.scan_type == "auto":
            args.scan_type = "syn"
    elif args.aggressive:
        args.timing = 4
        args.no_banners = False
        args.os_detect = True
        if not args.udp:
            args.udp = True

    # --pro is additive, not exclusive. It fans out into the individual flags
    # so users can still turn one feature off explicitly afterwards (argparse
    # processes flags in order, but boolean store_true is idempotent).
    if args.pro:
        args.whois = True
        args.vuln = True
        args.risk = True
        # If the user passed --pro without --report, they probably want HTML.
        if not args.report:
            args.report = ["html"]


# -----------------------------------------------------------------------------
# Banner grabbing (parallel across all open ports of all hosts)
# -----------------------------------------------------------------------------

def _grab_banners(hosts: List[HostResult], timeout: float, threads: int,
                  progress: Optional[ui.ProgressBar]) -> None:
    jobs: list[tuple[HostResult, PortResult]] = []
    for h in hosts:
        for p in h.open_ports:
            if p.proto == "tcp":
                jobs.append((h, p))
    if not jobs:
        return

    def _work(host: HostResult, pr: PortResult):
        banner_str, details = banners_mod.grab(host.ip, pr.port, timeout)
        pr.banner = banner_str
        pr.details = details or {}

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
# Default-credentials awareness output
# -----------------------------------------------------------------------------

def _print_default_creds(hosts: List[HostResult]) -> None:
    """Print historical default credentials for services detected in the scan.

    This is purely informational - the scanner never authenticates with these.
    """
    seen: dict[str, list[tuple[str, str, int]]] = {}
    for h in hosts:
        for p in h.open_ports:
            svc = (p.service or "").lower()
            if not svc:
                continue
            defaults = credentials.lookup(svc)
            if not defaults:
                continue
            seen.setdefault(svc, []).append((h.ip, h.hostname or "", p.port))

    if not seen:
        return

    print()
    print("=== Default credentials reference (informational) ===")
    print("Sources: vendor manuals + public-domain default-password lists.")
    print("If any of your gear still uses these, ROTATE THEM NOW.")
    print("The scanner does NOT attempt these credentials. This is a "
          "memory-aid only.\n")
    for svc, instances in sorted(seen.items()):
        defaults = credentials.lookup(svc)
        host_strs = [f"{ip}:{port}" + (f" ({hn})" if hn else "")
                     for ip, hn, port in instances]
        print(f"  {svc.upper()} - found on: {', '.join(host_strs)}")
        for user, pw in defaults:
            print(f"    {user!r:>16} : {pw!r}")
        print()


# -----------------------------------------------------------------------------
# Pro-summary stdout block (printed after the table)
# -----------------------------------------------------------------------------

def _print_pro_summary(hosts: List[HostResult]) -> None:
    """Quick text summary of risk + firewall + CVE counts."""
    if not hosts:
        return
    any_pro_data = any(
        h.risk_level or h.firewall_info or h.whois_data or h.dns_records
        or any(p.cves or p.ssl_info for p in h.ports)
        for h in hosts
    )
    if not any_pro_data:
        return
    print()
    print("=== EXO NET Pro summary ===")
    for h in hosts:
        bits = []
        if h.risk_level is not None:
            bits.append(f"risk={h.risk_level}({h.risk_score}/100)")
        if h.firewall_info is not None:
            fw = h.firewall_info
            label = "fw=" + ("on" if fw.get("detected") else "off")
            label += f"/{fw.get('confidence', '?')}"
            bits.append(label)
        n_cves = sum(len(p.cves or []) for p in h.open_ports)
        if n_cves:
            bits.append(f"cves={n_cves}")
        n_subs = len(h.subdomains)
        if n_subs:
            bits.append(f"subdomains={n_subs}")
        if not bits:
            continue
        print(f"  {h.ip:<16}  " + "  ".join(bits))


# -----------------------------------------------------------------------------
# Report writing
# -----------------------------------------------------------------------------

def _write_reports(hosts: List[HostResult], save_dir: Path,
                   formats: List[str], target: str, pro: bool,
                   output_pdf: bool) -> None:
    if not formats and not pro and not output_pdf:
        return
    generated_at = time.strftime("%Y-%m-%d %H:%M:%S %z").strip()
    for fmt in formats:
        try:
            if fmt == "html":
                if pro:
                    dest = save_dir / "report_pro.html"
                    report_pro.write_html(hosts, dest, generated_at, target,
                                          version=__version__)
                else:
                    dest = save_dir / "report.html"
                    report.write_html(hosts, dest, generated_at, target)
            elif fmt == "csv":
                dest = save_dir / "report.csv"
                report.write_csv(hosts, dest)
            elif fmt == "json":
                dest = save_dir / "report.json"
                report.write_json(hosts, dest)
            else:
                continue
            ui.good(f"Report written: {dest}")
        except Exception as exc:
            ui.warn(f"Failed to write {fmt} report: "
                    f"{exc.__class__.__name__}: {exc}")

    # PDF (pro only).
    if output_pdf:
        try:
            dest = save_dir / "report_pro.pdf"
            ok = report_pro.write_pdf(hosts, dest, generated_at, target,
                                      version=__version__)
            if ok:
                ui.good(f"Report written: {dest}")
        except Exception as exc:
            ui.warn(f"Failed to write PDF report: "
                    f"{exc.__class__.__name__}: {exc}")


# -----------------------------------------------------------------------------
# Pro phases
# -----------------------------------------------------------------------------

def _phase_whois(hosts: List[HostResult], with_subdomains: bool) -> None:
    ui.info("WHOIS / DNS recon...")
    for h in hosts:
        try:
            whois_mod.run(h, do_whois=True, do_dns=True,
                          do_subdomains=with_subdomains)
        except Exception as exc:
            ui.warn(f"WHOIS/DNS phase error for {h.ip}: "
                    f"{exc.__class__.__name__}: {exc}")


def _phase_vuln(hosts: List[HostResult]) -> None:
    ui.info("Vulnerability checks (CVE + SSL)...")
    for h in hosts:
        try:
            vuln.run(h, do_cves=True, do_ssl=True)
        except Exception as exc:
            ui.warn(f"Vuln phase error for {h.ip}: "
                    f"{exc.__class__.__name__}: {exc}")


def _phase_firewall(hosts: List[HostResult]) -> None:
    """Always cheap; runs whenever risk or firewall is needed."""
    for h in hosts:
        try:
            firewall_mod.detect(h)
        except Exception as exc:
            ui.warn(f"Firewall analysis error for {h.ip}: "
                    f"{exc.__class__.__name__}: {exc}")


def _phase_risk(hosts: List[HostResult]) -> None:
    ui.info("Computing risk scores...")
    for h in hosts:
        try:
            risk_mod.annotate(h)
        except Exception as exc:
            ui.warn(f"Risk scoring error for {h.ip}: "
                    f"{exc.__class__.__name__}: {exc}")
    # Show a short breakdown.
    breakdown = {}
    for h in hosts:
        breakdown[h.risk_level or "INFO"] = breakdown.get(h.risk_level or "INFO", 0) + 1
    if breakdown:
        rendered = " | ".join(f"{lvl}:{n}"
                              for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                              for n in (breakdown.get(lvl, 0),) if n)
        ui.good(f"Risk distribution: {rendered}")


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
    evasion_policy = evasion_mod.from_args(args.evasion)

    cap_line = (f"Timing: T{args.timing} ({profile.name}) | "
                f"caps: {privilege.describe_capabilities()}")
    if evasion_policy.enabled:
        cap_line += f" | evasion: jitter<={evasion_policy.jitter_max_s}s, random sport"
    ui.info(cap_line)

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

    # Optional external OUI table.
    extra_oui: dict = {}
    if args.oui_file:
        extra_oui = oui.load_from_file(args.oui_file)
        if extra_oui:
            ui.info(f"Loaded {len(extra_oui)} OUI entries from {args.oui_file}")
        else:
            ui.warn(f"OUI file {args.oui_file} loaded 0 entries; using bundled table only.")

    # Set up save directory if requested (or implied by --report / --screenshots / --output-pdf).
    save_dir: Optional[Path] = None
    needs_save = bool(args.save) or bool(args.report) or args.screenshots or args.output_pdf
    if needs_save:
        base = args.save or "./exonet_results"
        save_dir = storage.make_session_dir(base, str(args.target))
        ui.info(f"Saving outputs to {save_dir}")

    is_single_host = network.num_addresses == 1
    do_discover = args.discover or (not is_single_host and not args.scan)
    do_scan = args.scan or is_single_host or do_discover

    # ---- Phase 1: Discovery ------------------------------------------------
    if is_single_host:
        host = HostResult(ip=str(network.network_address), alive=True,
                          discovered_via=["assumed"])
        host.hostname = discovery.reverse_dns(host.ip)
        ttl = discovery.icmp_ping(host.ip, profile.discovery_timeout)
        if ttl is not None and ttl > 0:
            host.ttl = ttl
            if "icmp" not in host.discovered_via:
                host.discovered_via.append("icmp")
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
            if save_dir:
                _write_reports([], save_dir, args.report, str(args.target),
                               pro=args.pro, output_pdf=args.output_pdf)
            return 0
        ui.good(f"{len(hosts)} live host(s) discovered.")

    if not do_scan:
        for h in hosts:
            if h.mac:
                h.vendor = oui.lookup(h.mac, extra_oui)
            if args.os_detect:
                h.os_guess = osfp.guess_from_ttl(h.ttl)
        # Pro-only phases that don't need port data still run if requested.
        if args.whois:
            _phase_whois(hosts, with_subdomains=args.subdomains)
        if args.risk or args.pro:
            _phase_firewall(hosts)
            _phase_risk(hosts)
        _render(hosts, args)
        if save_dir:
            _write_reports(hosts, save_dir, args.report, str(args.target),
                           pro=args.pro, output_pdf=args.output_pdf)
        return 0

    # ---- Phase 2: Port scan ------------------------------------------------
    total_ports = len(hosts) * (len(tcp_ports) + (len(udp_ports) if args.udp else 0))
    scan_prog: Optional[ui.ProgressBar] = None
    if not args.no_progress:
        scan_prog = ui.ProgressBar(total_ports, label="portscan")

    t0 = time.time()
    for host in hosts:
        host.ports.extend(
            portscan.scan_tcp(host.ip, tcp_ports, profile, tcp_scan,
                              evasion=evasion_policy, progress=scan_prog)
        )
        if args.udp:
            host.ports.extend(
                portscan.scan_udp(host.ip, udp_ports, profile,
                                  evasion=evasion_policy, progress=scan_prog)
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
            host.vendor = oui.lookup(host.mac, extra_oui)
        if args.os_detect:
            host.os_guess = osfp.guess_from_ttl(host.ttl)

    # ---- Phase 4: Screenshots (optional) -----------------------------------
    if args.screenshots and save_dir:
        ss_dir = save_dir / "screenshots"
        ss_dir.mkdir(exist_ok=True)
        ui.info(f"Capturing HTTP pages to {ss_dir}/")
        for host in hosts:
            if any(p.port in (*screenshots.HTTP_PORTS, *screenshots.HTTPS_PORTS)
                   for p in host.open_ports):
                screenshots.capture(
                    host, ss_dir,
                    timeout=max(5.0, profile.timeout * 5),
                    png=args.screenshots_png,
                )

    # ---- Phase 5 (Pro): WHOIS / DNS recon ---------------------------------
    if args.whois:
        _phase_whois(hosts, with_subdomains=args.subdomains)

    # ---- Phase 6 (Pro): Vulnerability checks ------------------------------
    if args.vuln:
        _phase_vuln(hosts)

    # ---- Phase 7 (Pro): Firewall + risk -----------------------------------
    if args.risk or args.pro:
        _phase_firewall(hosts)
        _phase_risk(hosts)

    elapsed = time.time() - t0
    ui.info(f"Scan finished in {elapsed:.2f}s.")

    # ---- Phase 8: Output --------------------------------------------------
    _render(hosts, args)

    if save_dir:
        # Default to writing both HTML and JSON when --save is given without --report.
        formats = list(args.report)
        if not formats and args.save:
            formats = ["html", "json"]
        _write_reports(hosts, save_dir, formats, str(args.target),
                       pro=args.pro, output_pdf=args.output_pdf)

    if args.show_default_creds:
        _print_default_creds(hosts)

    _print_pro_summary(hosts)

    return 0


def _render(hosts: List[HostResult], args: argparse.Namespace) -> None:
    if args.output == "json":
        output.render_json(hosts)
    else:
        output.render_table(hosts)


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    # No CLI flags at all -> launch the interactive Rich TUI menu.
    # Any explicit flag (--target, --help, --version, ...) keeps the
    # original non-interactive behavior.
    if not argv:
        try:
            from . import menu
        except SystemExit as exc:
            return int(exc.code) if isinstance(exc.code, int) else 1
        try:
            return menu.run_interactive()
        except KeyboardInterrupt:
            print()
            ui.warn("Interrupted by user.")
            return 130

    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print()
        ui.warn("Interrupted by user.")
        return 130
