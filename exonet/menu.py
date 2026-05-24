"""Interactive Rich-powered TUI menu for EXO NET.

Shown when ``python exonet.py`` is invoked with no command-line arguments.
The user picks a scan preset (or builds a Custom one), confirms, watches a
live dashboard while it runs, and is offered to open the resulting HTML
report in their browser.

Anything that takes ``--target`` (or any other CLI flag) keeps the original
non-interactive path in :func:`exonet.cli.main`.
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import sys
import threading
import time
import webbrowser
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

# ---- rich (required) --------------------------------------------------------
try:
    from rich.align import Align
    from rich.box import DOUBLE, ROUNDED
    from rich.columns import Columns
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.prompt import Confirm, IntPrompt, Prompt
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
except ImportError as exc:  # pragma: no cover
    sys.stderr.write(
        "[!] EXO NET interactive menu requires the 'rich' package.\n"
        "    Install it with:  pip install rich\n"
    )
    raise SystemExit(2) from exc

from . import __version__
from .types import HostResult, PortResult


# ---- EXO NET theme ----------------------------------------------------------
GREEN = "#00ff41"
CYAN = "#00cfff"
RED = "#ff003c"
YELLOW = "#ffe600"
DIM = "grey50"

STYLE_TITLE = f"bold {GREEN}"
STYLE_SUB = f"italic {CYAN}"
STYLE_OK = f"bold {GREEN}"
STYLE_INFO = CYAN
STYLE_WARN = f"bold {YELLOW}"
STYLE_BAD = f"bold {RED}"
STYLE_ACCENT = f"bold {CYAN}"
STYLE_KEY = f"bold {YELLOW}"

# Single shared console; force a colored terminal even when stderr isn't a TTY.
console = Console(highlight=False)


# =============================================================================
# Static screens
# =============================================================================
def _banner_panel() -> Panel:
    title = Text("EXO NET Pro", style=STYLE_TITLE)
    title.stylize(STYLE_TITLE)
    sub = Text(f"v{__version__}  //  Professional Network Scanner",
               style=STYLE_SUB)
    body = Text.assemble(
        ("Only scan networks you own or have ", DIM),
        ("explicit written permission ", f"bold {YELLOW}"),
        ("to test.", DIM),
    )
    art = Text(
        "  ╔═╗ ╦╔═ ╔═╗   ╔╗╔ ╔═╗ ╔╦╗\n"
        "  ║╣  ╠╩╗ ║ ║   ║║║ ║╣   ║ \n"
        "  ╚═╝ ╩ ╩ ╚═╝   ╝╚╝ ╚═╝  ╩ ",
        style=f"bold {GREEN}",
    )
    inner = Group(
        Align.center(art),
        Align.center(title),
        Align.center(sub),
        Text(""),
        Align.center(body),
    )
    return Panel(inner, box=DOUBLE, border_style=GREEN, padding=(1, 4))


def _main_menu_panel() -> Panel:
    rows = Table.grid(padding=(0, 2), expand=True)
    rows.add_column(justify="right", width=5, style=STYLE_KEY)
    rows.add_column(justify="left", style=f"bold {GREEN}", min_width=18)
    rows.add_column(justify="left", style=DIM)

    items = [
        ("[1]", "Quick Scan",      "common ports only"),
        ("[2]", "Full Scan",       "discover + all ports"),
        ("[3]", "Pro Scan",        "full + vuln + report"),
        ("[4]", "Stealth Scan",    "slow + evasion"),
        ("[5]", "Aggressive Scan", "T4 + UDP + banners"),
        ("[6]", "Custom Scan",     "choose your options"),
    ]
    for k, name, desc in items:
        rows.add_row(k, name, f"— {desc}")
    rows.add_row("", "", "")
    rows.add_row(f"[Q]", Text("Quit", style=f"bold {RED}"), "")

    title = Text("  SELECT  SCAN  PROFILE  ", style=f"bold {CYAN} on grey11")
    return Panel(rows, title=title, box=DOUBLE, border_style=CYAN,
                 padding=(1, 4))


# =============================================================================
# Live-scan instrumentation
# =============================================================================
@dataclass
class LiveState:
    """Mutable state shared between the worker thread and the live dashboard."""
    target: str = ""
    scan_label: str = ""
    started_at: float = field(default_factory=time.time)
    log: deque = field(default_factory=lambda: deque(maxlen=12))
    hosts: Dict[str, HostResult] = field(default_factory=dict)
    final_hosts: List[HostResult] = field(default_factory=list)
    save_dir: Optional[Path] = None
    current_phase: str = "init"
    finished: bool = False
    error: Optional[str] = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add_log(self, level: str, msg: str) -> None:
        with self._lock:
            self.log.append((time.time(), level, msg))

    def upsert_host(self, host: HostResult) -> None:
        with self._lock:
            existing = self.hosts.get(host.ip)
            if existing is None:
                self.hosts[host.ip] = host
            else:
                # merge so we never lose data that came from another phase
                if host.hostname and not existing.hostname:
                    existing.hostname = host.hostname
                if host.mac and not existing.mac:
                    existing.mac = host.mac
                if host.vendor and not existing.vendor:
                    existing.vendor = host.vendor
                if host.ports:
                    existing.ports = host.ports

    def merge_ports(self, ip: str, results: List[PortResult]) -> None:
        with self._lock:
            host = self.hosts.get(ip)
            if host is None:
                host = HostResult(ip=ip, alive=True)
                self.hosts[ip] = host
            # de-dup by (port, proto)
            seen = {(p.port, p.proto) for p in host.ports}
            for r in results:
                if (r.port, r.proto) not in seen:
                    host.ports.append(r)


class _RichProgressBar:
    """Drop-in replacement for ``ui.ProgressBar`` that drives a phase task.

    The scanner constructs ``ui.ProgressBar(total, label="discover")`` etc.
    We attach each instance to the menu's shared :class:`Progress` so the
    dashboard renders real progress bars per phase.
    """

    def __init__(self, total: int, label: str = "") -> None:
        self.total = max(0, total)
        self.label = label
        self.done = 0
        prog = _state_holder.progress
        if prog is None:
            self._task = None
            return
        # Friendlier phase label
        nice = {
            "discover": "Host discovery",
            "portscan": "Port scan",
            "banners ": "Banner grabbing",
            "banners":  "Banner grabbing",
        }.get(label.strip(), label.strip().title() or "Working")
        self._task = prog.add_task(
            description=f"[{CYAN}]{nice}[/]",
            total=self.total or None,
        )
        if _state_holder.live is not None:
            _state_holder.live.state.current_phase = nice

    def tick(self, n: int = 1, note: Optional[str] = None) -> None:
        self.done = min(self.total, self.done + n) if self.total else self.done + n
        prog = _state_holder.progress
        if prog is not None and self._task is not None:
            prog.update(self._task, advance=n)

    def close(self) -> None:
        prog = _state_holder.progress
        if prog is not None and self._task is not None:
            # Mark as fully complete so the bar stops at 100%
            if self.total:
                prog.update(self._task, completed=self.total)


class _StateHolder:
    """Module-level pointer juggled while the live dashboard is mounted."""
    progress: Optional[Progress] = None
    live: Optional["_LiveSession"] = None


_state_holder = _StateHolder()


# =============================================================================
# Patch context: instrument exonet internals while the dashboard is up
# =============================================================================
@contextlib.contextmanager
def _instrumented(state: LiveState):
    """Monkey-patch the scanner so its events drive ``state``.

    Restores everything on exit, even if the scan raises.
    """
    from . import cli as cli_mod
    from . import discovery, output, portscan, storage, ui

    originals = {
        "ui.info":          ui.info,
        "ui.good":          ui.good,
        "ui.warn":          ui.warn,
        "ui.bad":           ui.bad,
        "ui.show_banner":   ui.show_banner,
        "ui.ProgressBar":   ui.ProgressBar,
        "cli.ui":           cli_mod.ui,
        "cli._render":      cli_mod._render,
        "discovery.discover": discovery.discover,
        "portscan.scan_tcp":  portscan.scan_tcp,
        "portscan.scan_udp":  portscan.scan_udp,
        "storage.make_session_dir": storage.make_session_dir,
        "output.render_table": output.render_table,
    }

    # ---- log capture ------------------------------------------------------
    def _make_logger(level: str):
        def _logger(msg: str) -> None:
            state.add_log(level, str(msg))
        return _logger

    ui.info = _make_logger("info")
    ui.good = _make_logger("good")
    ui.warn = _make_logger("warn")
    ui.bad  = _make_logger("bad")
    ui.show_banner = lambda *_a, **_kw: None  # we already showed our own
    ui.ProgressBar = _RichProgressBar
    cli_mod.ui = ui  # cli holds a module reference; refresh in case

    # ---- discovery: capture hosts as soon as they are found ---------------
    orig_discover = discovery.discover

    def _wrapped_discover(*args, **kwargs):
        hosts = orig_discover(*args, **kwargs)
        for h in hosts:
            state.upsert_host(h)
        return hosts

    discovery.discover = _wrapped_discover

    # ---- portscan: stream open-port updates per host ----------------------
    orig_scan_tcp = portscan.scan_tcp
    orig_scan_udp = portscan.scan_udp

    def _wrapped_scan_tcp(ip, ports, *a, **kw):
        results = orig_scan_tcp(ip, ports, *a, **kw)
        state.merge_ports(ip, results)
        return results

    def _wrapped_scan_udp(ip, ports, *a, **kw):
        results = orig_scan_udp(ip, ports, *a, **kw)
        state.merge_ports(ip, results)
        return results

    portscan.scan_tcp = _wrapped_scan_tcp
    portscan.scan_udp = _wrapped_scan_udp

    # ---- save dir capture --------------------------------------------------
    orig_make_session = storage.make_session_dir

    def _wrapped_make_session(base, target):
        path = orig_make_session(base, target)
        state.save_dir = Path(path)
        return path

    storage.make_session_dir = _wrapped_make_session

    # ---- final render: capture hosts, suppress stdout table ---------------
    def _wrapped_render(hosts, _args):
        state.final_hosts = list(hosts)
        for h in hosts:
            state.upsert_host(h)

    cli_mod._render = _wrapped_render
    output.render_table = lambda *_a, **_kw: None

    try:
        yield
    finally:
        ui.info = originals["ui.info"]
        ui.good = originals["ui.good"]
        ui.warn = originals["ui.warn"]
        ui.bad  = originals["ui.bad"]
        ui.show_banner = originals["ui.show_banner"]
        ui.ProgressBar = originals["ui.ProgressBar"]
        cli_mod.ui = originals["cli.ui"]
        cli_mod._render = originals["cli._render"]
        discovery.discover = originals["discovery.discover"]
        portscan.scan_tcp = originals["portscan.scan_tcp"]
        portscan.scan_udp = originals["portscan.scan_udp"]
        storage.make_session_dir = originals["storage.make_session_dir"]
        output.render_table = originals["output.render_table"]


# =============================================================================
# Live dashboard
# =============================================================================
def _format_elapsed(seconds: float) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def _build_header(state: LiveState) -> Panel:
    elapsed = _format_elapsed(time.time() - state.started_at)
    grid = Table.grid(expand=True)
    grid.add_column(justify="left", ratio=1)
    grid.add_column(justify="center", ratio=1)
    grid.add_column(justify="right", ratio=1)
    grid.add_row(
        Text.assemble((" target ", f"on {GREEN} black"),
                      ("  " + state.target, f"bold {GREEN}")),
        Text.assemble((" profile ", f"on {CYAN} black"),
                      ("  " + state.scan_label, f"bold {CYAN}")),
        Text.assemble((" elapsed ", f"on {YELLOW} black"),
                      ("  " + elapsed, f"bold {YELLOW}")),
    )
    return Panel(grid, box=ROUNDED, border_style=GREEN,
                 title=f"[bold {GREEN}]EXO NET // LIVE SCAN[/]",
                 padding=(0, 2))


def _build_hosts_panel(state: LiveState) -> Panel:
    table = Table(box=None, expand=True, header_style=f"bold {CYAN}",
                  pad_edge=False, show_edge=False)
    table.add_column("IP", style=f"bold {GREEN}", no_wrap=True)
    table.add_column("Hostname", style=CYAN, no_wrap=True)
    table.add_column("MAC / Vendor", style=DIM, no_wrap=True)
    table.add_column("Open ports", style=YELLOW)
    table.add_column("Risk", style=f"bold {RED}", no_wrap=True)

    with state._lock:
        hosts = list(state.hosts.values())

    if not hosts:
        return Panel(
            Align.center(Text("waiting for hosts…", style=DIM), vertical="middle"),
            title=f"[bold {GREEN}]hosts[/]", box=ROUNDED,
            border_style=GREEN, padding=(0, 2))

    # show up to 12 to keep the layout tidy
    for h in hosts[:12]:
        open_ports = [p for p in h.ports if p.state.startswith("open")]
        ports_txt = ", ".join(str(p.port) for p in sorted(open_ports, key=lambda r: r.port)) or "—"
        mac_bits = h.mac or "—"
        if h.vendor:
            mac_bits = f"{h.mac}  [{h.vendor}]"
        risk = ""
        if h.risk_level:
            color = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW,
                     "LOW": CYAN, "INFO": DIM}.get(h.risk_level, DIM)
            risk = f"[{color}]{h.risk_level}[/]"
        table.add_row(h.ip, h.hostname or "—", mac_bits, ports_txt, risk)

    if len(hosts) > 12:
        table.add_row("…", f"+{len(hosts) - 12} more", "", "", "")

    return Panel(
        table, title=f"[bold {GREEN}]hosts ({len(hosts)})[/]", box=ROUNDED,
        border_style=GREEN, padding=(0, 1))


def _build_log_panel(state: LiveState) -> Panel:
    with state._lock:
        entries = list(state.log)

    if not entries:
        body = Text("idle…", style=DIM)
    else:
        rendered = Text()
        styles = {"info": CYAN, "good": GREEN, "warn": YELLOW, "bad": RED}
        prefixes = {"info": "[*]", "good": "[+]", "warn": "[!]", "bad": "[-]"}
        for ts, level, msg in entries[-8:]:
            color = styles.get(level, "")
            tstamp = time.strftime("%H:%M:%S", time.localtime(ts))
            rendered.append(f"{tstamp} ", style=DIM)
            rendered.append(f"{prefixes.get(level, '[?]')} ", style=color)
            rendered.append(msg + "\n", style=color if level != "info" else "")
        body = rendered

    return Panel(body, title=f"[bold {YELLOW}]log[/]", box=ROUNDED,
                 border_style=YELLOW, padding=(0, 1))


def _build_progress_panel(progress: Progress) -> Panel:
    return Panel(progress, title=f"[bold {CYAN}]phase progress[/]",
                 box=ROUNDED, border_style=CYAN, padding=(0, 2))


class _LiveSession:
    """Owns the Layout + Progress + Live for one scan run."""

    def __init__(self, state: LiveState) -> None:
        self.state = state
        self.progress = Progress(
            SpinnerColumn(style=GREEN),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None, complete_style=GREEN, finished_style=GREEN,
                      pulse_style=CYAN),
            TextColumn(
                "[progress.percentage]{task.percentage:>5.1f}%",
                style=YELLOW),
            TextColumn("•"),
            TextColumn("{task.completed}/{task.total}", style=DIM),
            TimeElapsedColumn(),
            console=console,
            transient=False,
            expand=True,
        )
        self.layout = Layout(name="root")
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="phases", size=8),
            Layout(name="hosts", minimum_size=6, ratio=2),
            Layout(name="log", minimum_size=6, size=10),
        )

    def render(self) -> Layout:
        self.layout["header"].update(_build_header(self.state))
        self.layout["phases"].update(_build_progress_panel(self.progress))
        self.layout["hosts"].update(_build_hosts_panel(self.state))
        self.layout["log"].update(_build_log_panel(self.state))
        return self.layout


# =============================================================================
# Scan execution
# =============================================================================
def _run_scan_with_live(args: argparse.Namespace, state: LiveState) -> int:
    """Run ``cli.run`` in a worker thread while painting the live dashboard."""
    from . import cli as cli_mod

    session = _LiveSession(state)
    rc_box: Dict[str, int] = {"rc": 0}

    def _worker():
        try:
            rc_box["rc"] = cli_mod.run(args)
        except SystemExit as exc:
            rc_box["rc"] = int(exc.code) if isinstance(exc.code, int) else 1
            state.error = f"scanner exited: {exc.code}"
        except Exception as exc:
            rc_box["rc"] = 1
            state.error = f"{exc.__class__.__name__}: {exc}"
            state.add_log("bad", state.error)
        finally:
            state.finished = True

    _state_holder.progress = session.progress
    _state_holder.live = session

    with _instrumented(state):
        worker = threading.Thread(target=_worker, name="exonet-scan", daemon=True)
        worker.start()

        try:
            with Live(session.render(), console=console, refresh_per_second=8,
                      screen=False, redirect_stdout=False, redirect_stderr=False) as live:
                while not state.finished:
                    live.update(session.render())
                    time.sleep(0.15)
                # one final paint
                live.update(session.render())
        finally:
            worker.join(timeout=2.0)

    _state_holder.progress = None
    _state_holder.live = None
    return rc_box["rc"]


# =============================================================================
# Prompt helpers
# =============================================================================
def _ask_target() -> Optional[str]:
    console.print()
    console.print(Panel(
        Text.assemble(
            ("Enter target ", "bold"),
            ("IP", f"bold {GREEN}"), (" or ", "bold"),
            ("CIDR range\n\n", f"bold {GREEN}"),
            ("Examples:  ", DIM),
            ("192.168.1.1", f"bold {CYAN}"),
            ("   |   ", DIM),
            ("192.168.1.0/24", f"bold {CYAN}"),
        ),
        box=ROUNDED, border_style=CYAN, title=f"[bold {YELLOW}][?] target[/]",
        padding=(1, 2),
    ))
    while True:
        spec = Prompt.ask(
            f"[bold {YELLOW}]>[/]",
            console=console,
            default="",
            show_default=False,
        ).strip()
        if not spec:
            if Confirm.ask(f"[{DIM}]cancel and return to main menu?[/]",
                           console=console, default=True):
                return None
            continue
        try:
            ipaddress.IPv4Network(spec, strict=False)
            return spec
        except (ValueError, ipaddress.AddressValueError) as exc:
            console.print(f"[{STYLE_BAD}]invalid target:[/] {exc}")


def _ask_choice(prompt: str, options: List[Tuple[str, str, str]],
                default: str) -> str:
    """Render numbered options and return the chosen key."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style=STYLE_KEY, justify="right")
    table.add_column(style=f"bold {GREEN}")
    table.add_column(style=DIM)
    for k, name, desc in options:
        table.add_row(f"[{k}]", name, f"— {desc}" if desc else "")
    console.print(Panel(table, box=ROUNDED, border_style=CYAN,
                        title=f"[bold {YELLOW}][?] {prompt}[/]",
                        padding=(1, 2)))
    keys = [k for k, _, _ in options]
    return Prompt.ask(f"[bold {YELLOW}]>[/]", console=console,
                      choices=keys, default=default, show_choices=False)


def _ask_yes_no(prompt: str, default: bool = False) -> bool:
    return Confirm.ask(f"[bold {YELLOW}][?][/] {prompt}",
                       console=console, default=default)


# =============================================================================
# Args builder
# =============================================================================
def _make_args(target: str) -> argparse.Namespace:
    """Return a fully-defaulted argparse Namespace for ``cli.run``."""
    from .cli import _build_parser
    parser = _build_parser()
    args = parser.parse_args(["--target", target])
    args.no_banner = True       # already shown
    args.no_progress = False    # we want progress events for the dashboard
    return args


# =============================================================================
# Scan presets
# =============================================================================
@dataclass
class ScanPreset:
    label: str
    modules: str
    report_label: str
    timing_label: str
    apply: Callable[[argparse.Namespace], None]


def _preset_quick(args: argparse.Namespace) -> None:
    args.timing = 3
    args.scan_type = "auto"
    # Common ports only -> leave args.ports = None (cli uses COMMON_TCP_PORTS)
    args.no_banners = False


def _preset_full(args: argparse.Namespace) -> None:
    args.discover = True
    args.scan = True
    args.ports = "1-65535"
    args.timing = 4
    args.no_banners = False
    args.os_detect = True


def _preset_pro(args: argparse.Namespace) -> None:
    _preset_full(args)
    args.pro = True
    args.whois = True
    args.vuln = True
    args.risk = True
    args.report = ["html"]
    args.save = "./exonet_results"


def _preset_stealth(args: argparse.Namespace) -> None:
    args.stealth = True       # cli's _apply_presets will translate this
    args.evasion = True


def _preset_aggressive(args: argparse.Namespace) -> None:
    args.aggressive = True    # cli's _apply_presets will translate this
    args.no_banners = False
    args.os_detect = True


PRESETS: Dict[str, ScanPreset] = {
    "1": ScanPreset(
        "Quick Scan", "discover + portscan (common ports)",
        "stdout table", "T3 normal", _preset_quick),
    "2": ScanPreset(
        "Full Scan", "discover + portscan (1-65535) + banners + os-detect",
        "stdout table", "T4 aggressive", _preset_full),
    "3": ScanPreset(
        "Pro Scan",
        "discover + portscan + banners + whois + vuln + risk + firewall",
        "HTML report saved to exonet_results/", "T4 aggressive", _preset_pro),
    "4": ScanPreset(
        "Stealth Scan", "discover + portscan (SYN, low/slow) + evasion",
        "stdout table", "T1 sneaky", _preset_stealth),
    "5": ScanPreset(
        "Aggressive Scan", "discover + portscan + UDP + banners + os-detect",
        "stdout table", "T4 aggressive", _preset_aggressive),
}


# =============================================================================
# Custom Scan flow
# =============================================================================
def _custom_scan(target: str) -> Optional[Tuple[argparse.Namespace, ScanPreset]]:
    args = _make_args(target)

    # 1. Scan type
    st_key = _ask_choice("scan type", [
        ("1", "TCP Connect", "no privileges required"),
        ("2", "TCP SYN",     "stealthier, requires raw sockets"),
        ("3", "UDP",         "TCP connect + UDP scan"),
    ], default="1")
    if st_key == "2":
        args.scan_type = "syn"
    elif st_key == "3":
        args.scan_type = "connect"
        args.udp = True
    else:
        args.scan_type = "connect"

    # 2. Timing
    timing_key = _ask_choice("timing template", [
        ("0", "T0 paranoid",   "very slow, IDS evasion"),
        ("1", "T1 sneaky",     "slow, less noisy"),
        ("2", "T2 polite",     "minimal bandwidth"),
        ("3", "T3 normal",     "default"),
        ("4", "T4 aggressive", "fast, modern networks"),
        ("5", "T5 insane",     "fastest, may miss results"),
    ], default="3")
    args.timing = int(timing_key)

    # 3. Port range
    pk = _ask_choice("port range", [
        ("1", "Common ports", "curated common-services list"),
        ("2", "1 - 1024",     "well-known ports"),
        ("3", "All ports",    "1-65535 (slow!)"),
        ("4", "Custom",       "type your own list"),
    ], default="1")
    if pk == "2":
        args.ports = "1-1024"
    elif pk == "3":
        args.ports = "1-65535"
    elif pk == "4":
        args.ports = Prompt.ask(
            f"[bold {YELLOW}]>[/] ports (e.g. 22,80,443 or 1-1024)",
            console=console, default="1-1024")
    # else (1) -> leave None for COMMON_TCP_PORTS

    # 4. Banners
    args.no_banners = not _ask_yes_no("enable banner / version grabbing?",
                                      default=True)
    # 5. OS detect
    args.os_detect = _ask_yes_no("enable OS fingerprinting?", default=False)
    # 6. Vuln scan
    if _ask_yes_no("enable vulnerability checks (CVE + SSL)?", default=False):
        args.vuln = True
        args.risk = True

    # 7. Report
    rk = _ask_choice("save report", [
        ("1", "HTML", "browseable, recommended"),
        ("2", "JSON", "machine readable"),
        ("3", "CSV",  "spreadsheet friendly"),
        ("4", "All",  "html + csv + json"),
        ("5", "None", "stdout only"),
    ], default="1")
    if rk == "1":
        args.report = ["html"]; args.save = "./exonet_results"
    elif rk == "2":
        args.report = ["json"]; args.save = "./exonet_results"
    elif rk == "3":
        args.report = ["csv"];  args.save = "./exonet_results"
    elif rk == "4":
        args.report = ["html", "json", "csv"]; args.save = "./exonet_results"
    # else (5) -> no save

    # 8. Evasion
    args.evasion = _ask_yes_no("enable evasion (jitter + random source ports)?",
                               default=False)

    # ---- summary blob for the confirm screen -------------------------------
    modules = ["discover", "portscan"]
    if not args.no_banners: modules.append("banners")
    if args.os_detect:      modules.append("os-detect")
    if args.udp:            modules.append("udp")
    if args.vuln:           modules.append("vuln")
    if args.risk:           modules.append("risk")
    if args.evasion:        modules.append("evasion")

    if args.report:
        report_label = ("/".join(args.report).upper() +
                        " saved to exonet_results/")
    else:
        report_label = "stdout only"

    preset = ScanPreset(
        label="Custom Scan",
        modules=" + ".join(modules),
        report_label=report_label,
        timing_label=f"T{args.timing}",
        apply=lambda _a: None,  # already configured
    )
    return args, preset


# =============================================================================
# Confirm + summary screens
# =============================================================================
def _confirm_screen(args: argparse.Namespace, preset: ScanPreset) -> bool:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=STYLE_KEY, justify="right")
    grid.add_column(style=f"bold {GREEN}")
    grid.add_row("[*] target:",    str(args.target))
    grid.add_row("[*] scan type:", preset.label)
    grid.add_row("[*] modules:",   preset.modules)
    grid.add_row("[*] report:",    preset.report_label)
    grid.add_row("[*] timing:",    preset.timing_label)

    console.print()
    console.print(Panel(grid, box=DOUBLE, border_style=GREEN,
                        title=f"[bold {GREEN}]READY TO SCAN[/]",
                        padding=(1, 4)))
    return _ask_yes_no("start scan?", default=True)


def _results_screen(state: LiveState) -> str:
    hosts = state.final_hosts or list(state.hosts.values())
    open_count = sum(len(h.open_ports) for h in hosts)

    risk_counts: Dict[str, int] = {}
    for h in hosts:
        if h.risk_level:
            risk_counts[h.risk_level] = risk_counts.get(h.risk_level, 0) + 1

    if risk_counts:
        risk_summary = "  ".join(
            f"{n}x [{({'CRITICAL': RED, 'HIGH': RED, 'MEDIUM': YELLOW, 'LOW': CYAN, 'INFO': DIM}.get(lvl, DIM))}]{lvl}[/]"
            for lvl, n in sorted(
                risk_counts.items(),
                key=lambda kv: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(kv[0])
                if kv[0] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] else 99))
    else:
        risk_summary = f"[{DIM}](not computed)[/]"

    report_path = _find_report(state.save_dir)
    report_str = str(report_path) if report_path else f"[{DIM}]not saved[/]"

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=STYLE_KEY, justify="right")
    grid.add_column(style=f"bold {GREEN}")
    grid.add_row("hosts found:",   str(len(hosts)))
    grid.add_row("open ports:",    str(open_count))
    grid.add_row("risk scores:",   risk_summary)
    grid.add_row("report saved:",  report_str)

    actions = Table.grid(padding=(0, 2))
    actions.add_column(style=STYLE_KEY, justify="right")
    actions.add_column(style=f"bold {GREEN}")
    actions.add_row("[1]", "Scan again (same target & profile)")
    actions.add_row("[2]", "New target")
    actions.add_row("[3]", f"Open report{'  (no report)' if not report_path else ''}")
    actions.add_row("[Q]", Text("Quit", style=f"bold {RED}"))

    console.print()
    console.print(Panel(
        Group(grid, Rule(style=GREEN), actions),
        box=DOUBLE, border_style=GREEN,
        title=f"[bold {GREEN}]SCAN COMPLETE[/]",
        padding=(1, 4),
    ))

    while True:
        choice = Prompt.ask(
            f"[bold {YELLOW}]>[/]", console=console,
            choices=["1", "2", "3", "q", "Q"],
            default="2", show_choices=False).lower()
        if choice == "3":
            if not report_path:
                console.print(f"[{STYLE_WARN}]no report file to open.[/]")
                continue
            opened = False
            try:
                opened = webbrowser.open(report_path.resolve().as_uri())
            except Exception as exc:
                console.print(f"[{STYLE_BAD}]could not launch browser:[/] {exc}")
            if opened:
                console.print(f"[{STYLE_OK}]opened {report_path}[/]")
            else:
                console.print(
                    f"[{STYLE_WARN}]no browser available; report path:[/] "
                    f"{report_path}")
            continue
        return choice


def _find_report(save_dir: Optional[Path]) -> Optional[Path]:
    if save_dir is None or not save_dir.is_dir():
        return None
    for name in ("report_pro.html", "report.html"):
        candidate = save_dir / name
        if candidate.is_file():
            return candidate
    return None


# =============================================================================
# Top-level interactive loop
# =============================================================================
def run_interactive() -> int:
    """Entry point invoked from :func:`exonet.cli.main` when no args are given."""
    console.clear()
    console.print(_banner_panel())

    last_target: Optional[str] = None
    last_preset_key: Optional[str] = None
    last_args: Optional[argparse.Namespace] = None
    last_preset: Optional[ScanPreset] = None

    while True:
        console.print()
        console.print(_main_menu_panel())
        choice = Prompt.ask(
            f"[bold {YELLOW}]>[/]", console=console,
            choices=["1", "2", "3", "4", "5", "6", "q", "Q"],
            default="1", show_choices=False).lower()

        if choice == "q":
            console.print(f"[{STYLE_OK}]bye.[/]")
            return 0

        # ---- target -------------------------------------------------------
        target = _ask_target()
        if target is None:
            continue

        # ---- build args ---------------------------------------------------
        if choice == "6":
            built = _custom_scan(target)
            if built is None:
                continue
            args, preset = built
        else:
            preset = PRESETS[choice]
            args = _make_args(target)
            preset.apply(args)

        # ---- confirm ------------------------------------------------------
        if not _confirm_screen(args, preset):
            console.print(f"[{DIM}]aborted.[/]")
            continue

        # ---- run ---------------------------------------------------------
        last_target = target
        last_preset_key = choice
        last_args = args
        last_preset = preset

        rc = _scan_and_summarize(args, preset)
        if rc == "QUIT":
            return 0
        # rc == "AGAIN"  -> re-run same target+preset without re-prompting
        while rc == "AGAIN" and last_args is not None and last_preset is not None:
            # rebuild args fresh so a previous run's mutations don't leak
            if last_preset_key == "6":
                # custom-scan: re-use the configured args directly
                fresh = last_args
            else:
                fresh = _make_args(last_target or target)
                PRESETS[last_preset_key].apply(fresh)
            rc = _scan_and_summarize(fresh, last_preset)
        if rc == "QUIT":
            return 0
        # rc == "NEW"   -> outer loop, prompt for new target


def _scan_and_summarize(args: argparse.Namespace,
                        preset: ScanPreset) -> str:
    """Run one scan + show its results screen. Returns 'AGAIN' | 'NEW' | 'QUIT'."""
    state = LiveState(target=str(args.target), scan_label=preset.label)
    rc = _run_scan_with_live(args, state)

    if state.error:
        console.print(f"[{STYLE_BAD}]scan error:[/] {state.error}")

    choice = _results_screen(state)
    if choice == "1":
        return "AGAIN"
    if choice == "2":
        return "NEW"
    return "QUIT"
