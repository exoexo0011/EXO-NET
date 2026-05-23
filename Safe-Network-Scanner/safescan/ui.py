"""Colored output, banner, and a tiny thread-safe progress bar."""

from __future__ import annotations

import sys
import threading
from typing import Optional

# ---- colorama (graceful fallback) -------------------------------------------
try:
    from colorama import Fore, Style, init as _colorama_init
    _colorama_init(autoreset=True)
    _COLOR = True
except ImportError:  # pragma: no cover
    _COLOR = False

    class _Dummy:
        def __getattr__(self, _name): return ""
    Fore = Style = _Dummy()  # type: ignore


def _enabled() -> bool:
    return _COLOR and sys.stdout.isatty()


def c(text: str, color: str) -> str:
    """Return `text` wrapped in `color` if a TTY supports it."""
    if not _enabled():
        return text
    return f"{color}{text}{Style.RESET_ALL}"


# ---- log helpers ------------------------------------------------------------
# Logs go to stderr so they don't pollute machine-readable output (e.g. JSON)
# piped from stdout.

def info(msg: str) -> None:
    print(c("[*] ", Fore.CYAN) + msg, file=sys.stderr)


def good(msg: str) -> None:
    print(c("[+] ", Fore.GREEN) + msg, file=sys.stderr)


def warn(msg: str) -> None:
    print(c("[!] ", Fore.YELLOW) + msg, file=sys.stderr)


def bad(msg: str) -> None:
    print(c("[-] ", Fore.RED) + msg, file=sys.stderr)


def dim(msg: str) -> str:
    return c(msg, Style.DIM if _enabled() else "")


# ---- banner -----------------------------------------------------------------
BANNER = r"""
   _____        __         _   _      _      _____
  / ____|      / _|       | \ | |    | |    / ____|
 | (___   __ _| |_ ___    |  \| | ___| |_  | (___   ___ __ _ _ __
  \___ \ / _` |  _/ _ \   | . ` |/ _ \ __|  \___ \ / __/ _` | '_ \
  ____) | (_| | ||  __/   | |\  |  __/ |_   ____) | (_| (_| | | | |
 |_____/ \__,_|_| \___|   |_| \_|\___|\__| |_____/ \___\__,_|_| |_|

           Safe-Network-Scanner v{ver} - Educational Use Only
"""


def show_banner(version: str) -> None:
    print(c(BANNER.format(ver=version), Fore.MAGENTA), file=sys.stderr)
    warn("Only scan networks you OWN or have explicit WRITTEN permission to scan.")
    warn("Unauthorized scanning may violate computer-misuse laws in your jurisdiction.\n")


# ---- progress bar -----------------------------------------------------------
class ProgressBar:
    """Minimal thread-safe progress bar, written to stderr.

    Silent when stderr is not a TTY (so JSON output stays clean when redirected).
    """

    def __init__(self, total: int, label: str = "") -> None:
        self.total = max(0, total)
        self.label = label
        self.done = 0
        self._lock = threading.Lock()
        self._enabled = sys.stderr.isatty() and self.total > 0
        if self._enabled:
            self._render()

    def tick(self, n: int = 1, note: Optional[str] = None) -> None:
        if not self._enabled:
            return
        with self._lock:
            self.done = min(self.total, self.done + n)
            self._render(note)

    def close(self) -> None:
        if self._enabled:
            sys.stderr.write("\n")
            sys.stderr.flush()

    def _render(self, note: Optional[str] = None) -> None:
        width = 30
        pct = self.done / self.total if self.total else 1.0
        filled = int(width * pct)
        bar = "#" * filled + "-" * (width - filled)
        suffix = f" {note}" if note else ""
        sys.stderr.write(
            f"\r{self.label} [{bar}] {self.done}/{self.total} "
            f"{pct*100:5.1f}%{suffix}    "
        )
        sys.stderr.flush()
