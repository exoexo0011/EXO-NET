"""Per-port HTTP/HTTPS page snapshots.

For every open HTTP-ish port on a host we save:
  * the response body (HTML) to ``<ip>_<port>.html``
  * the response headers + status to ``<ip>_<port>.headers.txt``
  * optionally a PNG screenshot when ``playwright`` is installed.

This is intentionally stdlib-first: ``urllib.request`` handles HTTP and HTTPS
without adding a hard ``requests`` dependency. Playwright is a soft
dependency loaded lazily; if it's missing we skip the PNG step with a hint.

Useful for reconnaissance against networks you OWN, similar to EyeWitness
or aquatone.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import ui
from .types import HostResult

# Best-effort port -> scheme mapping. Extend as needed.
HTTP_PORTS = (80, 8000, 8080)
HTTPS_PORTS = (443, 8443)


def _fetch(url: str, timeout: float) -> Optional[Tuple[int, Dict[str, str], bytes]]:
    """GET `url` and return (status, headers, body) or None on error.

    TLS verification is disabled because we are usually scanning lab gear with
    self-signed certs; this is documented in the README.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "EXO-NET/1.0 (educational)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            # Read up to 1 MiB to keep saved pages small.
            return resp.status, dict(resp.headers), resp.read(1_000_000)
    except urllib.error.HTTPError as exc:
        # 4xx/5xx still has a useful body (login pages, error pages, etc.) -
        # save it instead of giving up.
        try:
            return exc.code, dict(exc.headers), exc.read()
        except Exception:
            return exc.code, dict(getattr(exc, "headers", {}) or {}), b""
    except (urllib.error.URLError, ssl.SSLError, ConnectionError, OSError, ValueError):
        return None


def _try_playwright_png(url: str, dest: Path, timeout: float) -> bool:
    """Render `url` to `dest` PNG via playwright. Returns True on success."""
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        return False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            try:
                page = browser.new_page(ignore_https_errors=True)
                page.goto(url, timeout=int(timeout * 1000))
                page.screenshot(path=str(dest), full_page=False)
            finally:
                browser.close()
        return True
    except Exception as exc:
        ui.warn(f"  playwright screenshot failed for {url}: {exc}")
        return False


def capture(
    host: HostResult,
    out_dir: Path,
    timeout: float = 5.0,
    png: bool = False,
) -> List[Path]:
    """Capture HTTP/HTTPS pages for all open web-ish ports on `host`."""
    written: List[Path] = []

    for port_result in host.open_ports:
        if port_result.proto != "tcp":
            continue
        if port_result.port in HTTP_PORTS:
            scheme = "http"
        elif port_result.port in HTTPS_PORTS:
            scheme = "https"
        else:
            continue

        url = f"{scheme}://{host.ip}:{port_result.port}/"
        result = _fetch(url, timeout)
        # Use a basename free of dots so we don't lose IP octets via with_suffix.
        ip_stem = host.ip.replace(".", "_")
        base = out_dir / f"{ip_stem}_{port_result.port}"

        if result is None:
            ui.warn(f"  screenshot: failed to fetch {url}")
            continue

        status, headers, body = result
        html_path = base.with_name(base.name + ".html")
        headers_path = base.with_name(base.name + ".headers.txt")
        try:
            html_path.write_bytes(body)
            headers_path.write_text(
                f"HTTP {status} {url}\n\n"
                + "\n".join(f"{k}: {v}" for k, v in headers.items()),
                encoding="utf-8",
            )
            written.extend([html_path, headers_path])
            ui.good(f"  saved {html_path.name}")
        except OSError as exc:
            ui.warn(f"  screenshot write failed for {url}: {exc}")
            continue

        if png:
            png_path = base.with_name(base.name + ".png")
            if _try_playwright_png(url, png_path, timeout):
                written.append(png_path)
                ui.good(f"  saved {png_path.name}")
            else:
                ui.warn(
                    "  PNG capture needs playwright "
                    "(`pip install playwright && playwright install chromium`)"
                )

    return written
