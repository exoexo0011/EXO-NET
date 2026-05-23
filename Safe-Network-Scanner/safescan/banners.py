"""Service version detection / banner grabbing for common ports.

Each grabber returns a tuple ``(banner_str, details_dict)``:
  * ``banner_str``  - short, human-readable summary string (or None)
  * ``details_dict`` - structured fingerprint fields, e.g.
                       ``{"server": "nginx/1.18", "title": "Login"}``

Protocol-specific handlers:
  * SSH                                    -> parse "SSH-2.0-OpenSSH_X.Y" line
  * FTP / SMTP / POP3 / IMAP / Telnet      -> passive read of greeting
  * HTTP / HTTPS                           -> HEAD + GET, parse Server + <title>
  * SMB                                    -> SMB2 NEGOTIATE, parse dialect
  * RDP                                    -> X.224 Connection Request + nego
  * VNC                                    -> passive (server speaks first)
  * Generic TCP                             -> short passive read

All grabbers swallow errors and return ``(None, {})`` on any failure.
"""

from __future__ import annotations

import re
import socket
import ssl
from typing import Dict, Optional, Tuple

BannerOut = Tuple[Optional[str], Dict[str, str]]
_MAX_BANNER_LEN = 160


def _truncate(s: str) -> str:
    s = s.strip()
    s = re.sub(r"[^\x20-\x7e]", ".", s)  # drop control chars for clean display
    return s[:_MAX_BANNER_LEN] + ("..." if len(s) > _MAX_BANNER_LEN else "")


# -----------------------------------------------------------------------------
# Generic passive read (server speaks first)
# -----------------------------------------------------------------------------
def _grab_passive_raw(ip: str, port: int, timeout: float, n: int = 256) -> str:
    """Return whatever the server says first, or '' on error."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(n)
            return data.decode("utf-8", errors="replace") if data else ""
    except OSError:
        return ""


def _grab_passive(ip: str, port: int, timeout: float) -> BannerOut:
    raw = _grab_passive_raw(ip, port, timeout)
    if not raw:
        return None, {}
    line = raw.splitlines()[0] if raw else ""
    return _truncate(line) if line else None, {}


# -----------------------------------------------------------------------------
# SSH - expected format: ``SSH-<protoversion>-<softwareversion>[ comments]``
# -----------------------------------------------------------------------------
_SSH_RE = re.compile(r"^SSH-([\d.]+)-([^\s]+)(?:\s+(.*))?$")


def _grab_ssh(ip: str, port: int, timeout: float) -> BannerOut:
    raw = _grab_passive_raw(ip, port, timeout)
    if not raw:
        return None, {}
    line = raw.splitlines()[0]
    details: Dict[str, str] = {}
    m = _SSH_RE.match(line.strip())
    if m:
        details["protocol"] = m.group(1)
        details["software"] = m.group(2)
        if m.group(3):
            details["comments"] = m.group(3).strip()
    return _truncate(line), details


# -----------------------------------------------------------------------------
# HTTP / HTTPS - HEAD then GET, parse Server header and <title>
# -----------------------------------------------------------------------------
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _http_request(sock: socket.socket, host: str, method: str, timeout: float) -> bytes:
    sock.settimeout(timeout)
    req = (
        f"{method} / HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Safe-Network-Scanner\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    )
    sock.sendall(req.encode("ascii"))
    buf = b""
    while len(buf) < 16_384:
        try:
            chunk = sock.recv(2048)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _parse_http(blob: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Return (server_header, title)."""
    text = blob.decode("utf-8", errors="replace")
    server = None
    for line in text.splitlines():
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break
    title = None
    body_start = text.find("\r\n\r\n")
    body = text[body_start + 4:] if body_start != -1 else text
    m = _TITLE_RE.search(body)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
    return server, title


def _grab_http(ip: str, port: int, timeout: float, tls: bool) -> BannerOut:
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None, {}

    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(sock, server_hostname=ip)
            except (ssl.SSLError, OSError):
                return None, {}

        # HEAD first (cheap, gives Server:); fall back to GET if title missing.
        head_blob = _http_request(sock, ip, "HEAD", timeout)
        try:
            sock.close()
        except Exception:
            pass
        server, title = _parse_http(head_blob)

        if title is None:
            # Title only appears in body; do a fresh GET on a new socket.
            try:
                sock2 = socket.create_connection((ip, port), timeout=timeout)
                if tls:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock2 = ctx.wrap_socket(sock2, server_hostname=ip)
                get_blob = _http_request(sock2, ip, "GET", timeout)
                try: sock2.close()
                except Exception: pass
                s2, t2 = _parse_http(get_blob)
                if server is None: server = s2
                if title is None:  title = t2
            except OSError:
                pass
    except Exception:
        try: sock.close()
        except Exception: pass
        return None, {}

    details: Dict[str, str] = {}
    if server: details["server"] = server[:120]
    if title:  details["title"]  = title

    summary_parts = []
    if server: summary_parts.append(server)
    if title:  summary_parts.append(f'"{title}"')
    banner = " | ".join(summary_parts) if summary_parts else None
    return (_truncate(banner) if banner else None), details


# -----------------------------------------------------------------------------
# SMB - minimal SMB2 NEGOTIATE_PROTOCOL request, parse DialectRevision in reply
# -----------------------------------------------------------------------------
_SMB2_NEGOTIATE = bytes.fromhex(
    "00000054"                                            # NetBIOS Session: type=0, len=0x54
    "fe534d42" "4000" "0000" "00000000" "0000" "0000"     # SMB2 header start
    "00000000" "00000000" "0000000000000000"              # ...
    "00000000" "00000000" "0000000000000000"              # ...
    "00000000000000000000000000000000"                    # Signature
    # Body
    "2400"      # StructureSize = 36
    "0500"      # DialectCount = 5
    "0100"      # SecurityMode
    "0000"      # Reserved
    "00000000"  # Capabilities
    "00000000000000000000000000000000"                    # ClientGuid
    "0000000000000000"                                    # ClientStartTime
    # Dialects: 0x0202, 0x0210, 0x0300, 0x0302, 0x0311
    "02020210030003020311"
)

_DIALECT_NAMES = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
    0x02ff: "SMB 2.x (multi-protocol negotiation)",
}


def _grab_smb(ip: str, port: int, timeout: float) -> BannerOut:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_SMB2_NEGOTIATE)
            data = sock.recv(1024)
    except OSError:
        return "SMB", {"protocol": "SMB"}
    if not data:
        return "SMB", {"protocol": "SMB"}
    # SMB2 response: NetBIOS(4) + SMB2 header(64) + body. DialectRevision @ +72.
    if b"\xfeSMB" in data and len(data) >= 74:
        try:
            dialect = int.from_bytes(data[72:74], "little")
            name = _DIALECT_NAMES.get(dialect, f"dialect 0x{dialect:04x}")
            return f"SMB2 ({name})", {
                "protocol": "SMB2",
                "dialect_id": f"0x{dialect:04x}",
                "dialect_name": name,
            }
        except Exception:
            return "SMB2", {"protocol": "SMB2"}
    if b"\xffSMB" in data:
        return "SMB1", {"protocol": "SMB1"}
    return "SMB", {"protocol": "SMB"}


# -----------------------------------------------------------------------------
# RDP - X.224 Class 0 Connection Request + RDP Negotiation Request
# -----------------------------------------------------------------------------
_RDP_X224_CR = bytes.fromhex(
    "0300" "0013"                # TPKT v3, length=19
    "0e" "e0" "0000" "0000" "00" # X.224 CR header
    "01" "00" "0800" "03000000"  # RDP Negotiation Request: type=1, len=8, protocols=3
)


def _grab_rdp(ip: str, port: int, timeout: float) -> BannerOut:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_RDP_X224_CR)
            data = sock.recv(64)
    except OSError:
        return None, {}
    if not data or len(data) < 11:
        return "RDP", {"protocol": "RDP"}
    if data[5] != 0xd0:                    # 0xd0 = X.224 Connection Confirm
        return "RDP", {"protocol": "RDP"}

    details: Dict[str, str] = {"protocol": "RDP"}
    # An optional RDP Negotiation Response (type=2) may be appended.
    if len(data) >= 19 and data[11] == 0x02:
        prots = int.from_bytes(data[15:19], "little")
        names = []
        if prots == 0:  names.append("Standard RDP")
        if prots & 1:   names.append("TLS")
        if prots & 2:   names.append("CredSSP/NLA")
        if prots & 8:   names.append("RDSTLS")
        details["protocols"] = ",".join(names) or "unknown"
        return f"RDP ({details['protocols']})", details
    return "RDP", details


# -----------------------------------------------------------------------------
# Dispatcher
# -----------------------------------------------------------------------------
_DISPATCH = {
    21:   ("ftp",     _grab_passive),
    22:   ("ssh",     _grab_ssh),
    23:   ("telnet",  _grab_passive),
    25:   ("smtp",    _grab_passive),
    80:   ("http",    lambda ip, p, t: _grab_http(ip, p, t, tls=False)),
    110:  ("pop3",    _grab_passive),
    143:  ("imap",    _grab_passive),
    443:  ("https",   lambda ip, p, t: _grab_http(ip, p, t, tls=True)),
    445:  ("smb",     _grab_smb),
    993:  ("imaps",   _grab_passive),
    995:  ("pop3s",   _grab_passive),
    3389: ("rdp",     _grab_rdp),
    5900: ("vnc",     _grab_passive),
    8000: ("http",    lambda ip, p, t: _grab_http(ip, p, t, tls=False)),
    8080: ("http",    lambda ip, p, t: _grab_http(ip, p, t, tls=False)),
    8443: ("https",   lambda ip, p, t: _grab_http(ip, p, t, tls=True)),
}


def grab(ip: str, port: int, timeout: float) -> BannerOut:
    """Best-effort fingerprint for `port`. Returns (summary, details_dict)."""
    handler = _DISPATCH.get(port)
    if handler is None:
        return _grab_passive(ip, port, timeout)
    return handler[1](ip, port, timeout)
