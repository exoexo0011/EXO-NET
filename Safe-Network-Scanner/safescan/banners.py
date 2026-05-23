"""Service version detection / banner grabbing for common ports.

Each grabber is best-effort and protocol-aware:
  - SSH / FTP / SMTP / POP3 / IMAP / Telnet -> server speaks first; passive read.
  - HTTP / HTTPS                              -> HEAD request, parse Server header.
  - SMB                                       -> SMB2 NEGOTIATE, parse dialect.
  - RDP                                       -> X.224 Connection Request.
  - Generic TCP                                -> short passive read.

All grabbers swallow errors and return ``None`` on any failure. Output is
truncated to keep terminals readable.
"""

from __future__ import annotations

import re
import socket
import ssl
from typing import Optional

_MAX_BANNER_LEN = 160


def _truncate(s: str) -> str:
    s = s.strip()
    s = re.sub(r"[^\x20-\x7e]", ".", s)  # strip control chars for clean display
    return s[:_MAX_BANNER_LEN] + ("..." if len(s) > _MAX_BANNER_LEN else "")


# ---- passive (server speaks first) ------------------------------------------
def _grab_passive(ip: str, port: int, timeout: float, n: int = 256) -> Optional[str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(n)
            if not data:
                return None
            text = data.decode("utf-8", errors="replace").splitlines()[0]
            return _truncate(text)
    except OSError:
        return None


# ---- HTTP / HTTPS -----------------------------------------------------------
def _grab_http(ip: str, port: int, timeout: float, tls: bool) -> Optional[str]:
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None

    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(sock, server_hostname=ip)
            except (ssl.SSLError, OSError):
                try: sock.close()
                except Exception: pass
                return None
        sock.settimeout(timeout)
        req = (
            f"HEAD / HTTP/1.0\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: Safe-Network-Scanner\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.sendall(req.encode("ascii"))

        buf = b""
        while len(buf) < 4096:
            try:
                chunk = sock.recv(2048)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf:
                break

        text = buf.decode("utf-8", errors="replace")
        for line in text.splitlines():
            if line.lower().startswith("server:"):
                return _truncate(line.split(":", 1)[1])
        first = text.splitlines()[0] if text else None
        return _truncate(first) if first else None
    finally:
        try: sock.close()
        except Exception: pass


# ---- SMB --------------------------------------------------------------------
# Minimal SMB2 NEGOTIATE_PROTOCOL request offering dialects 2.0.2 through 3.1.1.
_SMB2_NEGOTIATE = bytes.fromhex(
    "00000054"                                            # NetBIOS Session: type=0, len=0x54
    "fe534d42" "4000" "0000" "00000000" "0000" "0000"     # SMB2 header start
    "00000000" "00000000" "0000000000000000"              # ...
    "00000000" "00000000" "0000000000000000"              # ...
    "00000000000000000000000000000000"                    # Signature
    # Body
    "2400"      # StructureSize = 36
    "0500"      # DialectCount = 5
    "0100"      # SecurityMode = signing enabled
    "0000"      # Reserved
    "00000000"  # Capabilities
    "00000000000000000000000000000000"                    # ClientGuid
    "0000000000000000"                                    # ClientStartTime
    # Dialects: 0x0202, 0x0210, 0x0300, 0x0302, 0x0311
    "02020210030003020311"
)


def _grab_smb(ip: str, port: int, timeout: float) -> Optional[str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_SMB2_NEGOTIATE)
            data = sock.recv(1024)
    except OSError:
        return "SMB"
    if not data:
        return "SMB"
    if b"\xfeSMB" in data and len(data) >= 74:
        # SMB2 header at offset 4 (after 4-byte NetBIOS) -> body at 4+64 = 68
        # NEGOTIATE response: StructureSize(2) SecurityMode(2) DialectRevision(2)
        try:
            dialect = int.from_bytes(data[72:74], "little")
            return f"SMB2 (dialect 0x{dialect:04x})"
        except Exception:
            return "SMB2"
    if b"\xffSMB" in data:
        return "SMB1"
    return "SMB"


# ---- RDP --------------------------------------------------------------------
# X.224 Class 0 Connection Request with embedded RDP Negotiation Request asking
# for TLS (1) | CredSSP (2). Servers reply with 0xd0 (CC) and may include an
# RDP Negotiation Response listing the protocols they support.
_RDP_X224_CR = bytes.fromhex(
    "0300" "0013"                # TPKT v3, length=19
    "0e" "e0" "0000" "0000" "00" # X.224 CR header
    "01" "00" "0800" "03000000"  # RDP Negotiation Request: type=1, len=8, protocols=3
)


def _grab_rdp(ip: str, port: int, timeout: float) -> Optional[str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_RDP_X224_CR)
            data = sock.recv(64)
    except OSError:
        return None
    if not data or len(data) < 11:
        return "RDP"
    # data[5] should be 0xd0 = X.224 Connection Confirm
    if data[5] != 0xd0:
        return "RDP"
    # If a Negotiation Response (type=2) is appended, decode supported protocols.
    if len(data) >= 19 and data[11] == 0x02:
        prots = int.from_bytes(data[15:19], "little")
        names = []
        if prots == 0: names.append("Standard RDP")
        if prots & 1:  names.append("TLS")
        if prots & 2:  names.append("CredSSP/NLA")
        if prots & 8:  names.append("RDSTLS")
        return "RDP (" + (", ".join(names) or "unknown") + ")"
    return "RDP"


# ---- dispatcher -------------------------------------------------------------
_DISPATCH = {
    21:   ("ftp",     lambda ip, p, t: _grab_passive(ip, p, t)),
    22:   ("ssh",     lambda ip, p, t: _grab_passive(ip, p, t)),
    23:   ("telnet",  lambda ip, p, t: _grab_passive(ip, p, t)),
    25:   ("smtp",    lambda ip, p, t: _grab_passive(ip, p, t)),
    80:   ("http",    lambda ip, p, t: _grab_http(ip, p, t, tls=False)),
    110:  ("pop3",    lambda ip, p, t: _grab_passive(ip, p, t)),
    143:  ("imap",    lambda ip, p, t: _grab_passive(ip, p, t)),
    443:  ("https",   lambda ip, p, t: _grab_http(ip, p, t, tls=True)),
    445:  ("smb",     _grab_smb),
    993:  ("imaps",   lambda ip, p, t: _grab_passive(ip, p, t)),
    995:  ("pop3s",   lambda ip, p, t: _grab_passive(ip, p, t)),
    3389: ("rdp",     _grab_rdp),
    5900: ("vnc",     lambda ip, p, t: _grab_passive(ip, p, t)),
    8000: ("http",    lambda ip, p, t: _grab_http(ip, p, t, tls=False)),
    8080: ("http",    lambda ip, p, t: _grab_http(ip, p, t, tls=False)),
    8443: ("https",   lambda ip, p, t: _grab_http(ip, p, t, tls=True)),
}


def grab(ip: str, port: int, timeout: float) -> Optional[str]:
    """Best-effort banner / version string for `port`."""
    handler = _DISPATCH.get(port)
    if handler is None:
        return _grab_passive(ip, port, timeout)
    return handler[1](ip, port, timeout)
