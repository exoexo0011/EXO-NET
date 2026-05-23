# Safe-Network-Scanner

An educational, nmap-lite Python network scanner. Discovers live hosts,
fingerprints services, and reports results as a colored table or structured
JSON.

> **Use only on networks you own or have explicit written permission to scan.**
> Unauthorized scanning may be illegal in your jurisdiction.

## Features

- **Layered host discovery** - ARP sweep (when privileged + Scapy L2) +
  ICMP echo + TCP-ping fallback for ICMP-blocked hosts.
- **Scan types** - TCP `connect` (always works), TCP `SYN` (raw, fast,
  needs root + libpcap/Npcap), UDP (best-effort with protocol-aware probes
  for DNS/NTP/SNMP/NetBIOS/SSDP).
- **Service / version detection** - banner grabbers for SSH, FTP, SMTP,
  HTTP, HTTPS (TLS), SMB2 (with dialect parsing), RDP (X.224 + nego
  response), VNC, plus a generic passive grab for unknown ports.
- **OS fingerprinting** - basic TTL rounding (64 / 128 / 255).
- **MAC + vendor lookup** - Scapy ARP when privileged, system `arp` cache
  otherwise; vendor names from a small embedded OUI table.
- **Timing profiles** - `--timing 0..5` mirroring nmap's T0-T5.
- **Stealth / Aggressive presets** - one-flag scan profiles.
- **Output** - colored ASCII table (default) or JSON (`--output json`).
- **Progress bar** on stderr (kept off when not a TTY so JSON stays clean).
- **Windows-safe** - never crashes on missing Npcap; transparently falls
  back to TCP connect + subprocess ping when raw sockets aren't available.
- **Public-IP guard** - refuses to scan non-private ranges without
  `--allow-public`.

## Layout

```
Safe-Network-Scanner/
├── network_scanner.py      # thin CLI shim
├── safescan/               # the real scanner
│   ├── cli.py              # argparse + orchestration
│   ├── discovery.py        # ARP / ICMP / TCP-ping
│   ├── portscan.py         # TCP connect, TCP SYN, UDP
│   ├── banners.py          # protocol-specific version grabbers
│   ├── osfp.py             # TTL-based OS guess
│   ├── oui.py              # MAC vendor lookup
│   ├── output.py           # table + JSON renderers
│   ├── privilege.py        # admin + Scapy capability probes
│   ├── safety.py           # public-IP guard
│   ├── timing.py           # T0..T5 profiles
│   ├── ui.py               # colors, banner, progress bar
│   └── types.py            # HostResult / PortResult dataclasses
└── requirements.txt
```

## Install

```bash
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

`scapy` is optional. Without it (or without Npcap on Windows / root on
Unix) the scanner uses `socket.connect` + `subprocess.ping` and skips ARP.

## Run

```bash
# Single host, common ports:
python network_scanner.py --target 192.168.1.1

# /24 host discovery only:
python network_scanner.py --target 192.168.1.0/24 --discover

# Discover then port-scan every live host:
python network_scanner.py --target 192.168.1.0/24 --discover --scan

# Custom port range + faster timing + JSON output:
python network_scanner.py --target 192.168.1.1 --ports 1-1024 \
    --timing 4 --output json

# Aggressive preset (T4 + UDP + OS detect + banners):
python network_scanner.py --target 192.168.1.0/24 --aggressive

# Stealth preset (T1 + SYN + no banners):
sudo python network_scanner.py --target 192.168.1.0/24 --stealth

# Force TCP connect (bypass any SYN attempt):
python network_scanner.py --target 192.168.1.1 --scan-type connect

# UDP-only set:
python network_scanner.py --target 192.168.1.10 --udp --udp-ports 53,123,161
```

### Privileges

| Capability        | Unprivileged              | Root + Scapy + libpcap/Npcap |
|-------------------|---------------------------|------------------------------|
| Host discovery    | system ping + TCP-ping    | ARP sweep + ICMP via Scapy   |
| TCP scan          | connect()                 | SYN ("half-open")            |
| UDP scan          | best-effort (open\|filt)  | best-effort (open\|filt)     |
| MAC lookup        | OS arp cache              | live ARP                     |

On Windows without Npcap, Scapy is *imported* but raw sockets aren't
usable; the scanner detects this and silently falls back to the stdlib
backend instead of crashing mid-scan.

## CLI reference

```
--target           IP or CIDR  (required)
--ports            TCP ports: '80', '22,80,443', '1-1024', or any mix
--udp              Also run a UDP scan
--udp-ports        UDP ports list (same syntax as --ports)
--discover         Run host discovery
--scan             Run port scan (implied for single hosts)
--scan-type        auto | connect | syn       (default auto)
--timing 0-5       nmap-style template        (default 3)
--stealth          Preset: T1, no banners, no OS detect, prefer SYN
--aggressive       Preset: T4, UDP, banners, OS detect
--no-arp           Skip ARP layer in discovery
--no-tcp-ping      Skip TCP-ping fallback in discovery
--no-banners       Skip version grabbing on open ports
--os-detect        Enable TTL-based OS fingerprint
--output           table | json               (default table)
--no-banner        Hide the startup ASCII banner
--no-progress      Hide the progress bar
--allow-public     Required to scan non-private IP ranges
```

## Notes & limits

- This is a learning tool. For real engagements use `nmap`, `masscan`, or
  `rustscan`, and follow your organization's rules of engagement.
- OS fingerprinting here is intentionally simple - just initial-TTL
  bucketing. It will not survive against hosts that rewrite their TTL.
- The OUI table is hand-curated and short. Unrecognized vendors render
  as `mac=xx:xx:xx:xx:xx:xx` with no vendor tag.
- UDP scan classification is fundamentally limited without raw socket
  access; treat `open|filtered` as "no response, could be either".
