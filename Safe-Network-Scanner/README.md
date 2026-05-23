```
███████╗██╗  ██╗ ██████╗     ███╗   ██╗███████╗████████╗
██╔════╝╚██╗██╔╝██╔═══██╗    ████╗  ██║██╔════╝╚══██╔══╝
█████╗   ╚███╔╝ ██║   ██║    ██╔██╗ ██║█████╗     ██║   
██╔══╝   ██╔██╗ ██║   ██║    ██║╚██╗██║██╔══╝     ██║   
███████╗██╔╝ ██╗╚██████╔╝    ██║ ╚████║███████╗   ██║   
╚══════╝╚═╝  ╚═╝ ╚═════╝     ╚═╝  ╚═══╝╚══════╝   ╚═╝   
```

# EXO NET

**`[ Advanced Network Reconnaissance ]`**

> Educational use only. Only scan networks you own or have explicit written permission to scan.

EXO NET is an advanced, nmap-lite Python network reconnaissance toolkit.
It discovers live hosts, fingerprints services, captures HTTP page
snapshots, and emits results as a colored terminal table, JSON, CSV, or
a self-contained themed HTML report.

> **Use only on networks you own or have explicit written permission to scan.**
> Unauthorized scanning may be illegal in your jurisdiction.

## Features

- **Layered host discovery** - ARP sweep (when privileged + Scapy L2) +
  ICMP echo + TCP-ping fallback for ICMP-blocked hosts. Reverse DNS on
  alive hosts.
- **Multiple scan types** - TCP `connect` (always works), TCP `SYN` (raw,
  fast, needs root + libpcap/Npcap), UDP best-effort with protocol-aware
  probes for DNS / NTP / SNMP / NetBIOS / SSDP.
- **Service & version detection** - structured fingerprinters for SSH
  (protocol + software + comments), HTTP/HTTPS (`Server:` header + page
  `<title>`), SMB2 (NEGOTIATE with dialect parsing), RDP (X.224 + nego
  protocols), plus passive grabbers for FTP / SMTP / POP3 / IMAP / VNC
  and a generic fallback.
- **Basic OS fingerprinting** - TTL bucketing (64 / 128 / 255).
- **MAC + vendor lookup** - Scapy ARP when privileged, system `arp` cache
  otherwise. Vendor names from a small embedded OUI table; load a full
  IEEE / Wireshark `manuf` file with `--oui-file PATH` to widen coverage.
- **nmap-style timing** - `--timing 0..5` mirroring T0-T5.
- **Stealth / Aggressive presets** - one-flag scan profiles.
- **Evasion** - `--evasion` adds <=0.5s random per-probe jitter and
  randomizes source ports (TCP connect bind() + Scapy `sport=`).
- **Reports** - colored ASCII table on stdout (default), or write any of
  HTML / CSV / JSON files to disk via `--report` + `--save`. The HTML
  report ships a black / neon-green cyberpunk theme using `Share Tech
  Mono` for that authentic CRT feel.
- **Screenshots** - `--screenshots` saves HTML body + response headers for
  every open HTTP/HTTPS port. Add `playwright` (optional) for PNG.
- **Default-credentials awareness** - `--show-default-creds` prints
  historical default usernames/passwords for the services it found, as a
  reminder to rotate them. *The scanner never attempts logins.*
- **Windows-safe** - probes Scapy L3/L2 capability up front; transparently
  falls back to TCP connect + subprocess ping when raw sockets aren't
  available (e.g. no Npcap on Windows).
- **Public-IP guard** - refuses to scan non-RFC1918 ranges without
  `--allow-public`.

## Visual theme

| Token              | Color      |
|--------------------|------------|
| Background         | `#000000`  |
| Primary (neon)     | `#00ff41`  |
| Accent (red)       | `#ff003c`  |
| Info (cyan)        | `#00cfff`  |
| Warning (yellow)   | `#ffe600`  |

Terminal output uses the same palette via the four status prefixes:
`[*]` cyan info, `[+]` green hit, `[!]` red alert, `[-]` yellow miss.

## Layout

```
EXO-NET/
├── network_scanner.py      # thin CLI shim
├── safescan/
│   ├── cli.py              # argparse + orchestration
│   ├── discovery.py        # ARP / ICMP / TCP-ping + reverse DNS
│   ├── portscan.py         # TCP connect, TCP SYN, UDP (with evasion hooks)
│   ├── banners.py          # SSH / HTTP(S) / SMB2 / RDP / generic
│   ├── osfp.py             # TTL-based OS guess
│   ├── oui.py              # MAC vendor lookup (+ load_from_file)
│   ├── output.py           # stdout: colored table / JSON
│   ├── report.py           # files: HTML / CSV / JSON (themed)
│   ├── screenshots.py      # HTTP/HTTPS HTML + headers + optional PNG
│   ├── credentials.py      # default-creds reference table (display-only)
│   ├── evasion.py          # jitter + random source port policy
│   ├── storage.py          # timestamped session directory
│   ├── privilege.py        # admin + Scapy capability probes
│   ├── safety.py           # public-IP guard
│   ├── timing.py           # T0..T5 profiles
│   ├── ui.py               # colors, banner, progress bar (stderr)
│   └── types.py            # HostResult / PortResult dataclasses
└── requirements.txt
```

## Install

```bash
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Optional - enable PNG screenshots:
pip install playwright
playwright install chromium
```

`scapy` is optional. Without it (or without Npcap on Windows / root on
Unix) the scanner falls back to `socket.connect` + `subprocess.ping`
and skips the ARP sweep.

## Run

### Basic

```bash
# Single host, common ports, banners, table output:
python network_scanner.py --target 192.168.1.1

# Discover live hosts on a /24 (no port scan):
python network_scanner.py --target 192.168.1.0/24 --discover

# Discover then port-scan every live host:
python network_scanner.py --target 192.168.1.0/24 --discover --scan
```

### Reports & saving

```bash
# Save a timestamped session under ./safescan_results/ with HTML + JSON:
python network_scanner.py --target 192.168.1.0/24 --discover --scan --save

# Pick formats and a custom base directory:
python network_scanner.py --target 192.168.1.0/24 --discover --scan \
    --save /tmp/recon --report html,csv,json

# JSON to stdout for piping:
python network_scanner.py --target 192.168.1.1 --output json > scan.json
```

### Screenshots

```bash
# Save HTML body + response headers from every open HTTP/HTTPS port:
python network_scanner.py --target 192.168.1.0/24 --discover --scan \
    --screenshots --save

# Same, plus PNG screenshots (needs playwright):
python network_scanner.py --target 192.168.1.0/24 --discover --scan \
    --screenshots --screenshots-png --save
```

Output layout:
```
safescan_results/20260523_044021_192.168.1.0_24/
├── report.html
├── report.json
├── report.csv
└── screenshots/
    ├── 192_168_1_10_80.html
    ├── 192_168_1_10_80.headers.txt
    ├── 192_168_1_10_80.png            (if playwright installed)
    └── ...
```

### Stealth / Aggressive / Evasion

```bash
# Aggressive preset: T4 + UDP + banners + OS detect + reports:
python network_scanner.py --target 192.168.1.0/24 --aggressive \
    --report html,csv --save

# Stealth preset on a privileged shell (T1 + SYN, no banners):
sudo python network_scanner.py --target 192.168.1.0/24 --stealth

# Add evasion (random jitter + random source ports) to any scan:
python network_scanner.py --target 192.168.1.1 --ports 1-1024 --evasion
```

### MAC vendor lookup with an external OUI file

```bash
# Wireshark 'manuf' format (or IEEE oui.txt) - dramatically expands the
# bundled hand-curated list:
python network_scanner.py --target 192.168.1.0/24 --discover \
    --oui-file /usr/share/wireshark/manuf
```

### Default-credentials awareness

```bash
# Reminder list for any services we identified - DISPLAY ONLY.
# The scanner never attempts to authenticate.
python network_scanner.py --target 192.168.1.10 --show-default-creds
```

Sample output:
```
=== Default credentials reference (informational) ===
Sources: vendor manuals + public-domain default-password lists.
If any of your gear still uses these, ROTATE THEM NOW.
The scanner does NOT attempt these credentials. This is a memory-aid only.

  SSH - found on: 192.168.1.10:22 (myhost.lan)
              'root' : 'root'
              'root' : 'toor'
             'admin' : 'admin'
                'pi' : 'raspberry'
              'ubnt' : 'ubnt'
```

### Specific scan-type / UDP / port range

```bash
# Force TCP connect (Windows-friendly, no Npcap needed):
python network_scanner.py --target 192.168.1.10 --scan-type connect

# UDP-only on common services:
python network_scanner.py --target 192.168.1.10 --udp \
    --udp-ports 53,123,161,137,1900

# Big port range with faster timing:
python network_scanner.py --target 192.168.1.1 --ports 1-1024 --timing 4
```

## CLI reference

```
--target           IP or CIDR  (required)
--ports            TCP ports: '80', '22,80,443', '1-1024', or any mix
--udp / --udp-ports
--discover / --scan
--scan-type        auto | connect | syn   (default auto)
--timing 0-5       0=paranoid 1=sneaky 2=polite 3=normal 4=aggressive 5=insane
--stealth          Preset: T1 + SYN + no banners + no OS detect
--aggressive       Preset: T4 + UDP + banners + OS detect
--no-arp / --no-tcp-ping / --no-banners
--os-detect        TTL-based OS guess
--oui-file PATH    External Wireshark/IEEE OUI file
--evasion          Random jitter + random source ports
--output           table | json   (stdout)
--report html,csv,json   File reports written under --save
--save [DIR]       Timestamped session dir (default base ./safescan_results)
--screenshots / --screenshots-png    HTTP HTML + headers (+ optional PNG)
--show-default-creds      Display-only credential awareness
--no-banner / --no-progress
--allow-public     Required to scan non-RFC1918 ranges
```

## Privileges

| Capability      | Unprivileged              | Root + Scapy + libpcap/Npcap |
|-----------------|---------------------------|------------------------------|
| Host discovery  | system ping + TCP-ping    | ARP sweep + ICMP via Scapy   |
| TCP scan        | connect()                 | SYN ("half-open")            |
| UDP scan        | best-effort (open\|filt)  | best-effort (open\|filt)     |
| MAC lookup      | OS arp cache              | live ARP                     |

On Windows without Npcap, Scapy is *imported* but raw sockets aren't
usable; EXO NET detects this and silently falls back to the stdlib
backend instead of crashing mid-scan.

## Notes & limits

- This is a learning tool. For real engagements use `nmap`, `masscan`,
  or `rustscan`, and follow your organization's rules of engagement.
- OS fingerprinting here is intentionally simple - just initial-TTL
  bucketing. Will not survive against hosts that rewrite their TTL.
- The bundled OUI table is hand-curated and short. Use `--oui-file` with
  Wireshark's `manuf` for full coverage.
- UDP scan classification is fundamentally limited without raw socket
  access; treat `open|filtered` as "no response, could be either".
- Screenshot fetching uses stdlib `urllib` and disables TLS verification
  because lab gear typically uses self-signed certs.
- The default-credentials reference is **display-only**; EXO NET never
  attempts authentication. Information sourced from public vendor
  documentation, distro install guides, and public-domain default
  password lists.
