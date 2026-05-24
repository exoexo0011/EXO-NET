```
███████╗██╗  ██╗ ██████╗     ███╗   ██╗███████╗████████╗
██╔════╝╚██╗██╔╝██╔═══██╗    ████╗  ██║██╔════╝╚══██╔══╝
█████╗   ╚███╔╝ ██║   ██║    ██╔██╗ ██║█████╗     ██║   
██╔══╝   ██╔██╗ ██║   ██║    ██║╚██╗██║██╔══╝     ██║   
███████╗██╔╝ ██╗╚██████╔╝    ██║ ╚████║███████╗   ██║   
╚══════╝╚═╝  ╚═╝ ╚═════╝     ╚═╝  ╚═══╝╚══════╝   ╚═╝   

                                                  PRO
```

# EXO NET Pro

**`[ Professional Ethical Hacking Toolkit ]`**

> **AUTHORIZATION REQUIRED.** EXO NET Pro is an offensive security tool.
> Use it only on networks, hosts and applications you own or for which
> you hold explicit, **written** authorization to test. Unauthorized
> scanning may violate computer-misuse laws in your jurisdiction and is
> not covered by this project. The maintainers accept no liability for
> misuse.

EXO NET Pro is the v2.x evolution of EXO NET — a Python reconnaissance
and assessment toolkit. It does layered host discovery, multi-strategy
port scanning, service and version detection, WHOIS / DNS recon,
CVE lookup, SSL/TLS health checks, firewall fingerprinting, and a 0-100
risk score per host. Output ranges from a colored terminal table to a
self-contained themed HTML / PDF pentest report.

## What's new in 2.0 (Pro)

- **WHOIS + DNS recon** — registrar / org / country, A / MX / TXT / NS /
  CNAME / SOA records, optional subdomain brute-force.
- **CVE lookup** against the public [cve.circl.lu] API for every
  detected service banner, with CVSS-aware scoring.
- **SSL / TLS checker** — flags expired and self-signed certs, weak
  protocols (TLS 1.0/1.1, SSLv2/3) and weak ciphers (RC4, 3DES, NULL,
  EXPORT, ANON).
- **Firewall detection** by analyzing filtered/closed/open patterns and
  TTL anomalies on alive hosts.
- **Risk scoring engine** that combines open-port volume, sensitive
  services, default-credential exposure, CVE findings, outdated
  software, SSL findings and absence of a firewall into one 0..100
  score with `CRITICAL / HIGH / MEDIUM / LOW / INFO` levels and per-host
  remediation guidance.
- **Professional pentest report** — executive summary, glow-coded risk
  badges, per-host CVE tables, SSL findings, recon dump, firewall
  analysis, prioritized recommendations, footer with disclaimer and
  timestamp. Exports to PDF via WeasyPrint.

[cve.circl.lu]: https://cve.circl.lu/

## Visual theme

| Token              | Color      |
|--------------------|------------|
| Background         | `#000000`  |
| Primary (neon)     | `#00ff41`  |
| Accent (red)       | `#ff003c`  |
| Info (cyan)        | `#00cfff`  |
| Warning (yellow)   | `#ffe600`  |
| HIGH (orange)      | `#ff7700`  |

Risk badges glow with their color: red CRITICAL, orange HIGH, yellow
MEDIUM, neon-green LOW, cyan INFO. Terminal output keeps the four
status prefixes — `[*]` cyan info, `[+]` green hit, `[!]` red alert,
`[-]` yellow miss.

## Layout

```
EXO-NET/
├── exonet.py               # thin CLI shim
├── exonet/
│   ├── __init__.py
│   ├── cli.py              # argparse + orchestration
│   ├── discovery.py        # ARP / ICMP / TCP-ping + reverse DNS
│   ├── portscan.py         # TCP connect, TCP SYN, UDP (with evasion hooks)
│   ├── banners.py          # SSH / HTTP(S) / SMB2 / RDP / generic
│   ├── osfp.py             # TTL-based OS guess
│   ├── oui.py              # MAC vendor lookup (+ load_from_file)
│   ├── output.py           # stdout: colored table / JSON
│   ├── report.py           # files: HTML / CSV / JSON (themed)
│   ├── report_pro.py       # Pro pentest HTML/PDF report             [Pro]
│   ├── screenshots.py      # HTTP/HTTPS HTML + headers + optional PNG
│   ├── credentials.py      # default-creds reference table (display-only)
│   ├── evasion.py          # jitter + random source port policy
│   ├── storage.py          # timestamped session directory
│   ├── privilege.py        # admin + Scapy capability probes
│   ├── safety.py           # public-IP guard
│   ├── timing.py           # T0..T5 profiles
│   ├── ui.py               # colors, banner, progress bar (stderr)
│   ├── types.py            # HostResult / PortResult dataclasses
│   ├── whois.py            # WHOIS / DNS / subdomain scanner         [Pro]
│   ├── vuln.py             # CVE lookup + SSL/TLS health             [Pro]
│   ├── firewall.py         # Firewall detection                      [Pro]
│   └── risk.py             # 0-100 risk scoring engine               [Pro]
├── README.md
├── requirements.txt
└── .gitignore
```

## Install

```bash
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

All dependencies are **optional and lazy-loaded**. EXO NET Pro never
crashes when an external library or system command is missing — the
relevant feature is simply skipped with a warning. The minimal core
runs with only the standard library.

| Optional dep      | Enables                                                |
|-------------------|--------------------------------------------------------|
| `rich`            | Interactive TUI menu (no-arg launch)                   |
| `scapy`           | ARP sweep, SYN scan, raw ICMP                          |
| `python-whois`    | WHOIS lookup (else falls back to system `whois`)       |
| `dnspython`       | DNS A/AAAA/MX/TXT/NS/CNAME/SOA enumeration             |
| `requests`        | CVE lookup against cve.circl.lu                        |
| `cryptography`    | Detailed SSL certificate parsing                       |
| `weasyprint`      | PDF export of the pro report                           |
| `playwright`      | PNG screenshots (`--screenshots-png`)                  |

## Quickstart — two ways to use EXO NET Pro

EXO NET Pro can be driven in two ways. Pick whichever fits how you
work — **no command memorization is required**.

| Mode             | When to use it                              | Command                                                                     |
|------------------|---------------------------------------------|-----------------------------------------------------------------------------|
| **Interactive**  | Recommended for beginners, one-off scans    | `python exonet.py`                                                          |
| **CLI**          | Advanced users, scripting, CI, repeat runs  | `python exonet.py --target 192.168.1.0/24 --pro --report html --save`       |

Both modes use the same scan engine and produce the same reports.
The interactive menu just walks you through the choices step-by-step
instead of asking you to remember flag names.

## Interactive Mode

Run `exonet.py` with **no arguments** to launch the Rich-powered
interactive menu — a guided TUI that walks you through every choice,
shows a live dashboard while the scan runs, and offers to open the
HTML report in your browser when it finishes.

```bash
python exonet.py
```

```
╔═══════════════════════════════════════════════════════════╗
║                      EXO NET Pro v2.0.0                   ║
║              [ Professional Network Scanner ]             ║
╠═══════════════════════════════════════════════════════════╣
║   [1]  Quick Scan      — common ports only                ║
║   [2]  Full Scan       — discover + all ports             ║
║   [3]  Pro Scan        — full + vuln + report             ║
║   [4]  Stealth Scan    — slow + evasion                   ║
║   [5]  Aggressive Scan — T4 + UDP + banners               ║
║   [6]  Custom Scan     — choose your options              ║
║   [Q]  Quit                                               ║
╚═══════════════════════════════════════════════════════════╝
```

### Flow

1. **Pick a scan profile.** Choose one of the five presets, or
   `[6] Custom Scan` to build your own.
2. **Enter a target.** IP (`192.168.1.1`) or CIDR (`192.168.1.0/24`).
3. **Confirm.** A summary panel shows exactly what will run — target,
   scan type, modules, report format, timing — before anything
   touches the network.
4. **Watch the live dashboard.** Per-phase progress bars (discovery,
   port scan, banners), a live host table that fills in as hosts are
   found, and a color-coded log panel — green for hits, cyan for info,
   yellow for warnings, red for risks.
5. **Review the results screen.** Hosts found, open ports, risk
   distribution, and the path to the saved report. Pick `[3] Open
   report` to launch the HTML in your browser, `[1]` to scan the same
   target again, `[2]` for a new target, or `[Q]` to quit.

### Custom Scan (option 6)

The Custom Scan flow asks you, in order:

1. **Scan type** — `[1] TCP Connect` / `[2] TCP SYN` / `[3] UDP`
2. **Timing** — `[0..5]`, with a description of each template
3. **Port range** — `[1] Common` / `[2] 1-1024` / `[3] All ports` / `[4] Custom`
4. **Banners** — yes / no
5. **OS detect** — yes / no
6. **Vuln scan** — yes / no
7. **Save report** — `[1] HTML` / `[2] JSON` / `[3] CSV` / `[4] All` / `[5] None`
8. **Evasion** — yes / no

Then it shows the same confirm screen and runs.

### When to skip the menu

If you pass **any** flag — `--target`, `--help`, `--version`,
anything — EXO NET Pro skips the menu and runs in CLI mode exactly
as before. The menu only appears when you launch with no arguments.

## Run (CLI mode)

> Prefer a guided experience? See [Interactive Mode](#interactive-mode)
> above. Everything below documents the underlying CLI flags.

### Basic

```bash
# Single host, common ports, banners, table output:
python exonet.py --target 192.168.1.1

# Discover live hosts on a /24 (no port scan):
python exonet.py --target 192.168.1.0/24 --discover

# Discover then port-scan every live host:
python exonet.py --target 192.168.1.0/24 --discover --scan
```

### Pro: full assessment

```bash
# Everything: discovery + scan + WHOIS/DNS + CVE/SSL + firewall + risk
# + professional HTML pentest report. Saved to ./exonet_results/.
python exonet.py --target 192.168.1.0/24 --pro --report html --save

# A focused single-host audit with explicit feature flags:
python exonet.py --target 192.168.1.1 --whois --vuln --risk \
    --report html --save

# Same, plus a PDF export of the pro report (needs weasyprint):
python exonet.py --target 192.168.1.1 --pro --output-pdf --save
```

### Reports & saving

```bash
# Save a timestamped session under ./exonet_results/ with HTML + JSON:
python exonet.py --target 192.168.1.0/24 --discover --scan --save

# Pick formats and a custom base directory:
python exonet.py --target 192.168.1.0/24 --discover --scan \
    --save /tmp/recon --report html,csv,json

# JSON to stdout for piping:
python exonet.py --target 192.168.1.1 --output json > scan.json
```

### Pro reports

The pro HTML report is written to `report_pro.html` (instead of the
plain `report.html`) when `--pro` is on. PDF export goes to
`report_pro.pdf`. Sample session layout:

```
exonet_results/20260523_044021_192.168.1.0_24/
├── report_pro.html
├── report_pro.pdf            (with --output-pdf)
├── report.json
└── screenshots/              (with --screenshots)
    ├── 192_168_1_10_80.html
    ├── 192_168_1_10_80.headers.txt
    └── ...
```

### Stealth / Aggressive / Evasion

```bash
# Aggressive preset: T4 + UDP + banners + OS detect + reports:
python exonet.py --target 192.168.1.0/24 --aggressive \
    --report html,csv --save

# Stealth preset on a privileged shell (T1 + SYN, no banners):
sudo python exonet.py --target 192.168.1.0/24 --stealth

# Add evasion (random jitter + random source ports) to any scan:
python exonet.py --target 192.168.1.1 --ports 1-1024 --evasion
```

### Screenshots

```bash
# Save HTML body + response headers from every open HTTP/HTTPS port:
python exonet.py --target 192.168.1.0/24 --discover --scan \
    --screenshots --save

# Same, plus PNG screenshots (needs playwright):
python exonet.py --target 192.168.1.0/24 --discover --scan \
    --screenshots --screenshots-png --save
```

### MAC vendor lookup with an external OUI file

```bash
python exonet.py --target 192.168.1.0/24 --discover \
    --oui-file /usr/share/wireshark/manuf
```

### Default-credentials awareness

```bash
# Reminder list for any services we identified - DISPLAY ONLY.
# The scanner never attempts to authenticate.
python exonet.py --target 192.168.1.10 --show-default-creds
```

### Specific scan-type / UDP / port range

```bash
# Force TCP connect (Windows-friendly, no Npcap needed):
python exonet.py --target 192.168.1.10 --scan-type connect

# UDP-only on common services:
python exonet.py --target 192.168.1.10 --udp \
    --udp-ports 53,123,161,137,1900

# Big port range with faster timing:
python exonet.py --target 192.168.1.1 --ports 1-1024 --timing 4
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
--save [DIR]       Timestamped session dir (default base ./exonet_results)
--screenshots / --screenshots-png    HTTP HTML + headers (+ optional PNG)
--show-default-creds      Display-only credential awareness
--no-banner / --no-progress
--allow-public     Required to scan non-RFC1918 ranges

EXO NET Pro:
--pro              Enable WHOIS + vuln + risk + pro report
--whois            WHOIS + DNS recon
--subdomains       With --whois: brute-force common subdomains
--vuln             CVE lookup + SSL/TLS health checks
--risk             0-100 risk score per host
--output-pdf       Also export the pro report as a PDF (needs weasyprint)
```

## Risk scoring (Pro)

Each host gets a 0..100 score from the following ingredients:

| Signal                                  | Contribution             |
|-----------------------------------------|--------------------------|
| Open-port volume                        | +2 per port (cap +20)    |
| Sensitive service exposed               | +1..+25 per service      |
| Default credentials known for service   | +6 per service           |
| CVE found (CVSS-bucketed)               | +2..+12 per CVE (cap +30)|
| Outdated software heuristic             | +6 per port              |
| Expired / soon-to-expire TLS cert       | +3 / +8                  |
| Self-signed TLS cert                    | +4                       |
| Weak TLS protocols / ciphers            | +5 / +4                  |
| No firewall detected (with open ports)  | +6                       |

The score is capped at 100 and bucketed:

| Range   | Level    | Badge color |
|---------|----------|-------------|
| 80..100 | CRITICAL | `#ff003c`   |
| 60..79  | HIGH     | `#ff7700`   |
| 40..59  | MEDIUM   | `#ffe600`   |
| 20..39  | LOW      | `#00ff41`   |
| 0..19   | INFO     | `#00cfff`   |

Every contribution is recorded in `host.risk_factors` and rendered
verbatim in the pro report so the score is fully auditable.

## Privileges

| Capability      | Unprivileged              | Root + Scapy + libpcap/Npcap |
|-----------------|---------------------------|------------------------------|
| Host discovery  | system ping + TCP-ping    | ARP sweep + ICMP via Scapy   |
| TCP scan        | connect()                 | SYN ("half-open")            |
| UDP scan        | best-effort (open\|filt)  | best-effort (open\|filt)     |
| MAC lookup      | OS arp cache              | live ARP                     |
| WHOIS / DNS     | works unprivileged        | same                         |
| CVE / SSL       | works unprivileged        | same                         |
| Risk / firewall | works unprivileged        | same                         |

**All EXO NET Pro features run on Windows without admin rights**, with
the single exception of SYN scan (which requires Npcap and admin
rights). The pro modules use only outbound TCP/UDP/HTTPS, which doesn't
need elevated privileges.

## Notes & limits

- This is a learning / lab tool. For real engagements, supplement with
  `nmap`, `masscan`, `nuclei`, and your team's standard rules of
  engagement.
- OS fingerprinting is intentionally simple (initial-TTL bucketing).
- The bundled OUI table is short. Use `--oui-file` with Wireshark's
  `manuf` for full coverage.
- UDP classification is fundamentally noisy without raw sockets; treat
  `open|filtered` as "no response, could be either".
- The CVE feed depends on cve.circl.lu being reachable. Offline runs
  fall back to the built-in outdated-version heuristic.
- The default-credentials reference is **display-only**; EXO NET Pro
  never attempts authentication.
