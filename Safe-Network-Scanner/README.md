# Safe-Network-Scanner

An educational Python network scanner. Discover live hosts on a network range
and probe TCP ports on a target. Built with `scapy` (when available and
privileged) with a graceful fallback to the standard library.

> **Use only on networks you own or have explicit written permission to scan.**
> Unauthorized scanning may be illegal in your jurisdiction.

## Features

- Host discovery on an IPv4 CIDR via ICMP echo
- TCP port scan (SYN scan with Scapy when root/admin, TCP connect otherwise)
- Common-ports preset + flexible `--ports` parser (`80`, `22,80,443`, `1-1024`)
- Concurrent scanning with `ThreadPoolExecutor`
- Colored CLI output via `colorama`
- Safety guard: refuses to scan non-private ranges without `--allow-public`

## Install

```bash
# Optional but recommended:
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

`scapy` is optional. The scanner works without it; you just lose SYN-scan
mode and the Scapy ICMP probe.

## Run

```bash
# Single host, common ports:
python network_scanner.py --target 192.168.1.1

# Host discovery on a /24:
python network_scanner.py --target 192.168.1.0/24 --discover

# Port range with custom timeout/threads:
python network_scanner.py --target 192.168.1.1 --ports 1-1024 \
    --timeout 0.5 --threads 200

# Discover then scan each live host:
python network_scanner.py --target 192.168.1.0/24 --discover --scan

# Specific ports:
python network_scanner.py --target 192.168.1.1 --ports 22,80,443,8080
```

### Privileged vs unprivileged

- **Unprivileged (default):** uses the system `ping` for host discovery and
  TCP `connect()` for port probing. Works everywhere, no setup.
- **Privileged (`sudo` / Administrator):** uses Scapy to send raw ICMP and
  perform a SYN ("half-open") scan. Faster and stealthier on large ranges.

Force the stdlib backend with `--no-scapy`.

### Safety flags

- `--allow-public` is required to scan any non-RFC1918 range. This is a
  guardrail against accidentally scanning the open internet.

## CLI reference

```text
--target       IP or CIDR, e.g. 192.168.1.1 or 10.0.0.0/24  (required)
--ports        '80', '22,80,443', '1-1024', or a mix
--discover     Run ICMP host discovery
--scan         Run port scan (implied for single-host targets)
--timeout      Per-probe timeout in seconds (default 1.0)
--threads      Concurrent workers (default 100)
--no-scapy     Disable Scapy even if installed
--allow-public Allow scanning non-private ranges (off by default)
--no-banner    Suppress the startup banner
```

## Notes

- This tool is intentionally feature-limited. It is meant for learning how
  host discovery and port scanning work, not as a replacement for `nmap`.
- For real engagements, prefer mature tools (`nmap`, `masscan`, `rustscan`)
  and follow your organization's rules of engagement.
