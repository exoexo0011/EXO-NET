"""EXO NET Pro — professional ethical hacking toolkit.

Public CLI entry point lives in :mod:`exonet.cli` (the ``main`` function).
Data classes shared across modules are in :mod:`exonet.types`.

Pro-tier modules:
    :mod:`exonet.whois`       WHOIS + DNS recon
    :mod:`exonet.vuln`        CVE lookup + SSL/TLS health
    :mod:`exonet.firewall`    Firewall detection
    :mod:`exonet.risk`        Risk scoring
    :mod:`exonet.report_pro`  Pentest-style HTML / PDF report
"""

__title__ = "EXO NET Pro"
__version__ = "2.0.0"
