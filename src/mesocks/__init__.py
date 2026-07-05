"""MeSocks - transparent VPN proxy for restricted services on Raspberry Pi.

The package is split by responsibility:

    settings   - tunables and paths, with config_local.py overrides
    dnspacket  - raw DNS packet parsing/building (stdlib only)
    profiles   - service profiles (which domains to hijack, UDP rules)
    cache      - forward DNS cache + media IP tracker file
    ratelimit  - per-source-IP rate limiting for the DNS server
    dns_server - the hijacking DNS server (mesocks-dns)
    udp_proxy  - the UDP media/voice forwarder (mesocks-udp-proxy)
    setupinfo  - small CLI used by setup-services.sh
"""

__version__ = "0.2.0"
