# MeSocks

**Transparent VPN proxy for selected services on a Raspberry Pi.**

MeSocks lets devices route configured services through a VPN-connected Pi
without changing app-level proxy settings. Point a device's DNS server at the
Pi, and MeSocks hijacks only the configured service domains, forwards HTTPS via
SNI proxying, and forwards UDP media traffic when a profile needs it.

<p align="center">
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-blue"></a>
  <img alt="python" src="https://img.shields.io/badge/python-3.10%2B-blue">
  <img alt="platform" src="https://img.shields.io/badge/Raspberry%20Pi-supported-success">
</p>

---

## Highlights

- DNS hijack for selected service profiles only
- Discord built in by default, including text/API/CDN and voice/media routing
- Per-client UDP media routing so multiple clients can use different voice
  servers without clobbering each other
- Local SOCKS5 backend for `sniproxy`
- Private-network gates and rate limits to avoid open resolver/relay behavior
- Modular profiles for adding or disabling services without editing daemon code
- Backward-compatible launchers for existing `dns-proxy.py` and `udp-proxy.py`
  deployments

---

## Architecture

```text
[Client device]
    | DNS: service domain?
    v
[mesocks-dns :53] ---- resolve real IP ----> [Upstream DNS]
    | returns Pi IP
    | records media host -> real IP
    v
[mesocks-sniproxy :443/:80] ---- SOCKS5 ----> [VPN path] ----> Service TCP
[mesocks-udp-proxy :443/udp] ---------------> [VPN path] ----> Service UDP media
```

The DNS server is the control plane: it decides which domains belong to active
profiles and records real media server IPs for UDP. The TCP and UDP proxies are
the data plane.

---

## Install

Requirements:

- Raspberry Pi or Linux host on the VPN network path
- Python 3.10+
- `microsocks` (installed by `setup.sh`)
- `sniproxy` binary at `/usr/local/bin/sniproxy`

```bash
git clone https://github.com/meellm/MeSocks.git
cd MeSocks

# SOCKS5 backend + WiFi priority helper
sudo ./setup.sh

# DNS hijack + TCP proxy + UDP media proxy
sudo ./setup-services.sh YOUR_PI_IP

# Start the services
sudo systemctl start mesocks-dns mesocks-sniproxy mesocks-udp-proxy
```

For more operational detail, see [docs/Deployment.md](docs/Deployment.md).

---

## Configure a Device

Set the device's DNS server to the Pi IP.

| Platform | Where |
|---|---|
| Windows | Network settings -> IPv4 -> DNS |
| macOS | System Settings -> Network -> DNS |
| iOS | Wi-Fi -> info button -> Configure DNS -> Manual |
| Android | Wi-Fi -> Modify network -> Advanced -> DNS |
| Linux | NetworkManager or `/etc/resolv.conf` |

No browser extension or app proxy setting is needed.

---

## Service Profiles

If no local config exists, MeSocks uses the built-in `discord` profile. To
customize services:

```bash
cp services_config.example.py services_config.py
```

Each profile is a plain dictionary:

```python
SERVICES = {
    "discord": {
        "enabled": True,
        "domains": ["discord.com", "discord.gg", "discord.media"],
        "udp_proxy": {
            "enabled": True,
            "port": 443,
            "media_patterns": [
                r"^[a-z0-9\-]+\d+[a-z0-9\-]*\.discord\.media$",
            ],
        },
    },
}
```

Subdomains match automatically. UDP media patterns are tracked per client so
voice traffic is forwarded to the server that client actually resolved.

See [docs/Profiles.md](docs/Profiles.md) for profile fields and examples.

---

## Commands

| Command | Purpose |
|---|---|
| `sudo ./setup.sh` | Install/start local `microsocks` backend |
| `sudo ./setup-services.sh YOUR_PI_IP` | Write systemd units from active profiles |
| `sudo systemctl restart mesocks-dns mesocks-sniproxy mesocks-udp-proxy` | Restart after config/code changes |
| `journalctl -u mesocks-dns -f` | Watch DNS hijack and media tracking logs |
| `journalctl -u mesocks-udp-proxy -f` | Watch UDP voice/media sessions |
| `PYTHONPATH=src python -m mesocks.setupinfo summary` | Show active profile summary |

The installable package also exposes `mesocks-dns`, `mesocks-udp`, and
`mesocks-setupinfo` entry points for development installs.

---

## Project Layout

| Path | Purpose |
|---|---|
| `src/mesocks/settings.py` | Runtime tunables and `config_local.py` overrides |
| `src/mesocks/profiles.py` | Built-in profiles and service matching |
| `src/mesocks/dnspacket.py` | DNS wire-format parsing/building |
| `src/mesocks/cache.py` | Forward DNS cache and media IP tracker |
| `src/mesocks/ratelimit.py` | Private-network checks and per-IP rate limits |
| `src/mesocks/dns_server.py` | DNS hijack daemon |
| `src/mesocks/udp_proxy.py` | UDP media proxy daemon |
| `dns-proxy.py`, `udp-proxy.py` | Compatibility launchers |
| `tests/` | Unit tests |
| `docs/` | Deployment and profile guides |

---

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

pytest
bash -n setup.sh setup-services.sh
```

The runtime package has no third-party Python dependencies. Development uses
`pytest`.

---

## Troubleshooting

**Text works but voice does not**

```bash
sudo systemctl status mesocks-udp-proxy
journalctl -u mesocks-dns -f
cat /tmp/mesocks-media-ips.json
```

Join a voice channel and check whether a `discord.media` or `discord.gg` media
hostname appears in the DNS logs and cache file.

**DNS does not resolve through the Pi**

```bash
nslookup discord.com YOUR_PI_IP
sudo systemctl status mesocks-dns
```

**TCP proxy does not start**

Check that `/usr/local/bin/sniproxy` exists and that `socks-proxy` is listening
on `127.0.0.1:1080`.

---

## Known Limitations

- MeSocks only catches traffic that goes through DNS. A service using raw IP
  literals can bypass it.
- The UDP proxy has one listen port per deployment. Services with different UDP
  ports may need separate instances.
- Discord and other services can add domains over time. Keep profiles updated
  when logs show service-owned domains outside the active profile.
- Hijacking broad third-party domains can route unrelated traffic through the
  VPN, so profiles should stay conservative.

---

## License

MIT
