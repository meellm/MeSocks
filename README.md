# MeSocks

**Transparent VPN proxy for restricted services on Raspberry Pi.**

Route Discord, Spotify, Netflix, and other blocked services through VPN — no app configuration needed. Just point your device's DNS to the Pi.

## Features

- **Bypass blocks** — ISP, country, work/school networks
- **Full voice support** — UDP proxying for Discord calls
- **Any device** — Windows, Mac, Linux, iOS, Android, consoles
- **Transparent** — no app changes, just set DNS
- **Multi-service** — add any service via config file
- **Runs on Raspberry Pi**

## Architecture

```
[Any Device] ──DNS──> [Pi on VPN Network] ──> [VPN Exit] ──> [Internet]
                              │
                    ┌─────────┴─────────┐
                    │                   │
               TCP :443            UDP :443
               (sniproxy)        (udp-proxy)
                    │                   │
                    v                   v
              Service APIs       Voice/Media
```

**How it works:**
1. Device asks Pi for `discord.com` IP
2. Pi returns its own IP (hijack)
3. Device connects to Pi thinking it's the real server
4. Pi forwards traffic through VPN to the real server

## Quick Start

### Requirements

- Raspberry Pi connected to a VPN network
- Python 3.10+

### Installation

```bash
git clone https://github.com/meellm/MeSocks.git
cd MeSocks

# TCP only (text, API, images)
sudo ./setup.sh

# Full setup with voice/media support
sudo ./setup-services.sh YOUR_PI_IP
```

### Configure Your Device

Point your device's DNS to your Pi's IP:

| Platform | How |
|----------|-----|
| **Windows** | Network settings > IPv4 > DNS: `[Pi IP]` |
| **Mac** | System Preferences > Network > DNS |
| **iOS** | WiFi > (i) > Configure DNS > Manual |
| **Android** | WiFi > Modify > Advanced > DNS |
| **Linux** | `/etc/resolv.conf` or NetworkManager |

That's it! Configured services now route through VPN.

## Adding Services

Copy the example config and edit it:

```bash
cp services_config.example.py services_config.py
nano services_config.py
```

Each service is a dict entry with a list of domains:

```python
SERVICES = {
    "discord": {
        "domains": ["discord.com", "discord.gg", "discordapp.com", ...],
        "udp_proxy": {  # Optional: only for services needing UDP
            "enabled": True,
            "port": 443,
            "media_patterns": [r"^[a-z\-]+\d+\.discord\.gg$"],
        },
    },
    "spotify": {
        "domains": ["spotify.com", "scdn.co", "spotifycdn.com"],
    },
    "netflix": {
        "domains": ["netflix.com", "nflxvideo.net", "nflximg.net"],
    },
}
```

After editing, re-run setup to apply:

```bash
sudo ./setup-services.sh YOUR_PI_IP
sudo systemctl restart mesocks-dns mesocks-sniproxy
```

If you don't create `services_config.py`, the default Discord-only config is used automatically.

## Services

| Service | Port | Purpose |
|---------|------|---------|
| `mesocks-dns` | UDP 53 | DNS hijack + IP caching |
| `mesocks-udp-proxy` | UDP 443 | Voice/media traffic forwarding |
| `mesocks-sniproxy` | TCP 443/80 | HTTPS/HTTP forwarding |
| `socks-proxy` | TCP 1080 | SOCKS5 backend |

### Commands

```bash
# Check status
sudo systemctl status mesocks-dns
sudo systemctl status mesocks-udp-proxy

# View logs
journalctl -u mesocks-dns -f

# Restart all
sudo systemctl restart mesocks-dns mesocks-sniproxy mesocks-udp-proxy
```

## Components

| File | Purpose |
|------|---------|
| `dns-proxy.py` | DNS server — hijacks domains, caches real IPs |
| `udp-proxy.py` | UDP proxy — forwards voice/media traffic |
| `setup.sh` | Basic setup (TCP only) |
| `setup-services.sh` | Full setup with voice/media support |
| `services_default.py` | Built-in Discord config (fallback) |
| `services_config.example.py` | Example config with Spotify/Netflix/YouTube |

### External Dependencies

- **[sniproxy](https://github.com/ameshkov/sniproxy)** — SNI-based TCP proxy
- **[microsocks](https://github.com/rofl0r/microsocks)** — Lightweight SOCKS5 server

## Troubleshooting

**Text works, voice doesn't:**
```bash
sudo systemctl status mesocks-udp-proxy
cat /tmp/mesocks-media-ips.json
```

**DNS not resolving:**
```bash
nslookup discord.com YOUR_PI_IP
```

**Can't reach service at all:**
```bash
# Check if Pi can reach the service through VPN
curl -I https://discord.com
```

## File Locations

| File | Location |
|------|----------|
| Media IP cache | `/tmp/mesocks-media-ips.json` |
| Services | `/etc/systemd/system/mesocks-*.service` |
| sniproxy | `/usr/local/bin/sniproxy` |
| User config | `services_config.py` (create from example) |

## License

MIT

---

Built for bypassing unfair restrictions.
