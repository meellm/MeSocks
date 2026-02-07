# 🧦 MeSocks

**Transparent VPN proxy for restricted services on Raspberry Pi.**

Route Discord (and other blocked services) through VPN — no app configuration needed. Just point your device's DNS to the Pi.

## ✨ Features

- 🌍 **Bypass blocks** — ISP, country, work/school networks
- 🎤 **Full voice support** — UDP proxying for Discord calls
- 📱 **Any device** — Windows, Mac, Linux, iOS, Android, consoles
- ⚡ **Transparent** — no app changes, just set DNS
- 🔌 **Extensible** — add any restricted domain
- 🍓 **Runs on Raspberry Pi**

## 🏗️ Architecture

```
[Any Device] ──DNS──▶ [Pi on VPN Network] ──▶ [VPN Exit] ──▶ [Internet]
                              │
                    ┌─────────┴─────────┐
                    │                   │
               TCP :443            UDP :443
               (sniproxy)      (discord-udp-proxy)
                    │                   │
                    ▼                   ▼
              Discord API         Discord Voice
```

**How it works:**
1. Device asks Pi for `discord.com` IP
2. Pi returns its own IP (hijack)
3. Device connects to Pi thinking it's Discord
4. Pi forwards traffic through VPN to real Discord

## 🚀 Quick Start

### Requirements

- Raspberry Pi connected to a VPN network
- Python 3.10+

### Installation

```bash
git clone https://github.com/meellm/MeSocks.git
cd MeSocks

# TCP only (text, API, images)
sudo ./setup.sh

# Full setup with voice support
sudo ./setup-voice.sh YOUR_PI_IP
```

### Configure Your Device

Point your device's DNS to your Pi's IP:

| Platform | How |
|----------|-----|
| **Windows** | Network settings → IPv4 → DNS: `[Pi IP]` |
| **Mac** | System Preferences → Network → DNS |
| **iOS** | WiFi → (i) → Configure DNS → Manual |
| **Android** | WiFi → Modify → Advanced → DNS |
| **Linux** | `/etc/resolv.conf` or NetworkManager |

That's it! Discord now routes through VPN.

## 📋 Services

| Service | Port | Purpose |
|---------|------|---------|
| `discord-dns` | UDP 53 | DNS hijack + IP caching |
| `discord-udp-proxy` | UDP 443 | Voice traffic forwarding |
| `sniproxy-discord` | TCP 443/80 | HTTPS/HTTP forwarding |
| `socks-proxy` | TCP 1080 | SOCKS5 backend |

### Commands

```bash
# Check status
sudo systemctl status discord-dns
sudo systemctl status discord-udp-proxy

# View logs
journalctl -u discord-dns -f

# Restart all
sudo systemctl restart discord-dns sniproxy-discord discord-udp-proxy
```

## 🌐 Covered Domains

Currently configured for Discord:
- `discord.com`, `discord.gg`, `discord.media`
- `discordapp.com`, `discordapp.net`, `discordcdn.com`
- Voice servers (`*.discord.gg`)
- And 15+ more Discord-related domains

### Adding More Services

Edit the domain list in `discord-dns.py` to add other blocked services:

```python
DISCORD_DOMAINS = [
    "discord.com",
    "discord.gg",
    # Add your domains here:
    "example-blocked-site.com",
]
```

## 🔧 Components

| File | Purpose |
|------|---------|
| `discord-dns.py` | DNS server — hijacks domains, caches real IPs |
| `discord-udp-proxy.py` | UDP proxy — forwards voice traffic |
| `setup.sh` | Basic setup (TCP only) |
| `setup-voice.sh` | Full setup with voice support |

### External Dependencies

- **[sniproxy](https://github.com/ameshkov/sniproxy)** — SNI-based TCP proxy
- **[microsocks](https://github.com/rofl0r/microsocks)** — Lightweight SOCKS5 server

## 🔍 Troubleshooting

**Text works, voice doesn't:**
```bash
sudo systemctl status discord-udp-proxy
cat /tmp/discord-voice-ips.json
```

**DNS not resolving:**
```bash
nslookup discord.com YOUR_PI_IP
```

**Can't reach Discord at all:**
```bash
# Check if Pi can reach Discord through VPN
curl -I https://discord.com
```

## 📁 File Locations

| File | Location |
|------|----------|
| Voice IP cache | `/tmp/discord-voice-ips.json` |
| Services | `/etc/systemd/system/discord-*.service` |
| sniproxy | `/usr/local/bin/sniproxy` |

## 📄 License

MIT

---

Built for bypassing unfair restrictions. 🧦
