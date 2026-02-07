#!/bin/bash
#
# Discord Voice Proxy Setup
# Adds UDP (voice) support to existing sniproxy-discord setup
#
# Architecture:
#   discord-dns.py      - Port 53: DNS hijack + real IP tracking
#   sniproxy            - Port 443/80: TCP (HTTPS/HTTP) proxy  
#   discord-udp-proxy.py - Port 443 UDP: Voice forwarding
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PI_IP="${1:-YOUR_PI_IP}"

echo "========================================"
echo "Discord Voice (UDP) Proxy Setup"
echo "========================================"
echo "Pi IP: $PI_IP"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Run with sudo:"
    echo "   sudo $0 [$PI_IP]"
    exit 1
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found"
    exit 1
fi
echo "✅ Python3 found"

# Make scripts executable
chmod +x "$SCRIPT_DIR/discord-dns.py"
chmod +x "$SCRIPT_DIR/discord-udp-proxy.py"
echo "✅ Scripts marked executable"

# ============================================================
# Service: discord-dns (replaces sniproxy's DNS)
# ============================================================
cat > /etc/systemd/system/discord-dns.service << EOF
[Unit]
Description=Discord DNS Server (hijack + IP tracking)
After=network.target
Before=sniproxy-discord.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $SCRIPT_DIR/discord-dns.py $PI_IP
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
echo "✅ discord-dns.service created"

# ============================================================
# Service: discord-udp-proxy (voice forwarding)
# ============================================================
cat > /etc/systemd/system/discord-udp-proxy.service << EOF
[Unit]
Description=Discord Voice UDP Proxy
After=network.target discord-dns.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $SCRIPT_DIR/discord-udp-proxy.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
echo "✅ discord-udp-proxy.service created"

# ============================================================
# Update sniproxy: disable its DNS, keep only TCP proxy
# ============================================================
SNIPROXY_SERVICE="/etc/systemd/system/sniproxy-discord.service"
SNIPROXY_BACKUP="/etc/systemd/system/sniproxy-discord.service.pre-voice"

if [ -f "$SNIPROXY_SERVICE" ]; then
    # Backup original
    if [ ! -f "$SNIPROXY_BACKUP" ]; then
        cp "$SNIPROXY_SERVICE" "$SNIPROXY_BACKUP"
        echo "✅ Backed up original sniproxy config"
    fi
    
    # Create new config without DNS (TCP only)
    cat > "$SNIPROXY_SERVICE" << 'EOF'
[Unit]
Description=SNI Proxy for Discord (TCP only, DNS handled by discord-dns)
After=network.target socks-proxy.service discord-dns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/sniproxy \
  --tls-address=0.0.0.0 \
  --tls-port=443 \
  --http-address=0.0.0.0 \
  --http-port=80 \
  --forward-proxy=socks5://127.0.0.1:1080 \
  --forward-rule=discord.com --forward-rule=*.discord.com \
  --forward-rule=discord.gg --forward-rule=*.discord.gg \
  --forward-rule=discord.media --forward-rule=*.discord.media \
  --forward-rule=discord.gift --forward-rule=*.discord.gift \
  --forward-rule=discord.gifts --forward-rule=*.discord.gifts \
  --forward-rule=discord.new --forward-rule=*.discord.new \
  --forward-rule=discord.dev --forward-rule=*.discord.dev \
  --forward-rule=discord.co --forward-rule=*.discord.co \
  --forward-rule=discord.store --forward-rule=*.discord.store \
  --forward-rule=discord.tools --forward-rule=*.discord.tools \
  --forward-rule=discord.design --forward-rule=*.discord.design \
  --forward-rule=discordapp.com --forward-rule=*.discordapp.com \
  --forward-rule=discordapp.net --forward-rule=*.discordapp.net \
  --forward-rule=discordapp.io --forward-rule=*.discordapp.io \
  --forward-rule=discordcdn.com --forward-rule=*.discordcdn.com \
  --forward-rule=discordstatus.com --forward-rule=*.discordstatus.com \
  --forward-rule=discordmerch.com --forward-rule=*.discordmerch.com \
  --forward-rule=discordactivities.com --forward-rule=*.discordactivities.com \
  --forward-rule=discord-activities.com --forward-rule=*.discord-activities.com \
  --forward-rule=discordpartygames.com --forward-rule=*.discordpartygames.com \
  --forward-rule=discordsays.com --forward-rule=*.discordsays.com \
  --forward-rule=dis.gd --forward-rule=*.dis.gd
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    echo "✅ sniproxy updated (DNS removed, TCP only)"
else
    echo "⚠️  sniproxy-discord.service not found"
fi

# Reload systemd
systemctl daemon-reload
echo "✅ Systemd reloaded"

echo
echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo
echo "Architecture:"
echo "  discord-dns.py       → Port 53 (DNS hijack + IP tracking)"
echo "  sniproxy             → Port 443/80 TCP (HTTPS proxy)"
echo "  discord-udp-proxy.py → Port 443 UDP (voice forwarding)"
echo
echo "To start services:"
echo "  sudo systemctl stop sniproxy-discord    # Stop old combined service"
echo "  sudo systemctl start discord-dns        # Start new DNS"
echo "  sudo systemctl start sniproxy-discord   # Start TCP proxy"
echo "  sudo systemctl start discord-udp-proxy  # Start UDP proxy"
echo
echo "Or all at once:"
echo "  sudo systemctl restart sniproxy-discord discord-dns discord-udp-proxy"
echo
echo "To enable on boot:"
echo "  sudo systemctl enable discord-dns discord-udp-proxy"
echo
echo "Check status:"
echo "  sudo systemctl status discord-dns"
echo "  sudo systemctl status discord-udp-proxy"
echo "  cat /tmp/discord-voice-ips.json"
echo
echo "Logs:"
echo "  journalctl -u discord-dns -f"
echo "  journalctl -u discord-udp-proxy -f"
echo
echo "To revert sniproxy to original:"
echo "  sudo cp $SNIPROXY_BACKUP $SNIPROXY_SERVICE"
echo "  sudo systemctl daemon-reload"
echo
