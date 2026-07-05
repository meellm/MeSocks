#!/bin/bash
#
# MeSocks Service Setup
# Sets up DNS proxy, sniproxy (TCP), and UDP media proxy for all configured services.
#
# Architecture:
#   dns-proxy.py   - Port 53: DNS hijack + real IP tracking
#   sniproxy       - Port 443/80: TCP (HTTPS/HTTP) proxy
#   udp-proxy.py   - Port 443 UDP: Media/voice forwarding (if any service needs it)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Load local config if exists
[ -f "$SCRIPT_DIR/config_local.sh" ] && source "$SCRIPT_DIR/config_local.sh"

# Allow override via command line arg
PI_IP="${1:-${PI_IP:-YOUR_PI_IP}}"

echo "========================================"
echo "MeSocks Service Setup"
echo "========================================"
echo "Pi IP: $PI_IP"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Run with sudo:"
    echo "   sudo $0 [$PI_IP]"
    exit 1
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Python3 not found"
    exit 1
fi
echo "Python3 found"

# Check sniproxy binary (required for the TCP path)
SNIPROXY_BIN="/usr/local/bin/sniproxy"
if [ ! -x "$SNIPROXY_BIN" ]; then
    echo
    echo "WARNING: $SNIPROXY_BIN not found."
    echo "The TCP (HTTPS) path needs it. Install from:"
    echo "  https://github.com/ameshkov/sniproxy/releases"
    echo "Download the binary for your architecture (arm64 for Pi 3/4/5),"
    echo "then: sudo install sniproxy $SNIPROXY_BIN"
    echo
    echo "Continuing setup; mesocks-sniproxy will fail to start until installed."
    echo
fi

# Make scripts executable
chmod +x "$SCRIPT_DIR/dns-proxy.py"
chmod +x "$SCRIPT_DIR/udp-proxy.py"
echo "Scripts marked executable"

# ============================================================
# Read the active services config (mesocks.setupinfo flattens the
# profiles; services_config.py in this directory wins over built-ins)
# ============================================================
setupinfo() {
    PYTHONPATH="$SCRIPT_DIR/src:$SCRIPT_DIR" python3 -m mesocks.setupinfo "$1"
}

FORWARD_RULES=$(setupinfo forward-rules)
SERVICE_SUMMARY=$(setupinfo summary)
HAS_UDP=$(setupinfo has-udp)

echo "Configured: $SERVICE_SUMMARY"
echo

# ============================================================
# Migrate old services if they exist
# ============================================================
for old_svc in discord-dns discord-udp-proxy; do
    if systemctl is-enabled "$old_svc" 2>/dev/null; then
        systemctl stop "$old_svc" 2>/dev/null || true
        systemctl disable "$old_svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/$old_svc.service"
        echo "Migrated old service: $old_svc"
    fi
done

# ============================================================
# Service: mesocks-dns (DNS hijack + IP tracking)
# ============================================================
cat > /etc/systemd/system/mesocks-dns.service << EOF
[Unit]
Description=MeSocks DNS Proxy (hijack + IP tracking)
After=network.target
Before=mesocks-sniproxy.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $SCRIPT_DIR/dns-proxy.py $PI_IP
Restart=always
RestartSec=5
User=root
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF
echo "mesocks-dns.service created"

# ============================================================
# Service: mesocks-udp-proxy (media/voice forwarding) - conditional
# ============================================================
if [ "$HAS_UDP" = "True" ]; then
    cat > /etc/systemd/system/mesocks-udp-proxy.service << EOF
[Unit]
Description=MeSocks UDP Media Proxy
After=network.target mesocks-dns.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $SCRIPT_DIR/udp-proxy.py
Restart=always
RestartSec=5
User=root
LimitNOFILE=4096
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF
    echo "mesocks-udp-proxy.service created"
else
    # Remove old UDP service if no services need it
    if [ -f /etc/systemd/system/mesocks-udp-proxy.service ]; then
        systemctl stop mesocks-udp-proxy 2>/dev/null || true
        systemctl disable mesocks-udp-proxy 2>/dev/null || true
        rm -f /etc/systemd/system/mesocks-udp-proxy.service
    fi
    echo "No UDP services configured, skipping UDP proxy"
fi

# ============================================================
# Update sniproxy: TCP proxy plus its private localhost DNS helper
# Rules generated dynamically from the active services config
# ============================================================

# Check for old sniproxy-discord service and migrate
if [ -f /etc/systemd/system/sniproxy-discord.service ] && [ ! -f /etc/systemd/system/mesocks-sniproxy.service ]; then
    systemctl stop sniproxy-discord 2>/dev/null || true
    systemctl disable sniproxy-discord 2>/dev/null || true
    echo "Migrated old sniproxy-discord service"
fi

SNIPROXY_SERVICE="/etc/systemd/system/mesocks-sniproxy.service"
SNIPROXY_BACKUP="/etc/systemd/system/mesocks-sniproxy.service.bak"

if [ -f "$SNIPROXY_SERVICE" ] && [ ! -f "$SNIPROXY_BACKUP" ]; then
    cp "$SNIPROXY_SERVICE" "$SNIPROXY_BACKUP"
    echo "Backed up previous sniproxy config"
fi

cat > "$SNIPROXY_SERVICE" << EOF
[Unit]
Description=MeSocks SNI Proxy (TCP only, DNS handled by mesocks-dns)
After=network.target socks-proxy.service mesocks-dns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/sniproxy \\
  --tls-address=0.0.0.0 \\
  --tls-port=443 \\
  --http-address=0.0.0.0 \\
  --http-port=80 \\
  --dns-address=127.0.0.1 \\
  --dns-port=1053 \\
  --dns-redirect-ipv4-to=$PI_IP \\
  --forward-proxy=socks5://127.0.0.1:1080 \\
$FORWARD_RULES
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF
echo "mesocks-sniproxy.service created with dynamic forward rules"

# Reload systemd
systemctl daemon-reload
echo "Systemd reloaded"

echo
echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo
echo "Services: $SERVICE_SUMMARY"
echo
echo "Architecture:"
echo "  dns-proxy.py   -> Port 53 (DNS hijack + IP tracking)"
echo "  sniproxy       -> Port 443/80 TCP (HTTPS proxy)"
if [ "$HAS_UDP" = "True" ]; then
echo "  udp-proxy.py   -> Port 443 UDP (media/voice forwarding)"
fi
echo
echo "To start services:"
if [ "$HAS_UDP" = "True" ]; then
echo "  sudo systemctl start mesocks-dns mesocks-sniproxy mesocks-udp-proxy"
else
echo "  sudo systemctl start mesocks-dns mesocks-sniproxy"
fi
echo
echo "To enable on boot:"
if [ "$HAS_UDP" = "True" ]; then
echo "  sudo systemctl enable mesocks-dns mesocks-sniproxy mesocks-udp-proxy"
else
echo "  sudo systemctl enable mesocks-dns mesocks-sniproxy"
fi
echo
echo "Check status:"
echo "  sudo systemctl status mesocks-dns"
echo "  sudo systemctl status mesocks-sniproxy"
if [ "$HAS_UDP" = "True" ]; then
echo "  sudo systemctl status mesocks-udp-proxy"
fi
echo "  cat /tmp/mesocks-media-ips.json"
echo
echo "Logs:"
echo "  journalctl -u mesocks-dns -f"
if [ "$HAS_UDP" = "True" ]; then
echo "  journalctl -u mesocks-udp-proxy -f"
fi
echo
echo "To add/remove services:"
echo "  1. Edit $SCRIPT_DIR/services_config.py"
echo "  2. Re-run: sudo $0 $PI_IP"
echo
