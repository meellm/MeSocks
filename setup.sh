#!/bin/bash
# MeSocks - VPN Proxy Setup Script
# Turns Pi into a SOCKS5 proxy that exits through a VPN WiFi network

set -e

echo "🧦 MeSocks VPN Proxy Setup"
echo "=========================="

# Check if running as root for some commands
if [ "$EUID" -ne 0 ]; then
    echo "Note: Some commands need sudo, you may be prompted for password"
fi

# --- Configuration ---
VPN_WIFI="YOUR_VPN_WIFI"           # WiFi network with VPN
NORMAL_WIFI="YOUR_NORMAL_WIFI"           # Normal WiFi (fallback)
VPN_PRIORITY=100
NORMAL_PRIORITY=50
PROXY_PORT=1080

# Load local config if exists (keeps secrets out of git)
[ -f "$(dirname "$0")/config_local.sh" ] && source "$(dirname "$0")/config_local.sh"

echo ""
echo "Configuration:"
echo "  VPN WiFi:     $VPN_WIFI (priority: $VPN_PRIORITY)"
echo "  Normal WiFi:  $NORMAL_WIFI (priority: $NORMAL_PRIORITY)"
echo "  Proxy Port:   $PROXY_PORT"
echo ""

# --- Step 1: Install microsocks ---
echo "[1/4] Installing microsocks..."
sudo apt update
sudo apt install -y microsocks
echo "✅ microsocks installed"

# --- Step 2: Create systemd service ---
echo "[2/4] Creating systemd service..."
sudo tee /etc/systemd/system/socks-proxy.service > /dev/null << EOF
[Unit]
Description=SOCKS5 Proxy (microsocks)
After=network.target

[Service]
ExecStart=/usr/bin/microsocks -i 0.0.0.0 -p $PROXY_PORT
Restart=always
RestartSec=5
User=nobody

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable socks-proxy
sudo systemctl start socks-proxy
echo "✅ SOCKS proxy service created and started"

# --- Step 3: Set WiFi priorities ---
echo "[3/4] Setting WiFi priorities..."
if nmcli connection show "$VPN_WIFI" &>/dev/null; then
    sudo nmcli connection modify "$VPN_WIFI" connection.autoconnect-priority $VPN_PRIORITY
    echo "  $VPN_WIFI → priority $VPN_PRIORITY"
else
    echo "  ⚠️  $VPN_WIFI not found - connect to it first, then re-run"
fi

if nmcli connection show "$NORMAL_WIFI" &>/dev/null; then
    sudo nmcli connection modify "$NORMAL_WIFI" connection.autoconnect-priority $NORMAL_PRIORITY
    echo "  $NORMAL_WIFI → priority $NORMAL_PRIORITY"
else
    echo "  ⚠️  $NORMAL_WIFI not found"
fi
echo "✅ WiFi priorities set"

# --- Step 4: Verify ---
echo "[4/4] Verifying setup..."
echo ""
if systemctl is-active --quiet socks-proxy; then
    echo "✅ Proxy Status: RUNNING"
else
    echo "❌ Proxy Status: NOT RUNNING"
fi

LOCAL_IP=$(hostname -I | awk '{print $1}')
echo "📍 Local IP: $LOCAL_IP"
echo "🔌 Proxy: $LOCAL_IP:$PROXY_PORT"

echo ""
echo "Testing proxy..."
if curl -s --max-time 5 --socks5 127.0.0.1:$PROXY_PORT ifconfig.me; then
    echo " ← Exit IP"
    echo "✅ Proxy working!"
else
    echo "❌ Proxy test failed"
fi

echo ""
echo "=========================="
echo "🎉 Setup complete!"
echo ""
echo "Proxy settings (for apps like Discord, etc.):"
echo "  Type: SOCKS5"
echo "  Host: $LOCAL_IP"
echo "  Port: $PROXY_PORT"
echo ""
