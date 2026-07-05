# Deployment

This guide assumes a Raspberry Pi that already has network access through the
VPN path you want selected services to use.

## Install

```bash
git clone https://github.com/meellm/MeSocks.git
cd MeSocks

sudo ./setup.sh
sudo ./setup-services.sh YOUR_PI_IP
sudo systemctl enable --now mesocks-dns mesocks-sniproxy mesocks-udp-proxy
```

`setup.sh` installs and starts the local SOCKS5 backend. It binds to
`127.0.0.1:1080` by default because `microsocks` has no authentication.

`setup-services.sh` writes the DNS, TCP, and UDP systemd units. It keeps using
the top-level compatibility launchers so existing deployments continue to work
after the package refactor.

## Required External Binaries

- `microsocks`: installed by `setup.sh` from the OS package manager.
- `sniproxy`: expected at `/usr/local/bin/sniproxy`.

If `sniproxy` is missing, `setup-services.sh` warns and still writes the unit;
the TCP path will not start until the binary exists.

## Verify

```bash
sudo systemctl status mesocks-dns mesocks-sniproxy mesocks-udp-proxy socks-proxy
journalctl -u mesocks-dns -f
journalctl -u mesocks-udp-proxy -f
cat /tmp/mesocks-media-ips.json
```

Point a client device's DNS server at the Pi IP, open a configured service, and
watch `mesocks-dns` logs. Hijacked domains should resolve to the Pi, while the
real upstream IPs are recorded for UDP media routing.

## Redeploy After Code Changes

```bash
sudo ./setup-services.sh YOUR_PI_IP
sudo systemctl restart mesocks-dns mesocks-sniproxy mesocks-udp-proxy
```

Restarting interrupts active proxied connections. For Discord voice, leave and
rejoin the call after restarting the UDP proxy.
