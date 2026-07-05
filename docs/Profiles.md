# Service Profiles

Profiles decide which domains MeSocks hijacks and whether a service needs UDP
media forwarding.

## Built-In Profiles

MeSocks ships with one built-in profile:

- `discord`: app/API domains, legacy domains, CDN/media domains, invite and
  activity domains, plus UDP tracking for common Discord voice/media hosts.

If no `services_config.py` exists, the built-in Discord profile is active.

## Local Overrides

Copy the example file:

```bash
cp services_config.example.py services_config.py
```

`services_config.py` is ignored by git. It replaces the built-in profile set,
so include every service you want active.

```python
SERVICES = {
    "discord": {
        "enabled": True,
        "domains": ["discord.com", "discord.gg", "discord.media"],
        "udp_proxy": {
            "enabled": True,
            "port": 50000,
            "media_patterns": [r"^[a-z0-9\-]+\d+[a-z0-9\-]*\.discord\.media$"],
        },
    },
}
```

## Profile Fields

| Field | Required | Meaning |
|---|---:|---|
| `domains` | yes | Base domains to hijack. Subdomains match automatically. |
| `enabled` | no | Set `False` to keep a profile in the file but disable it. |
| `udp_proxy.enabled` | no | Enables DNS media tracking and the UDP proxy for this service. |
| `udp_proxy.port` | no | UDP listen and remote port. Defaults to `443`; Discord uses `50000`. |
| `udp_proxy.media_patterns` | no | Regexes for media/voice hostnames that should be tracked per client. |

## Notes

- MeSocks routes configured domains only. It cannot catch raw IP literals.
- If two UDP-enabled profiles use different UDP ports, the UDP proxy falls back
  to port `443`; split deployments would need separate proxy instances.
- Be conservative with broad domains. Hijacking a large provider domain can
  route unrelated traffic through the VPN.
