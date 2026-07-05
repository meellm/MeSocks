"""Service profiles: which domains get hijacked and which need UDP forwarding.

A profile is a plain dict:

    {
        "domains": ["example.com", ...],   # base domains; subdomains match too
        "enabled": True,                   # optional, defaults to True
        "udp_proxy": {                     # optional, only for UDP media services
            "enabled": True,
            "port": 50000,
            "media_patterns": [r"^media\\d+\\.example\\.com$"],
        },
    }

Built-in profiles live in BUILTIN_PROFILES. Users override the active
set by creating a ``services_config.py`` next to the launcher scripts
(copy ``services_config.example.py``); if that file doesn't exist, the
built-ins are used.
"""

import re

# Built-in profiles

DISCORD = {
    "domains": [
        "discord.com",
        "discord.gg",
        "discord.media",
        "discord.gift",
        "discord.gifts",
        "discord.new",
        "discord.dev",
        "discord.co",
        "discord.store",
        "discord.tools",
        "discord.design",
        "discord.app",
        "discordapp.com",
        "discordapp.net",
        "discordapp.io",
        "discordcdn.com",
        "discordstatus.com",
        "discordmerch.com",
        "discordactivities.com",
        "discord-activities.com",
        "discordpartygames.com",
        "discordsays.com",
        "discordsez.com",
        "discordquests.com",
        "discordstatic.com",
        "dis.gd",
    ],
    "udp_proxy": {
        "enabled": True,
        "port": 50000,
        "media_patterns": [
            # Voice/media hostnames like "russia9001.discord.gg" or
            # "ams1234.discord.media" - a region word plus a number.
            r"^[a-z0-9\-]+\d+[a-z0-9\-]*\.discord\.gg$",
            r"^[a-z0-9\-]+\d+[a-z0-9\-]*\.discord\.media$",
        ],
    },
}

BUILTIN_PROFILES = {
    "discord": DISCORD,
}


def load_services() -> dict:
    """Return the active service profiles, keyed by name.

    A user ``services_config.py`` (importable from sys.path - normally the
    repo root, where the launcher scripts live) wins over the built-ins.
    Profiles with ``"enabled": False`` are dropped here so callers never
    see them.
    """
    try:
        from services_config import SERVICES  # user override
        services = SERVICES
    except ImportError:
        services = BUILTIN_PROFILES
    active = {}
    for name, cfg in services.items():
        if not isinstance(cfg, dict):
            print(f"[Profiles] Warning: service '{name}' is not a dict, skipping")
            continue
        if not cfg.get('enabled', True):
            continue
        if not cfg.get('domains'):
            print(f"[Profiles] Warning: service '{name}' has no domains, skipping")
            continue
        active[name] = cfg
    return active


def udp_configs(services: dict) -> dict:
    """Return {service_name: {'port': int}} for UDP-enabled services."""
    configs = {}
    for name, cfg in services.items():
        udp = cfg.get('udp_proxy')
        if udp and udp.get('enabled'):
            configs[name] = {'port': udp.get('port', 443)}
    return configs


def udp_listen_port(services: dict, default: int = 443) -> int:
    """Port the UDP proxy should listen on.

    If every UDP-enabled service agrees on a port, honor it; otherwise
    (or when none are configured) fall back to the default.
    """
    ports = {c['port'] for c in udp_configs(services).values()}
    return ports.pop() if len(ports) == 1 else default


class ServiceMatcher:
    """Answers "is this domain one of ours?" for a set of profiles.

    Built once at daemon start; all methods are read-only afterwards, so
    it's safe to share across threads.
    """

    def __init__(self, services: dict):
        self.services = services
        self.hijack_domains: list[str] = []
        self.media_patterns: list[re.Pattern] = []
        self._domain_to_service: dict[str, str] = {}
        for name, cfg in services.items():
            for domain in cfg.get('domains', []):
                self.hijack_domains.append(domain)
                self._domain_to_service[domain] = name
            udp = cfg.get('udp_proxy')
            if udp and udp.get('enabled'):
                for pattern in udp.get('media_patterns', []):
                    self.media_patterns.append(re.compile(pattern))

    def is_hijacked(self, domain: str) -> bool:
        """True if domain (or a parent of it) belongs to an active profile."""
        if not domain:
            return False
        domain = domain.lower()
        for d in self.hijack_domains:
            if domain == d or domain.endswith('.' + d):
                return True
        return False

    def is_media(self, domain: str) -> bool:
        """True if domain looks like a media/voice server (needs UDP tracking)."""
        if not domain:
            return False
        domain = domain.lower()
        return any(p.match(domain) for p in self.media_patterns)

    def service_for(self, domain: str) -> str:
        """Name of the profile a hijacked domain belongs to ('unknown' if none)."""
        domain = domain.lower()
        for d, svc in self._domain_to_service.items():
            if domain == d or domain.endswith('.' + d):
                return svc
        return 'unknown'
