"""Runtime settings for the MeSocks daemons.

Everything here is a plain module attribute so the daemons can read
(and, for PI_IP, override via CLI argument) without a config framework.
A ``config_local.py`` on sys.path - normally the repo root, which is
where the launcher scripts live - can override any name listed in
``_OVERRIDABLE`` without touching tracked files.
"""

import ipaddress

# Network
LISTEN_HOST = '0.0.0.0'
DNS_LISTEN_PORT = 53
UPSTREAM_DNS_SERVERS = ['8.8.8.8', '1.1.1.1', '8.8.4.4']  # Fallback order
UPSTREAM_PORT = 53
PI_IP = 'YOUR_PI_IP'  # IP returned for hijacked domains (config_local.py or CLI arg)

# Cache files (shared between the DNS server and UDP proxy)
CACHE_FILE = '/tmp/mesocks-media-ips.json'
OLD_CACHE_FILE = '/tmp/discord-voice-ips.json'  # Pre-rename path, migrated on start

# DNS server tunables
CACHE_TTL = 300  # Seconds a "_latest_media" entry stays usable
HIJACK_TTL = 300  # TTL on hijacked responses (the Pi IP doesn't change)
FORWARD_CACHE_MAX = 4096  # Max cached non-hijacked DNS responses
FORWARD_CACHE_DEFAULT_TTL = 60  # Fallback TTL if parsing fails
FORWARD_CACHE_MAX_TTL = 3600  # Cap cached TTL so bogus records can't pin entries
MEDIA_RE_RESOLVE_INTERVAL = 60  # Re-resolve media domains every N seconds
MEDIA_ACTIVE_WINDOW = 3600  # Keep re-resolving a media domain this long after last client query
CLIENT_MEDIA_TTL = 3600  # How long a per-client media mapping stays valid
QUERY_WORKERS = 32  # Max concurrent query handler threads
RATE_LIMIT_PER_SEC = 50  # Max queries per second per source IP
STATS_INTERVAL = 60  # Print stats every N seconds

# UDP proxy tunables
UDP_DEFAULT_PORT = 443  # Used when profiles disagree or none set a port
SESSION_TIMEOUT = 90  # Seconds of silence before a UDP session is dropped
IP_CHECK_INTERVAL = 10  # Seconds between re-reading the tracker file
TRACKED_IP_MAX_AGE = 300  # Ignore tracked IPs older than this
UDP_BUFFER_SIZE = 65535
MAX_SESSIONS = 512  # Total session cap (each session holds a socket/fd)
MAX_SESSIONS_PER_CLIENT = 64  # Per client IP

# Only accept traffic from private networks (prevents open resolver/relay abuse)
ALLOWED_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
]

_OVERRIDABLE = (
    'PI_IP', 'UPSTREAM_DNS_SERVERS', 'CACHE_FILE',
    'RATE_LIMIT_PER_SEC', 'UDP_DEFAULT_PORT',
)


def _load_local_overrides():
    try:
        import config_local
    except ImportError:
        return
    except Exception as e:  # config_local exists but is broken: warn, keep defaults
        print(f"[Settings] Warning: config_local.py error: {e}, using defaults")
        return
    for name in _OVERRIDABLE:
        if hasattr(config_local, name):
            globals()[name] = getattr(config_local, name)


_load_local_overrides()
