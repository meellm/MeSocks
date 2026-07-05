"""Per-source-IP rate limiting and private-network gating for the DNS server."""

import ipaddress
import threading
import time

from . import settings


class RateLimiter:
    """Per-IP rate limiter using sliding window counters.

    Also owns the "is this a private address?" check, since both gates
    run on every incoming packet and share the per-IP cache.
    """

    def __init__(self, max_per_sec: int = settings.RATE_LIMIT_PER_SEC,
                 allowed_networks=None):
        self.max_per_sec = max_per_sec
        self.allowed_networks = allowed_networks or settings.ALLOWED_NETWORKS
        self.counters: dict[str, list[float]] = {}
        self.lock = threading.Lock()
        self._allowed_cache: dict[str, bool] = {}  # IP -> is_allowed

    def is_private(self, ip: str) -> bool:
        """Check if IP is in the allowed networks (cached per IP)."""
        if ip in self._allowed_cache:
            return self._allowed_cache[ip]
        try:
            addr = ipaddress.ip_address(ip)
            allowed = any(addr in net for net in self.allowed_networks)
        except ValueError:
            allowed = False
        # Bound the cache so spoofed source addresses can't exhaust memory
        if len(self._allowed_cache) >= 4096:
            self._allowed_cache.clear()
        self._allowed_cache[ip] = allowed
        return allowed

    def allow(self, ip: str) -> bool:
        """Return True if a query from this IP should be processed."""
        if not self.is_private(ip):
            return False
        now = time.time()
        with self.lock:
            timestamps = self.counters.get(ip, [])
            cutoff = now - 1.0
            timestamps = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= self.max_per_sec:
                self.counters[ip] = timestamps
                return False
            timestamps.append(now)
            self.counters[ip] = timestamps
        return True

    def cleanup(self):
        """Remove stale entries (call periodically)."""
        cutoff = time.time() - 2.0
        with self.lock:
            stale = [ip for ip, ts in self.counters.items() if not ts or ts[-1] < cutoff]
            for ip in stale:
                del self.counters[ip]
