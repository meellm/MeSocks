"""Caches shared by the DNS server, plus the media IP tracker file.

ForwardCache keeps upstream DNS responses in memory so repeated queries
don't hit the upstream servers. MediaCache is the JSON file the DNS
server writes and the UDP proxy reads - it maps media/voice domains
(and the clients that asked for them) to their real IPs.
"""

import json
import os
import tempfile
import threading
import time
from collections import OrderedDict

from . import settings
from .dnspacket import is_cacheable_response, parse_answer_ttl


class ForwardCache:
    """In-memory cache for non-hijacked DNS responses (LRU, TTL-aware)."""

    def __init__(self, max_entries: int = settings.FORWARD_CACHE_MAX):
        self.max_entries = max_entries
        self.cache: OrderedDict[tuple, tuple] = OrderedDict()  # (domain, qtype) -> (response_bytes, expiry)
        self.lock = threading.Lock()

    def _parse_ttl(self, response: bytes) -> int | None:
        """TTL from the first answer, floored at 10s and capped (see settings)."""
        ttl = parse_answer_ttl(response)
        if ttl is None:
            return None
        return max(min(ttl, settings.FORWARD_CACHE_MAX_TTL), 10)

    def get(self, domain: str, qtype: int, new_txid: bytes) -> bytes | None:
        """Look up cached response. Rewrites transaction ID for the new query."""
        key = (domain, qtype)
        with self.lock:
            entry = self.cache.get(key)
            if entry is None:
                return None
            response_bytes, expiry = entry
            if time.time() > expiry:
                del self.cache[key]
                return None
            self.cache.move_to_end(key)  # most recently used
        return new_txid + response_bytes[2:]

    def put(self, domain: str, qtype: int, response: bytes):
        """Cache a DNS response, parsing TTL from the answer."""
        if not is_cacheable_response(response):
            return
        ttl = self._parse_ttl(response) or settings.FORWARD_CACHE_DEFAULT_TTL
        key = (domain, qtype)
        expiry = time.time() + ttl
        with self.lock:
            self.cache[key] = (response, expiry)
            self.cache.move_to_end(key)
            while len(self.cache) > self.max_entries:
                self.cache.popitem(last=False)


class MediaCache:
    """Media/voice IP tracker with atomic JSON file persistence.

    Layout of the file (all timestamps are epoch seconds):

        {
          "<domain>": {"ip", "timestamp", "is_media", "last_query"},
          "_latest_media":  {"domain", "ip", "timestamp"},
          "_media_domains": {"<domain>": {"ip", "timestamp", "last_query"}},
          "_client_media":  {"<client_ip>": {"domain", "ip", "timestamp"}}
        }
    """

    def __init__(self, cache_file: str):
        self.cache_file = cache_file
        self.cache = {}
        self.lock = threading.Lock()
        self.load()

    def load(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                self.cache = data if isinstance(data, dict) else {}
        except Exception:
            self.cache = {}

    def save(self):
        """Atomic write to prevent the UDP proxy from reading partial JSON."""
        try:
            with self.lock:
                self._prune_locked()
                snapshot = json.dumps(self.cache, indent=2)
            dir_name = os.path.dirname(self.cache_file) or '/tmp'
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.tmp')
            with os.fdopen(fd, 'w') as f:
                f.write(snapshot)
            os.replace(tmp_path, self.cache_file)
        except Exception as e:
            print(f"[Cache] Save error: {e}")

    def _prune_locked(self):
        """Drop long-stale entries so the cache file stays bounded (lock held)."""
        now = time.time()
        for domain in [d for d, e in self.cache.items()
                       if not d.startswith('_') and (
                           not isinstance(e, dict)
                           or now - e.get('timestamp', 0) > settings.MEDIA_ACTIVE_WINDOW)]:
            del self.cache[domain]
        for table, ttl in (('_media_domains', settings.MEDIA_ACTIVE_WINDOW),
                           ('_client_media', settings.CLIENT_MEDIA_TTL)):
            entries = self.cache.get(table, {})
            if not isinstance(entries, dict):
                self.cache[table] = {}
                continue
            for key in [k for k, e in entries.items()
                        if not isinstance(e, dict) or now - e.get('timestamp', 0) > ttl]:
                del entries[key]

    def set(self, domain: str, ip: str, is_media: bool = False,
            client_ip: str | None = None, refresh: bool = False):
        """Record a resolved IP.

        client_ip ties the resolution to the client that asked, so the UDP
        proxy can route each client to its own media server. refresh=True
        marks background re-resolutions, which update the IP but must not
        extend the domain's active window (or it would never age out).
        """
        now = time.time()
        with self.lock:
            prev = self.cache.get(domain, {})
            self.cache[domain] = {
                'ip': ip,
                'timestamp': now,
                'is_media': is_media,
                'last_query': prev.get('last_query', now) if refresh else now,
            }
            if is_media:
                self.cache['_latest_media'] = {
                    'domain': domain,
                    'ip': ip,
                    'timestamp': now
                }
                media_domains = self.cache.setdefault('_media_domains', {})
                prev_md = media_domains.get(domain, {})
                media_domains[domain] = {
                    'ip': ip,
                    'timestamp': now,
                    'last_query': prev_md.get('last_query', now) if refresh else now,
                }
                if client_ip:
                    self.cache.setdefault('_client_media', {})[client_ip] = {
                        'domain': domain,
                        'ip': ip,
                        'timestamp': now,
                    }
        # Save outside lock to avoid blocking other threads on file I/O
        self.save()

    def get_media_domains(self) -> list[str]:
        """Return media domains a client asked about recently (for re-resolution)."""
        with self.lock:
            vd = self.cache.get('_media_domains', {})
            if not isinstance(vd, dict):
                return []
            now = time.time()
            return [d for d, e in vd.items()
                    if isinstance(e, dict)
                    and now - e.get('last_query', e.get('timestamp', 0)) < settings.MEDIA_ACTIVE_WINDOW]

    def get_latest_media(self) -> tuple[str, str] | None:
        with self.lock:
            entry = self.cache.get('_latest_media')
            if isinstance(entry, dict):
                timestamp = entry.get('timestamp')
                domain = entry.get('domain')
                ip = entry.get('ip')
                if (isinstance(timestamp, (int, float))
                        and isinstance(domain, str)
                        and isinstance(ip, str)
                        and time.time() - timestamp < settings.CACHE_TTL):
                    return (domain, ip)
        return None
