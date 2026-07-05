"""MeSocks DNS server (the `mesocks-dns` systemd service).

What it does:
1. Hijacks domains from the active service profiles (returns the Pi's IP)
2. Resolves and caches the real IPs so the UDP proxy can forward media
3. Forwards every other query to upstream DNS, with an in-memory cache
"""

import os
import shutil
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import settings
from .cache import ForwardCache, MediaCache
from .dnspacket import (
    build_a_query,
    build_empty_response,
    build_response,
    parse_a_answer,
    parse_question,
    validate_ipv4,
)
from .profiles import ServiceMatcher, load_services
from .ratelimit import RateLimiter


# ============================================================
# Upstream resolution
# ============================================================

def _exchange_upstream(query: bytes, timeout: float) -> bytes | None:
    """Send query to upstream servers, return the first response whose
    transaction ID matches. connect() filters datagrams from other sources."""
    txid = query[:2]
    for dns_server in settings.UPSTREAM_DNS_SERVERS:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.connect((dns_server, settings.UPSTREAM_PORT))
            sock.send(query)
            deadline = time.time() + timeout
            while time.time() < deadline:
                response = sock.recv(4096)
                if len(response) >= 12 and response[:2] == txid and response[2] & 0x80:
                    return response
            print(f"[DNS] Upstream {dns_server}: no matching response")
        except Exception as e:
            print(f"[DNS] Upstream {dns_server} failed: {e}")
        finally:
            if sock:
                sock.close()
    return None


def resolve_upstream(domain: str) -> str | None:
    """Resolve domain via upstream DNS with fallback servers, return IP or None."""
    query = build_a_query(domain, os.urandom(2))
    response = _exchange_upstream(query, timeout=3)
    if response is None:
        print(f"[DNS] All upstream servers failed for {domain}")
        return None
    return parse_a_answer(response)


def forward_query(query: bytes) -> bytes | None:
    """Forward a raw client query to upstream DNS with fallback servers."""
    return _exchange_upstream(query, timeout=5)


# ============================================================
# Stats
# ============================================================

class Stats:
    """Thread-safe query statistics."""

    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.hijacked = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.upstream_failures = 0
        self.rate_limited = 0
        self.blocked = 0  # non-private IPs

    def inc(self, field: str, n: int = 1):
        with self.lock:
            setattr(self, field, getattr(self, field) + n)

    def snapshot(self) -> dict:
        with self.lock:
            return {
                'total': self.total, 'hijacked': self.hijacked,
                'cache_hits': self.cache_hits, 'cache_misses': self.cache_misses,
                'upstream_failures': self.upstream_failures,
                'rate_limited': self.rate_limited, 'blocked': self.blocked,
            }


# ============================================================
# DNS Proxy Server
# ============================================================

class DNSProxy:
    def __init__(self, services: dict | None = None):
        services = load_services() if services is None else services
        self.matcher = ServiceMatcher(services)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((settings.LISTEN_HOST, settings.DNS_LISTEN_PORT))
        self.cache = MediaCache(settings.CACHE_FILE)
        self.forward_cache = ForwardCache()
        self.rate_limiter = RateLimiter()
        self.stats = Stats()
        self.resolver_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix='dns-resolve')
        self.query_pool = ThreadPoolExecutor(
            max_workers=settings.QUERY_WORKERS, thread_name_prefix='dns-query')

        # Background threads
        threading.Thread(target=self._periodic_re_resolve, daemon=True).start()
        threading.Thread(target=self._periodic_stats, daemon=True).start()

        svc_names = ', '.join(services.keys())
        print(f"[DNS] MeSocks DNS Proxy")
        print(f"[DNS] Listening on {settings.LISTEN_HOST}:{settings.DNS_LISTEN_PORT}")
        print(f"[DNS] Upstream: {', '.join(settings.UPSTREAM_DNS_SERVERS)}")
        print(f"[DNS] Hijack IP: {settings.PI_IP}")
        print(f"[DNS] Cache file: {settings.CACHE_FILE}")
        print(f"[DNS] Hijacking {len(self.matcher.hijack_domains)} domains across "
              f"{len(services)} service(s): {svc_names}")
        print(f"[DNS] Rate limit: {settings.RATE_LIMIT_PER_SEC}/sec per IP, private networks only")

    def _resolve_and_cache(self, domain: str, is_media: bool,
                           client_ip: str | None = None, refresh: bool = False):
        """Resolve real IP in background and cache it."""
        real_ip = resolve_upstream(domain)
        svc = self.matcher.service_for(domain)
        if real_ip:
            self.cache.set(domain, real_ip, is_media, client_ip=client_ip, refresh=refresh)
            if is_media:
                print(f"[DNS] [{svc}] MEDIA: {domain} -> {real_ip}"
                      + (f" (client {client_ip})" if client_ip else ""))
            else:
                print(f"[DNS] [{svc}] {domain} -> {real_ip}")
        else:
            print(f"[DNS] [{svc}] Failed to resolve: {domain}")

    def _periodic_re_resolve(self):
        """Re-resolve known media domains periodically to detect IP rotations."""
        while True:
            time.sleep(settings.MEDIA_RE_RESOLVE_INTERVAL)
            try:
                domains = self.cache.get_media_domains()
                for domain in domains:
                    self._resolve_and_cache(domain, is_media=True, refresh=True)
            except Exception as e:
                print(f"[DNS] Re-resolve error: {e}")

    def _periodic_stats(self):
        """Print stats and clean up rate limiter periodically."""
        while True:
            time.sleep(settings.STATS_INTERVAL)
            try:
                s = self.stats.snapshot()
                media_domains = self.cache.get_media_domains()
                fwd_cache_size = len(self.forward_cache.cache)
                print(f"[DNS] Stats: {s['total']} queries | "
                      f"{s['hijacked']} hijacked | "
                      f"{s['cache_hits']} cache hits / {s['cache_misses']} misses | "
                      f"{s['rate_limited']} rate-limited | {s['blocked']} blocked | "
                      f"fwd_cache={fwd_cache_size} | media_domains={len(media_domains)}")
                self.rate_limiter.cleanup()
            except Exception as e:
                print(f"[DNS] Stats error: {e}")

    def handle_query(self, data: bytes, addr: tuple):
        """Handle an incoming DNS query."""
        self.stats.inc('total')
        source_ip = addr[0]

        # Rate limiting + private network check
        if not self.rate_limiter.allow(source_ip):
            if not self.rate_limiter.is_private(source_ip):
                self.stats.inc('blocked')
            else:
                self.stats.inc('rate_limited')
            return

        question = parse_question(data)
        if not question or not question[0]:
            return
        domain, qtype, question_end = question

        if self.matcher.is_hijacked(domain):
            self.stats.inc('hijacked')
            if qtype == 1:  # A record
                is_media = self.matcher.is_media(domain)

                # Send hijacked response immediately (don't block on upstream)
                response = build_response(data, settings.PI_IP, question_end,
                                          ttl=settings.HIJACK_TTL)
                self.sock.sendto(response, addr)

                # Resolve and cache real IP in background for the UDP proxy.
                # Pass the client IP so the UDP proxy can route this client
                # to the media server it actually asked for.
                self.resolver_pool.submit(
                    self._resolve_and_cache, domain, is_media,
                    source_ip if is_media else None)
            else:
                # Non-A queries (AAAA, HTTPS, etc) for hijacked domains: return
                # empty response to prevent leaking real IPs via IPv6 lookups
                response = build_empty_response(data, question_end)
                self.sock.sendto(response, addr)
        else:
            # Non-hijacked: check forward cache first
            cached = self.forward_cache.get(domain, qtype, data[:2])
            if cached:
                self.stats.inc('cache_hits')
                self.sock.sendto(cached, addr)
            else:
                self.stats.inc('cache_misses')
                response = forward_query(data)
                if response:
                    self.forward_cache.put(domain, qtype, response)
                    self.sock.sendto(response, addr)
                else:
                    self.stats.inc('upstream_failures')

    def run(self):
        """Main loop."""
        print("[DNS] Running...")
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
                self.query_pool.submit(self.handle_query, data, addr)
            except Exception as e:
                print(f"[DNS] Error: {e}")


# ============================================================
# Main
# ============================================================

def migrate_cache():
    """Migrate the pre-rename cache file to the new path if needed."""
    if os.path.exists(settings.OLD_CACHE_FILE) and not os.path.exists(settings.CACHE_FILE):
        try:
            shutil.move(settings.OLD_CACHE_FILE, settings.CACHE_FILE)
            print(f"[DNS] Migrated cache: {settings.OLD_CACHE_FILE} -> {settings.CACHE_FILE}")
        except Exception as e:
            print(f"[DNS] Cache migration failed: {e}")


def main(argv: list[str] | None = None):
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        settings.PI_IP = argv[0]
        print(f"[*] Using custom hijack IP: {settings.PI_IP}")

    if not validate_ipv4(settings.PI_IP):
        print(f"[DNS] Invalid PI_IP: '{settings.PI_IP}'")
        print(f"      Set it via: config_local.py, or pass as argument:")
        print(f"      sudo {sys.argv[0]} <your-pi-ip>")
        sys.exit(1)

    migrate_cache()

    services = load_services()
    svc_list = ', '.join(services.keys())
    print("=" * 60)
    print("MeSocks DNS Proxy")
    print("=" * 60)
    print()
    print("This server:")
    print(f"  1. Hijacks service domains -> returns Pi's IP")
    print(f"  2. Resolves real IPs -> caches for UDP proxy")
    print(f"  3. Forwards other queries -> {', '.join(settings.UPSTREAM_DNS_SERVERS)}")
    print(f"  4. Services: {svc_list}")
    print()

    try:
        server = DNSProxy(services)
        server.run()
    except KeyboardInterrupt:
        print("\n[DNS] Shutting down...")
    except PermissionError:
        print("\n[DNS] Permission denied. Run with sudo:")
        print(f"      sudo {sys.argv[0]}")
        sys.exit(1)


if __name__ == '__main__':
    main()
