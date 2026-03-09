#!/usr/bin/env python3
"""
Discord DNS Server

Custom DNS server that:
1. Hijacks Discord domains (returns Pi's IP)
2. BUT also resolves and caches real IPs for UDP forwarding
3. Forwards all other queries to upstream

This replaces sniproxy's DNS functionality.
"""

import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
import ipaddress
import tempfile
import time
import json
import os
import re
import sys

# ============================================================
# Configuration
# ============================================================

LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 53
UPSTREAM_DNS_SERVERS = ['8.8.8.8', '1.1.1.1', '8.8.4.4']  # Fallback DNS servers
UPSTREAM_PORT = 53
PI_IP = 'YOUR_PI_IP'  # IP to return for hijacked domains (override in config_local.py)
CACHE_FILE = '/tmp/discord-voice-ips.json'
CACHE_TTL = 300  # 5 minutes
HIJACK_TTL = 300  # TTL for hijacked responses (Pi IP doesn't change)
FORWARD_CACHE_MAX = 4096  # Max cached non-Discord DNS responses
FORWARD_CACHE_DEFAULT_TTL = 60  # Fallback TTL if parsing fails
VOICE_RE_RESOLVE_INTERVAL = 60  # Re-resolve voice domains every N seconds
QUERY_WORKERS = 32  # Max concurrent query handler threads
RATE_LIMIT_PER_SEC = 50  # Max queries per second per source IP
STATS_INTERVAL = 60  # Print stats every N seconds

# Only accept queries from private networks (prevents open resolver abuse)
ALLOWED_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
]

# Load local config if exists (keeps secrets out of git)
try:
    from config_local import PI_IP
except ImportError:
    pass
except Exception as e:
    print(f"[DNS] Warning: config_local.py error: {e}, using defaults")

# Discord domains to hijack
DISCORD_DOMAINS = [
    'discord.com',
    'discord.gg',
    'discord.media',
    'discord.gift',
    'discord.gifts',
    'discord.new',
    'discord.dev',
    'discord.co',
    'discord.store',
    'discord.tools',
    'discord.design',
    'discordapp.com',
    'discordapp.net',
    'discordapp.io',
    'discordcdn.com',
    'discordstatus.com',
    'discordmerch.com',
    'discordactivities.com',
    'discord-activities.com',
    'discordpartygames.com',
    'discordsays.com',
    'discordsez.com',
    'discordquests.com',
    'discord.app',
    'dis.gd',
    'discordstatic.com',
]

# Voice server patterns (for logging)
VOICE_PATTERNS = [
    r'^[a-z\-]+\d+\.discord\.gg$',
    r'^[a-z\-]+\d+\.discord\.media$',
]

# ============================================================
# DNS Utilities
# ============================================================

def parse_domain(data: bytes) -> str | None:
    """Extract domain name from DNS query packet"""
    try:
        pos = 12  # Skip header
        parts = []
        while data[pos] != 0:
            length = data[pos]
            pos += 1
            parts.append(data[pos:pos+length].decode('ascii', errors='ignore'))
            pos += length
        return '.'.join(parts).lower()
    except Exception:
        return None


def parse_query_type(data: bytes) -> int:
    """Extract query type from DNS packet"""
    try:
        pos = 12
        while data[pos] != 0:
            pos += data[pos] + 1
        pos += 1  # null terminator
        qtype = struct.unpack('>H', data[pos:pos+2])[0]
        return qtype
    except Exception:
        return 0


def build_response(query: bytes, ip: str) -> bytes:
    """Build DNS response with A record pointing to ip"""
    # Copy transaction ID and set response flags
    response = bytearray()
    response += query[:2]  # Transaction ID
    response += b'\x81\x80'  # Flags: response, recursion available
    response += query[4:6]  # Questions count
    response += b'\x00\x01'  # Answers count = 1
    response += b'\x00\x00'  # Authority count
    response += b'\x00\x00'  # Additional count
    
    # Copy question section
    pos = 12
    while query[pos] != 0:
        pos += query[pos] + 1
    pos += 5  # null + qtype + qclass
    response += query[12:pos]
    
    # Add answer
    response += b'\xc0\x0c'  # Pointer to domain name in question
    response += b'\x00\x01'  # Type A
    response += b'\x00\x01'  # Class IN
    response += struct.pack('>I', HIJACK_TTL)  # TTL for hijacked response
    response += b'\x00\x04'  # Data length
    response += bytes(int(x) for x in ip.split('.'))  # IP address
    
    return bytes(response)


def build_empty_response(query: bytes) -> bytes:
    """Build DNS response with no answers (NXDOMAIN-style empty response)"""
    response = bytearray()
    response += query[:2]  # Transaction ID
    response += b'\x81\x80'  # Flags: response, recursion available
    response += query[4:6]  # Questions count
    response += b'\x00\x00'  # Answers count = 0
    response += b'\x00\x00'  # Authority count
    response += b'\x00\x00'  # Additional count

    # Copy question section
    pos = 12
    while query[pos] != 0:
        pos += query[pos] + 1
    pos += 5  # null + qtype + qclass
    response += query[12:pos]

    return bytes(response)


def resolve_upstream(domain: str) -> str | None:
    """Resolve domain via upstream DNS with fallback servers, return IP or None"""
    # Build query
    transaction_id = os.urandom(2)
    flags = b'\x01\x00'
    qdcount = b'\x00\x01'
    counts = b'\x00\x00\x00\x00\x00\x00'

    qname = b''
    for part in domain.split('.'):
        qname += bytes([len(part)]) + part.encode()
    qname += b'\x00'

    qtype = b'\x00\x01'  # A
    qclass = b'\x00\x01'  # IN

    query = transaction_id + flags + qdcount + counts + qname + qtype + qclass

    for dns_server in UPSTREAM_DNS_SERVERS:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(query, (dns_server, UPSTREAM_PORT))
            response, _ = sock.recvfrom(1024)
            sock.close()
            sock = None

            # Parse response for A record
            ancount = struct.unpack('>H', response[6:8])[0]
            if ancount == 0:
                return None

            pos = 12
            while response[pos] != 0:
                pos += response[pos] + 1
            pos += 5

            for _ in range(ancount):
                if response[pos] & 0xC0 == 0xC0:
                    pos += 2
                else:
                    while response[pos] != 0:
                        pos += response[pos] + 1
                    pos += 1

                rtype = struct.unpack('>H', response[pos:pos+2])[0]
                pos += 8
                rdlength = struct.unpack('>H', response[pos:pos+2])[0]
                pos += 2

                if rtype == 1 and rdlength == 4:
                    return '.'.join(str(b) for b in response[pos:pos+4])
                pos += rdlength

            return None
        except Exception as e:
            print(f"[DNS] Upstream {dns_server} failed for {domain}: {e}")
            continue
        finally:
            if sock:
                sock.close()

    print(f"[DNS] All upstream servers failed for {domain}")
    return None


def forward_query(query: bytes) -> bytes | None:
    """Forward query to upstream DNS with fallback servers"""
    for dns_server in UPSTREAM_DNS_SERVERS:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(query, (dns_server, UPSTREAM_PORT))
            response, _ = sock.recvfrom(4096)
            return response
        except Exception as e:
            print(f"[DNS] Forward to {dns_server} failed: {e}")
            continue
        finally:
            if sock:
                sock.close()
    return None


# ============================================================
# Forward DNS Cache (non-Discord queries)
# ============================================================

class ForwardCache:
    """In-memory cache for non-Discord DNS responses to avoid repeated upstream queries."""

    def __init__(self, max_entries: int = FORWARD_CACHE_MAX):
        self.max_entries = max_entries
        self.cache: OrderedDict[tuple, tuple] = OrderedDict()  # (domain, qtype) -> (response_bytes, expiry)
        self.lock = threading.Lock()

    def _parse_ttl(self, response: bytes) -> int | None:
        """Extract TTL from first answer record in DNS response."""
        try:
            ancount = struct.unpack('>H', response[6:8])[0]
            if ancount == 0:
                return None
            # Skip question section
            pos = 12
            while response[pos] != 0:
                pos += response[pos] + 1
            pos += 5  # null + qtype + qclass
            # Parse first answer name (handle pointer or labels)
            if response[pos] & 0xC0 == 0xC0:
                pos += 2
            else:
                while response[pos] != 0:
                    pos += response[pos] + 1
                pos += 1
            # pos is now at TYPE; TTL is at pos+4 (skip type=2, class=2)
            ttl = struct.unpack('>I', response[pos + 4:pos + 8])[0]
            return max(ttl, 10)  # Floor at 10s to avoid constant re-queries
        except Exception:
            return None

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
            # Move to end (most recently used)
            self.cache.move_to_end(key)
        # Rewrite transaction ID (bytes 0:2)
        return new_txid + response_bytes[2:]

    def put(self, domain: str, qtype: int, response: bytes):
        """Cache a DNS response, parsing TTL from the answer."""
        ttl = self._parse_ttl(response) or FORWARD_CACHE_DEFAULT_TTL
        key = (domain, qtype)
        expiry = time.time() + ttl
        with self.lock:
            self.cache[key] = (response, expiry)
            self.cache.move_to_end(key)
            # Evict oldest if over capacity
            while len(self.cache) > self.max_entries:
                self.cache.popitem(last=False)


# ============================================================
# Discord IP Cache (voice tracking + file persistence)
# ============================================================

class DNSCache:
    def __init__(self, cache_file: str):
        self.cache_file = cache_file
        self.cache = {}
        self.lock = threading.Lock()
        self.load()

    def load(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
        except Exception:
            self.cache = {}

    def save(self):
        """Atomic write to prevent UDP proxy from reading partial JSON."""
        try:
            dir_name = os.path.dirname(self.cache_file) or '/tmp'
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.tmp')
            with os.fdopen(fd, 'w') as f:
                json.dump(self.cache, f, indent=2)
            os.replace(tmp_path, self.cache_file)
        except Exception as e:
            print(f"[Cache] Save error: {e}")

    def set(self, domain: str, ip: str, is_voice: bool = False):
        with self.lock:
            self.cache[domain] = {
                'ip': ip,
                'timestamp': time.time(),
                'is_voice': is_voice
            }
            if is_voice:
                self.cache['_latest_voice'] = {
                    'domain': domain,
                    'ip': ip,
                    'timestamp': time.time()
                }
                # Per-domain voice IP tracking
                if '_voice_domains' not in self.cache:
                    self.cache['_voice_domains'] = {}
                self.cache['_voice_domains'][domain] = {
                    'ip': ip,
                    'timestamp': time.time()
                }
        # Save outside lock to avoid blocking other threads on file I/O
        self.save()

    def get_voice_domains(self) -> list[str]:
        """Return list of recently-seen voice domains for re-resolution."""
        with self.lock:
            vd = self.cache.get('_voice_domains', {})
            now = time.time()
            return [d for d, e in vd.items() if now - e['timestamp'] < CACHE_TTL]

    def get_latest_voice(self) -> tuple[str, str] | None:
        with self.lock:
            if '_latest_voice' in self.cache:
                entry = self.cache['_latest_voice']
                if time.time() - entry['timestamp'] < CACHE_TTL:
                    return (entry['domain'], entry['ip'])
        return None


# ============================================================
# Rate Limiter
# ============================================================

class RateLimiter:
    """Per-IP rate limiter using sliding window counters."""

    def __init__(self, max_per_sec: int = RATE_LIMIT_PER_SEC):
        self.max_per_sec = max_per_sec
        self.counters: dict[str, list[float]] = {}
        self.lock = threading.Lock()
        self._allowed_cache: dict[str, bool] = {}  # IP -> is_allowed (private network check)

    def is_private(self, ip: str) -> bool:
        """Check if IP is in ALLOWED_NETWORKS (cached per IP)."""
        if ip in self._allowed_cache:
            return self._allowed_cache[ip]
        try:
            addr = ipaddress.ip_address(ip)
            allowed = any(addr in net for net in ALLOWED_NETWORKS)
        except ValueError:
            allowed = False
        self._allowed_cache[ip] = allowed
        return allowed

    def allow(self, ip: str) -> bool:
        """Return True if query from this IP should be processed."""
        if not self.is_private(ip):
            return False
        now = time.time()
        with self.lock:
            timestamps = self.counters.get(ip, [])
            # Remove entries older than 1 second
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


# ============================================================
# Stats Counter
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
# DNS Server
# ============================================================

class DiscordDNS:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((LISTEN_HOST, LISTEN_PORT))
        self.cache = DNSCache(CACHE_FILE)
        self.forward_cache = ForwardCache()
        self.rate_limiter = RateLimiter()
        self.stats = Stats()
        self.resolver_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix='dns-resolve')
        self.query_pool = ThreadPoolExecutor(max_workers=QUERY_WORKERS, thread_name_prefix='dns-query')

        # Background threads
        threading.Thread(target=self._periodic_re_resolve, daemon=True).start()
        threading.Thread(target=self._periodic_stats, daemon=True).start()

        print(f"[DNS] Discord DNS Server")
        print(f"[DNS] Listening on {LISTEN_HOST}:{LISTEN_PORT}")
        print(f"[DNS] Upstream: {', '.join(UPSTREAM_DNS_SERVERS)}")
        print(f"[DNS] Hijack IP: {PI_IP}")
        print(f"[DNS] Cache file: {CACHE_FILE}")
        print(f"[DNS] Hijacking {len(DISCORD_DOMAINS)} Discord domains")
        print(f"[DNS] Rate limit: {RATE_LIMIT_PER_SEC}/sec per IP, private networks only")
    
    def is_discord_domain(self, domain: str) -> bool:
        """Check if domain should be hijacked"""
        if not domain:
            return False
        domain = domain.lower()
        for d in DISCORD_DOMAINS:
            if domain == d or domain.endswith('.' + d):
                return True
        return False
    
    def is_voice_domain(self, domain: str) -> bool:
        """Check if domain is a voice server"""
        if not domain:
            return False
        for pattern in VOICE_PATTERNS:
            if re.match(pattern, domain.lower()):
                return True
        return False
    
    def _resolve_and_cache(self, domain: str, is_voice: bool):
        """Resolve real Discord IP in background and cache it"""
        real_ip = resolve_upstream(domain)
        if real_ip:
            self.cache.set(domain, real_ip, is_voice)
            if is_voice:
                print(f"[DNS] 🎤 VOICE: {domain} -> {real_ip}")
            else:
                print(f"[DNS] 📝 Discord: {domain} -> {real_ip}")
        else:
            print(f"[DNS] ⚠️  Failed to resolve: {domain}")

    def _periodic_re_resolve(self):
        """Re-resolve known voice domains periodically to detect IP rotations."""
        while True:
            time.sleep(VOICE_RE_RESOLVE_INTERVAL)
            try:
                domains = self.cache.get_voice_domains()
                for domain in domains:
                    self._resolve_and_cache(domain, is_voice=True)
            except Exception as e:
                print(f"[DNS] Re-resolve error: {e}")

    def _periodic_stats(self):
        """Print stats and clean up rate limiter periodically."""
        while True:
            time.sleep(STATS_INTERVAL)
            try:
                s = self.stats.snapshot()
                voice_domains = self.cache.get_voice_domains()
                fwd_cache_size = len(self.forward_cache.cache)
                print(f"[DNS] Stats: {s['total']} queries | "
                      f"{s['hijacked']} hijacked | "
                      f"{s['cache_hits']} cache hits / {s['cache_misses']} misses | "
                      f"{s['rate_limited']} rate-limited | {s['blocked']} blocked | "
                      f"fwd_cache={fwd_cache_size} | voice_domains={len(voice_domains)}")
                self.rate_limiter.cleanup()
            except Exception as e:
                print(f"[DNS] Stats error: {e}")

    def handle_query(self, data: bytes, addr: tuple):
        """Handle incoming DNS query"""
        self.stats.inc('total')
        source_ip = addr[0]

        # Rate limiting + private network check
        if not self.rate_limiter.allow(source_ip):
            if not self.rate_limiter.is_private(source_ip):
                self.stats.inc('blocked')
            else:
                self.stats.inc('rate_limited')
            return

        domain = parse_domain(data)
        qtype = parse_query_type(data)

        if not domain:
            return

        if self.is_discord_domain(domain):
            self.stats.inc('hijacked')
            if qtype == 1:  # A record
                is_voice = self.is_voice_domain(domain)

                # Send hijacked response immediately (don't block on upstream)
                response = build_response(data, PI_IP)
                self.sock.sendto(response, addr)

                # Resolve and cache real IP in background for the UDP proxy
                self.resolver_pool.submit(self._resolve_and_cache, domain, is_voice)
            else:
                # Non-A queries (AAAA, etc) for Discord domains: return empty
                # response to prevent leaking real IPs via IPv6 lookups
                response = build_empty_response(data)
                self.sock.sendto(response, addr)
        else:
            # Non-Discord: check forward cache first
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
        """Main loop"""
        print("[DNS] Running...")
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                self.query_pool.submit(self.handle_query, data, addr)
            except Exception as e:
                print(f"[DNS] Error: {e}")


# ============================================================
# Main
# ============================================================

def validate_ip(ip: str) -> bool:
    """Check if string is a valid IPv4 address"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def main():
    # Check for custom PI_IP
    global PI_IP
    if len(sys.argv) > 1:
        PI_IP = sys.argv[1]
        print(f"[*] Using custom hijack IP: {PI_IP}")

    if not validate_ip(PI_IP):
        print(f"[DNS] ❌ Invalid PI_IP: '{PI_IP}'")
        print(f"      Set it via: config_local.py, or pass as argument:")
        print(f"      sudo python3 {sys.argv[0]} <your-pi-ip>")
        sys.exit(1)

    print("=" * 60)
    print("Discord DNS Server with IP Tracking")
    print("=" * 60)
    print()
    print("This server:")
    print("  1. Hijacks Discord domains → returns Pi's IP")
    print("  2. Resolves real IPs → caches for UDP proxy")
    print(f"  3. Forwards other queries → {', '.join(UPSTREAM_DNS_SERVERS)}")
    print()

    try:
        server = DiscordDNS()
        server.run()
    except KeyboardInterrupt:
        print("\n[DNS] Shutting down...")
    except PermissionError:
        print("\n[DNS] ❌ Permission denied. Run with sudo:")
        print(f"      sudo python3 {sys.argv[0]}")
        sys.exit(1)


if __name__ == '__main__':
    main()
