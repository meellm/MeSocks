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
UPSTREAM_DNS = '8.8.8.8'
UPSTREAM_PORT = 53
PI_IP = 'YOUR_PI_IP'  # IP to return for hijacked domains
CACHE_FILE = '/tmp/discord-voice-ips.json'
CACHE_TTL = 300  # 5 minutes

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
    response += struct.pack('>I', 60)  # TTL = 60 seconds
    response += b'\x00\x04'  # Data length
    response += bytes(int(x) for x in ip.split('.'))  # IP address
    
    return bytes(response)


def resolve_upstream(domain: str) -> str | None:
    """Resolve domain via upstream DNS, return IP or None"""
    try:
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
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(query, (UPSTREAM_DNS, UPSTREAM_PORT))
        response, _ = sock.recvfrom(1024)
        sock.close()
        
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
        print(f"[DNS] Upstream resolve error for {domain}: {e}")
        return None


def forward_query(query: bytes) -> bytes | None:
    """Forward query to upstream and return response"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(query, (UPSTREAM_DNS, UPSTREAM_PORT))
        response, _ = sock.recvfrom(4096)
        sock.close()
        return response
    except Exception as e:
        print(f"[DNS] Forward error: {e}")
        return None


# ============================================================
# DNS Cache
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
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
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
            self.save()
    
    def get_latest_voice(self) -> tuple[str, str] | None:
        with self.lock:
            if '_latest_voice' in self.cache:
                entry = self.cache['_latest_voice']
                if time.time() - entry['timestamp'] < CACHE_TTL:
                    return (entry['domain'], entry['ip'])
        return None


# ============================================================
# DNS Server
# ============================================================

class DiscordDNS:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((LISTEN_HOST, LISTEN_PORT))
        self.cache = DNSCache(CACHE_FILE)
        
        print(f"[DNS] Discord DNS Server")
        print(f"[DNS] Listening on {LISTEN_HOST}:{LISTEN_PORT}")
        print(f"[DNS] Upstream: {UPSTREAM_DNS}")
        print(f"[DNS] Hijack IP: {PI_IP}")
        print(f"[DNS] Cache file: {CACHE_FILE}")
        print(f"[DNS] Hijacking {len(DISCORD_DOMAINS)} Discord domains")
    
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
    
    def handle_query(self, data: bytes, addr: tuple):
        """Handle incoming DNS query"""
        domain = parse_domain(data)
        qtype = parse_query_type(data)
        
        if not domain:
            return
        
        # Only handle A queries for Discord domains
        if qtype == 1 and self.is_discord_domain(domain):
            is_voice = self.is_voice_domain(domain)
            
            # Resolve real IP in background (or foreground for voice)
            real_ip = resolve_upstream(domain)
            
            if real_ip:
                self.cache.set(domain, real_ip, is_voice)
                if is_voice:
                    print(f"[DNS] 🎤 VOICE: {domain} -> {real_ip} (returning {PI_IP})")
                else:
                    print(f"[DNS] 📝 Discord: {domain} -> {real_ip} (returning {PI_IP})")
            else:
                print(f"[DNS] ⚠️  Failed to resolve: {domain}")
            
            # Return hijacked response
            response = build_response(data, PI_IP)
            self.sock.sendto(response, addr)
        else:
            # Forward to upstream
            response = forward_query(data)
            if response:
                self.sock.sendto(response, addr)
    
    def run(self):
        """Main loop"""
        print("[DNS] Running...")
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                threading.Thread(
                    target=self.handle_query,
                    args=(data, addr),
                    daemon=True
                ).start()
            except Exception as e:
                print(f"[DNS] Error: {e}")


# ============================================================
# Main
# ============================================================

def main():
    # Check for custom PI_IP
    global PI_IP
    if len(sys.argv) > 1:
        PI_IP = sys.argv[1]
        print(f"[*] Using custom hijack IP: {PI_IP}")
    
    print("=" * 60)
    print("Discord DNS Server with IP Tracking")
    print("=" * 60)
    print()
    print("This server:")
    print("  1. Hijacks Discord domains → returns Pi's IP")
    print("  2. Resolves real IPs → caches for UDP proxy")
    print("  3. Forwards other queries → upstream DNS")
    print()
    
    server = DiscordDNS()
    
    try:
        server.run()
    except KeyboardInterrupt:
        print("\n[DNS] Shutting down...")
    except PermissionError:
        print("\n[DNS] ❌ Permission denied. Run with sudo:")
        print(f"      sudo python3 {sys.argv[0]}")
        sys.exit(1)


if __name__ == '__main__':
    main()
