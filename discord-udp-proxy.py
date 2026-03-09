#!/usr/bin/env python3
"""
Discord Voice UDP Proxy

Forwards Discord voice UDP traffic through Pi's VPN network.

Architecture:
1. DNS hijack returns Pi's IP for Discord domains
2. Client sends UDP to Pi thinking it's Discord
3. This proxy receives UDP, looks up real Discord IP from DNS tracker
4. Forwards to real Discord through Pi's network (which is VPN)
5. Returns replies to client

Usage:
    ./discord-udp-proxy.py                    # Auto mode - reads from DNS tracker
    ./discord-udp-proxy.py 162.159.128.232    # Manual mode - fixed IP
"""

import socket
import select
import threading
import resource
import time
import json
import sys
import os

# Config
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 443
DISCORD_VOICE_PORT = 443  # Discord voice server destination port
TRACKING_FILE = '/tmp/discord-voice-ips.json'
SESSION_TIMEOUT = 90  # seconds (Discord sends keepalives every ~5s)
IP_CHECK_INTERVAL = 10  # seconds between re-reading tracked IP
BUFFER_SIZE = 65535


class Session:
    """UDP session between client and Discord"""
    
    def __init__(self, client_addr: tuple, discord_addr: tuple):
        self.client_addr = client_addr
        self.discord_addr = discord_addr
        self.last_activity = time.time()
        
        # Create socket for Discord communication
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        self.sock.bind(('', 0))
        self.local_port = self.sock.getsockname()[1]
    
    def is_expired(self) -> bool:
        return time.time() - self.last_activity > SESSION_TIMEOUT
    
    def touch(self):
        self.last_activity = time.time()
    
    def close(self):
        try:
            self.sock.close()
        except:
            pass


class DiscordUDPProxy:
    def __init__(self, fixed_discord_ip: str = None):
        self.fixed_discord_ip = fixed_discord_ip
        
        # Main listening socket
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.setblocking(False)
        self.listen_sock.bind((LISTEN_HOST, LISTEN_PORT))
        
        # Sessions: client_addr -> Session
        self.sessions: dict[tuple, Session] = {}
        self.sessions_lock = threading.Lock()
        
        # Reverse lookup: discord_sock fileno -> Session
        self.sock_to_session: dict[int, Session] = {}
        
        # Cached IP lookup to avoid reading file on every packet
        self._cached_ip: str | None = None
        self._cached_ip_time: float = 0

        print(f"[UDP Proxy] Listening on {LISTEN_HOST}:{LISTEN_PORT}")
        if fixed_discord_ip:
            print(f"[UDP Proxy] Fixed Discord IP: {fixed_discord_ip}")
        else:
            print(f"[UDP Proxy] Auto mode - reading from {TRACKING_FILE}")

    def _read_discord_ip_from_file(self) -> str | None:
        """Read Discord voice server IP from tracking file."""
        try:
            if os.path.exists(TRACKING_FILE):
                with open(TRACKING_FILE, 'r') as f:
                    data = json.load(f)
                # Prefer per-domain voice IPs (most recently resolved)
                if '_voice_domains' in data:
                    best = None
                    for domain, entry in data['_voice_domains'].items():
                        age = time.time() - entry['timestamp']
                        if age < 300 and (best is None or entry['timestamp'] > best[1]):
                            best = (entry['ip'], entry['timestamp'], domain)
                    if best:
                        return best[0]
                # Fallback to _latest_voice
                if '_latest_voice' in data:
                    age = time.time() - data['_latest_voice']['timestamp']
                    if age < 300:
                        return data['_latest_voice']['ip']
                    else:
                        print(f"[UDP Proxy] Tracked IP too old: {age:.0f}s")
        except Exception as e:
            print(f"[UDP Proxy] Error reading tracking file: {e}")
        return None

    def get_discord_ip(self) -> str | None:
        """Get Discord voice server IP (cached to avoid file reads per packet)."""
        if self.fixed_discord_ip:
            return self.fixed_discord_ip
        now = time.time()
        if now - self._cached_ip_time > IP_CHECK_INTERVAL:
            new_ip = self._read_discord_ip_from_file()
            if new_ip and new_ip != self._cached_ip:
                if self._cached_ip:
                    print(f"[UDP Proxy] Discord IP changed: {self._cached_ip} -> {new_ip}")
                else:
                    print(f"[UDP Proxy] Using tracked IP: {new_ip}")
                self._cached_ip = new_ip
            self._cached_ip_time = now
        return self._cached_ip
    
    def _close_session(self, client_addr: tuple):
        """Close and remove a session (must be called with sessions_lock held)."""
        session = self.sessions.pop(client_addr, None)
        if session:
            try:
                del self.sock_to_session[session.sock.fileno()]
            except (KeyError, OSError):
                pass
            session.close()

    def handle_client_packet(self, data: bytes, client_addr: tuple):
        """Handle packet from client → Discord"""
        with self.sessions_lock:
            session = self.sessions.get(client_addr)
            discord_ip = self.get_discord_ip()

            # Detect IP change on existing session
            if session is not None and discord_ip and discord_ip != session.discord_addr[0]:
                print(f"[UDP Proxy] IP rotated for {client_addr}: "
                      f"{session.discord_addr[0]} -> {discord_ip}, recreating session")
                self._close_session(client_addr)
                session = None

            if session is None:
                if not discord_ip:
                    print(f"[UDP Proxy] ❌ No Discord IP known, dropping packet from {client_addr}")
                    return

                discord_addr = (discord_ip, DISCORD_VOICE_PORT)
                session = Session(client_addr, discord_addr)
                self.sessions[client_addr] = session
                self.sock_to_session[session.sock.fileno()] = session

                print(f"[UDP Proxy] ✅ New session: {client_addr[0]}:{client_addr[1]} -> {discord_ip}:{DISCORD_VOICE_PORT}")

        # Forward to Discord
        try:
            session.sock.sendto(data, session.discord_addr)
            session.touch()
        except Exception as e:
            print(f"[UDP Proxy] Error forwarding to Discord: {e}")
    
    def handle_discord_reply(self, session: Session):
        """Handle packet from Discord → client"""
        try:
            data, _ = session.sock.recvfrom(BUFFER_SIZE)
            self.listen_sock.sendto(data, session.client_addr)
            session.touch()
        except BlockingIOError:
            pass
        except Exception as e:
            print(f"[UDP Proxy] Error forwarding to client: {e}")
    
    def cleanup_sessions(self):
        """Remove expired sessions"""
        with self.sessions_lock:
            expired = [addr for addr, s in self.sessions.items() if s.is_expired()]
            for addr in expired:
                print(f"[UDP Proxy] Session expired: {addr}")
                self._close_session(addr)
    
    def run(self):
        """Main loop using select for efficiency"""
        print("[UDP Proxy] Running...")
        last_cleanup = time.time()
        
        while True:
            # Build list of sockets to monitor
            read_socks = [self.listen_sock]
            with self.sessions_lock:
                read_socks.extend(s.sock for s in self.sessions.values())
            
            try:
                readable, _, _ = select.select(read_socks, [], [], 1.0)
            except (ValueError, OSError):
                # Socket was closed
                continue
            
            for sock in readable:
                if sock is self.listen_sock:
                    # Client packet
                    try:
                        data, client_addr = sock.recvfrom(BUFFER_SIZE)
                        self.handle_client_packet(data, client_addr)
                    except BlockingIOError:
                        pass
                else:
                    # Discord reply
                    with self.sessions_lock:
                        session = self.sock_to_session.get(sock.fileno())
                    if session:
                        self.handle_discord_reply(session)
            
            # Periodic cleanup
            if time.time() - last_cleanup > 30:
                self.cleanup_sessions()
                last_cleanup = time.time()


def main():
    # Raise file descriptor limit for many concurrent sessions
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 4096), hard))
    except Exception:
        pass

    fixed_ip = sys.argv[1] if len(sys.argv) > 1 else None

    print("=" * 60)
    print("Discord Voice UDP Proxy")
    print("=" * 60)
    
    if not fixed_ip:
        print("\n⚠️  No Discord IP provided!")
        print("The proxy will read from DNS tracker when UDP arrives.")
        print("Make sure dns-tracker.py is running and sniproxy uses it.")
        print("\nOr provide IP manually: ./discord-udp-proxy.py <ip>")
        print("\nTo find Discord voice IP, check on Windows:")
        print("  nslookup bucharest1234.discord.gg 8.8.8.8")
        print("  or: ipconfig /displaydns | findstr discord")
        print()
    
    proxy = DiscordUDPProxy(fixed_ip)
    
    try:
        proxy.run()
    except KeyboardInterrupt:
        print("\n[UDP Proxy] Shutting down...")


if __name__ == '__main__':
    main()
