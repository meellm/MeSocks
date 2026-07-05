"""MeSocks UDP media proxy (the `mesocks-udp-proxy` systemd service).

Forwards UDP media traffic (e.g., Discord voice) through the Pi's VPN
network:

1. DNS hijack returns the Pi's IP for configured service domains
2. Client sends UDP to the Pi thinking it's the real server
3. This proxy receives UDP, looks up the real IP from the DNS tracker
4. Forwards to the real server through the Pi's network (which is VPN)
5. Returns replies to the client

Each client is routed to the media server *it* resolved via DNS
(the DNS server records a per-client mapping), so multiple clients
can be on different voice servers at the same time. The latest
globally-seen media IP is only a fallback.

Usage:
    mesocks-udp                    # Auto mode - reads from DNS tracker
    mesocks-udp 203.0.113.7        # Manual mode - fixed IP
"""

import ipaddress
import json
import os
import resource
import select
import socket
import sys
import threading
import time

from . import settings
from .profiles import load_services, udp_configs, udp_listen_port

# Resolved once at import from the active profiles: which services need
# UDP and what port they use. If every UDP-enabled service agrees on a
# port, honor it; else fall back to the default.
SERVICES = load_services()
UDP_CONFIGS = udp_configs(SERVICES)
LISTEN_PORT = udp_listen_port(SERVICES, settings.UDP_DEFAULT_PORT)
REMOTE_PORT = LISTEN_PORT  # Remote server destination port
TRACKED_IP_MAX_AGE = settings.TRACKED_IP_MAX_AGE


def pick_remote_ip(tracking: dict, client_ip: str,
                   now: float | None = None) -> tuple[str, float] | None:
    """Select the remote media IP for a client from tracker data.

    Preference order:
    1. The IP this specific client resolved via DNS (per-client mapping)
    2. Most recently resolved media domain (any client)
    3. Legacy keys from older cache formats

    Returns (ip, mapping_timestamp) or None.
    """
    now = time.time() if now is None else now

    def valid_entry(entry: dict | None) -> tuple[str, float] | None:
        if not isinstance(entry, dict):
            return None
        ip = entry.get('ip')
        timestamp = entry.get('timestamp')
        if not isinstance(ip, str) or not isinstance(timestamp, (int, float)):
            return None
        if now - timestamp >= TRACKED_IP_MAX_AGE:
            return None
        return ip, timestamp

    client_map = tracking.get('_client_media', {})
    if isinstance(client_map, dict):
        entry = valid_entry(client_map.get(client_ip))
        if entry:
            return entry

    for key in ('_media_domains', '_voice_domains'):
        best = None
        entries = tracking.get(key, {})
        if not isinstance(entries, dict):
            continue
        for _domain, entry in entries.items():
            candidate = valid_entry(entry)
            if candidate and (best is None or candidate[1] > best[1]):
                best = candidate
        if best:
            return best

    for key in ('_latest_media', '_latest_voice'):
        entry = valid_entry(tracking.get(key))
        if entry:
            return entry

    return None


class Session:
    """UDP session between a client and a remote server."""

    def __init__(self, client_addr: tuple, remote_addr: tuple):
        self.client_addr = client_addr
        self.remote_addr = remote_addr
        self.created_at = time.time()
        self.last_activity = self.created_at

        # Create socket for remote communication
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        self.sock.bind(('', 0))
        self.local_port = self.sock.getsockname()[1]

    def is_expired(self) -> bool:
        return time.time() - self.last_activity > settings.SESSION_TIMEOUT

    def touch(self):
        self.last_activity = time.time()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class UDPProxy:
    def __init__(self, fixed_remote_ip: str | None = None):
        self.fixed_remote_ip = fixed_remote_ip

        # Main listening socket
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.setblocking(False)
        self.listen_sock.bind((settings.LISTEN_HOST, LISTEN_PORT))

        # Sessions: client_addr -> Session
        self.sessions: dict[tuple, Session] = {}
        self.sessions_lock = threading.Lock()

        # Reverse lookup: remote_sock fileno -> Session
        self.sock_to_session: dict[int, Session] = {}

        # Cached tracking data to avoid reading file on every packet
        self._tracking: dict = {}
        self._tracking_time: float = 0

        # Cached private-network check per client IP
        self._allowed_cache: dict[str, bool] = {}

        svc_names = ', '.join(UDP_CONFIGS.keys()) if UDP_CONFIGS else 'none'
        print(f"[UDP Proxy] Listening on {settings.LISTEN_HOST}:{LISTEN_PORT}")
        print(f"[UDP Proxy] UDP-enabled services: {svc_names}")
        print(f"[UDP Proxy] Accepting clients from private networks only")
        if fixed_remote_ip:
            print(f"[UDP Proxy] Fixed remote IP: {fixed_remote_ip}")
        else:
            print(f"[UDP Proxy] Auto mode - reading from {settings.CACHE_FILE}")

    def is_allowed_client(self, ip: str) -> bool:
        """Only private-network sources may use the proxy."""
        cached = self._allowed_cache.get(ip)
        if cached is not None:
            return cached
        try:
            addr = ipaddress.ip_address(ip)
            allowed = any(addr in net for net in settings.ALLOWED_NETWORKS)
        except ValueError:
            allowed = False
        if len(self._allowed_cache) >= 4096:
            self._allowed_cache.clear()
        self._allowed_cache[ip] = allowed
        return allowed

    def _read_tracking_file(self) -> dict:
        """Read tracker data written by the DNS server."""
        try:
            tracking_file = settings.CACHE_FILE
            if not os.path.exists(tracking_file) and os.path.exists(settings.OLD_CACHE_FILE):
                tracking_file = settings.OLD_CACHE_FILE
            if os.path.exists(tracking_file):
                with open(tracking_file, 'r') as f:
                    data = json.load(f)
                return data if isinstance(data, dict) else {}
        except Exception as e:
            print(f"[UDP Proxy] Error reading tracking file: {e}")
        return {}

    def get_tracking(self) -> dict:
        """Get tracker data (cached to avoid file reads per packet)."""
        now = time.time()
        if now - self._tracking_time > settings.IP_CHECK_INTERVAL:
            self._tracking = self._read_tracking_file()
            self._tracking_time = now
        return self._tracking

    def remote_for_client(self, client_ip: str) -> tuple[str, float] | None:
        """Pick the remote (ip, mapping_timestamp) for a client."""
        if self.fixed_remote_ip:
            return self.fixed_remote_ip, 0
        return pick_remote_ip(self.get_tracking(), client_ip)

    def _close_session(self, client_addr: tuple):
        """Close and remove a session (must be called with sessions_lock held)."""
        session = self.sessions.pop(client_addr, None)
        if session:
            try:
                del self.sock_to_session[session.sock.fileno()]
            except (KeyError, OSError):
                pass
            session.close()

    def _client_session_count(self, client_ip: str) -> int:
        """Count sessions for one client IP (lock held)."""
        return sum(1 for addr in self.sessions if addr[0] == client_ip)

    def handle_client_packet(self, data: bytes, client_addr: tuple):
        """Handle packet from client -> remote server."""
        client_ip = client_addr[0]
        if not self.is_allowed_client(client_ip):
            return

        remote = self.remote_for_client(client_ip)

        with self.sessions_lock:
            session = self.sessions.get(client_addr)

            # If this client's own DNS mapping changed *after* the session
            # was created, it moved to a different media server: re-pin.
            # Never tear down a session because some other client resolved
            # a different server.
            if (session is not None and remote is not None
                    and remote[0] != session.remote_addr[0]
                    and remote[1] > session.created_at):
                print(f"[UDP Proxy] Remote changed for {client_ip}: "
                      f"{session.remote_addr[0]} -> {remote[0]}, recreating session")
                self._close_session(client_addr)
                session = None

            if session is None:
                if remote is None:
                    print(f"[UDP Proxy] No remote IP known, dropping packet from {client_addr}")
                    return
                if (len(self.sessions) >= settings.MAX_SESSIONS
                        or self._client_session_count(client_ip) >= settings.MAX_SESSIONS_PER_CLIENT):
                    print(f"[UDP Proxy] Session limit reached, dropping packet from {client_addr}")
                    return

                remote_addr = (remote[0], REMOTE_PORT)
                session = Session(client_addr, remote_addr)
                self.sessions[client_addr] = session
                self.sock_to_session[session.sock.fileno()] = session

                print(f"[UDP Proxy] New session: {client_addr[0]}:{client_addr[1]} "
                      f"-> {remote_addr[0]}:{remote_addr[1]}")

        # Forward to remote server
        try:
            session.sock.sendto(data, session.remote_addr)
            session.touch()
        except Exception as e:
            print(f"[UDP Proxy] Error forwarding to remote: {e}")

    def handle_remote_reply(self, session: Session):
        """Handle packet from remote server -> client."""
        try:
            data, sender = session.sock.recvfrom(settings.UDP_BUFFER_SIZE)
            # Only relay datagrams from the server this session talks to
            if sender[0] != session.remote_addr[0]:
                return
            self.listen_sock.sendto(data, session.client_addr)
            session.touch()
        except BlockingIOError:
            pass
        except Exception as e:
            print(f"[UDP Proxy] Error forwarding to client: {e}")

    def cleanup_sessions(self):
        """Remove expired sessions."""
        with self.sessions_lock:
            expired = [addr for addr, s in self.sessions.items() if s.is_expired()]
            for addr in expired:
                print(f"[UDP Proxy] Session expired: {addr}")
                self._close_session(addr)

    def run(self):
        """Main loop using select for efficiency."""
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
                        data, client_addr = sock.recvfrom(settings.UDP_BUFFER_SIZE)
                        self.handle_client_packet(data, client_addr)
                    except BlockingIOError:
                        pass
                else:
                    # Remote reply
                    with self.sessions_lock:
                        session = self.sock_to_session.get(sock.fileno())
                    if session:
                        self.handle_remote_reply(session)

            # Periodic cleanup
            if time.time() - last_cleanup > 30:
                self.cleanup_sessions()
                last_cleanup = time.time()


def main(argv: list[str] | None = None):
    argv = sys.argv[1:] if argv is None else argv

    # Raise file descriptor limit for many concurrent sessions
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 4096), hard))
    except Exception:
        pass

    fixed_ip = argv[0] if argv else None

    svc_names = ', '.join(UDP_CONFIGS.keys()) if UDP_CONFIGS else 'none'
    print("=" * 60)
    print("MeSocks UDP Media Proxy")
    print("=" * 60)

    if not fixed_ip:
        print(f"\nAuto mode - will read media IPs from DNS tracker.")
        print(f"Make sure the mesocks-dns service is running.")
        print(f"UDP-enabled services: {svc_names}")
        print(f"\nOr provide IP manually: {sys.argv[0]} <ip>")
        print()

    proxy = UDPProxy(fixed_ip)

    try:
        proxy.run()
    except KeyboardInterrupt:
        print("\n[UDP Proxy] Shutting down...")


if __name__ == '__main__':
    main()
