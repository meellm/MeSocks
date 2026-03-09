#!/usr/bin/env python3
"""
MeSocks UDP Media Proxy

Forwards UDP media traffic (e.g., Discord voice) through Pi's VPN network.

Architecture:
1. DNS hijack returns Pi's IP for configured service domains
2. Client sends UDP to Pi thinking it's the real server
3. This proxy receives UDP, looks up real IP from DNS tracker
4. Forwards to real server through Pi's network (which is VPN)
5. Returns replies to client

Usage:
    ./udp-proxy.py                    # Auto mode - reads from DNS tracker
    ./udp-proxy.py 162.159.128.232    # Manual mode - fixed IP
"""

import socket
import select
import threading
import resource
import time
import json
import sys
import os

# Load service definitions
try:
    from services_config import SERVICES
except ImportError:
    from services_default import SERVICES

# Find UDP-enabled services
UDP_CONFIGS = {}
for _svc_name, _svc_cfg in SERVICES.items():
    _udp = _svc_cfg.get('udp_proxy')
    if _udp and _udp.get('enabled'):
        UDP_CONFIGS[_svc_name] = {
            'port': _udp.get('port', 443),
        }

# Config
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 443
REMOTE_PORT = 443  # Remote server destination port
TRACKING_FILE = '/tmp/mesocks-media-ips.json'
OLD_TRACKING_FILE = '/tmp/discord-voice-ips.json'  # For migration
SESSION_TIMEOUT = 90  # seconds
IP_CHECK_INTERVAL = 10  # seconds between re-reading tracked IP
BUFFER_SIZE = 65535


class Session:
    """UDP session between client and remote server"""

    def __init__(self, client_addr: tuple, remote_addr: tuple):
        self.client_addr = client_addr
        self.remote_addr = remote_addr
        self.last_activity = time.time()

        # Create socket for remote communication
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


class UDPProxy:
    def __init__(self, fixed_remote_ip: str = None):
        self.fixed_remote_ip = fixed_remote_ip

        # Main listening socket
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.setblocking(False)
        self.listen_sock.bind((LISTEN_HOST, LISTEN_PORT))

        # Sessions: client_addr -> Session
        self.sessions: dict[tuple, Session] = {}
        self.sessions_lock = threading.Lock()

        # Reverse lookup: remote_sock fileno -> Session
        self.sock_to_session: dict[int, Session] = {}

        # Cached IP lookup to avoid reading file on every packet
        self._cached_ip: str | None = None
        self._cached_ip_time: float = 0

        svc_names = ', '.join(UDP_CONFIGS.keys()) if UDP_CONFIGS else 'none'
        print(f"[UDP Proxy] Listening on {LISTEN_HOST}:{LISTEN_PORT}")
        print(f"[UDP Proxy] UDP-enabled services: {svc_names}")
        if fixed_remote_ip:
            print(f"[UDP Proxy] Fixed remote IP: {fixed_remote_ip}")
        else:
            print(f"[UDP Proxy] Auto mode - reading from {TRACKING_FILE}")

    def _read_remote_ip_from_file(self) -> str | None:
        """Read media server IP from tracking file."""
        try:
            tracking_file = TRACKING_FILE
            if not os.path.exists(tracking_file) and os.path.exists(OLD_TRACKING_FILE):
                tracking_file = OLD_TRACKING_FILE

            if os.path.exists(tracking_file):
                with open(tracking_file, 'r') as f:
                    data = json.load(f)
                # Prefer per-domain media IPs (most recently resolved)
                if '_media_domains' in data:
                    best = None
                    for domain, entry in data['_media_domains'].items():
                        age = time.time() - entry['timestamp']
                        if age < 300 and (best is None or entry['timestamp'] > best[1]):
                            best = (entry['ip'], entry['timestamp'], domain)
                    if best:
                        return best[0]
                # Fallback to old key names for migration
                if '_voice_domains' in data:
                    best = None
                    for domain, entry in data['_voice_domains'].items():
                        age = time.time() - entry['timestamp']
                        if age < 300 and (best is None or entry['timestamp'] > best[1]):
                            best = (entry['ip'], entry['timestamp'], domain)
                    if best:
                        return best[0]
                # Fallback to _latest_media or _latest_voice
                for key in ('_latest_media', '_latest_voice'):
                    if key in data:
                        age = time.time() - data[key]['timestamp']
                        if age < 300:
                            return data[key]['ip']
                        else:
                            print(f"[UDP Proxy] Tracked IP too old: {age:.0f}s")
        except Exception as e:
            print(f"[UDP Proxy] Error reading tracking file: {e}")
        return None

    def get_remote_ip(self) -> str | None:
        """Get remote server IP (cached to avoid file reads per packet)."""
        if self.fixed_remote_ip:
            return self.fixed_remote_ip
        now = time.time()
        if now - self._cached_ip_time > IP_CHECK_INTERVAL:
            new_ip = self._read_remote_ip_from_file()
            if new_ip and new_ip != self._cached_ip:
                if self._cached_ip:
                    print(f"[UDP Proxy] Remote IP changed: {self._cached_ip} -> {new_ip}")
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
        """Handle packet from client -> remote server"""
        with self.sessions_lock:
            session = self.sessions.get(client_addr)
            remote_ip = self.get_remote_ip()

            # Detect IP change on existing session
            if session is not None and remote_ip and remote_ip != session.remote_addr[0]:
                print(f"[UDP Proxy] IP rotated for {client_addr}: "
                      f"{session.remote_addr[0]} -> {remote_ip}, recreating session")
                self._close_session(client_addr)
                session = None

            if session is None:
                if not remote_ip:
                    print(f"[UDP Proxy] No remote IP known, dropping packet from {client_addr}")
                    return

                remote_addr = (remote_ip, REMOTE_PORT)
                session = Session(client_addr, remote_addr)
                self.sessions[client_addr] = session
                self.sock_to_session[session.sock.fileno()] = session

                print(f"[UDP Proxy] New session: {client_addr[0]}:{client_addr[1]} -> {remote_ip}:{REMOTE_PORT}")

        # Forward to remote server
        try:
            session.sock.sendto(data, session.remote_addr)
            session.touch()
        except Exception as e:
            print(f"[UDP Proxy] Error forwarding to remote: {e}")

    def handle_remote_reply(self, session: Session):
        """Handle packet from remote server -> client"""
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
                    # Remote reply
                    with self.sessions_lock:
                        session = self.sock_to_session.get(sock.fileno())
                    if session:
                        self.handle_remote_reply(session)

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

    svc_names = ', '.join(UDP_CONFIGS.keys()) if UDP_CONFIGS else 'none'
    print("=" * 60)
    print("MeSocks UDP Media Proxy")
    print("=" * 60)

    if not fixed_ip:
        print(f"\nAuto mode - will read media IPs from DNS tracker.")
        print(f"Make sure dns-proxy.py is running.")
        print(f"UDP-enabled services: {svc_names}")
        print(f"\nOr provide IP manually: ./udp-proxy.py <ip>")
        print()

    proxy = UDPProxy(fixed_ip)

    try:
        proxy.run()
    except KeyboardInterrupt:
        print("\n[UDP Proxy] Shutting down...")


if __name__ == '__main__':
    main()
