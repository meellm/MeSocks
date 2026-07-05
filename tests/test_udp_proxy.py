"""Tests for UDP proxy remote IP selection from tracker data."""

import os
import sys
import time
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, 'src'))

from mesocks import settings
from mesocks import udp_proxy

NOW = 1_000_000.0


class TestPickRemoteIp(unittest.TestCase):
    def test_empty_tracking(self):
        self.assertIsNone(udp_proxy.pick_remote_ip({}, '192.168.1.20', NOW))

    def test_prefers_client_mapping(self):
        tracking = {
            '_client_media': {
                '192.168.1.20': {'domain': 'a.discord.gg', 'ip': '1.1.1.1', 'timestamp': NOW - 5},
                '192.168.1.30': {'domain': 'b.discord.gg', 'ip': '2.2.2.2', 'timestamp': NOW - 5},
            },
            '_media_domains': {
                'b.discord.gg': {'ip': '2.2.2.2', 'timestamp': NOW - 1},
            },
            '_latest_media': {'domain': 'b.discord.gg', 'ip': '2.2.2.2', 'timestamp': NOW - 1},
        }
        # Each client gets the server it resolved, not the globally-latest one
        self.assertEqual(udp_proxy.pick_remote_ip(tracking, '192.168.1.20', NOW)[0], '1.1.1.1')
        self.assertEqual(udp_proxy.pick_remote_ip(tracking, '192.168.1.30', NOW)[0], '2.2.2.2')

    def test_stale_client_mapping_falls_back(self):
        tracking = {
            '_client_media': {
                '192.168.1.20': {'domain': 'a.discord.gg', 'ip': '1.1.1.1',
                                 'timestamp': NOW - udp_proxy.TRACKED_IP_MAX_AGE - 1},
            },
            '_media_domains': {
                'b.discord.gg': {'ip': '2.2.2.2', 'timestamp': NOW - 10},
            },
        }
        self.assertEqual(udp_proxy.pick_remote_ip(tracking, '192.168.1.20', NOW)[0], '2.2.2.2')

    def test_unknown_client_uses_latest_media_domain(self):
        tracking = {
            '_media_domains': {
                'old.discord.gg': {'ip': '3.3.3.3', 'timestamp': NOW - 200},
                'new.discord.gg': {'ip': '4.4.4.4', 'timestamp': NOW - 5},
            },
        }
        self.assertEqual(udp_proxy.pick_remote_ip(tracking, '192.168.1.99', NOW)[0], '4.4.4.4')

    def test_all_stale_returns_none(self):
        tracking = {
            '_media_domains': {
                'a.discord.gg': {'ip': '1.1.1.1',
                                 'timestamp': NOW - udp_proxy.TRACKED_IP_MAX_AGE - 1},
            },
            '_latest_media': {'domain': 'a.discord.gg', 'ip': '1.1.1.1',
                              'timestamp': NOW - udp_proxy.TRACKED_IP_MAX_AGE - 1},
        }
        self.assertIsNone(udp_proxy.pick_remote_ip(tracking, '192.168.1.20', NOW))

    def test_legacy_keys(self):
        tracking = {
            '_voice_domains': {
                'a.discord.gg': {'ip': '5.5.5.5', 'timestamp': NOW - 5},
            },
        }
        self.assertEqual(udp_proxy.pick_remote_ip(tracking, '192.168.1.20', NOW)[0], '5.5.5.5')

    def test_latest_voice_fallback(self):
        tracking = {
            '_latest_voice': {'domain': 'a.discord.gg', 'ip': '6.6.6.6', 'timestamp': NOW - 5},
        }
        self.assertEqual(udp_proxy.pick_remote_ip(tracking, '192.168.1.20', NOW)[0], '6.6.6.6')

    def test_returns_mapping_timestamp(self):
        tracking = {
            '_client_media': {
                '192.168.1.20': {'domain': 'a.discord.gg', 'ip': '1.1.1.1', 'timestamp': NOW - 5},
            },
        }
        ip, ts = udp_proxy.pick_remote_ip(tracking, '192.168.1.20', NOW)
        self.assertEqual(ts, NOW - 5)

    def test_ignores_malformed_entries(self):
        tracking = {
            '_client_media': {
                '192.168.1.20': {'domain': 'bad.discord.gg', 'ip': '1.1.1.1'},
            },
            '_media_domains': {
                'bad.discord.gg': {'ip': 123, 'timestamp': NOW - 5},
                'good.discord.gg': {'ip': '2.2.2.2', 'timestamp': NOW - 5},
            },
            '_latest_media': 'not-a-dict',
        }
        self.assertEqual(udp_proxy.pick_remote_ip(tracking, '192.168.1.20', NOW)[0],
                         '2.2.2.2')


class TestConfig(unittest.TestCase):
    def test_ports_consistent(self):
        self.assertEqual(udp_proxy.LISTEN_PORT, udp_proxy.REMOTE_PORT)


if __name__ == '__main__':
    unittest.main()
