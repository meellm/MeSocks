"""Tests for service profile loading and matching."""

import unittest

from mesocks.profiles import BUILTIN_PROFILES, ServiceMatcher, udp_configs, udp_listen_port


class TestProfiles(unittest.TestCase):
    def test_matcher_matches_base_and_subdomains(self):
        matcher = ServiceMatcher({
            'demo': {
                'domains': ['example.com'],
                'udp_proxy': {
                    'enabled': True,
                    'media_patterns': [r'^voice\d+\.example\.com$'],
                },
            },
        })

        self.assertTrue(matcher.is_hijacked('example.com'))
        self.assertTrue(matcher.is_hijacked('api.example.com'))
        self.assertFalse(matcher.is_hijacked('badexample.com'))
        self.assertTrue(matcher.is_media('voice12.example.com'))
        self.assertEqual(matcher.service_for('api.example.com'), 'demo')

    def test_udp_port_uses_single_enabled_port(self):
        services = {
            'one': {'domains': ['one.test'], 'udp_proxy': {'enabled': True, 'port': 8443}},
            'two': {'domains': ['two.test']},
        }
        self.assertEqual(udp_configs(services), {'one': {'port': 8443}})
        self.assertEqual(udp_listen_port(services, default=443), 8443)

    def test_discord_builtin_uses_voice_udp_port(self):
        self.assertEqual(
            BUILTIN_PROFILES['discord']['udp_proxy']['port'],
            50000,
        )

    def test_udp_port_falls_back_when_profiles_disagree(self):
        services = {
            'one': {'domains': ['one.test'], 'udp_proxy': {'enabled': True, 'port': 8443}},
            'two': {'domains': ['two.test'], 'udp_proxy': {'enabled': True, 'port': 9443}},
        }
        self.assertEqual(udp_listen_port(services, default=443), 443)


if __name__ == '__main__':
    unittest.main()
