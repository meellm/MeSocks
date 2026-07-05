"""Tests for DNS packet parsing, caches, and rate limiting."""

import os
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, 'src'))

from mesocks import settings
from mesocks.cache import ForwardCache, MediaCache
from mesocks.dnspacket import (
    build_a_query,
    build_empty_response,
    build_response,
    parse_a_answer,
    parse_domain,
    parse_query_type,
    parse_question,
    validate_ipv4,
)
from mesocks.ratelimit import RateLimiter

dns_proxy = SimpleNamespace(
    ForwardCache=ForwardCache,
    MediaCache=MediaCache,
    RateLimiter=RateLimiter,
    build_a_query=build_a_query,
    build_empty_response=build_empty_response,
    build_response=build_response,
    parse_a_answer=parse_a_answer,
    parse_domain=parse_domain,
    parse_query_type=parse_query_type,
    parse_question=parse_question,
    validate_ip=validate_ipv4,
    FORWARD_CACHE_MAX_TTL=settings.FORWARD_CACHE_MAX_TTL,
    MEDIA_ACTIVE_WINDOW=settings.MEDIA_ACTIVE_WINDOW,
)


def encode_name(domain: str) -> bytes:
    out = b''
    for part in domain.split('.'):
        out += bytes([len(part)]) + part.encode()
    return out + b'\x00'


def make_query(domain: str, qtype: int = 1, txid: bytes = b'\xab\xcd',
               rd: bool = True) -> bytes:
    flags = b'\x01\x00' if rd else b'\x00\x00'
    header = txid + flags + b'\x00\x01' + b'\x00\x00' * 3
    return header + encode_name(domain) + struct.pack('>HH', qtype, 1)


def make_response(txid: bytes, domain: str, answers: list,
                  flags: int = 0x8180) -> bytes:
    """answers: list of (name_bytes, rtype, ttl, rdata_bytes)"""
    header = txid + struct.pack('>HHHHH', flags, 1, len(answers), 0, 0)
    body = encode_name(domain) + struct.pack('>HH', 1, 1)
    for name, rtype, ttl, rdata in answers:
        body += name + struct.pack('>HHIH', rtype, 1, ttl, len(rdata)) + rdata
    return header + body


class TestParseQuestion(unittest.TestCase):
    def test_valid_query(self):
        q = make_query('voice1.discord.gg', qtype=1)
        self.assertEqual(dns_proxy.parse_domain(q), 'voice1.discord.gg')
        self.assertEqual(dns_proxy.parse_query_type(q), 1)

    def test_aaaa_query(self):
        q = make_query('discord.com', qtype=28)
        self.assertEqual(dns_proxy.parse_query_type(q), 28)

    def test_case_is_lowered(self):
        q = make_query('DisCord.CoM')
        self.assertEqual(dns_proxy.parse_domain(q), 'discord.com')

    def test_truncated_packet(self):
        q = make_query('discord.com')
        self.assertIsNone(dns_proxy.parse_question(q[:14]))
        self.assertIsNone(dns_proxy.parse_question(b''))
        self.assertIsNone(dns_proxy.parse_question(q[:len(q) - 3]))

    def test_rejects_compression_in_question(self):
        header = b'\xab\xcd\x01\x00\x00\x01' + b'\x00\x00' * 3
        q = header + b'\xc0\x0c' + struct.pack('>HH', 1, 1)
        self.assertIsNone(dns_proxy.parse_question(q))

    def test_rejects_oversized_label(self):
        header = b'\xab\xcd\x01\x00\x00\x01' + b'\x00\x00' * 3
        q = header + bytes([64]) + (b'a' * 64) + b'\x00' + struct.pack('>HH', 1, 1)
        self.assertIsNone(dns_proxy.parse_question(q))

    def test_rejects_multiple_questions(self):
        q = bytearray(make_query('discord.com'))
        q[4:6] = b'\x00\x02'
        self.assertIsNone(dns_proxy.parse_question(bytes(q)))

    def test_rejects_oversized_name(self):
        long_domain = '.'.join(['a' * 60] * 6)
        q = make_query(long_domain)
        self.assertIsNone(dns_proxy.parse_question(q))


class TestBuildResponse(unittest.TestCase):
    def test_a_response_roundtrip(self):
        q = make_query('discord.com', txid=b'\x12\x34')
        _, _, end = dns_proxy.parse_question(q)
        resp = dns_proxy.build_response(q, '192.168.1.50', end)
        self.assertEqual(resp[:2], b'\x12\x34')
        self.assertTrue(resp[2] & 0x80)  # QR bit
        self.assertTrue(resp[2] & 0x01)  # RD echoed
        self.assertEqual(dns_proxy.parse_a_answer(resp), '192.168.1.50')

    def test_rd_not_set_when_query_lacks_it(self):
        q = make_query('discord.com', rd=False)
        _, _, end = dns_proxy.parse_question(q)
        resp = dns_proxy.build_response(q, '10.0.0.1', end)
        self.assertFalse(resp[2] & 0x01)

    def test_empty_response(self):
        q = make_query('discord.com', qtype=28)
        _, _, end = dns_proxy.parse_question(q)
        resp = dns_proxy.build_empty_response(q, end)
        ancount = struct.unpack('>H', resp[6:8])[0]
        rcode = resp[3] & 0x0F
        self.assertEqual(ancount, 0)
        self.assertEqual(rcode, 0)  # NOERROR/NODATA, not NXDOMAIN
        self.assertIsNone(dns_proxy.parse_a_answer(resp))


class TestParseAAnswer(unittest.TestCase):
    def test_pointer_name(self):
        resp = make_response(b'\x00\x01', 'discord.com',
                             [(b'\xc0\x0c', 1, 300, bytes([1, 2, 3, 4]))])
        self.assertEqual(dns_proxy.parse_a_answer(resp), '1.2.3.4')

    def test_cname_then_a(self):
        cname_rdata = encode_name('edge.discord.com')
        answers = [
            (b'\xc0\x0c', 5, 300, cname_rdata),
            (encode_name('edge.discord.com'), 1, 300, bytes([5, 6, 7, 8])),
        ]
        resp = make_response(b'\x00\x01', 'discord.com', answers)
        self.assertEqual(dns_proxy.parse_a_answer(resp), '5.6.7.8')

    def test_labels_ending_with_pointer(self):
        # Answer name: "edge" label followed by pointer to question name
        name = b'\x04edge\xc0\x0c'
        resp = make_response(b'\x00\x01', 'discord.com',
                             [(name, 1, 300, bytes([9, 9, 9, 9]))])
        self.assertEqual(dns_proxy.parse_a_answer(resp), '9.9.9.9')

    def test_no_answers(self):
        resp = make_response(b'\x00\x01', 'discord.com', [])
        self.assertIsNone(dns_proxy.parse_a_answer(resp))

    def test_garbage(self):
        self.assertIsNone(dns_proxy.parse_a_answer(b'\x00' * 5))
        self.assertIsNone(dns_proxy.parse_a_answer(os.urandom(40)))


class TestForwardCache(unittest.TestCase):
    def _response(self, txid=b'\x11\x11', ttl=300, flags=0x8180):
        return make_response(txid, 'example.com',
                             [(b'\xc0\x0c', 1, ttl, bytes([1, 1, 1, 1]))],
                             flags=flags)

    def test_put_get_rewrites_txid(self):
        cache = dns_proxy.ForwardCache()
        cache.put('example.com', 1, self._response(txid=b'\x11\x11'))
        got = cache.get('example.com', 1, b'\x99\x99')
        self.assertIsNotNone(got)
        self.assertEqual(got[:2], b'\x99\x99')
        self.assertEqual(got[2:], self._response()[2:])

    def test_miss_on_other_qtype(self):
        cache = dns_proxy.ForwardCache()
        cache.put('example.com', 1, self._response())
        self.assertIsNone(cache.get('example.com', 28, b'\x99\x99'))

    def test_does_not_cache_truncated(self):
        cache = dns_proxy.ForwardCache()
        cache.put('example.com', 1, self._response(flags=0x8380))  # TC set
        self.assertIsNone(cache.get('example.com', 1, b'\x99\x99'))

    def test_does_not_cache_servfail(self):
        cache = dns_proxy.ForwardCache()
        cache.put('example.com', 1, self._response(flags=0x8182))  # rcode 2
        self.assertIsNone(cache.get('example.com', 1, b'\x99\x99'))

    def test_expiry(self):
        cache = dns_proxy.ForwardCache()
        cache.put('example.com', 1, self._response())
        key = ('example.com', 1)
        resp_bytes, _ = cache.cache[key]
        cache.cache[key] = (resp_bytes, time.time() - 1)
        self.assertIsNone(cache.get('example.com', 1, b'\x99\x99'))

    def test_eviction(self):
        cache = dns_proxy.ForwardCache(max_entries=2)
        for i in range(3):
            cache.put(f'host{i}.example.com', 1, self._response())
        self.assertEqual(len(cache.cache), 2)
        self.assertIsNone(cache.get('host0.example.com', 1, b'\x99\x99'))

    def test_ttl_cap(self):
        cache = dns_proxy.ForwardCache()
        ttl = cache._parse_ttl(self._response(ttl=999999))
        self.assertEqual(ttl, dns_proxy.FORWARD_CACHE_MAX_TTL)


class TestRateLimiter(unittest.TestCase):
    def test_public_ip_blocked(self):
        rl = dns_proxy.RateLimiter()
        self.assertFalse(rl.allow('8.8.8.8'))
        self.assertFalse(rl.is_private('203.0.113.7'))

    def test_private_ip_allowed(self):
        rl = dns_proxy.RateLimiter()
        self.assertTrue(rl.allow('192.168.1.10'))
        self.assertTrue(rl.allow('10.1.2.3'))

    def test_rate_limit_enforced(self):
        rl = dns_proxy.RateLimiter(max_per_sec=5)
        results = [rl.allow('192.168.1.10') for _ in range(10)]
        self.assertEqual(results[:5], [True] * 5)
        self.assertEqual(results[5:], [False] * 5)

    def test_invalid_ip(self):
        rl = dns_proxy.RateLimiter()
        self.assertFalse(rl.allow('not-an-ip'))

    def test_allowed_cache_bounded(self):
        rl = dns_proxy.RateLimiter()
        for i in range(5000):
            rl.is_private(f'203.0.{i // 250}.{i % 250}')
        self.assertLessEqual(len(rl._allowed_cache), 4096)


class TestMediaCache(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        os.unlink(self.path)
        self.cache = dns_proxy.MediaCache(self.path)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_set_and_latest(self):
        self.cache.set('voice1.discord.gg', '1.2.3.4', is_media=True)
        self.assertEqual(self.cache.get_latest_media(),
                         ('voice1.discord.gg', '1.2.3.4'))

    def test_client_mapping_persisted(self):
        self.cache.set('voice1.discord.gg', '1.2.3.4', is_media=True,
                       client_ip='192.168.1.20')
        reloaded = dns_proxy.MediaCache(self.path)
        entry = reloaded.cache['_client_media']['192.168.1.20']
        self.assertEqual(entry['ip'], '1.2.3.4')
        self.assertEqual(entry['domain'], 'voice1.discord.gg')

    def test_refresh_does_not_extend_active_window(self):
        self.cache.set('voice1.discord.gg', '1.2.3.4', is_media=True)
        # Age the client-query timestamp beyond the active window
        old = time.time() - dns_proxy.MEDIA_ACTIVE_WINDOW - 10
        with self.cache.lock:
            self.cache.cache['_media_domains']['voice1.discord.gg']['last_query'] = old
        self.cache.set('voice1.discord.gg', '5.6.7.8', is_media=True, refresh=True)
        self.assertNotIn('voice1.discord.gg', self.cache.get_media_domains())

    def test_client_query_extends_active_window(self):
        self.cache.set('voice1.discord.gg', '1.2.3.4', is_media=True)
        self.assertIn('voice1.discord.gg', self.cache.get_media_domains())

    def test_malformed_cache_file_is_ignored(self):
        with open(self.path, 'w') as f:
            f.write('[]')
        reloaded = dns_proxy.MediaCache(self.path)
        self.assertEqual(reloaded.cache, {})

    def test_malformed_cache_entries_are_pruned(self):
        with self.cache.lock:
            self.cache.cache = {
                'bad.discord.gg': 'not-a-dict',
                '_media_domains': {'bad.discord.gg': 'not-a-dict'},
                '_client_media': ['not-a-dict'],
            }
        self.cache.save()
        self.assertNotIn('bad.discord.gg', self.cache.cache)
        self.assertEqual(self.cache.cache['_media_domains'], {})
        self.assertEqual(self.cache.cache['_client_media'], {})


class TestQueryBuild(unittest.TestCase):
    def test_build_a_query_parses_back(self):
        q = dns_proxy.build_a_query('voice1.discord.gg', b'\x42\x42')
        self.assertEqual(q[:2], b'\x42\x42')
        self.assertEqual(dns_proxy.parse_domain(q), 'voice1.discord.gg')
        self.assertEqual(dns_proxy.parse_query_type(q), 1)


class TestValidateIp(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(dns_proxy.validate_ip('192.168.1.1'))

    def test_invalid(self):
        self.assertFalse(dns_proxy.validate_ip('YOUR_PI_IP'))
        self.assertFalse(dns_proxy.validate_ip('256.1.1.1'))
        self.assertFalse(dns_proxy.validate_ip('1.2.3'))


if __name__ == '__main__':
    unittest.main()
