"""Builders for raw DNS packets used across the test modules."""

import struct


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
