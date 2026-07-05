"""Raw DNS packet parsing and building (stdlib only, UDP wire format).

Only the small slice of RFC 1035 that MeSocks needs: single-question
queries, A-record answers, and NODATA responses. Anything outside that
(compressed question names, multi-question packets, oversized labels)
is rejected. Stub resolvers never send it, so it is garbage or abuse.
"""

import struct

MAX_NAME_LEN = 253  # RFC 1035 limit on a full domain name

QTYPE_A = 1


def parse_question(data: bytes) -> tuple[str, int, int] | None:
    """Parse the question section of a DNS query.

    Returns (domain, qtype, end_of_question_pos) or None if malformed.
    """
    if len(data) < 12:
        return None
    if struct.unpack('>H', data[4:6])[0] != 1:  # QDCOUNT must be exactly 1
        return None
    pos = 12
    parts = []
    total = 0
    try:
        while True:
            length = data[pos]
            if length == 0:
                pos += 1
                break
            if length & 0xC0:  # compression pointer / reserved bits
                return None
            if length > 63:
                return None
            total += length + 1
            if total > MAX_NAME_LEN:
                return None
            pos += 1
            if pos + length > len(data):
                return None
            parts.append(data[pos:pos+length].decode('ascii', errors='ignore'))
            pos += length
        if pos + 4 > len(data):
            return None
        qtype = struct.unpack('>H', data[pos:pos+2])[0]
        return '.'.join(parts).lower(), qtype, pos + 4
    except IndexError:
        return None


def parse_domain(data: bytes) -> str | None:
    """Extract domain name from a DNS query packet."""
    q = parse_question(data)
    return q[0] if q else None


def parse_query_type(data: bytes) -> int:
    """Extract query type from a DNS packet (0 if malformed)."""
    q = parse_question(data)
    return q[1] if q else 0


def skip_name(data: bytes, pos: int) -> int:
    """Skip over a (possibly compressed) name in a DNS response, return new pos.

    Handles label sequences that end with a compression pointer.
    Raises IndexError/ValueError on truncated or looping data.
    """
    hops = 0
    while True:
        length = data[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:  # pointer terminates the name
            return pos + 2
        if length & 0xC0:
            raise ValueError('reserved label type')
        pos += 1 + length
        hops += 1
        if hops > 64:
            raise ValueError('name too long')


def parse_a_answer(response: bytes) -> str | None:
    """Extract the first A record from a DNS response, or None."""
    try:
        ancount = struct.unpack('>H', response[6:8])[0]
        qdcount = struct.unpack('>H', response[4:6])[0]
        if ancount == 0:
            return None
        pos = 12
        for _ in range(qdcount):
            pos = skip_name(response, pos) + 4  # qtype + qclass
        for _ in range(ancount):
            pos = skip_name(response, pos)
            if pos + 10 > len(response):
                return None
            rtype = struct.unpack('>H', response[pos:pos+2])[0]
            rdlength = struct.unpack('>H', response[pos+8:pos+10])[0]
            pos += 10
            if pos + rdlength > len(response):
                return None
            if rtype == QTYPE_A and rdlength == 4:
                return '.'.join(str(b) for b in response[pos:pos+4])
            pos += rdlength
        return None
    except (IndexError, ValueError, struct.error):
        return None


def parse_answer_ttl(response: bytes) -> int | None:
    """Extract the TTL of the first answer record, or None if unparseable."""
    try:
        ancount = struct.unpack('>H', response[6:8])[0]
        if ancount == 0:
            return None
        qdcount = struct.unpack('>H', response[4:6])[0]
        pos = 12
        for _ in range(qdcount):
            pos = skip_name(response, pos) + 4  # qtype + qclass
        pos = skip_name(response, pos)
        # pos is now at TYPE; TTL is at pos+4 (skip type=2, class=2)
        return struct.unpack('>I', response[pos + 4:pos + 8])[0]
    except Exception:
        return None


def _response_flags(query: bytes) -> bytes:
    """Response flags: QR=1, RA=1, echo the client's RD bit."""
    rd = query[2] & 0x01
    return bytes([0x80 | rd, 0x80])


def build_response(query: bytes, ip: str, question_end: int, ttl: int = 300) -> bytes:
    """Build a DNS response with a single A record pointing at ip."""
    response = bytearray()
    response += query[:2]  # Transaction ID
    response += _response_flags(query)
    response += b'\x00\x01'  # Questions count = 1
    response += b'\x00\x01'  # Answers count = 1
    response += b'\x00\x00'  # Authority count
    response += b'\x00\x00'  # Additional count
    response += query[12:question_end]  # Question section

    response += b'\xc0\x0c'  # Pointer to domain name in question
    response += b'\x00\x01'  # Type A
    response += b'\x00\x01'  # Class IN
    response += struct.pack('>I', ttl)
    response += b'\x00\x04'  # Data length
    response += bytes(int(x) for x in ip.split('.'))

    return bytes(response)


def build_empty_response(query: bytes, question_end: int) -> bytes:
    """Build a NOERROR response with no answers (NODATA, e.g. for AAAA)."""
    response = bytearray()
    response += query[:2]  # Transaction ID
    response += _response_flags(query)
    response += b'\x00\x01'  # Questions count = 1
    response += b'\x00\x00'  # Answers count = 0
    response += b'\x00\x00'  # Authority count
    response += b'\x00\x00'  # Additional count
    response += query[12:question_end]  # Question section

    return bytes(response)


def build_a_query(domain: str, transaction_id: bytes) -> bytes:
    """Build a DNS A query packet for domain."""
    flags = b'\x01\x00'
    qdcount = b'\x00\x01'
    counts = b'\x00\x00\x00\x00\x00\x00'

    qname = b''
    for part in domain.split('.'):
        qname += bytes([len(part)]) + part.encode()
    qname += b'\x00'

    qtype = b'\x00\x01'  # A
    qclass = b'\x00\x01'  # IN

    return transaction_id + flags + qdcount + counts + qname + qtype + qclass


def is_cacheable_response(response: bytes) -> bool:
    """Only complete NOERROR/NXDOMAIN responses are safe to cache."""
    if len(response) < 12:
        return False
    if response[2] & 0x02:  # TC (truncated)
        return False
    return response[3] & 0x0F in (0, 3)  # NOERROR or NXDOMAIN


def validate_ipv4(ip: str) -> bool:
    """Check if string is a valid dotted-quad IPv4 address."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
