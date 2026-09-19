"""
Regression tests for HTTP/2 header field validation and frame size limits.

HPACK places no restriction on the octets a field carries.  Everything that
later re-serialises a request as HTTP/1.1 -- the reverse proxy, the request log
-- trusts these strings, so the h2 layer has to reject the octets that would
let a peer forge header lines or whole extra requests.
"""

import struct

import pytest

from helpers import (
    collect_frames,
    h2_frame_bytes,
    make_h2_connection,
    minimal_hpack_get,
)

GOAWAY = 0x07
RST_STREAM = 0x03
HEADERS = 0x01
PROTOCOL_ERROR = 0x01
FRAME_SIZE_ERROR = 0x06


def hpack_literal(name: bytes, value: bytes) -> bytes:
    """Literal header field with incremental indexing, new name, no Huffman."""
    return bytes([0x40, len(name)]) + name + bytes([len(value)]) + value


def _error_codes(frames):
    """Error codes from any GOAWAY / RST_STREAM frames in *frames*."""
    codes = []
    for f in frames:
        if f["type"] == GOAWAY and len(f["payload"]) >= 8:
            codes.append(struct.unpack(">I", f["payload"][4:8])[0])
        elif f["type"] == RST_STREAM and len(f["payload"]) >= 4:
            codes.append(struct.unpack(">I", f["payload"][:4])[0])
    return codes


def _send_request_with_field(name: bytes, value: bytes):
    tls = make_h2_connection()
    try:
        block = minimal_hpack_get() + hpack_literal(name, value)
        tls.sendall(h2_frame_bytes(HEADERS, 0x05, 1, block))   # END_STREAM|END_HEADERS
        return collect_frames(tls, n=8, timeout=2.0)
    finally:
        tls.close()


@pytest.mark.parametrize("name,value,why", [
    (b"x-injected", b"a\r\nx-smuggled: yes",      "CRLF in value"),
    (b"x-injected", b"a\nx-smuggled: yes",        "bare LF in value"),
    (b"x-injected", b"a\rx-smuggled: yes",        "bare CR in value"),
    (b"x-injected", b"a\x00b",                    "NUL in value"),
    (b"X-Upper",    b"fine",                      "uppercase field name"),
    (b"x-inj\r\ny", b"fine",                      "CRLF in field name"),
    (b"x-injected", b" leading",                  "leading whitespace in value"),
    (b"x-injected", b"trailing ",                 "trailing whitespace in value"),
    (b"transfer-encoding", b"chunked",            "connection-specific field"),
    (b"connection", b"close",                     "connection-specific field"),
])
def test_malformed_header_field_is_rejected(server, name, value, why):
    frames = _send_request_with_field(name, value)
    codes = _error_codes(frames)
    assert codes, f"{why}: server answered without an error frame"
    assert PROTOCOL_ERROR in codes, f"{why}: got error codes {codes}"
    assert server.poll() is None


def test_well_formed_header_field_is_accepted(server):
    """The validation must not reject ordinary requests."""
    frames = _send_request_with_field(b"x-ordinary", b"value-1")
    assert not _error_codes(frames), "a well-formed header was rejected"
    assert any(f["type"] == HEADERS for f in frames), "no response headers"
    assert server.poll() is None


def test_frame_larger_than_advertised_max_is_rejected(server):
    """
    The server advertises the default SETTINGS_MAX_FRAME_SIZE of 16384 but used
    to accept anything up to 2^24-1, letting a peer make it buffer 16MB per
    connection for the price of a 9 byte header.
    """
    tls = make_h2_connection()
    try:
        oversized = h2_frame_bytes(HEADERS, 0x05, 1, b"\x00" * 16385)
        tls.sendall(oversized)
        frames = collect_frames(tls, n=8, timeout=2.0)
    finally:
        tls.close()

    codes = _error_codes(frames)
    assert FRAME_SIZE_ERROR in codes, f"expected FRAME_SIZE_ERROR, got {codes}"
    assert server.poll() is None
