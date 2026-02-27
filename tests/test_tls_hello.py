"""
Tests for TLS ClientHello extension parsing bugs fixed in hello.cpp.

Each test sends a syntactically complete ClientHello (with the required
supported_versions, key_share, and ALPN extensions) but appends or replaces
one extension with a malformed payload that would have triggered undefined
behaviour (span OOB access) or an incorrect exception on the bugs branch.

The invariant under test: the server process must not crash (abort/SIGSEGV)
when it receives any of these inputs.  The server may respond with a TLS
alert or simply close the connection — either is acceptable; crashing is not.
"""

import socket
import struct
import time

import pytest

from helpers import (
    TEST_HOST,
    TEST_HTTPS_PORT,
    build_extension,
    send_raw_client_hello,
)


# ── Helper ────────────────────────────────────────────────────────────────────

def _check_server_alive(server) -> None:
    """Assert the server process is still running and accepting connections."""
    time.sleep(0.05)
    assert server.poll() is None, "Server process exited (likely crashed via abort/SIGSEGV)"
    try:
        s = socket.create_connection((TEST_HOST, TEST_HTTPS_PORT), timeout=1)
        s.close()
    except OSError:
        pytest.fail("Server is no longer accepting new connections")


def _send_and_drain(extra_ext: bytes, server) -> None:
    """Send a ClientHello with extra_ext, drain any response, check server alive."""
    sock = send_raw_client_hello(extra_ext)
    try:
        sock.settimeout(1.0)
        try:
            sock.recv(4096)         # TLS alert, ServerHello fragment, or EOF — all OK
        except (socket.timeout, OSError):
            pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    _check_server_alive(server)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_supported_groups_empty(server):
    """
    supported_groups extension (0x000a) with zero bytes of data.

    Bug: get_supported_groups() called extension_data.subspan(2) without first
    checking that extension_data.size() >= 2.  When size == 0 this is UB
    (span::subspan with out-of-range offset).
    Fix: early return {} when size < 2.
    """
    _send_and_drain(build_extension(0x000A, b""), server)


def test_supported_groups_one_byte(server):
    """
    supported_groups extension with exactly 1 byte.

    Bug: same subspan(2) OOB as above — span has size 1, subspan(2) is UB.
    Fix: early return when size < 2.
    """
    _send_and_drain(build_extension(0x000A, bytes([0x00])), server)


def test_signature_algorithms_one_byte(server):
    """
    signature_algorithms extension (0x000d) with exactly 1 byte.

    Bug: get_signature_schemes() had the same missing size-check as
    get_supported_groups() and called subspan(2) on a 1-byte span.
    Fix: early return when size < 2.
    """
    _send_and_drain(build_extension(0x000D, bytes([0x00])), server)


def test_supported_versions_empty(server):
    """
    supported_versions extension (0x002b) with zero bytes.

    Bug: get_supported_versions() read extension_data[0] (the version-list
    length byte) without checking that the span was non-empty.
    Fix: return {} immediately when extension_data.empty().
    """
    # Replace the well-formed supported_versions with an empty one.
    # The server won't negotiate TLS 1.3 but must not crash.
    _send_and_drain(build_extension(0x002B, b""), server)


def test_key_share_entry_length_overflow(server):
    """
    key_share extension (0x0033) where an entry's key_length field declares
    more bytes than actually remain in the extension.

    Bug: get_named_group_keys() called extension_data.subspan(4, len) without
    verifying extension_data.size() >= 4 + len; when len > remaining bytes
    this is a span OOB → UB / abort in debug builds.
    Fix: throw ssl_error(decode_error) when the entry overflows.
    """
    # Entry: group=x25519 (0x001d), key_length=100, but only 4 bytes total
    entry = struct.pack(">H", 0x001D) + struct.pack(">H", 100)  # length claims 100, no data follows
    extra = build_extension(0x0033, struct.pack(">H", len(entry)) + entry)
    _send_and_drain(extra, server)
