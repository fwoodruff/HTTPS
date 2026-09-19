"""
Regression tests for TLS record-layer and handshake-reassembly handling of
malformed input.
"""

import os
import socket
import ssl
import struct
import time

import pytest

from helpers import TEST_HOST, TEST_HTTPS_PORT, SERVER_HOSTNAME


# ── short CBC record ──────────────────────────────────────────────────────────

def _cbc_connection():
    """
    Negotiate TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.  Skips the test when the
    local OpenSSL refuses to offer the legacy CBC suite.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers("ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0")
    except ssl.SSLError:
        pytest.skip("local OpenSSL will not offer ECDHE-ECDSA-AES128-SHA")

    raw = socket.create_connection((TEST_HOST, TEST_HTTPS_PORT), timeout=5)
    try:
        tls = ctx.wrap_socket(raw, server_hostname=SERVER_HOSTNAME)
    except ssl.SSLError:
        raw.close()
        pytest.skip("server would not negotiate a CBC cipher suite")
    return tls


def _server_still_handshakes(attempts: int = 10) -> bool:
    """
    Liveness probe that survives the race between a crash and the next connect:
    a dying process can still have connections sitting in its listen backlog, so
    require a full TLS handshake rather than a bare TCP connect.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for _ in range(attempts):
        time.sleep(0.1)
        try:
            with socket.create_connection((TEST_HOST, TEST_HTTPS_PORT), timeout=2) as raw:
                with ctx.wrap_socket(raw, server_hostname=SERVER_HOSTNAME):
                    return True
        except (OSError, ssl.SSLError):
            continue
    return False


def test_short_cbc_record_does_not_crash_server(server):
    """
    A CBC application record carrying a single ciphertext block decrypts to 16
    bytes of plaintext, fewer than the 20-byte SHA-1 MAC that deprotect then
    copies out.  That read ran off the end of the buffer and tripped an assert,
    so one 32-byte record aborted the whole server.
    """
    tls = _cbc_connection()
    fd = tls.fileno()
    try:
        # explicit IV block + one ciphertext block, no valid MAC or padding
        record = bytes([0x17, 0x03, 0x03, 0x00, 0x20]) + os.urandom(32)
        os.write(fd, record)        # bypass the TLS layer, write the raw record
        try:
            tls.setblocking(False)
            os.read(fd, 4096)       # expect an alert or a close, never a crash
        except (BlockingIOError, OSError, ssl.SSLError):
            pass
    finally:
        try:
            tls.close()
        except OSError:
            pass

    assert _server_still_handshakes(), "server died on a short CBC record"
    assert server.poll() is None


# ── handshake reassembly ──────────────────────────────────────────────────────

def _tls12_client_hello_body() -> bytes:
    """A ClientHello handshake message (no record header) that negotiates TLS 1.2."""
    ciphers = struct.pack(">H", 0xC02B)             # ECDHE-ECDSA-AES128-GCM-SHA256
    body = (
        bytes([0x03, 0x03])                         # legacy version: TLS 1.2
        + os.urandom(32)                            # client random
        + bytes([0])                                # empty session id
        + struct.pack(">H", len(ciphers)) + ciphers
        + bytes([1, 0])                             # null compression
        + struct.pack(">H", 0)                      # no extensions
    )
    return bytes([0x01]) + struct.pack(">I", len(body))[1:] + body


def _tls_record(payload: bytes, content_type: int = 0x16) -> bytes:
    return bytes([content_type, 0x03, 0x03]) + struct.pack(">H", len(payload)) + payload


def _read_alert(sock, timeout=3.0):
    """Drain records until an Alert arrives; return its (level, description)."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            buf += chunk
            while len(buf) >= 5:
                length = struct.unpack(">H", buf[3:5])[0]
                if len(buf) < 5 + length:
                    break
                ctype, body, buf = buf[0], buf[5:5 + length], buf[5 + length:]
                if ctype == 0x15 and len(body) >= 2:
                    return body[0], body[1]
    except (socket.timeout, OSError):
        return None


@pytest.mark.parametrize("trailing", [1, 2, 3])
def test_consumed_handshake_messages_are_not_replayed(server, trailing):
    """
    A handshake record may end partway through the 4-byte header of the next
    message.  The reassembly buffer only dropped consumed messages on the other
    branch, so in this case the ClientHello stayed buffered and was handed to
    the state machine a second time once the next byte arrived.

    The replay showed up as an unexpected_message(10) alert for out-of-order
    handshake data.  Correct behaviour is to parse only the newly completed
    message -- an unknown handshake type -- and answer decode_error(50).
    """
    unknown_message = bytes([0xFF, 0x00, 0x00, 0x00])   # unknown type, length 0

    s = socket.create_connection((TEST_HOST, TEST_HTTPS_PORT), timeout=5)
    try:
        # record 1: a complete ClientHello plus the first bytes of the next message
        s.sendall(_tls_record(_tls12_client_hello_body() + unknown_message[:trailing]))
        s.settimeout(3.0)
        try:
            assert s.recv(4096)[:1] == b"\x16", "expected a ServerHello flight"
        except socket.timeout:
            pytest.fail("server did not answer the ClientHello")

        # record 2: the rest of that unknown handshake message
        s.sendall(_tls_record(unknown_message[trailing:]))
        alert = _read_alert(s)
        assert alert is not None, "expected a fatal alert"
        level, description = alert
        assert level == 2
        assert description == 50, (
            f"got alert description {description}, expected decode_error(50); "
            "description 10 means the ClientHello was replayed"
        )
    finally:
        s.close()

    assert server.poll() is None
