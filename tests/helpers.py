"""
Low-level helpers for crafting raw TLS ClientHellos and HTTP/2 frames.
Used to send the exact malformed inputs that triggered each network-crashable bug.
"""

import os
import ssl
import socket
import struct
import time

TEST_HOST       = os.environ.get("TEST_HOST",       "127.0.0.1")
TEST_HTTPS_PORT = int(os.environ.get("TEST_HTTPS_PORT", "8443"))

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# ── HTTP/2 frame primitives ────────────────────────────────────────────────────

def h2_frame_bytes(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Serialize a complete HTTP/2 frame."""
    n = len(payload)
    header = bytes([
        (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF,
        frame_type, flags,
        (stream_id >> 24) & 0x7F,
        (stream_id >> 16) & 0xFF,
        (stream_id >> 8) & 0xFF,
        stream_id & 0xFF,
    ])
    return header + payload


def read_h2_frame(sock, timeout: float = 1.0):
    """
    Read one HTTP/2 frame from *sock*.
    Returns a dict {'type', 'flags', 'stream_id', 'payload'} or None on
    timeout / connection close / error.
    """
    old = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        hdr = b""
        while len(hdr) < 9:
            chunk = sock.recv(9 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        length = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
        frame_type = hdr[3]
        flags = hdr[4]
        stream_id = ((hdr[5] & 0x7F) << 24) | (hdr[6] << 16) | (hdr[7] << 8) | hdr[8]
        payload = b""
        while len(payload) < length:
            chunk = sock.recv(length - len(payload))
            if not chunk:
                return None
            payload += chunk
        return {"type": frame_type, "flags": flags, "stream_id": stream_id, "payload": payload}
    except (socket.timeout, OSError, ssl.SSLError):
        return None
    finally:
        sock.settimeout(old)


def collect_frames(sock, n: int = 8, timeout: float = 1.0) -> list:
    """Read up to *n* frames, stopping on the first None."""
    frames = []
    for _ in range(n):
        f = read_h2_frame(sock, timeout=timeout)
        if f is None:
            break
        frames.append(f)
    return frames


def do_h2_handshake(sock) -> None:
    """
    Perform the HTTP/2 connection preface exchange:
      client → PREFACE + empty SETTINGS
      server → SETTINGS (we ACK) + SETTINGS_ACK
    Blocks until the server's SETTINGS_ACK arrives or times out.
    """
    sock.sendall(HTTP2_PREFACE)
    sock.sendall(h2_frame_bytes(0x04, 0x00, 0, b""))  # empty client SETTINGS

    for _ in range(12):
        frame = read_h2_frame(sock, timeout=3.0)
        if frame is None:
            break
        if frame["type"] == 0x04:
            if not (frame["flags"] & 0x01):
                # Server's SETTINGS (non-ACK) — reply with ACK
                sock.sendall(h2_frame_bytes(0x04, 0x01, 0, b""))
            else:
                # SETTINGS_ACK for our own SETTINGS — handshake done
                break


def make_h2_connection():
    """
    Open a TLS connection with ALPN 'h2' and perform the full HTTP/2
    preface exchange.  Certificate verification is disabled (test server
    uses a self-signed cert).
    Returns the ssl.SSLSocket ready for frame exchange.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    raw = socket.create_connection((TEST_HOST, TEST_HTTPS_PORT), timeout=5)
    tls = ctx.wrap_socket(raw, server_hostname="localhost")
    do_h2_handshake(tls)
    return tls


def minimal_hpack_get(authority: str = "localhost") -> bytes:
    """
    Return an HPACK-encoded minimal GET / request.
    Uses only static-table indexed entries to keep the encoding trivial.
      index 2  → :method: GET
      index 4  → :path: /
      index 7  → :scheme: https
      index 1  → :authority (literal with incremental indexing)
    """
    block = bytes([0x82, 0x84, 0x87])       # :method:GET, :path:/, :scheme:https
    val = authority.encode()
    # Literal header with incremental indexing, name at static index 1 (:authority)
    block += bytes([0x41, len(val)]) + val
    return block


# ── Raw TLS ClientHello builder ───────────────────────────────────────────────

def build_extension(ext_type: int, data: bytes) -> bytes:
    """Build one TLS extension: type (2) + length (2) + data."""
    return struct.pack(">HH", ext_type, len(data)) + data


def ext_supported_versions_tls13() -> bytes:
    """supported_versions extension advertising TLS 1.3 (required for TLS 1.3 negotiation)."""
    versions = struct.pack(">H", 0x0304)            # TLS 1.3
    return build_extension(0x002B, bytes([len(versions)]) + versions)


def ext_key_share_x25519() -> bytes:
    """key_share extension with a dummy x25519 public key."""
    pub_key = bytes(32)
    entry = struct.pack(">H", 0x001D) + struct.pack(">H", 32) + pub_key
    return build_extension(0x0033, struct.pack(">H", len(entry)) + entry)


def ext_alpn_h2() -> bytes:
    """ALPN extension advertising 'h2'."""
    proto = b"h2"
    proto_list = bytes([len(proto)]) + proto
    return build_extension(0x0010, struct.pack(">H", len(proto_list)) + proto_list)


def build_raw_client_hello(
    extra_extensions: bytes,
    *,
    skip_supported_versions: bool = False,
    skip_key_share: bool = False,
) -> bytes:
    """
    Build a TLS record wrapping a ClientHello.

    By default the hello contains the minimum extensions required for TLS 1.3
    (supported_versions, key_share, ALPN) plus any *extra_extensions* appended
    at the end.

    Pass ``skip_supported_versions=True`` or ``skip_key_share=True`` to omit
    the corresponding standard extension.  This is useful when a test needs to
    supply its own (possibly malformed) copy of that extension as the *only*
    occurrence in the hello so that the server must process it.
    """
    random_bytes = os.urandom(32)
    session_id = bytes([32]) + bytes(32)            # 32-byte fake session ID
    ciphers = struct.pack(">H", 0x1301)             # TLS_AES_128_GCM_SHA256
    compression = bytes([1, 0])                     # null compression

    extensions = b""
    if not skip_supported_versions:
        extensions += ext_supported_versions_tls13()
    if not skip_key_share:
        extensions += ext_key_share_x25519()
    extensions += ext_alpn_h2()
    extensions += extra_extensions

    hello_body = (
        bytes([0x03, 0x03])                         # legacy version: TLS 1.2
        + random_bytes
        + session_id
        + struct.pack(">H", len(ciphers)) + ciphers
        + compression
        + struct.pack(">H", len(extensions)) + extensions
    )

    length_3 = struct.pack(">I", len(hello_body))[1:]   # 3-byte length
    handshake = bytes([0x01]) + length_3 + hello_body   # ClientHello msg type = 1
    return bytes([0x16, 0x03, 0x01]) + struct.pack(">H", len(handshake)) + handshake


def send_raw_client_hello(extra_extensions: bytes, **kw) -> socket.socket:
    """
    Send a ClientHello with extra_extensions over a plain TCP socket and
    return the socket (caller is responsible for closing it).

    Keyword arguments are forwarded to ``build_raw_client_hello``
    (e.g. ``skip_supported_versions=True``).
    """
    s = socket.create_connection((TEST_HOST, TEST_HTTPS_PORT), timeout=5)
    s.sendall(build_raw_client_hello(extra_extensions, **kw))
    return s
