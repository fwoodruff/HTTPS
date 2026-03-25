"""
Tests for QUIC Initial packet parsing and decryption (RFC 9001).

The server must be running before these tests execute.  Tests send raw UDP
datagrams to the same port as the HTTPS server.

Two categories:
  1. Structural tests - verify the server survives malformed/truncated packets.
  2. Crypto tests - build a fully valid, decryptable QUIC Initial packet
     (correct HKDF key derivation + AES-128-GCM + AES-128-ECB HP) and verify
     the server stays alive after receiving it.
"""

import hashlib
import hmac as hmac_mod
import os
import socket
import struct
import time

import pytest

TEST_HOST       = os.environ.get("TEST_HOST",       "127.0.0.1")
TEST_HTTPS_PORT = int(os.environ.get("TEST_HTTPS_PORT", "8443"))


# ── QUIC varint ────────────────────────────────────────────────────────────────

def quic_varint(n: int) -> bytes:
    """Encode n as a QUIC variable-length integer (RFC 9000 §16)."""
    if n < 0x40:
        return bytes([n])
    if n < 0x4000:
        return struct.pack(">H", 0x4000 | n)
    if n < 0x40000000:
        return struct.pack(">I", 0x80000000 | n)
    return struct.pack(">Q", 0xC000000000000000 | n)


# ── Key derivation (RFC 9001 §5.2) ────────────────────────────────────────────

# QUICv1 initial salt
QUIC_V1_SALT = bytes([
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
])


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac_mod.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm = b""
    T = b""
    i = 1
    while len(okm) < length:
        T = hmac_mod.new(prk, T + info + bytes([i]), hashlib.sha256).digest()
        okm += T
        i += 1
    return okm[:length]


def hkdf_expand_label(prk: bytes, label: str, context: bytes, length: int) -> bytes:
    full_label = b"tls13 " + label.encode()
    info = (
        struct.pack(">H", length)
        + bytes([len(full_label)]) + full_label
        + bytes([len(context)]) + context
    )
    return hkdf_expand(prk, info, length)


def derive_client_initial_keys(dcid: bytes) -> tuple[bytes, bytes, bytes]:
    """Return (key, iv, hp) for the client Initial packet-number space."""
    initial_secret = hkdf_extract(QUIC_V1_SALT, dcid)
    client_secret  = hkdf_expand_label(initial_secret, "client in", b"", 32)
    key = hkdf_expand_label(client_secret, "quic key", b"", 16)
    iv  = hkdf_expand_label(client_secret, "quic iv",  b"", 12)
    hp  = hkdf_expand_label(client_secret, "quic hp",  b"", 16)
    return key, iv, hp


# ── AES helpers ────────────────────────────────────────────────────────────────

def aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    c = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    enc = c.encryptor()
    return enc.update(block) + enc.finalize()


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    return ct_tag[:-16], ct_tag[-16:]   # ciphertext, tag


# ── Minimal TLS ClientHello for QUIC (RFC 9001 §8.1) ─────────────────────────

def build_quic_client_hello() -> bytes:
    """
    Build a minimal TLS 1.3 ClientHello suitable for wrapping in a QUIC
    CRYPTO frame.  The contents only need to be structurally valid enough
    for the server's frame parser to not crash; actual TLS negotiation is
    not expected at this stage.
    """
    random_bytes   = os.urandom(32)
    session_id     = bytes([0])                # legacy session ID: empty
    cipher_suites  = struct.pack(">H", 0x1301) # TLS_AES_128_GCM_SHA256
    compression    = bytes([1, 0])             # null compression

    # Minimal extensions: supported_versions (TLS 1.3) + key_share (x25519 dummy)
    sv_data = bytes([2]) + struct.pack(">H", 0x0304)           # 1 version: TLS 1.3
    sv_ext  = struct.pack(">HH", 0x002B, len(sv_data)) + sv_data

    ks_entry = struct.pack(">HH", 0x001D, 32) + bytes(32)      # x25519, zero key
    ks_data  = struct.pack(">H", len(ks_entry)) + ks_entry
    ks_ext   = struct.pack(">HH", 0x0033, len(ks_data)) + ks_data

    # QUIC transport parameters extension (type 0x0039)
    # Minimal: max_idle_timeout (0x01) = 30 000 ms, encoded as varint
    tp_data = bytes([0x01, 0x02, 0x75, 0x30])  # param_id=1, len=2, value=30000
    tp_ext  = struct.pack(">HH", 0x0039, len(tp_data)) + tp_data

    extensions = sv_ext + ks_ext + tp_ext

    hello_body = (
        bytes([0x03, 0x03])                                   # legacy_version
        + random_bytes
        + bytes([len(session_id)]) + session_id
        + struct.pack(">H", len(cipher_suites)) + cipher_suites
        + compression
        + struct.pack(">H", len(extensions)) + extensions
    )

    length_3 = struct.pack(">I", len(hello_body))[1:]          # 3-byte length
    return bytes([0x01]) + length_3 + hello_body               # handshake msg type 1


# ── Fully encrypted QUIC Initial packet builder ───────────────────────────────

def build_encrypted_quic_initial(dcid: bytes, scid: bytes = b"") -> bytes:
    """
    Build a QUIC Initial packet that the server can fully decrypt:
      - Keys derived from dcid via RFC 9001 §5.2
      - Payload: one CRYPTO frame (type 0x06) wrapping a TLS ClientHello
      - PADDING frames to reach minimum 1200-byte datagram (QUIC requirement)
      - AES-128-GCM AEAD-protected payload
      - AES-128-ECB header protection applied
    """
    pytest.importorskip("cryptography", reason="cryptography package not available")

    key, iv, hp_key = derive_client_initial_keys(dcid)

    client_hello = build_quic_client_hello()

    # CRYPTO frame: type=0x06, offset=0, length=<len>, data=<ClientHello>
    crypto_frame = (
        bytes([0x06])
        + quic_varint(0)                     # offset
        + quic_varint(len(client_hello))     # length
        + client_hello
    )
    # Pad to 1200 bytes total datagram.  We'll know the header size after
    # building it, so add padding conservatively (padding frame = 0x00).
    frames_unpadded = crypto_frame
    # Enough padding: we'll compute the exact needed amount after header construction.

    packet_number    = 0
    packet_number_len = 1  # 1-byte packet number
    # First byte: Long header | Fixed | Initial (00) | reserved (00) | pn_len-1 (00)
    first_byte_unprotected = 0xC0 | (packet_number_len - 1)

    # Build the plain header (up to and including the Length field).
    # Length = pn_len + len(plaintext) + 16 (AEAD tag).
    # We need to know the plaintext size first.
    # Use a placeholder and compute padding.
    header_prefix = (
        bytes([first_byte_unprotected])
        + struct.pack(">I", 0x00000001)      # QUICv1
        + bytes([len(dcid)]) + dcid
        + bytes([len(scid)]) + scid
        + quic_varint(0)                     # token length = 0
    )

    min_datagram = 1200
    # total = len(header_prefix) + len(length_varint) + pn_len + len(plaintext) + 16
    # len(length_varint) is 2 for values 64–16383
    overhead = len(header_prefix) + 2 + packet_number_len + 16
    plaintext_min = max(min_datagram - overhead, len(frames_unpadded))
    padding_needed = plaintext_min - len(frames_unpadded)
    plaintext = frames_unpadded + bytes(padding_needed)  # 0x00 = PADDING frame

    payload_length = packet_number_len + len(plaintext) + 16
    length_varint  = quic_varint(payload_length)

    header_bytes = header_prefix + length_varint

    # Build AAD = header_bytes || packet_number_bytes
    pn_bytes = packet_number.to_bytes(packet_number_len, "big")
    aad = header_bytes + pn_bytes

    # Nonce = IV ⊕ zero-padded packet number
    nonce = bytearray(iv)
    for i, b in enumerate(pn_bytes):
        nonce[len(nonce) - len(pn_bytes) + i] ^= b
    nonce = bytes(nonce)

    # AEAD encrypt
    ciphertext, tag = aes_gcm_encrypt(key, nonce, plaintext, aad)

    # raw_payload (before header protection) = pn_bytes || ciphertext || tag
    raw_payload_unprotected = pn_bytes + ciphertext + tag

    # Apply header protection (RFC 9001 §5.4.3):
    # sample = raw_payload[4..20]
    sample = raw_payload_unprotected[4:20]
    mask   = aes_ecb_encrypt(hp_key, sample)

    protected_first_byte = first_byte_unprotected ^ (mask[0] & 0x0f)
    protected_pn = bytes(
        raw_payload_unprotected[i] ^ mask[1 + i] for i in range(packet_number_len)
    )
    protected_payload = (
        protected_pn
        + raw_payload_unprotected[packet_number_len:]
    )

    packet = bytes([protected_first_byte]) + header_bytes[1:] + protected_payload
    return packet


def build_fake_quic_initial(dcid: bytes, scid: bytes = b"", token: bytes = b"") -> bytes:
    """
    Build a QUIC Initial packet with a valid header but fake (unencrypted)
    payload.  The server will not be able to decrypt it, but it must parse
    the header without crashing.
    """
    first_byte = 0xC0
    payload    = os.urandom(20)
    pkt = (
        bytes([first_byte])
        + struct.pack(">I", 0x00000001)
        + bytes([len(dcid)]) + dcid
        + bytes([len(scid)]) + scid
        + quic_varint(len(token)) + token
        + quic_varint(len(payload))
        + payload
    )
    return pkt


# ── Helpers ────────────────────────────────────────────────────────────────────

def send_udp(data: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(data, (TEST_HOST, TEST_HTTPS_PORT))


# ── Structural / robustness tests ─────────────────────────────────────────────

def test_quic_initial_fake_payload(server):
    """Well-formed header but fake payload: server discards, does not crash."""
    send_udp(build_fake_quic_initial(dcid=os.urandom(8)))
    time.sleep(0.1)
    assert server.poll() is None


def test_quic_initial_truncated_header(server):
    """Datagram cut off inside DCID: silently dropped."""
    truncated = bytes([0xC0]) + struct.pack(">I", 0x00000001) + bytes([0x08, 0xAA])
    send_udp(truncated)
    time.sleep(0.1)
    assert server.poll() is None


def test_quic_initial_empty_datagram(server):
    """Empty UDP datagram must be silently ignored."""
    send_udp(b"")
    time.sleep(0.1)
    assert server.poll() is None


def test_quic_initial_unknown_version(server):
    """Unknown QUIC version must not crash the server."""
    dcid = os.urandom(8)
    pkt  = (
        bytes([0xC0])
        + struct.pack(">I", 0xBADC0FFE)
        + bytes([len(dcid)]) + dcid
        + bytes([0])           # scid len
        + quic_varint(0)       # token len
        + quic_varint(20)      # length
        + os.urandom(20)
    )
    send_udp(pkt)
    time.sleep(0.1)
    assert server.poll() is None


def test_quic_initial_with_token(server):
    """Non-empty Retry token is parsed without crash."""
    send_udp(build_fake_quic_initial(dcid=os.urandom(8), token=os.urandom(16)))
    time.sleep(0.1)
    assert server.poll() is None


def test_quic_initial_burst(server):
    """Five rapid Initial packets must not crash the server."""
    for _ in range(5):
        send_udp(build_fake_quic_initial(dcid=os.urandom(8)))
    time.sleep(0.2)
    assert server.poll() is None


# ── Crypto test ───────────────────────────────────────────────────────────────

def test_quic_initial_fully_encrypted(server):
    """
    Send a fully encrypted, spec-compliant QUIC Initial packet.

    The server should derive the correct keys from the DCID, remove header
    protection, and decrypt the AEAD payload (which contains a CRYPTO frame
    with a TLS ClientHello).  If key derivation or decryption is wrong the
    server will log an AEAD failure and discard; either way it must not crash.
    """
    dcid   = os.urandom(8)
    packet = build_encrypted_quic_initial(dcid)
    assert len(packet) >= 1200, "QUIC spec: client Initial must be >= 1200 bytes"
    send_udp(packet)
    time.sleep(0.15)
    assert server.poll() is None


def test_quic_initial_verify_key_derivation():
    """
    Offline sanity-check: verify our Python key derivation matches the
    RFC 9001 Appendix A test vector.
    """
    # RFC 9001 Appendix A.1 test vector
    dcid = bytes([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08])
    key, iv, hp = derive_client_initial_keys(dcid)

    expected_key = bytes([
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
    ])
    expected_iv = bytes([
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
        0x46, 0xfb, 0x25, 0x5c,
    ])
    expected_hp = bytes([
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
    ])

    assert key == expected_key, f"key mismatch:\n  got {key.hex()}\n  exp {expected_key.hex()}"
    assert iv  == expected_iv,  f"iv mismatch:\n  got {iv.hex()}\n  exp {expected_iv.hex()}"
    assert hp  == expected_hp,  f"hp mismatch:\n  got {hp.hex()}\n  exp {expected_hp.hex()}"
