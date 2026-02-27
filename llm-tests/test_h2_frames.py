"""
Tests for HTTP/2 frame-parsing bugs fixed in h2frame.cpp and hpack.cpp.

Each test establishes a proper TLS+HTTP/2 session (via the h2_conn fixture)
and then injects a single malformed frame.  The server must respond with a
GOAWAY (or at minimum a graceful connection close) instead of crashing.

Frame type constants (RFC 9113 §11.2):
  0x00 DATA  0x01 HEADERS  0x04 SETTINGS  0x07 GOAWAY

Flag constants:
  0x01 END_STREAM   0x04 END_HEADERS   0x08 PADDED
"""

import struct
import time

from helpers import (
    collect_frames,
    h2_frame_bytes,
)

GOAWAY     = 0x07
RST_STREAM = 0x03


# ── Helpers ───────────────────────────────────────────────────────────────────

def _assert_goaway(frames: list, *, error_code: int | None = None) -> None:
    """Assert that at least one GOAWAY frame is present, optionally checking the error code."""
    goaway = [f for f in frames if f["type"] == GOAWAY]
    assert goaway, f"Expected GOAWAY but got frame types {[f['type'] for f in frames]}"
    if error_code is not None:
        actual = struct.unpack(">I", goaway[0]["payload"][4:8])[0]
        assert actual == error_code, (
            f"Expected GOAWAY error_code=0x{error_code:02X}, got 0x{actual:02X}"
        )


def _assert_alive(server) -> None:
    time.sleep(0.05)
    assert server.poll() is None, "Server process exited (crashed)"


# ── DATA frame padding overflow ───────────────────────────────────────────────

def test_data_frame_pad_length_overflow(h2_conn, server):
    """
    DATA frame (type=0) with PADDED flag where pad_length >= payload size.

    Payload layout when PADDED: [pad_length(1)] [data] [padding(pad_length)]
    If pad_length (1) >= size (1) the old code computed:
        begin + size-1 - pad_length  →  begin + (size_t)(-1)  →  OOB iterator
    which is undefined behaviour and crashes on real hardware.

    Fix: throw h2_error(PROTOCOL_ERROR) before the assign() call.
    Expected: GOAWAY(PROTOCOL_ERROR = 0x01).

    Frame bytes:
      length=1, type=DATA(0), flags=PADDED(0x08), stream_id=1
      payload=[0x01]   ← this is both the pad_length byte (=1) AND the full payload
    """
    frame = h2_frame_bytes(0x00, 0x08, 1, bytes([0x01]))
    h2_conn.sendall(frame)

    frames = collect_frames(h2_conn)
    _assert_goaway(frames, error_code=0x01)   # PROTOCOL_ERROR
    _assert_alive(server)


# ── HEADERS frame padding overflow ────────────────────────────────────────────

def test_headers_frame_pad_length_overflow(h2_conn, server):
    """
    HEADERS frame (type=1) with PADDED flag where idx + pad_length > payload size.

    With only the PADDED flag set (no PRIORITY), idx = 1 after reading pad_length.
    Check: 1 + pad_length > size.
    Sending size=1, pad_length=1 → 2 > 1 → overflow path.

    Without the fix, field_block_fragment.assign() computed
        begin + size - idx - pad_length  →  begin + (size_t)(-1)  →  OOB.
    Fix: throw h2_error(PROTOCOL_ERROR).

    Frame bytes:
      length=1, type=HEADERS(1), flags=PADDED(0x08)|END_HEADERS(0x04)=0x0C, stream_id=3
      payload=[0x01]
    """
    frame = h2_frame_bytes(0x01, 0x0C, 3, bytes([0x01]))
    h2_conn.sendall(frame)

    frames = collect_frames(h2_conn)
    _assert_goaway(frames, error_code=0x01)   # PROTOCOL_ERROR
    _assert_alive(server)


# ── HPACK index 0 (assert → abort) ───────────────────────────────────────────

def test_hpack_index_zero(h2_conn, server):
    """
    HEADERS frame whose HPACK field-block fragment contains an Indexed Header
    Field representation at index 0 (byte 0x80 = 0b10000000).

    Index 0 is reserved by RFC 7541 §2.3.3.  The old code asserted:
        assert(key != 0);
    which invokes abort() and kills the server process.

    Fix: throw h2_error("HPACK index 0 is reserved", COMPRESSION_ERROR).
    Expected: GOAWAY(COMPRESSION_ERROR = 0x09).

    Frame bytes:
      length=1, type=HEADERS(1), flags=END_HEADERS(0x04), stream_id=5
      payload=[0x80]   ← indexed representation, index=0
    """
    frame = h2_frame_bytes(0x01, 0x04, 5, bytes([0x80]))
    h2_conn.sendall(frame)

    frames = collect_frames(h2_conn)
    _assert_goaway(frames, error_code=0x09)   # COMPRESSION_ERROR
    _assert_alive(server)
