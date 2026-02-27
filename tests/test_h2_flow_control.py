"""
Tests for HTTP/2 flow-control bugs fixed in h2_ctx.cpp.

RFC 9113 §6.5.2 / §6.9:
  SETTINGS_INITIAL_WINDOW_SIZE values above 2^31-1 are a connection error
  (FLOW_CONTROL_ERROR).
  A WINDOW_UPDATE with an increment of 0 is a stream error (PROTOCOL_ERROR).
  A WINDOW_UPDATE that causes a stream window to exceed 2^31-1 is a stream
  error (FLOW_CONTROL_ERROR).

Frame type constants:
  0x01 HEADERS  0x04 SETTINGS  0x07 GOAWAY  0x03 RST_STREAM  0x08 WINDOW_UPDATE

Error code constants (RFC 9113 §7):
  0x01 PROTOCOL_ERROR   0x03 FLOW_CONTROL_ERROR
"""

import struct
import time

import pytest

from helpers import (
    collect_frames,
    h2_frame_bytes,
    minimal_hpack_get,
)

GOAWAY     = 0x07
RST_STREAM = 0x03


# ── SETTINGS: initial window size exceeds INT32_MAX ──────────────────────────

def test_settings_initial_window_size_too_large(h2_conn, server):
    """
    SETTINGS frame with SETTINGS_INITIAL_WINDOW_SIZE (0x0004) = 0x80000000.

    The old code stored the value unchecked, then later computed a signed
    delta by casting the uint32_t to int32_t, producing INT32_MIN — causing
    all stream windows to become huge negative numbers (signed overflow, UB).

    In practice deserialise_SETTINGS also has a generic "value > INT32_MAX →
    PROTOCOL_ERROR" guard that fires first (before update_client_settings can
    throw FLOW_CONTROL_ERROR).  The observable difference between branches is
    therefore not the error code but whether a GOAWAY is sent at all:

      main branch  : h2_error propagates past extract_and_handle (no try-catch
                     there) to http_client's outer handler → connection closed
                     silently, no GOAWAY frame emitted.
      bugs branch  : extract_and_handle catches h2_error and calls
                     handle_connection_error → GOAWAY(PROTOCOL_ERROR) sent.

    Expected on bugs branch: GOAWAY with error code PROTOCOL_ERROR (0x01).
    """
    payload = struct.pack(">HI", 0x0004, 0x80000000)    # SETTINGS_INITIAL_WINDOW_SIZE
    h2_conn.sendall(h2_frame_bytes(0x04, 0x00, 0, payload))

    frames = collect_frames(h2_conn)
    goaway = [f for f in frames if f["type"] == GOAWAY]
    assert goaway, f"Expected GOAWAY; got {[f['type'] for f in frames]}"

    error_code = struct.unpack(">I", goaway[0]["payload"][4:8])[0]
    assert error_code == 0x01, f"Expected PROTOCOL_ERROR(0x01), got 0x{error_code:02X}"

    time.sleep(0.05)
    assert server.poll() is None, "Server crashed on oversized INITIAL_WINDOW_SIZE"


# ── WINDOW_UPDATE with zero increment on a stream ────────────────────────────

def test_stream_window_update_zero_increment(h2_conn, server):
    """
    WINDOW_UPDATE (type=0x08) on an open stream with increment = 0.

    RFC 9113 §6.9.1: "A receiver MUST treat the receipt of a
    WINDOW_UPDATE frame with a flow-control window increment of 0 as a
    stream error (Section 5.4.2) of type PROTOCOL_ERROR."

    The old code erroneously sent RST_STREAM(STREAM_CLOSED = 0x05) instead
    of RST_STREAM(PROTOCOL_ERROR = 0x01).

    Setup: open stream 1 with a HEADERS frame (no END_STREAM so stream stays open).
    Then send WINDOW_UPDATE(stream=1, increment=0).
    Expected: RST_STREAM(stream=1, PROTOCOL_ERROR = 0x01).
    """
    # Open stream 1: HEADERS + END_HEADERS, no END_STREAM → stream stays open
    headers = minimal_hpack_get()
    h2_conn.sendall(h2_frame_bytes(0x01, 0x04, 1, headers))
    time.sleep(0.1)     # let server register the stream

    h2_conn.sendall(h2_frame_bytes(0x08, 0x00, 1, struct.pack(">I", 0)))

    frames = collect_frames(h2_conn, n=8, timeout=1.0)
    rst = [f for f in frames if f["type"] == RST_STREAM and f["stream_id"] == 1]
    assert rst, (
        f"Expected RST_STREAM on stream 1; got {[(f['type'], f['stream_id']) for f in frames]}"
    )

    error_code = struct.unpack(">I", rst[0]["payload"])[0]
    assert error_code == 0x01, f"Expected PROTOCOL_ERROR(0x01), got 0x{error_code:02X}"

    time.sleep(0.05)
    assert server.poll() is None, "Server crashed on WINDOW_UPDATE increment=0"


# ── WINDOW_UPDATE that overflows a stream's 31-bit window ────────────────────

def test_stream_window_update_overflow(h2_conn, server):
    """
    WINDOW_UPDATE on an open stream whose increment would push the stream
    window above 2^31-1.

    RFC 9113 §6.9.1: "A sender MUST NOT allow a flow-control window to
    exceed 2^31-1 octets.  If a sender receives a WINDOW_UPDATE that
    causes a flow-control window to exceed this maximum, it MUST treat
    this as a connection or stream error (Section 5.4) of type
    FLOW_CONTROL_ERROR."

    The old code applied the increment without checking for overflow, leading
    to signed-integer overflow (UB) and negative window sizes.

    Setup: open stream 3 (default window = 65535).
    Send WINDOW_UPDATE(stream=3, increment=INT32_MAX = 0x7FFFFFFF).
    65535 + 2147483647 = 2147549182 > INT32_MAX → overflow.
    Expected: RST_STREAM(stream=3, FLOW_CONTROL_ERROR = 0x03).
    """
    headers = minimal_hpack_get()
    h2_conn.sendall(h2_frame_bytes(0x01, 0x04, 3, headers))
    time.sleep(0.1)

    h2_conn.sendall(h2_frame_bytes(0x08, 0x00, 3, struct.pack(">I", 0x7FFFFFFF)))

    frames = collect_frames(h2_conn, n=8, timeout=1.0)
    rst = [f for f in frames if f["type"] == RST_STREAM and f["stream_id"] == 3]
    assert rst, (
        f"Expected RST_STREAM on stream 3; got {[(f['type'], f['stream_id']) for f in frames]}"
    )

    error_code = struct.unpack(">I", rst[0]["payload"])[0]
    assert error_code == 0x03, f"Expected FLOW_CONTROL_ERROR(0x03), got 0x{error_code:02X}"

    time.sleep(0.05)
    assert server.poll() is None, "Server crashed on stream window overflow"
