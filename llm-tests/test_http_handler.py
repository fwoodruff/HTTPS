"""
Regression tests for the HTTP/1.1 request handler: descriptor lifetime, request
smuggling, and webroot containment.
"""

import os
import re
import socket
import ssl
import subprocess

import pytest

from helpers import TEST_HOST, TEST_HTTPS_PORT, SERVER_HOSTNAME


def _https_connection():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    raw = socket.create_connection((TEST_HOST, TEST_HTTPS_PORT), timeout=5)
    return ctx.wrap_socket(raw, server_hostname=SERVER_HOSTNAME)


def _request(raw_request: bytes, timeout: float = 5.0) -> bytes:
    tls = _https_connection()
    try:
        tls.sendall(raw_request)
        tls.settimeout(timeout)
        out = b""
        while True:
            try:
                chunk = tls.recv(65536)
            except (socket.timeout, ssl.SSLError, OSError):
                break
            if not chunk:
                break
            out += chunk
        return out
    finally:
        try:
            tls.close()
        except OSError:
            pass


def _status(response: bytes) -> int:
    m = re.match(rb"HTTP/1\.1 (\d{3})", response)
    assert m, f"not an HTTP response: {response[:80]!r}"
    return int(m.group(1))


def _server_pid() -> int:
    try:
        out = subprocess.run(["pgrep", "-f", "codeymccodeface"],
                             capture_output=True, text=True).stdout.split()
    except FileNotFoundError:
        pytest.skip("pgrep unavailable")
    if not out:
        pytest.skip("cannot locate the server process to count descriptors")
    return int(out[0])


def _open_fd_count(pid: int) -> int:
    # Linux (the CI image) exposes the descriptor table directly; it is both
    # exact and always present, unlike lsof.  macOS has no /proc, so fall back.
    fd_dir = os.path.join("/proc", str(pid), "fd")
    if os.path.isdir(fd_dir):
        try:
            return len(os.listdir(fd_dir))
        except OSError:
            pytest.skip("cannot read /proc/<pid>/fd")
    try:
        proc = subprocess.run(["lsof", "-p", str(pid)], capture_output=True, text=True)
    except FileNotFoundError:
        pytest.skip("no /proc and lsof unavailable")
    if proc.returncode != 0 or not proc.stdout:
        pytest.skip("lsof unavailable")
    return len(proc.stdout.splitlines())


def test_malformed_range_header_does_not_leak_descriptor(server):
    """
    handle_get_request opened the file before parsing the Range header, and
    parse_range_header throws a 416 on a malformed one.  Every such request
    leaked the descriptor, so a client could exhaust the process file table.
    """
    pid = _server_pid()

    request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: " + SERVER_HOSTNAME.encode() + b"\r\n"
        b"Range: bytes=not-a-range\r\n"
        b"Connection: close\r\n\r\n"
    )
    assert _status(_request(request)) == 416

    baseline = _open_fd_count(pid)
    for _ in range(60):
        _request(request)
    after = _open_fd_count(pid)

    # A handful of descriptors may legitimately move around (accepted sockets in
    # TIME_WAIT, the ip-ban log); a leak shows up as roughly one per request.
    assert after - baseline < 20, (
        f"open descriptors grew from {baseline} to {after} over 60 bad-Range requests"
    )


def test_transfer_encoding_is_rejected(server):
    """
    Chunked request bodies are not decoded anywhere in this server.  Accepting
    the header left the chunk data in the read buffer, where it was parsed as a
    pipelined request -- classic request smuggling.
    """
    smuggled = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + SERVER_HOSTNAME.encode() + b"\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"0\r\n\r\n"
        b"GET /smuggled HTTP/1.1\r\n"
        b"Host: " + SERVER_HOSTNAME.encode() + b"\r\n\r\n"
    )
    response = _request(smuggled)
    assert _status(response) == 501
    # exactly one response: the smuggled request must not be answered
    assert response.count(b"HTTP/1.1 ") == 1, "smuggled request produced a second response"


@pytest.mark.parametrize("host", ["..", "../..", "/etc", "../../../../etc"])
def test_host_header_cannot_escape_the_webroot(server, host):
    """
    The Host header is joined straight onto the webroot.  An absolute or
    dot-dot host used to canonicalise outside it, and the containment check
    walked off the end of the shorter path while comparing.
    """
    request = (
        b"GET /passwd HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Connection: close\r\n\r\n"
    )
    response = _request(request)
    assert _status(response) in (403, 404), f"unexpected status for Host: {host}"
    assert server.poll() is None
