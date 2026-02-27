"""
pytest configuration for the integration test suite.

The tests always connect to an already-running server; they never start one
themselves.  The default target is localhost:8443.

Usage examples:
    python3 -m pytest tests/ -v                        # target localhost:8443
    python3 -m pytest tests/ -v --server=localhost:443 # different port
    make test                                          # same as first line
"""

import os
import socket
import time

import pytest

_DEFAULT_SERVER = "localhost:8443"


# ── CLI option ─────────────────────────────────────────────────────────────────

def pytest_addoption(parser):
    parser.addoption(
        "--server",
        action="store",
        default=_DEFAULT_SERVER,
        help=f"host:port of the running server under test (default: {_DEFAULT_SERVER})",
    )


def pytest_configure(config):
    """Set TEST_HOST / TEST_HTTPS_PORT env vars before test modules are imported."""
    addr = config.getoption("--server", default=_DEFAULT_SERVER)
    host, _, port = addr.rpartition(":")
    if not host:
        host = "127.0.0.1"
    os.environ["TEST_HOST"]       = host
    os.environ["TEST_HTTPS_PORT"] = port


# ── Helpers ────────────────────────────────────────────────────────────────────

def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    """Return True once the port accepts TCP connections, False on timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=0.5)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


class _Server:
    """
    Represents the externally-managed server under test.
    poll() probes the TCP port so tests can call ``server.poll() is None``
    to check whether the server is still alive (None) or has crashed (-1).
    """
    def __init__(self, host: str, port: int) -> None:
        self._host = host
        self._port = port

    def poll(self):
        try:
            s = socket.create_connection((self._host, self._port), timeout=0.5)
            s.close()
            return None     # alive
        except OSError:
            return -1       # crashed / not reachable


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def server(request):
    """
    Verify the target server is reachable, then yield a _Server object.
    Tests use server.poll() to check whether the process is still alive.
    """
    addr = request.config.getoption("--server")
    host, _, port_str = addr.rpartition(":")
    if not host:
        host = "127.0.0.1"
    port = int(port_str)

    if not _wait_for_port(host, port):
        pytest.fail(
            f"Server not reachable at {host}:{port} — start it before running tests"
        )

    yield _Server(host, port)


@pytest.fixture
def h2_conn(server):
    """Open a fresh TLS+HTTP/2 connection for each test and close it afterwards."""
    from helpers import make_h2_connection
    conn = make_h2_connection()
    yield conn
    try:
        conn.close()
    except Exception:
        pass
