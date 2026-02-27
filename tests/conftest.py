"""
pytest configuration: generates a self-signed test certificate, writes a
test server config, starts the server subprocess, and tears it down after
the session.

Directory layout created under tests/resources/:
  keypair/localhost/ecc_cert.pem
  keypair/localhost/ecc_key.pem
  webpages/localhost/index.html
  ip_ban.txt

The test config (tests/test_config.txt) uses paths relative to its own
location, so global.cpp's relative_to() resolves them correctly regardless
of the working directory.

CLI options
-----------
--server-binary  : path to the binary to start (default: target/codeymccodeface)
--server-port    : HTTPS port to connect to (default: 19443)
--no-start-server: skip launching a binary; connect to an already-running server
                   (combine with --server-port to target e.g. localhost:8443)

Example — crash the unfixed main-branch server already running on port 8443:

    python3 -m pytest tests/ -v --no-start-server --server-port=8443
"""

import os
import socket
import subprocess
import time

import pytest

# ── Paths ──────────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

SERVER_BINARY    = os.path.join(_ROOT, "target", "codeymccodeface")
TEST_CONFIG_PATH = os.path.join(_HERE, "test_config.txt")
TEST_RESOURCES   = os.path.join(_HERE, "resources")

TEST_DOMAIN      = "localhost"
TEST_HTTPS_PORT  = 19443          # default; overridden by --server-port
TEST_HTTP_PORT   = 19080


# ── CLI options ────────────────────────────────────────────────────────────────

def pytest_addoption(parser):
    parser.addoption(
        "--server-binary",
        action="store",
        default=None,
        help=(
            "Path to the server binary under test.  "
            "Defaults to target/codeymccodeface in the repo root.  "
            "Pass a main-branch binary here to verify that the pre-fix "
            "crashes are detected."
        ),
    )
    parser.addoption(
        "--server-port",
        action="store",
        default=None,
        help=(
            "HTTPS port to connect to (default: 19443).  "
            "When --no-start-server is also passed this lets you target an "
            "already-running server on a non-default port."
        ),
    )
    parser.addoption(
        "--no-start-server",
        action="store_true",
        default=False,
        help=(
            "Do not launch a server subprocess.  Instead, connect to a server "
            "that is already running on --server-port (default 19443).  "
            "Use this to run the crash tests against a live main-branch server."
        ),
    )


def pytest_configure(config):
    """Propagate --server-port to helpers.py via env var before test collection."""
    port = config.getoption("--server-port", default=None)
    if port is not None:
        os.environ["TEST_HTTPS_PORT"] = str(port)


# ── Resource setup ─────────────────────────────────────────────────────────────

def _setup_resources() -> None:
    """Create test resource tree and generate a self-signed ECC certificate."""
    keypair_dir  = os.path.join(TEST_RESOURCES, "keypair", TEST_DOMAIN)
    webpages_dir = os.path.join(TEST_RESOURCES, "webpages", TEST_DOMAIN)
    os.makedirs(keypair_dir,  exist_ok=True)
    os.makedirs(webpages_dir, exist_ok=True)

    cert_path = os.path.join(keypair_dir, "ecc_cert.pem")
    key_path  = os.path.join(keypair_dir, "ecc_key.pem")

    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        result = subprocess.run(
            [
                "openssl", "req", "-x509",
                "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:P-256",
                "-days", "3650",
                "-nodes",
                "-keyout", key_path,
                "-out",    cert_path,
                "-subj",   f"/CN={TEST_DOMAIN}",
            ],
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"openssl certificate generation failed:\n{result.stderr.decode()}"
            )

    index_html = os.path.join(webpages_dir, "index.html")
    if not os.path.exists(index_html):
        with open(index_html, "w") as fh:
            fh.write("<html><body>test</body></html>\n")

    ip_ban = os.path.join(TEST_RESOURCES, "ip_ban.txt")
    open(ip_ban, "a").close()   # create if missing

    # Write test_config.txt next to this file.
    # All paths below are relative to the config file's directory (tests/).
    # global.cpp's relative_to() resolves them accordingly.
    config = (
        f"REDIRECT_PORT={TEST_HTTP_PORT}\n"
        f"SERVER_PORT={TEST_HTTPS_PORT}\n"
        f"KEY_FOLDER=resources/keypair\n"
        f"CERTIFICATE_FILE=ecc_cert.pem\n"
        f"KEY_FILE=ecc_key.pem\n"
        f"WEBPAGE_FOLDER=resources/webpages\n"
        f"DEFAULT_SUBFOLDER={TEST_DOMAIN}\n"
        f"TLD_FILE=../resources/tld.txt\n"
        f"MIME_FOLDER=../resources/MIME\n"
        f"HTTP_STRICT_TRANSPORT_SECURITY=false\n"
        f"IP_BAN_PATH=resources/ip_ban.txt\n"
    )
    with open(TEST_CONFIG_PATH, "w") as fh:
        fh.write(config)


def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
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


# ── External-server shim ───────────────────────────────────────────────────────

class _ExternalServer:
    """
    Drop-in replacement for subprocess.Popen used when --no-start-server is
    given.  Tests call server.poll() to check whether the server is still
    alive; here we probe the port rather than a process exit code.

    Returns None  (alive)   if a TCP connection to the port succeeds.
    Returns -1    (dead)    if the connection is refused / times out.
    """
    def __init__(self, port: int) -> None:
        self._port = port

    def poll(self):
        try:
            s = socket.create_connection(("127.0.0.1", self._port), timeout=0.5)
            s.close()
            return None
        except OSError:
            return -1

    def terminate(self): pass
    def kill(self):      pass


# ── Session-scoped server fixture ──────────────────────────────────────────────

@pytest.fixture(scope="session")
def server(request):
    """
    Start the HTTPS server with the test configuration, or connect to one that
    is already running (when --no-start-server is given).

    The fixture yields an object whose .poll() method returns None while the
    server is alive and non-None once it has crashed, allowing individual tests
    to assert ``server.poll() is None``.

    Typical usage:
        make test                                  # test the bugs-branch binary
        pytest tests/ --server-binary=<path>       # test an arbitrary binary
        pytest tests/ --no-start-server            # target server on port 19443
        pytest tests/ --no-start-server \\
                      --server-port=8443           # target server on port 8443
    """
    port      = int(request.config.getoption("--server-port") or TEST_HTTPS_PORT)
    no_start  = request.config.getoption("--no-start-server")
    binary    = request.config.getoption("--server-binary") or SERVER_BINARY

    if no_start:
        if not _wait_for_port("127.0.0.1", port, timeout=5.0):
            pytest.fail(
                f"--no-start-server: no server found on 127.0.0.1:{port} "
                f"(is the server running?)"
            )
        yield _ExternalServer(port)
        return

    _setup_resources()

    proc = subprocess.Popen(
        [binary, "--config", TEST_CONFIG_PATH],
        cwd=_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,     # capture stderr to aid debugging on failure
    )

    if not _wait_for_port("127.0.0.1", port, timeout=15.0):
        proc.terminate()
        _, err = proc.communicate(timeout=5)
        pytest.fail(
            f"Server did not start within 15 s.\n"
            f"stderr: {err.decode(errors='replace')}"
        )

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ── Per-test HTTP/2 connection fixture ────────────────────────────────────────

@pytest.fixture
def h2_conn(server):
    """
    Open a fresh TLS+HTTP/2 connection for each test and close it afterwards.
    Importing here avoids a circular dependency at module-collection time.
    """
    from helpers import make_h2_connection
    conn = make_h2_connection()
    yield conn
    try:
        conn.close()
    except Exception:
        pass
