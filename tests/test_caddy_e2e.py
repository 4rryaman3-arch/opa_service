"""End-to-end through the production edge config:
OpmClient -> Caddy (deploy/Caddyfile, TLS + mTLS) -> uvicorn/FastAPI -> OPA.

Requires both OPA and Caddy binaries (OPM_TEST_OPA_BINARY, OPM_TEST_CADDY_BINARY).
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest
import uvicorn

from app.main import create_app

from .helpers import TOKENS, item, recent_period, rotation

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
sys.path.insert(0, str(ROOT / "scripts"))

pytestmark = [pytest.mark.opa, pytest.mark.caddy]
pytest.importorskip("cryptography")
import gen_certs  # noqa: E402
from securden_opm_client import OpmClient, OpmError, RetryPolicy  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def edge(tmp_path_factory, clients_file, opa_url):
    caddy = os.environ.get("OPM_TEST_CADDY_BINARY") or shutil.which("caddy")
    if not caddy:
        pytest.skip("Caddy binary not available (set OPM_TEST_CADDY_BINARY)")
    from .conftest import make_settings

    pki = tmp_path_factory.mktemp("edge-pki")
    gen_certs.main(["--out", str(pki), "--dns", "opm.test", "--ip", "127.0.0.1", "--client-cn", "securden-e2e"])

    api_port, edge_port = _free_port(), _free_port()
    app = create_app(make_settings(tmp_path_factory.mktemp("edge-app"), clients_file, opa_url))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=api_port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)

    env = {**os.environ, "OPM_CERT_DIR": str(pki).replace("\\", "/"), "OPM_UPSTREAM": f"127.0.0.1:{api_port}",
           "OPM_LISTEN_PORT": str(edge_port), "OPM_TLS_SERVER_NAME": "opm.test", "OPM_MAX_BODY_SIZE": "1MB"}
    proc = subprocess.Popen([caddy, "run", "--config", str(ROOT / "deploy" / "Caddyfile"), "--adapter", "caddyfile"],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", edge_port), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail("caddy did not start")
    yield pki, edge_port
    proc.terminate()
    proc.wait(timeout=10)
    server.should_exit = True
    thread.join(timeout=10)


def _client(port, pki, cert=True):
    return OpmClient(
        base_url=f"https://127.0.0.1:{port}", token=TOKENS["securden-a"], ca_bundle=pki / "ca.crt",
        client_cert=(pki / "client.crt", pki / "client.key") if cert else None,
        retry=RetryPolicy(max_attempts=1), timeout_seconds=10,
    )


def test_full_https_evaluation_through_caddy(edge):
    pki, port = edge
    start, end = recent_period()
    with _client(port, pki) as c:
        assert c.ready()["status"] == "ready"
        assert c.version()["policy_versions_consistent"] is True
        res = c.evaluate("tenant-a", item("PAM-ROTATION-001", "credential_rotation",
                                          [rotation(1, rotated_at=end - timedelta(days=95))], period=(start, end)))
        assert res["status"] == "FAIL"
        batch = c.evaluate_batch("tenant-a", [item("PAM-ROTATION-001", "credential_rotation",
                                                   [rotation(i, rotated_at=end)], period=(start, end))
                                              for i in range(7)], chunk_size=3)
        assert [r["index"] for r in batch] == list(range(7))
        assert all(r["ok"] and r["result"]["status"] == "PASS" for r in batch)


def test_caddy_requires_client_certificate(edge):
    pki, port = edge
    with _client(port, pki, cert=False) as c:
        with pytest.raises(OpmError):
            c.health()


def test_caddy_enforces_body_limit(edge):
    import httpx
    import ssl

    pki, port = edge
    ctx = ssl.create_default_context(cafile=str(pki / "ca.crt"))
    ctx.load_cert_chain(str(pki / "client.crt"), str(pki / "client.key"))
    url = f"https://127.0.0.1:{port}/api/v1/evaluate"
    headers = {"Authorization": f"Bearer {TOKENS['securden-a']}", "Content-Type": "application/json"}
    # Under the 1MB edge limit: reaches the API (which rejects the junk as 422).
    assert httpx.post(url, content=b"x" * 1000, headers=headers, verify=ctx).status_code == 422
    # Over the limit: Caddy answers 413 or aborts the upload (connection reset).
    try:
        r = httpx.post(url, content=b"x" * (2 * 1024 * 1024), headers=headers, verify=ctx)
        assert r.status_code == 413
    except (httpx.ReadError, httpx.WriteError, httpx.RemoteProtocolError):
        pass


def test_no_plain_http(edge):
    import httpx

    _, port = edge
    with pytest.raises(httpx.HTTPError):
        r = httpx.get(f"http://127.0.0.1:{port}/health", timeout=3)
        assert r.status_code >= 400  # Caddy answers plain HTTP on a TLS port with 400
        raise httpx.HTTPError("plain http rejected")
