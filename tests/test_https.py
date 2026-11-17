"""HTTPS certificate validation with the Securden integration client.

Serves the real app over TLS with mandatory client certificates (uvicorn's
TLS stack stands in for Caddy here; tests/test_caddy.py exercises Caddy
itself when the binary is available). OPA is mocked: this file is about the
transport, not decisions.
"""

from __future__ import annotations

import socket
import ssl
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from app.main import create_app

from .helpers import TOKENS
from .test_opa_failures import GOOD_DECISION

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
sys.path.insert(0, str(ROOT / "scripts"))

pytest.importorskip("cryptography")
import gen_certs  # noqa: E402
from securden_opm_client import OpmClient, OpmError, OpmRequestError, RetryPolicy  # noqa: E402


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    good = tmp_path_factory.mktemp("pki")
    gen_certs.main(["--out", str(good), "--dns", "opm.test", "--ip", "127.0.0.1", "--client-cn", "securden-test"])
    rogue = tmp_path_factory.mktemp("rogue")  # unrelated CA + client cert
    gen_certs.main(["--out", str(rogue), "--dns", "opm.test", "--ip", "127.0.0.1", "--client-cn", "intruder"])
    return good, rogue


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def tls_server(pki, tmp_path_factory, clients_file):
    from .conftest import make_settings

    good, _ = pki
    tmp = tmp_path_factory.mktemp("tlsapp")

    def handler(request):
        if request.url.path == "/health":
            return httpx.Response(200, json={})
        return httpx.Response(200, json={"result": {"bundle_version": GOOD_DECISION["bundle_version"],
                                                    "opa_version": "1.4.2"}})

    app = create_app(make_settings(tmp, clients_file, "http://opa.invalid"), opa_transport=httpx.MockTransport(handler))
    port = _free_port()
    config = uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="error",
        ssl_certfile=str(good / "server.crt"), ssl_keyfile=str(good / "server.key"),
        ssl_ca_certs=str(good / "client-ca.crt"), ssl_cert_reqs=ssl.CERT_REQUIRED,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started
    yield port
    server.should_exit = True
    thread.join(timeout=10)


def make_client(port, ca, cert=None, host="127.0.0.1", token=None):
    return OpmClient(
        base_url=f"https://{host}:{port}", token=token or TOKENS["securden-a"], ca_bundle=ca,
        client_cert=cert, retry=RetryPolicy(max_attempts=1), timeout_seconds=5,
    )


def test_valid_chain_and_client_cert(tls_server, pki):
    good, _ = pki
    with make_client(tls_server, good / "ca.crt", (good / "client.crt", good / "client.key")) as c:
        assert c.health() == {"status": "ok"}
        v = c.version()
        assert v["policy_versions_consistent"] is True


def test_untrusted_server_certificate_rejected(tls_server, pki):
    good, rogue = pki
    with make_client(tls_server, rogue / "ca.crt", (good / "client.crt", good / "client.key")) as c:
        with pytest.raises(OpmError) as exc:
            c.health()
    assert exc.value.code == "TLS_VERIFICATION_FAILED"


def test_hostname_mismatch_rejected(tls_server, pki):
    good, _ = pki
    # Certificate covers opm.test and 127.0.0.1 only, not "localhost".
    with make_client(tls_server, good / "ca.crt", (good / "client.crt", good / "client.key"), host="localhost") as c:
        with pytest.raises(OpmError) as exc:
            c.health()
    assert exc.value.code == "TLS_VERIFICATION_FAILED"


def test_missing_client_certificate_rejected(tls_server, pki):
    good, _ = pki
    with make_client(tls_server, good / "ca.crt") as c:
        with pytest.raises(OpmError):
            c.health()


def test_client_certificate_from_untrusted_ca_rejected(tls_server, pki):
    good, rogue = pki
    with make_client(tls_server, good / "ca.crt", (rogue / "client.crt", rogue / "client.key")) as c:
        with pytest.raises(OpmError):
            c.health()


def test_mtls_alone_is_not_enough(tls_server, pki):
    good, _ = pki
    with make_client(tls_server, good / "ca.crt", (good / "client.crt", good / "client.key"),
                     token="securden-a.not-the-secret") as c:
        with pytest.raises(OpmRequestError) as exc:
            c.version()
    assert exc.value.status_code == 401


def test_client_refuses_insecure_configuration(pki):
    good, _ = pki
    with pytest.raises(ValueError):
        OpmClient(base_url="http://127.0.0.1:1", token="x.y", ca_bundle=good / "ca.crt")
    with pytest.raises(ValueError):
        OpmClient(base_url="https://127.0.0.1:1", token="x.y", ca_bundle=False)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        OpmClient(base_url="https://127.0.0.1:1", token="x.y", ca_bundle="")
