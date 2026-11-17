from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

from . import helpers

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "policy-bundle"
OPA_TOKEN = secrets.token_urlsafe(48)

CLIENTS = [
    ("securden-a", ["tenant-a"], ["evaluate", "rules:read", "rules:write", "rules:admin", "metrics:read"], True),
    ("securden-b", ["tenant-b"], ["evaluate", "rules:read", "rules:write", "rules:admin", "metrics:read"], True),
    ("readonly-a", ["tenant-a"], ["rules:read"], True),
    ("disabled-a", ["tenant-a"], ["evaluate"], False),
    ("catalog-sync", [], ["catalog:read"], True),
]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def opa_binary() -> str | None:
    return os.environ.get("OPM_TEST_OPA_BINARY") or shutil.which("opa")


@pytest.fixture(scope="session")
def clients_file(tmp_path_factory) -> Path:
    path = tmp_path_factory.mktemp("secrets") / "api_clients.json"
    entries = []
    for key_id, tenants, scopes, enabled in CLIENTS:
        secret = secrets.token_urlsafe(32)
        helpers.TOKENS[key_id] = f"{key_id}.{secret}"
        entries.append({
            "key_id": key_id, "secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
            "tenants": tenants, "scopes": scopes, "enabled": enabled,
        })
    path.write_text(json.dumps({"clients": entries}), encoding="utf-8")
    return path


@pytest.fixture(scope="session")
def opa_url() -> str:
    binary = opa_binary()
    if not binary:
        pytest.skip("OPA binary not available (set OPM_TEST_OPA_BINARY)")
    port = _free_port()
    env = {**os.environ, "OPA_AUTH_TOKEN": OPA_TOKEN}
    proc = subprocess.Popen(
        [binary, "run", "--server", "--addr", f"127.0.0.1:{port}", "--authentication=token",
         # Relative path on purpose: OPA parses "D:\..." as "<data prefix>:<path>".
         "--authorization=basic", "--log-level=error", "--disable-telemetry", BUNDLE.name],
        env=env, cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            if httpx.get(f"{url}/health", headers={"Authorization": f"Bearer {OPA_TOKEN}"}, timeout=1).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.2)
    else:
        proc.kill()
        raise RuntimeError("OPA did not start: " + (proc.stderr.read().decode() if proc.stderr else ""))
    yield url
    proc.terminate()
    proc.wait(timeout=10)


def make_settings(tmp_path: Path, clients_file: Path, opa_url: str, **overrides) -> Settings:
    values = dict(
        opa_url=opa_url,
        opa_token=OPA_TOKEN,
        policy_bundle_dir=BUNDLE,
        db_path=tmp_path / "opm.db",
        api_clients_file=clients_file,
        log_level="WARNING",
        trust_proxy_headers=False,
    )
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings_factory(tmp_path, clients_file):
    def factory(opa: str = "http://127.0.0.1:9", **overrides) -> Settings:
        return make_settings(tmp_path, clients_file, opa, **overrides)

    return factory


@pytest.fixture
def client(tmp_path, clients_file, opa_url):
    app = create_app(make_settings(tmp_path, clients_file, opa_url))
    with TestClient(app) as c:
        yield c


@pytest.fixture
def offline_client(tmp_path, clients_file):
    """App whose OPA endpoint is unreachable (nothing listens on the port)."""
    app = create_app(make_settings(tmp_path, clients_file, f"http://127.0.0.1:{_free_port()}",
                                   opa_connect_timeout_seconds=0.5))
    with TestClient(app) as c:
        yield c
