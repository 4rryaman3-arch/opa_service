"""Authentication, authorization, rate limits, request limits, headers.
These run without OPA (auth is checked before any policy call)."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.security import ApiKeyStore

from .helpers import TOKENS, auth


@pytest.fixture
def app_client(settings_factory):
    def make(**overrides):
        return TestClient(create_app(settings_factory(**overrides)))

    return make


def test_health_is_public_and_minimal(offline_client):
    r = offline_client.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


@pytest.mark.parametrize("path,method", [
    ("/api/v1/version", "get"), ("/api/v1/rules?tenant_id=tenant-a", "get"), ("/api/v1/metrics", "get"),
    ("/api/v1/evaluate", "post"), ("/api/v1/evaluate/batch", "post"), ("/api/v1/rules/validate", "post"),
    ("/api/v1/rules/test", "post"), ("/api/v1/rules/custom", "post"),
])
def test_all_non_health_endpoints_require_auth(offline_client, path, method):
    r = getattr(offline_client, method)(path, **({"json": {}} if method == "post" else {}))
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"
    assert r.json()["error"]["code"] == "UNAUTHENTICATED"


@pytest.mark.parametrize("header", [
    "Bearer nonsense", "Bearer securden-a.wrong-secret", "Basic dXNlcjpwYXNz", "securden-a", "Bearer ",
    "Bearer unknown-key.abcdef",
])
def test_invalid_credentials(offline_client, header):
    assert offline_client.get("/api/v1/version", headers={"Authorization": header}).status_code == 401


def test_disabled_key_rejected(offline_client):
    assert offline_client.get("/api/v1/version", headers=auth("disabled-a")).status_code == 401


def test_scope_enforced(offline_client):
    r = offline_client.post("/api/v1/evaluate", json={}, headers=auth("readonly-a"))
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"


def test_tenant_authorization_before_validation(offline_client):
    r = offline_client.post("/api/v1/rules/validate", json={"tenant_id": "tenant-b", "rule": {}}, headers=auth())
    assert r.status_code == 403 and r.json()["error"]["code"] == "TENANT_FORBIDDEN"


def test_rate_limit_per_client(app_client):
    with app_client(rate_limit_burst=3, rate_limit_per_minute=1) as c:
        codes = [c.get("/api/v1/metrics", headers=auth()).status_code for _ in range(4)]
        assert codes == [200, 200, 200, 429]
        r = c.get("/api/v1/metrics", headers=auth())
        assert int(r.headers["retry-after"]) >= 1
        # Other clients are unaffected.
        assert c.get("/api/v1/metrics", headers=auth("securden-b")).status_code == 200


def test_auth_failure_throttling(app_client):
    with app_client(auth_failure_limit_per_minute=3) as c:
        codes = [c.get("/api/v1/version", headers={"Authorization": "Bearer x.y"}).status_code for _ in range(5)]
        assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]


def test_body_size_limit(app_client):
    with app_client(max_body_bytes=2048) as c:
        r = c.post("/api/v1/evaluate", content=b"{" + b" " * 4096 + b"}", headers={
            **auth(), "Content-Type": "application/json"})
        assert r.status_code == 413 and r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"

        def chunks():  # no Content-Length: enforced while streaming
            for _ in range(10):
                yield b" " * 1024

        r = c.post("/api/v1/evaluate", content=chunks(), headers={**auth(), "Content-Type": "application/json"})
        assert r.status_code == 413


def test_security_headers_and_correlation_id(offline_client):
    r = offline_client.get("/health", headers={"X-Correlation-ID": "securden-abc12345"})
    assert r.headers["x-correlation-id"] == "securden-abc12345"
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"
    bad = offline_client.get("/health", headers={"X-Correlation-ID": "<script>"})
    assert bad.headers["x-correlation-id"].startswith("opm-")


def test_docs_disabled_by_default(offline_client):
    assert offline_client.get("/docs").status_code == 404
    assert offline_client.get("/openapi.json").status_code == 404


def test_secrets_not_logged(app_client, capsys):
    with app_client(log_level="INFO") as c:
        c.get("/api/v1/version", headers={"Authorization": "Bearer securden-a.super-secret-value"})
        c.post("/api/v1/evaluate", headers=auth(), json={"tenant_id": "tenant-a", "secret_marker": "hunter2-xyz"})
    out = capsys.readouterr()
    text = out.out + out.err
    assert "super-secret-value" not in text
    assert TOKENS["securden-a"].split(".")[1] not in text
    assert "hunter2-xyz" not in text
    assert '"path": "/api/v1/evaluate"' in text  # access log present, sanitized


def test_key_store_rejects_bad_files(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"clients": [{"key_id": "A!", "secret_sha256": "0" * 64}]}))
    with pytest.raises(RuntimeError):
        ApiKeyStore.from_file(p)
    p.write_text(json.dumps({"clients": [{"key_id": "abc", "secret_sha256": "0" * 64, "scopes": ["root"]}]}))
    with pytest.raises(RuntimeError):
        ApiKeyStore.from_file(p)
    with pytest.raises(RuntimeError):
        ApiKeyStore.from_file(tmp_path / "missing.json")


def test_refuses_to_start_without_opa_token(settings_factory):
    with pytest.raises(RuntimeError):
        create_app(settings_factory(opa_token="short"))
