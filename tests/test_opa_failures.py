"""Fail-secure behaviour when OPA is down, slow, or returns bad decisions.
No case may ever produce a PASS."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app

from .conftest import BUNDLE
from .helpers import auth, item, recent_period, request, rotation

START, END = recent_period()
BUNDLE_VERSION = json.loads((BUNDLE / "securden" / "bundle" / "data.json").read_text(encoding="utf-8"))["version"]
BODY = request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
               [rotation(1, rotated_at=END - timedelta(days=1))], period=(START, END))

GOOD_DECISION = {
    "rule_id": "PAM-ROTATION-001", "rule_version": "1.1", "bundle_version": BUNDLE_VERSION,
    "status": "PASS", "summary": "ok", "metrics": {}, "violations": [], "violation_count": 0, "tolerance": 0,
    "excepted": [], "undetermined": [], "in_scope_record_count": 1, "evaluated_record_count": 1,
    "completeness": {"complete": True, "gaps": [], "expected_record_count": 1, "received_record_count": 1},
    "as_of": "x",
}


def mocked(settings_factory, handler, **overrides):
    return TestClient(create_app(settings_factory("http://opa.invalid", **overrides),
                                 opa_transport=httpx.MockTransport(handler)))


def respond(payload, status=200):
    def handler(request: httpx.Request):
        if request.url.path == "/health":
            return httpx.Response(200, json={})
        return httpx.Response(status, json=payload)

    return handler


def test_opa_unreachable_returns_503(offline_client):
    r = offline_client.post("/api/v1/evaluate", json=BODY, headers=auth())
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "POLICY_ENGINE_UNAVAILABLE"
    assert "status" not in r.json()


def test_ready_fails_when_opa_down(offline_client):
    r = offline_client.get("/ready")
    assert r.status_code == 503 and r.json()["checks"]["opa"] == "fail"


def test_batch_items_error_when_opa_down(offline_client):
    batch = {"tenant_id": "tenant-a", "items": [item("PAM-ROTATION-001", "credential_rotation",
                                                     [rotation(1, rotated_at=END)], period=(START, END))] * 3}
    r = offline_client.post("/api/v1/evaluate/batch", json=batch, headers=auth())
    assert r.status_code == 200
    body = r.json()
    assert body["summary"] == {"total": 3, "succeeded": 0, "failed": 3, "by_status": {}}
    assert all(x["error"]["code"] == "POLICY_ENGINE_UNAVAILABLE" and x["result"] is None for x in body["results"])


def test_control_check_sanity(settings_factory):
    with mocked(settings_factory, respond({"result": GOOD_DECISION})) as c:
        r = c.post("/api/v1/evaluate", json=BODY, headers=auth())
        assert r.status_code == 200 and r.json()["status"] == "PASS"


@pytest.mark.parametrize("payload,status,code", [
    ({}, 200, "POLICY_DECISION_UNDEFINED"),
    ({"result": None}, 200, "POLICY_DECISION_INVALID"),
    ({"result": {"status": "PASS"}}, 200, "POLICY_DECISION_INVALID"),
    ({"result": {**GOOD_DECISION, "status": "MAYBE"}}, 200, "POLICY_DECISION_INVALID"),
    ({"result": {**GOOD_DECISION, "bundle_version": "evil-1"}}, 200, "POLICY_VERSION_MISMATCH"),
    ({"result": {**GOOD_DECISION, "rule_version": "1.0"}}, 200, "POLICY_DECISION_INCONSISTENT"),
    ({"result": {**GOOD_DECISION, "evaluated_record_count": 0}}, 200, "POLICY_DECISION_INCONSISTENT"),
    ({"result": {**GOOD_DECISION, "violation_count": 1}}, 200, "POLICY_DECISION_INCONSISTENT"),
    ({"result": {**GOOD_DECISION, "status": "FAIL"}}, 200, "POLICY_DECISION_INCONSISTENT"),
    ({"result": {**GOOD_DECISION, "extra": 1}}, 200, "POLICY_DECISION_INVALID"),
    ({"code": "internal_error"}, 500, "POLICY_EVALUATION_FAILED"),
    ({"code": "unauthorized"}, 401, "POLICY_EVALUATION_FAILED"),
])
def test_bad_decisions_are_errors_not_pass(settings_factory, payload, status, code):
    with mocked(settings_factory, respond(payload, status)) as c:
        r = c.post("/api/v1/evaluate", json=BODY, headers=auth())
        assert r.status_code in (502, 503), r.text
        assert r.json()["error"]["code"] == code


def test_non_json_from_opa(settings_factory):
    with mocked(settings_factory, lambda req: httpx.Response(200, content=b"<html>")) as c:
        assert c.post("/api/v1/evaluate", json=BODY, headers=auth()).json()["error"]["code"] == "POLICY_EVALUATION_FAILED"


def test_opa_timeout(settings_factory):
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    with mocked(settings_factory, handler) as c:
        r = c.post("/api/v1/evaluate", json=BODY, headers=auth())
        assert r.status_code == 504 and r.json()["error"]["code"] == "POLICY_ENGINE_TIMEOUT"


def test_overall_evaluation_timeout(settings_factory):
    class Slow(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            await asyncio.sleep(2)
            return httpx.Response(200, json={"result": GOOD_DECISION})

    app = create_app(settings_factory("http://opa.invalid", evaluation_timeout_seconds=0.2), opa_transport=Slow())
    with TestClient(app) as c:
        r = c.post("/api/v1/evaluate", json=BODY, headers=auth())
        assert r.status_code == 504 and r.json()["error"]["code"] == "EVALUATION_TIMEOUT"


def test_ready_detects_bundle_version_mismatch(settings_factory):
    def handler(request):
        if request.url.path == "/health":
            return httpx.Response(200, json={})
        return httpx.Response(200, json={"result": {"bundle_version": "other", "opa_version": "1.4.2"}})

    with mocked(settings_factory, handler) as c:
        r = c.get("/ready")
        assert r.status_code == 503 and r.json()["checks"]["policy_bundle"] == "fail"


def test_opa_receives_token_and_no_secrets(settings_factory):
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"result": GOOD_DECISION})

    with mocked(settings_factory, handler) as c:
        c.post("/api/v1/evaluate", json=BODY, headers=auth())
    assert seen["auth"].startswith("Bearer ") and len(seen["auth"]) > 40
    assert set(seen["body"]["input"]) == {"rule", "reporting_period", "params", "evidence", "exceptions"}
    assert "tenant_id" not in json.dumps(seen["body"])  # tenant context never reaches policy input
