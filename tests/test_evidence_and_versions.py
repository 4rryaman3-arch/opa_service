"""Evidence validation, time-zone normalisation, historical/version semantics,
determinism and policy-version consistency (real OPA)."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from .helpers import auth, recent_period, request, rotation, session, z

pytestmark = pytest.mark.opa

START, END = recent_period()
P = (START, END)


def post(client, body, key="securden-a"):
    return client.post("/api/v1/evaluate", json=body, headers=auth(key))


def base(records=None, **kw):
    return request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                   records if records is not None else [rotation(1, rotated_at=END - timedelta(days=95))],
                   period=P, **kw)


# ------------------------------------------------------------ malformed evidence


def test_duplicate_record_ids_rejected(client):
    rec = rotation(1, rotated_at=END)
    r = post(client, base([rec, dict(rec)]))
    assert r.status_code == 422
    assert "duplicate record_id" in r.text


def test_naive_timestamp_rejected(client):
    rec = rotation(1, rotated_at=END)
    rec["last_rotated_at"] = "2026-09-01T10:00:00"  # no offset
    r = post(client, base([rec]))
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"


def test_unknown_or_secret_fields_rejected_and_not_echoed(client):
    rec = rotation(1, rotated_at=END)
    rec["password"] = "hunter2-SyntheticSecret"
    r = post(client, base([rec]))
    assert r.status_code == 422
    assert "hunter2" not in r.text  # validation errors never echo input values


def test_string_numbers_and_bools_rejected(client):
    rec = rotation(1, rotated_at=END)
    rec["privileged"] = "true"
    assert post(client, base([rec])).status_code == 422


def test_received_count_must_match(client):
    body = base()
    body["evidence"]["completeness"]["received_record_count"] = 7
    r = post(client, body)
    assert r.status_code == 422
    assert "received_record_count" in r.text


def test_evidence_type_mismatch(client):
    body = request("tenant-a", "PAM-ROTATION-001", "privileged_session",
                   [session(1, started=START + timedelta(days=1))], period=P)
    r = post(client, body)
    assert r.status_code == 422 and r.json()["error"]["code"] == "EVIDENCE_TYPE_MISMATCH"


def test_evidence_after_period_end_rejected(client):
    r = post(client, base([rotation(1, rotated_at=END + timedelta(minutes=1))]))
    assert r.status_code == 422 and r.json()["error"]["code"] == "EVIDENCE_AFTER_PERIOD_END"
    assert r.json()["error"]["details"]["record_ids"] == ["rot-00001"]


def test_invalid_period(client):
    body = base()
    body["reporting_period"] = {"start": z(END), "end": z(START)}
    assert post(client, body).status_code == 422


def test_future_period_rejected(client):
    body = base()
    future = datetime.now(timezone.utc) + timedelta(days=2)
    body["reporting_period"] = {"start": z(future - timedelta(days=1)), "end": z(future)}
    r = post(client, body)
    assert r.status_code == 422 and r.json()["error"]["code"] == "PERIOD_IN_FUTURE"


@pytest.mark.parametrize("field", ["evaluated_at", "evaluation_id", "status", "principal", "authorized_tenants"])
def test_server_owned_fields_cannot_be_spoofed(client, field):
    body = base()
    body[field] = "2020-01-01T00:00:00Z"
    r = post(client, body)
    assert r.status_code == 422


def test_server_timestamp_is_server_generated(client):
    before = datetime.now(timezone.utc) - timedelta(seconds=5)
    res = post(client, base()).json()
    ts = datetime.strptime(res["evaluated_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    assert before <= ts <= datetime.now(timezone.utc) + timedelta(seconds=5)


def test_too_many_records(tmp_path, clients_file, opa_url):
    from fastapi.testclient import TestClient

    from app.main import create_app

    from .conftest import make_settings

    app = create_app(make_settings(tmp_path, clients_file, opa_url, max_records_per_evaluation=3))
    with TestClient(app) as c:
        r = post(c, base([rotation(i, rotated_at=END) for i in range(4)]))
        assert r.status_code == 413 and r.json()["error"]["code"] == "TOO_MANY_RECORDS"


# ------------------------------------------------------------ time zones & determinism


def test_timezone_normalisation_is_equivalent(client):
    ts = END - timedelta(days=95)
    utc = base([rotation(1, rotated_at=ts)])
    ist = copy.deepcopy(utc)
    ist["evidence"]["records"][0]["last_rotated_at"] = ts.astimezone(timezone(timedelta(hours=5, minutes=30))).isoformat()
    ist["reporting_period"]["end"] = END.astimezone(timezone(timedelta(hours=-7))).isoformat()
    a, b = post(client, utc).json(), post(client, ist).json()
    assert a["status"] == b["status"] == "FAIL"
    assert a["decision_details"]["input_digest"] == b["decision_details"]["input_digest"]
    assert b["reporting_period"]["end"].endswith("Z")


def test_deterministic_results_and_order_independence(client):
    records = [rotation(i, rotated_at=END - timedelta(days=i * 10)) for i in range(1, 15)]
    first = post(client, base(records)).json()
    second = post(client, base(list(reversed(records)))).json()
    for key in ("status", "violations", "metrics", "evidence_references", "evidence_completeness"):
        assert first[key] == second[key], key
    assert first["decision_details"]["input_digest"] == second["decision_details"]["input_digest"]
    assert first["evaluation_id"] != second["evaluation_id"]


# ------------------------------------------------------------ historical & versions

MARCH = (datetime(2026, 3, 1, tzinfo=timezone.utc), datetime(2026, 3, 31, tzinfo=timezone.utc))


def march_body(**kw):
    return request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                   [rotation(1, rotated_at=MARCH[1] - timedelta(days=5), status="FAILED")], period=MARCH, **kw)


def test_old_period_requires_historical_mode(client):
    r = post(client, march_body())
    assert r.status_code == 422 and r.json()["error"]["code"] == "HISTORICAL_MODE_REQUIRED"


def test_historical_requires_version_and_policy_context(client):
    r = post(client, march_body(evaluation_mode="HISTORICAL"))
    assert r.json()["error"]["code"] == "RULE_VERSION_REQUIRED"
    r = post(client, march_body(evaluation_mode="HISTORICAL", rule_version="1.0"))
    assert r.json()["error"]["code"] == "HISTORICAL_POLICY_CONTEXT_REQUIRED"


def test_historical_evaluation_uses_retired_version(client):
    settings = {"policy_version": "acme-pam-policy-2026.02", "effective_from": "2026-02-01T00:00:00Z"}
    r = post(client, march_body(evaluation_mode="HISTORICAL", rule_version="1.0", policy_settings=settings))
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["rule_version"] == "1.0"
    assert res["status"] == "PASS"  # v1.0 does not treat FAILED attempts as violations
    assert res["decision_details"]["evaluation_mode"] == "HISTORICAL"
    assert res["decision_details"]["customer_policy_version"] == "acme-pam-policy-2026.02"
    assert res["decision_details"]["policy_package"] == "securden.rules.pam_rotation_001.v1_0"


def test_historical_wrong_version_for_period(client):
    settings = {"policy_version": "p1", "effective_from": "2026-02-01T00:00:00Z"}
    r = post(client, march_body(evaluation_mode="HISTORICAL", rule_version="1.1", policy_settings=settings))
    assert r.status_code == 422 and r.json()["error"]["code"] == "RULE_VERSION_NOT_EFFECTIVE"


def test_policy_settings_must_cover_period(client):
    settings = {"policy_version": "p1", "effective_from": "2026-03-15T00:00:00Z"}
    r = post(client, march_body(evaluation_mode="HISTORICAL", rule_version="1.0", policy_settings=settings))
    assert r.status_code == 422 and r.json()["error"]["code"] == "POLICY_SETTINGS_NOT_EFFECTIVE"


def test_retired_version_rejected_in_current_mode(client):
    r = post(client, base(rule_version="1.0"))
    assert r.status_code in (409, 422)
    assert r.json()["error"]["code"] in ("RULE_NOT_ACTIVE", "RULE_VERSION_NOT_EFFECTIVE")


def test_unknown_rule_and_version(client):
    body = base()
    body["rule_id"] = "PAM-NOPE-001"
    assert post(client, body).status_code == 404
    assert post(client, base(rule_version="9.9")).json()["error"]["code"] == "RULE_VERSION_NOT_FOUND"


def test_policy_version_consistency(client):
    version = client.get("/api/v1/version", headers=auth()).json()
    assert version["policy_versions_consistent"] is True
    assert version["opa_version"]
    res = post(client, base()).json()
    assert res["policy_bundle_version"] == version["policy_bundle_version"] == version["catalog_bundle_version"]


def test_ready(client):
    r = client.get("/ready")
    assert r.status_code == 200
    assert r.json() == {"status": "ready", "checks": {"opa": "ok", "policy_bundle": "ok", "rule_store": "ok"}}


# ------------------------------------------------------------ tenant isolation


def test_tenant_isolation_on_evaluate(client):
    body = base()
    body["tenant_id"] = "tenant-b"
    r = post(client, body, key="securden-a")
    assert r.status_code == 403 and r.json()["error"]["code"] == "TENANT_FORBIDDEN"
    # Unknown tenant gets the same answer (no enumeration).
    body["tenant_id"] = "tenant-zzz"
    assert post(client, body, key="securden-a").json()["error"]["code"] == "TENANT_FORBIDDEN"


def test_tenant_isolation_on_rule_listing(client):
    r = client.get("/api/v1/rules", params={"tenant_id": "tenant-b"}, headers=auth("securden-a"))
    assert r.status_code == 403
