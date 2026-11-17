"""Batch evaluation (real OPA)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from .helpers import account, auth, item, recent_period, rotation

pytestmark = pytest.mark.opa

START, END = recent_period()
P = (START, END)


def test_large_batch(client):
    items = []
    for n in range(100):
        records = [rotation(n * 1000 + i, rotated_at=END - timedelta(days=(i * 7) % 120)) for i in range(100)]
        items.append(item("PAM-ROTATION-001", "credential_rotation", records, period=P, item_reference=f"item-{n}"))
    r = client.post("/api/v1/evaluate/batch", json={"tenant_id": "tenant-a", "items": items}, headers=auth())
    assert r.status_code == 200, r.text[:500]
    body = r.json()
    assert body["summary"]["total"] == 100 and body["summary"]["succeeded"] == 100
    assert [x["index"] for x in body["results"]] == list(range(100))
    assert all(x["result"]["item_reference"] == f"item-{x['index']}" for x in body["results"])
    assert all(x["result"]["evidence_completeness"]["evaluated_record_count"] == 100 for x in body["results"])
    # every item: ages 0..119 days in steps of 7 => some > 90 => FAIL
    assert body["summary"]["by_status"] == {"FAIL": 100}


def test_batch_isolates_item_errors(client):
    good = item("PAM-ROTATION-001", "credential_rotation", [rotation(1, rotated_at=END)], period=P)
    wrong_type = item("PAM-ROTATION-001", "privileged_account",
                      [account(1, created=START, last_used=None)], period=P)
    unknown = item("PAM-UNKNOWN-001", "credential_rotation", [rotation(1, rotated_at=END)], period=P)
    r = client.post("/api/v1/evaluate/batch", headers=auth(),
                    json={"tenant_id": "tenant-a", "items": [good, wrong_type, unknown, good]})
    body = r.json()
    assert body["summary"] == {"total": 4, "succeeded": 2, "failed": 2, "by_status": {"PASS": 2}}
    assert body["results"][1]["error"]["code"] == "EVIDENCE_TYPE_MISMATCH"
    assert body["results"][2]["error"]["code"] == "RULE_NOT_FOUND"


def test_batch_limits(tmp_path, clients_file, opa_url):
    from fastapi.testclient import TestClient

    from app.main import create_app

    from .conftest import make_settings

    one = item("PAM-ROTATION-001", "credential_rotation", [rotation(i, rotated_at=END) for i in range(5)], period=P)
    app = create_app(make_settings(tmp_path, clients_file, opa_url, max_batch_items=3, max_batch_total_records=12))
    with TestClient(app) as c:
        r = c.post("/api/v1/evaluate/batch", json={"tenant_id": "tenant-a", "items": [one] * 4}, headers=auth())
        assert r.status_code == 413 and "items" in r.json()["error"]["message"]
        r = c.post("/api/v1/evaluate/batch", json={"tenant_id": "tenant-a", "items": [one] * 3}, headers=auth())
        assert r.status_code == 413 and "records" in r.json()["error"]["message"]


def test_batch_is_tenant_scoped(client):
    one = item("PAM-ROTATION-001", "credential_rotation", [rotation(1, rotated_at=END)], period=P)
    r = client.post("/api/v1/evaluate/batch", json={"tenant_id": "tenant-b", "items": [one]}, headers=auth())
    assert r.status_code == 403
    one_with_tenant = {**one, "tenant_id": "tenant-b"}  # per-item tenant override is not allowed
    r = client.post("/api/v1/evaluate/batch", json={"tenant_id": "tenant-a", "items": [one_with_tenant]},
                    headers=auth())
    assert r.status_code == 422
