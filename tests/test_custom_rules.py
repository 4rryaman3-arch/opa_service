"""Customer-defined rules: validation, compilation, testing, lifecycle and
tenant isolation."""

from __future__ import annotations

import copy
from datetime import timedelta

import pytest

from app.engine.compiler import compile_rule

from .helpers import account, auth, exception_doc, item, recent_period, z

START, END = recent_period()
P = (START, END)

GOOD_RULE = {
    "rule_id": "CUST-ACME-DORMANT-001",
    "version": "1.0",
    "title": "Production admin accounts unused for 30 days",
    "description": "Stricter dormancy rule for production admins.",
    "severity": "HIGH",
    "evidence_type": "privileged_account",
    "subject_field": "account_id",
    "scope": {"all": [{"field": "enabled", "op": "eq", "value": True},
                      {"field": "scope_tags", "op": "contains", "value": "prod"}]},
    "violation_when": {"any": [
        {"field": "last_used_at", "op": "older_than_days", "value": 30},
        {"all": [{"field": "last_used_at", "op": "is_null"},
                 {"field": "created_at", "op": "older_than_days", "value": 30}]},
    ]},
    "tolerance": 0,
    "effective_from": "2025-01-01T00:00:00Z",
    "framework_mappings": [{"framework": "ISO27001:2022", "control": "8.2"}],
    "remediation": "Disable the account.",
}


def rule(**changes):
    r = copy.deepcopy(GOOD_RULE)
    r.update(changes)
    return r


def records():
    def tagged(rec, tags):
        rec["scope_tags"] = tags
        return rec

    return [
        tagged(account(1, created=END - timedelta(days=200), last_used=END - timedelta(days=5)), ["prod"]),
        tagged(account(2, created=END - timedelta(days=200), last_used=END - timedelta(days=31)), ["prod"]),
        tagged(account(3, created=END - timedelta(days=200), last_used=None), ["prod"]),
        tagged(account(4, created=END - timedelta(days=200), last_used=END - timedelta(days=60)), ["dev"]),
    ]


# ------------------------------------------------------------ compiler (no OPA needed)


def test_compiler_accepts_good_rule():
    res = compile_rule(GOOD_RULE)
    assert res.valid, res.errors
    v = res.compiled["violation"]
    assert v["mode"] == "any"
    assert v["conditions"][0] == {"id": "c1", "field": "last_used_at", "type": "datetime",
                                  "op": "older_than_days", "value": 30}
    assert v["groups"][0]["conditions"][0]["id"] == "g1.c1"
    assert res.warnings  # nullable field with older_than_days


def test_compiler_datetime_values_become_nanoseconds():
    res = compile_rule(rule(violation_when={"all": [
        {"field": "created_at", "op": "lt", "value": "2026-01-01T05:30:00+05:30"}]}))
    assert res.valid, res.errors
    assert res.compiled["violation"]["conditions"][0]["value"] == 1767225600 * 10**9


@pytest.mark.parametrize("changes,fragment", [
    ({"violation_when": {"all": [{"field": "password", "op": "eq", "value": "x"}]}}, "not allowed"),
    ({"violation_when": {"all": [{"field": "enabled", "op": "gt", "value": 1}]}}, "operator 'gt'"),
    ({"violation_when": {"all": [{"field": "enabled", "op": "eq", "value": "yes"}]}}, "boolean"),
    ({"violation_when": {"all": [{"field": "created_at", "op": "is_null"}]}}, "never null"),
    ({"violation_when": {"all": [{"field": "created_at", "op": "lt", "value": "2026-01-01T00:00:00"}]}}, "timezone"),
    ({"violation_when": {"all": [{"field": "last_used_at", "op": "older_than_days", "value": 99999}]}}, "days"),
    ({"violation_when": {"all": [{"field": "account_id", "op": "in", "value": []}]}}, "list"),
    ({"violation_when": {"all": [{"field": "account_id", "op": "eq", "value": "x\"; allow := true #"}]}}, "identifier"),
    ({"subject_field": "last_used_at"}, "subject_field"),
    ({"evidence_type": "raw_sql"}, "evidence_type"),
    ({"rule_id": "PAM-ROTATION-001"}, "rule_id"),
    ({"severity": "APOCALYPTIC"}, "severity"),
    ({"tolerance": -1}, "tolerance"),
    ({"rego": "package x"}, "rego"),
    ({"violation_when": {"all": [{"any": [{"all": [{"field": "enabled", "op": "eq", "value": True}]}]}]}}, ""),
    ({"violation_when": {"all": [{"field": "enabled", "op": "eq", "value": True}],
                         "any": [{"field": "enabled", "op": "eq", "value": True}]}}, "exactly one"),
    ({"violation_when": {"all": [{"field": "enabled", "op": "regex", "value": ".*"}]}}, "op"),
    ({"effective_to": "2024-01-01T00:00:00Z"}, "effective_to"),
])
def test_compiler_rejects_invalid_rules(changes, fragment):
    res = compile_rule(rule(**changes))
    assert not res.valid
    assert res.compiled is None
    text = repr(res.errors)
    assert fragment in text, text


def test_compiler_limits_condition_count():
    conds = [{"field": "enabled", "op": "eq", "value": True}] * 20
    res = compile_rule(rule(scope={"all": conds}, violation_when={"all": conds[:10]}))
    assert not res.valid and "at most 25" in repr(res.errors)


# ------------------------------------------------------------ API (real OPA)


@pytest.mark.opa
def test_validate_endpoint(client):
    r = client.post("/api/v1/rules/validate", json={"tenant_id": "tenant-a", "rule": GOOD_RULE}, headers=auth())
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True and body["activated"] is False
    assert body["definition_digest"].startswith("sha256:")
    bad = client.post("/api/v1/rules/validate", headers=auth(),
                      json={"tenant_id": "tenant-a", "rule": rule(severity="NOPE")}).json()
    assert bad["valid"] is False and bad["errors"]


@pytest.mark.opa
def test_test_endpoint_runs_draft_against_supplied_evidence(client):
    ev = item("CUST-ACME-DORMANT-001", "privileged_account", records(), period=P)
    body = {"tenant_id": "tenant-a", "rule": GOOD_RULE, "reporting_period": ev["reporting_period"],
            "evidence": ev["evidence"]}
    r = client.post("/api/v1/rules/test", json=body, headers=auth())
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["status"] == "FAIL"
    assert res["decision_details"]["rule_source"] == "DRAFT"
    assert res["decision_details"]["evaluation_mode"] == "TEST"
    found = {v["record_id"]: v["reasons"] for v in res["violations"]}
    assert found == {"pa-00002": ["c1"], "pa-00003": ["g1.c1", "g1.c2"]}  # pa-00004 is out of scope (dev)
    assert res["evidence_completeness"]["in_scope_record_count"] == 3
    # Not persisted / not activated:
    listed = client.get("/api/v1/rules", params={"tenant_id": "tenant-a"}, headers=auth()).json()
    assert listed["custom_rules"] == []


@pytest.mark.opa
def test_tolerance_threshold(client):
    ev = item("CUST-ACME-DORMANT-001", "privileged_account", records(), period=P)
    body = {"tenant_id": "tenant-a", "rule": rule(tolerance=2), "reporting_period": ev["reporting_period"],
            "evidence": ev["evidence"]}
    res = client.post("/api/v1/rules/test", json=body, headers=auth()).json()
    assert res["status"] == "PASS" and res["decision_details"]["violation_count"] == 2


@pytest.mark.opa
def test_test_endpoint_rejects_invalid_rule(client):
    ev = item("CUST-ACME-DORMANT-001", "privileged_account", records(), period=P)
    body = {"tenant_id": "tenant-a", "rule": rule(subject_field="nope"), "reporting_period": ev["reporting_period"],
            "evidence": ev["evidence"]}
    r = client.post("/api/v1/rules/test", json=body, headers=auth())
    assert r.status_code == 422 and r.json()["error"]["code"] == "RULE_INVALID"


@pytest.mark.opa
def test_custom_rule_lifecycle_and_tenant_isolation(client):
    create = client.post("/api/v1/rules/custom", json={"tenant_id": "tenant-a", "rule": GOOD_RULE}, headers=auth())
    assert create.status_code == 201, create.text
    assert create.json()["status"] == "DRAFT"

    # Versions are immutable.
    dup = client.post("/api/v1/rules/custom", json={"tenant_id": "tenant-a", "rule": GOOD_RULE}, headers=auth())
    assert dup.status_code == 409

    ev = {"tenant_id": "tenant-a", **item("CUST-ACME-DORMANT-001", "privileged_account", records(), period=P)}
    # Draft cannot be evaluated.
    assert client.post("/api/v1/evaluate", json=ev, headers=auth()).status_code == 404
    ev_v = {**ev, "rule_version": "1.0"}
    assert client.post("/api/v1/evaluate", json=ev_v, headers=auth()).json()["error"]["code"] == "RULE_NOT_ACTIVE"

    act = client.post("/api/v1/rules/custom/CUST-ACME-DORMANT-001/versions/1.0/activate",
                      json={"tenant_id": "tenant-a"}, headers=auth())
    assert act.status_code == 200 and act.json()["status"] == "ACTIVE"

    res = client.post("/api/v1/evaluate", json=ev, headers=auth()).json()
    assert res["status"] == "FAIL" and res["decision_details"]["rule_source"] == "CUSTOM"
    assert res["framework_mappings"] == [{"framework": "ISO27001:2022", "control": "8.2", "title": None}]

    # Exceptions apply to custom rules too.
    exc = exception_doc("ex-9", "CUST-ACME-DORMANT-001", ["acct-00002", "acct-00003"], START, END + timedelta(days=5))
    res = client.post("/api/v1/evaluate", json={**ev, "exceptions": [exc]}, headers=auth()).json()
    assert res["status"] == "PASS" and len(res["excepted"]) == 2

    # Tenant B cannot see or use tenant A's rule, even with its own valid credential.
    ev_b = {**ev, "tenant_id": "tenant-b"}
    rb = client.post("/api/v1/evaluate", json=ev_b, headers=auth("securden-b"))
    assert rb.status_code == 404 and rb.json()["error"]["code"] == "RULE_NOT_FOUND"
    listed_b = client.get("/api/v1/rules", params={"tenant_id": "tenant-b"}, headers=auth("securden-b")).json()
    assert listed_b["custom_rules"] == []
    hijack = client.post("/api/v1/rules/custom/CUST-ACME-DORMANT-001/versions/1.0/deactivate",
                         json={"tenant_id": "tenant-b"}, headers=auth("securden-b"))
    assert hijack.status_code == 404
    # ...and tenant B's key cannot address tenant A.
    cross = client.post("/api/v1/rules/custom/CUST-ACME-DORMANT-001/versions/1.0/deactivate",
                        json={"tenant_id": "tenant-a"}, headers=auth("securden-b"))
    assert cross.status_code == 403

    # New version activation deactivates the previous one.
    client.post("/api/v1/rules/custom", json={"tenant_id": "tenant-a", "rule": rule(version="1.1", tolerance=5)},
                headers=auth())
    client.post("/api/v1/rules/custom/CUST-ACME-DORMANT-001/versions/1.1/activate",
                json={"tenant_id": "tenant-a"}, headers=auth())
    listed = client.get("/api/v1/rules", params={"tenant_id": "tenant-a"}, headers=auth()).json()["custom_rules"]
    assert {(r["version"], r["status"]) for r in listed} == {("1.0", "INACTIVE"), ("1.1", "ACTIVE")}
    res = client.post("/api/v1/evaluate", json=ev, headers=auth()).json()
    assert res["rule_version"] == "1.1" and res["status"] == "PASS"


@pytest.mark.opa
def test_custom_rules_reject_parameters(client):
    client.post("/api/v1/rules/custom", json={"tenant_id": "tenant-a", "rule": GOOD_RULE}, headers=auth())
    client.post("/api/v1/rules/custom/CUST-ACME-DORMANT-001/versions/1.0/activate",
                json={"tenant_id": "tenant-a"}, headers=auth())
    ev = {"tenant_id": "tenant-a", **item("CUST-ACME-DORMANT-001", "privileged_account", records(), period=P),
          "policy_settings": {"parameters": {"dormant_after_days": 1}}}
    r = client.post("/api/v1/evaluate", json=ev, headers=auth())
    assert r.status_code == 422 and r.json()["error"]["code"] == "UNKNOWN_PARAMETER"


@pytest.mark.opa
def test_rule_admin_scope_required(client):
    r = client.post("/api/v1/rules/custom", json={"tenant_id": "tenant-a", "rule": GOOD_RULE},
                    headers=auth("readonly-a"))
    assert r.status_code == 403


def test_every_operator_compiles_for_its_types():
    cases = [
        ("account_id", "eq", "acct-1"), ("account_id", "ne", "acct-1"), ("account_id", "in", ["a", "b"]),
        ("account_id", "not_in", ["a"]), ("last_used_at", "is_null", None), ("last_used_at", "not_null", None),
        ("created_at", "gte", z(END)), ("created_at", "within_last_days", 7), ("scope_tags", "contains", "prod"),
    ]
    for field, op, value in cases:
        res = compile_rule(rule(violation_when={"all": [{"field": field, "op": op, "value": value}]}))
        assert res.valid, (field, op, res.errors)


def test_field_allowlist_matches_evidence_models():
    from app.models.evidence import CUSTOM_RULE_FIELDS, EVIDENCE_MODELS

    assert set(CUSTOM_RULE_FIELDS) == set(EVIDENCE_MODELS)
    for evidence_type, model in EVIDENCE_MODELS.items():
        assert set(CUSTOM_RULE_FIELDS[evidence_type]) == set(model.model_fields), evidence_type
