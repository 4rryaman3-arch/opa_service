"""Policy decisions for the predefined control tests (real OPA)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from .helpers import (
    access_request,
    account,
    auth,
    auth_summary,
    authorization,
    break_glass,
    coverage,
    exception_doc,
    policy_exception,
    recent_period,
    request,
    review,
    rotation,
    session,
)

pytestmark = pytest.mark.opa

START, END = recent_period()
P = (START, END)


def evaluate(client, body):
    r = client.post("/api/v1/evaluate", json=body, headers=auth())
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------------------ rotation


def test_rotation_pass_and_fail(client):
    ok = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                                  [rotation(1, rotated_at=END - timedelta(days=10))], period=P))
    assert ok["status"] == "PASS"
    assert ok["violations"] == []
    bad = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                                   [rotation(1, rotated_at=END - timedelta(days=95)),
                                    rotation(2, rotated_at=None)], period=P))
    assert bad["status"] == "FAIL"
    assert bad["metrics"]["password_age_days"] == 95
    assert bad["metrics"]["maximum_allowed_days"] == 90
    reasons = {v["record_id"]: v["reasons"] for v in bad["violations"]}
    assert reasons == {"rot-00001": ["ROTATION_AGE_EXCEEDED"], "rot-00002": ["NEVER_ROTATED"]}
    assert bad["severity"] == "HIGH"
    assert {"framework": "ISO27001:2022", "control": "8.2", "title": "Privileged access rights"} in bad["framework_mappings"]
    assert "not certification" in bad["framework_mapping_disclaimer"]


def test_rotation_threshold_boundary(client):
    exactly = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                                       [rotation(1, rotated_at=END - timedelta(days=90))], period=P))
    assert exactly["status"] == "PASS"  # age == max is allowed
    over = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                                    [rotation(1, rotated_at=END - timedelta(days=90, seconds=1))], period=P))
    assert over["status"] == "FAIL"


def test_rotation_custom_threshold_parameter(client):
    body = request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                   [rotation(1, rotated_at=END - timedelta(days=40))], period=P,
                   policy_settings={"parameters": {"max_rotation_age_days": 30}})
    res = evaluate(client, body)
    assert res["status"] == "FAIL"
    assert res["decision_details"]["parameters"]["max_rotation_age_days"] == 30


@pytest.mark.parametrize("params,code", [
    ({"max_rotation_age_days": 0}, "INVALID_PARAMETER"),
    ({"max_rotation_age_days": 10_000}, "INVALID_PARAMETER"),
    ({"max_rotation_age_days": True}, "INVALID_PARAMETER"),
    ({"unknown_knob": 5}, "UNKNOWN_PARAMETER"),
])
def test_rotation_invalid_parameters(client, params, code):
    body = request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                   [rotation(1, rotated_at=END - timedelta(days=1))], period=P,
                   policy_settings={"parameters": params})
    r = client.post("/api/v1/evaluate", json=body, headers=auth())
    assert r.status_code == 422
    assert r.json()["error"]["code"] == code


def test_rotation_v11_failed_rotation_attempt(client):
    res = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                                   [rotation(1, rotated_at=END - timedelta(days=5), status="FAILED")], period=P))
    assert res["rule_version"] == "1.1"
    assert res["violations"][0]["reasons"] == ["LAST_ROTATION_FAILED"]


def test_non_privileged_accounts_not_applicable(client):
    res = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                                   [rotation(1, rotated_at=None, privileged=False)], period=P))
    assert res["status"] == "NOT_APPLICABLE"


def test_scope_tags_filter(client):
    records = [rotation(1, rotated_at=None, tags=["prod"]), rotation(2, rotated_at=END, tags=["dev"])]
    prod = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation", records, period=P,
                                    policy_settings={"scope_tags": ["prod"]}))
    dev = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation", records, period=P,
                                   policy_settings={"scope_tags": ["dev"]}))
    assert prod["status"] == "FAIL" and dev["status"] == "PASS"
    assert dev["evidence_completeness"]["in_scope_record_count"] == 1


# ------------------------------------------------------------ evidence completeness semantics


def test_missing_evidence_is_insufficient(client):
    res = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                                   [rotation(1, rotated_at=END - timedelta(days=1))], period=P, expected=5))
    assert res["status"] == "INSUFFICIENT_EVIDENCE"
    assert res["evidence_completeness"]["gaps"] == ["RECORD_COUNT_BELOW_EXPECTED"]
    assert res["evidence_completeness"]["complete"] is False


def test_source_incomplete_and_collection_errors(client):
    res = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                                   [rotation(1, rotated_at=END)], period=P,
                                   source_complete=False, collection_errors=2))
    assert res["status"] == "INSUFFICIENT_EVIDENCE"
    assert res["evidence_completeness"]["gaps"] == ["COLLECTION_ERRORS_REPORTED", "SOURCE_REPORTED_INCOMPLETE"]


def test_confirmed_violation_beats_incomplete_evidence(client):
    res = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                                   [rotation(1, rotated_at=None)], period=P, expected=10))
    assert res["status"] == "FAIL"
    assert res["evidence_completeness"]["complete"] is False


def test_no_records_complete_is_not_applicable(client):
    res = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation", [], period=P))
    assert res["status"] == "NOT_APPLICABLE"


def test_no_records_but_incomplete_is_insufficient(client):
    res = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation", [], period=P,
                                   source_complete=False))
    assert res["status"] == "INSUFFICIENT_EVIDENCE"


# ------------------------------------------------------------ exceptions


def test_valid_exception_suppresses_violation(client):
    exc = exception_doc("ex-1", "PAM-ROTATION-001", ["acct-00001"], START - timedelta(days=10), END + timedelta(days=30))
    res = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                                   [rotation(1, rotated_at=None)], period=P, exceptions=[exc]))
    assert res["status"] == "PASS"
    assert res["excepted"][0]["exception_ids"] == ["ex-1"]


def test_expired_exception_does_not_suppress(client):
    exc = exception_doc("ex-1", "PAM-ROTATION-001", ["acct-00001"], START - timedelta(days=60), END - timedelta(days=1))
    res = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                                   [rotation(1, rotated_at=None)], period=P, exceptions=[exc]))
    assert res["status"] == "FAIL"
    assert res["excepted"] == []


def test_exception_expiring_exactly_at_as_of_does_not_suppress(client):
    exc = exception_doc("ex-1", "PAM-ROTATION-001", ["acct-00001"], START, END)
    res = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                                   [rotation(1, rotated_at=None)], period=P, exceptions=[exc]))
    assert res["status"] == "FAIL"


def test_exception_for_other_subject_does_not_suppress(client):
    exc = exception_doc("ex-1", "PAM-ROTATION-001", ["acct-99999"], START, END + timedelta(days=1))
    res = evaluate(client, request("tenant-a", "PAM-ROTATION-001", "credential_rotation",
                                   [rotation(1, rotated_at=None)], period=P, exceptions=[exc]))
    assert res["status"] == "FAIL"


def test_exception_for_other_rule_rejected(client):
    exc = exception_doc("ex-1", "PAM-DORMANT-001", ["acct-00001"], START, END + timedelta(days=1))
    r = client.post("/api/v1/evaluate", headers=auth(), json=request(
        "tenant-a", "PAM-ROTATION-001", "credential_rotation", [rotation(1, rotated_at=None)], period=P,
        exceptions=[exc]))
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "EXCEPTION_RULE_MISMATCH"


# ------------------------------------------------------------ other rules


def test_session_recordings(client):
    t = START + timedelta(days=1)
    res = evaluate(client, request("tenant-a", "PAM-SESSREC-001", "privileged_session", [
        session(1, started=t), session(2, started=t, status="MISSING"), session(3, started=t, status="PARTIAL"),
        session(4, started=t, status="FAILED", required=False),
    ], period=P))
    assert res["status"] == "FAIL"
    assert {v["record_id"] for v in res["violations"]} == {"sess-00002", "sess-00003"}
    partial_ok = evaluate(client, request("tenant-a", "PAM-SESSREC-001", "privileged_session",
                                          [session(3, started=t, status="PARTIAL")], period=P,
                                          policy_settings={"parameters": {"accept_partial_recordings": True}}))
    assert partial_ok["status"] == "PASS"
    processing = evaluate(client, request("tenant-a", "PAM-SESSREC-001", "privileged_session",
                                          [session(5, started=t, status="PROCESSING")], period=P))
    assert processing["status"] == "INSUFFICIENT_EVIDENCE"
    assert processing["undetermined"][0]["reasons"] == ["RECORDING_PROCESSING"]


def test_sessions_outside_period_not_in_scope(client):
    res = evaluate(client, request("tenant-a", "PAM-SESSREC-001", "privileged_session",
                                   [session(1, started=START - timedelta(days=2), status="MISSING")], period=P))
    assert res["status"] == "NOT_APPLICABLE"
    assert res["metrics"]["sessions_out_of_period"] == 1


def test_access_approval(client):
    t = START + timedelta(days=2)
    res = evaluate(client, request("tenant-a", "PAM-APPROVAL-001", "privileged_access_request", [
        access_request(1, accessed=t, approved=t - timedelta(hours=1)),
        access_request(2, accessed=t, status="PENDING"),
        access_request(3, accessed=t, approved=t + timedelta(minutes=5)),
        access_request(4, accessed=t, approved=t - timedelta(hours=25)),
        access_request(5, accessed=t, approved=t - timedelta(hours=1), approver="user-1"),
    ], period=P))
    reasons = {v["record_id"]: v["reasons"] for v in res["violations"]}
    assert res["status"] == "FAIL"
    assert reasons == {
        "acc-00002": ["NO_APPROVED_REQUEST"],
        "acc-00003": ["APPROVAL_AFTER_ACCESS"],
        "acc-00004": ["APPROVAL_TOO_OLD"],
        "acc-00005": ["SELF_APPROVAL"],
    }
    assert res["severity"] == "CRITICAL"


def test_approval_boundary_exactly_max_age(client):
    t = START + timedelta(days=2)
    res = evaluate(client, request("tenant-a", "PAM-APPROVAL-001", "privileged_access_request",
                                   [access_request(1, accessed=t, approved=t - timedelta(hours=24))], period=P))
    assert res["status"] == "PASS"


def test_dormant_accounts(client):
    res = evaluate(client, request("tenant-a", "PAM-DORMANT-001", "privileged_account", [
        account(1, created=END - timedelta(days=400), last_used=END - timedelta(days=90)),        # boundary: ok
        account(2, created=END - timedelta(days=400), last_used=END - timedelta(days=91)),        # dormant
        account(3, created=END - timedelta(days=100), last_used=None),                            # never used
        account(4, created=END - timedelta(days=400), last_used=None, enabled=False),             # disabled
    ], period=P))
    reasons = {v["record_id"]: v["reasons"] for v in res["violations"]}
    assert reasons == {"pa-00002": ["DORMANT_SINCE_LAST_USE"], "pa-00003": ["NEVER_USED_SINCE_CREATION"]}
    assert res["metrics"]["max_inactive_days"] == 100


def test_failed_auth_threshold_boundaries(client):
    t = START + timedelta(days=1)
    at_limit = evaluate(client, request("tenant-a", "PAM-AUTHFAIL-001", "authentication_summary",
                                        [auth_summary(1, start=t, failed=5)], period=P))
    assert at_limit["status"] == "PASS"
    over = evaluate(client, request("tenant-a", "PAM-AUTHFAIL-001", "authentication_summary",
                                    [auth_summary(1, start=t, failed=6)], period=P))
    assert over["status"] == "FAIL"
    assert over["metrics"]["max_failed_attempts_observed"] == 6
    mitigated = evaluate(client, request("tenant-a", "PAM-AUTHFAIL-001", "authentication_summary",
                                         [auth_summary(1, start=t, failed=50, lockout=True)], period=P,
                                         policy_settings={"parameters": {"lockout_is_mitigation": True}}))
    assert mitigated["status"] == "PASS"
    long_window = evaluate(client, request("tenant-a", "PAM-AUTHFAIL-001", "authentication_summary",
                                           [auth_summary(1, start=t, failed=2, minutes=60)], period=P))
    assert long_window["status"] == "INSUFFICIENT_EVIDENCE"
    assert long_window["undetermined"][0]["reasons"] == ["WINDOW_LONGER_THAN_CONFIGURED"]


def test_unauthorized_access(client):
    t = START + timedelta(days=3)
    res = evaluate(client, request("tenant-a", "PAM-UNAUTH-001", "access_authorization", [
        authorization(1, accessed=t, valid_from=t - timedelta(days=1), valid_to=t + timedelta(days=1)),
        authorization(2, accessed=t, status="NOT_AUTHORIZED"),
        authorization(3, accessed=t, status="REVOKED"),
        authorization(4, accessed=t, valid_from=t + timedelta(hours=1)),
    ], period=P))
    reasons = {v["record_id"]: v["reasons"] for v in res["violations"]}
    assert reasons == {
        "authz-00002": ["NOT_AUTHORIZED"],
        "authz-00003": ["ENTITLEMENT_REVOKED"],
        "authz-00004": ["OUTSIDE_ENTITLEMENT_WINDOW"],
    }
    unknown = evaluate(client, request("tenant-a", "PAM-UNAUTH-001", "access_authorization",
                                       [authorization(5, accessed=t, status="UNKNOWN")], period=P))
    assert unknown["status"] == "INSUFFICIENT_EVIDENCE"


def test_break_glass(client):
    t = END - timedelta(days=10)
    res = evaluate(client, request("tenant-a", "PAM-BREAKGLASS-001", "break_glass_event", [
        break_glass(1, activated=t, reviewed_at=t + timedelta(hours=10)),
        break_glass(2, activated=t, provided=False, reviewed_at=t + timedelta(hours=10)),
        break_glass(3, activated=t, length=5, reviewed_at=t + timedelta(hours=10)),
        break_glass(4, activated=t, ticket=None, reviewed_at=t + timedelta(hours=10)),
        break_glass(5, activated=t),                                         # overdue review
        break_glass(6, activated=t, reviewed_at=t + timedelta(hours=73)),    # late review
        break_glass(7, activated=END - timedelta(hours=2)),                  # review not yet due
    ], period=P))
    reasons = {v["record_id"]: v["reasons"] for v in res["violations"]}
    assert reasons == {
        "bg-00002": ["JUSTIFICATION_MISSING"],
        "bg-00003": ["JUSTIFICATION_TOO_SHORT"],
        "bg-00004": ["TICKET_REFERENCE_MISSING"],
        "bg-00005": ["POST_REVIEW_OVERDUE"],
        "bg-00006": ["POST_REVIEW_LATE"],
    }


def test_expired_policy_exceptions(client):
    res = evaluate(client, request("tenant-a", "PAM-EXCEPTION-001", "policy_exception", [
        policy_exception(1, approved=START - timedelta(days=30), expires=END + timedelta(days=30)),
        policy_exception(2, approved=START - timedelta(days=30), expires=END - timedelta(days=1)),
        policy_exception(3, approved=START - timedelta(days=30), expires=START + timedelta(days=1),
                         status="EXPIRED", last_used=START + timedelta(days=2)),
        policy_exception(4, approved=START - timedelta(days=400), expires=END + timedelta(days=30)),
    ], period=P))
    reasons = {v["record_id"]: v["reasons"] for v in res["violations"]}
    assert reasons == {
        "pex-00002": ["ACTIVE_AFTER_EXPIRY"],
        "pex-00003": ["USED_AFTER_EXPIRY"],
        "pex-00004": ["DURATION_EXCEEDS_MAXIMUM"],
    }


def test_access_reviews(client):
    res = evaluate(client, request("tenant-a", "PAM-REVIEW-001", "access_review", [
        review(1, completed=END - timedelta(days=30)),
        review(2, completed=None),
        review(3, completed=END - timedelta(days=91)),
        review(4, completed=END - timedelta(days=5), reviewer="owner-1"),
        review(5, completed=END - timedelta(days=5), outcome="REVOKED"),
    ], period=P))
    reasons = {v["record_id"]: v["reasons"] for v in res["violations"]}
    assert reasons == {
        "rev-00002": ["NEVER_REVIEWED"],
        "rev-00003": ["REVIEW_OVERDUE"],
        "rev-00004": ["SELF_REVIEW"],
        "rev-00005": ["REVOCATION_NOT_ENFORCED"],
    }


def test_audit_completeness(client):
    res = evaluate(client, request("tenant-a", "PAM-AUDITCOMP-001", "audit_log_coverage", [
        coverage(1, start=START, end=END),
        coverage(2, start=START + timedelta(hours=1), end=END),
        coverage(3, start=START, end=END, received=999),
        coverage(4, start=START, end=END, gap=301),
        coverage(5, start=START, end=END, integrity=False),
    ], period=P))
    reasons = {v["record_id"]: v["reasons"] for v in res["violations"]}
    assert reasons == {
        "cov-00002": ["COVERAGE_STARTS_AFTER_PERIOD_START"],
        "cov-00003": ["EVENT_COMPLETENESS_BELOW_MINIMUM"],
        "cov-00004": ["GAP_EXCEEDS_MAXIMUM"],
        "cov-00005": ["INTEGRITY_NOT_VERIFIED"],
    }
    assert res["metrics"]["min_completeness_percent_observed"] == 99
    relaxed = evaluate(client, request("tenant-a", "PAM-AUDITCOMP-001", "audit_log_coverage",
                                       [coverage(3, start=START, end=END, received=990)], period=P,
                                       policy_settings={"parameters": {"min_completeness_percent": 99}}))
    assert relaxed["status"] == "PASS"


def test_audit_completeness_no_sources_is_insufficient(client):
    res = evaluate(client, request("tenant-a", "PAM-AUDITCOMP-001", "audit_log_coverage", [], period=P))
    assert res["status"] == "INSUFFICIENT_EVIDENCE"
    assert res["undetermined"][0]["reasons"] == ["NO_AUDIT_SOURCES_SUPPLIED"]


def test_rules_listing(client):
    r = client.get("/api/v1/rules", params={"tenant_id": "tenant-a"}, headers=auth())
    assert r.status_code == 200
    rules = {x["rule_id"]: x for x in r.json()["predefined_rules"]}
    assert len(rules) == 21
    for rule in rules.values():
        for v in rule["versions"]:
            for key in ("rule_id", "version", "description", "evidence_requirements", "severity",
                        "framework_mappings", "remediation"):
                assert v[key], (rule["rule_id"], key)
    assert [v["version"] for v in rules["PAM-ROTATION-001"]["versions"]] == ["1.0", "1.1"]


def test_predefined_rule_deactivation(client):
    body = request("tenant-a", "PAM-DORMANT-001", "privileged_account", [], period=P)
    assert client.post("/api/v1/rules/predefined/PAM-DORMANT-001/deactivate", json={"tenant_id": "tenant-a"},
                       headers=auth()).status_code == 200
    r = client.post("/api/v1/evaluate", json=body, headers=auth())
    assert r.status_code == 409 and r.json()["error"]["code"] == "RULE_INACTIVE"
    # Tenant isolation: tenant-b is unaffected.
    rb = client.post("/api/v1/evaluate", json={**body, "tenant_id": "tenant-b"}, headers=auth("securden-b"))
    assert rb.status_code == 200
    client.post("/api/v1/rules/predefined/PAM-DORMANT-001/activate", json={"tenant_id": "tenant-a"}, headers=auth())
    assert client.post("/api/v1/evaluate", json=body, headers=auth()).status_code == 200
