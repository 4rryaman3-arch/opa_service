"""MFA configuration / MFA at access / session idle / session duration rules (real OPA).
These rules have no Securden default: every parameter must be stated."""

from __future__ import annotations

from datetime import timedelta

import pytest

from .helpers import auth, recent_period, request, session, z

pytestmark = pytest.mark.opa

START, END = recent_period()
P = (START, END)
METHODS = {"accepted_methods": ["fido2", "totp"]}


def evaluate(client, body, status=200):
    r = client.post("/api/v1/evaluate", json=body, headers=auth())
    assert r.status_code == status, r.text
    return r.json()


def cfg(i, enforced, methods, captured=None):
    return {"record_id": f"cfg-{i}", "principal_id": f"user-{i}", "principal_type": "USER", "privileged": True,
            "enabled": True, "mfa_enforced": enforced, "mfa_methods": methods,
            "captured_at": z(captured or END - timedelta(hours=2))}


def access(i, status, method=None, granted=True):
    return {"record_id": f"acc-{i}", "access_id": f"acc-{i}", "user_id": "u-1", "account_id": "a-1",
            "accessed_at": z(END - timedelta(days=1)), "access_granted": granted, "mfa_status": status,
            "mfa_method": method}


def policy(i, enabled, minutes, captured=None):
    return {"record_id": f"pol-{i}", "policy_id": f"sp-{i}", "applies_to_privileged": True,
            "idle_timeout_enabled": enabled, "idle_timeout_minutes": minutes,
            "captured_at": z(captured or END - timedelta(hours=2))}


def test_parameters_without_default_must_be_stated(client):
    body = request("tenant-a", "PAM-MFACFG-001", "mfa_configuration", [cfg(1, True, ["totp"])], period=P)
    missing = evaluate(client, body, 422)
    assert missing["error"]["code"] == "MISSING_PARAMETER"
    for bad in (["totp", "totp"], [], ["carrier_pigeon"], "totp"):
        r = evaluate(client, {**body, "policy_settings": {"parameters": {"accepted_methods": bad}}}, 422)
        assert r["error"]["code"] in ("INVALID_PARAMETER", "VALIDATION_ERROR")
    for rule, etype in (("PAM-SESSIDLE-001", "session_policy_configuration"),
                        ("PAM-SESSDUR-001", "privileged_session")):
        assert evaluate(client, request("tenant-a", rule, etype, [], period=P), 422)["error"]["code"] == "MISSING_PARAMETER"


def test_mfa_configuration_snapshot(client):
    def run(records):
        return evaluate(client, request("tenant-a", "PAM-MFACFG-001", "mfa_configuration", records, period=P,
                                        policy_settings={"parameters": METHODS}))

    ok = run([cfg(1, True, ["totp", "sms"])])
    assert ok["status"] == "PASS" and ok["metrics"]["assessment_basis"] == "CONFIGURATION_SNAPSHOT"
    bad = run([cfg(1, False, []), cfg(2, True, ["sms"])])
    assert {v["subject_id"]: v["reasons"] for v in bad["violations"]} == {
        "user-1": ["MFA_NOT_ENFORCED"], "user-2": ["NO_ACCEPTED_MFA_METHOD"]}
    old = run([cfg(1, True, ["totp"], captured=START - timedelta(days=3))])
    assert old["status"] == "INSUFFICIENT_EVIDENCE" and old["undetermined"][0]["reasons"] == ["SNAPSHOT_OUTSIDE_PERIOD"]
    # evidence contract: methods only when enforced, no repeats, no unknown fields
    r = client.post("/api/v1/evaluate", headers=auth(), json=request(
        "tenant-a", "PAM-MFACFG-001", "mfa_configuration", [cfg(1, False, ["totp"])], period=P,
        policy_settings={"parameters": METHODS}))
    assert r.status_code == 422


def test_mfa_at_access_event_history(client):
    def run(records):
        return evaluate(client, request("tenant-a", "PAM-MFAACC-001", "privileged_access_authentication", records,
                                        period=P, policy_settings={"parameters": METHODS}))

    res = run([access(1, "VERIFIED", "fido2"), access(2, "NOT_PERFORMED"), access(3, "FAILED"),
               access(4, "VERIFIED", "sms"), access(5, "FAILED", granted=False)])
    assert res["status"] == "FAIL" and res["metrics"]["granted_accesses"] == 4
    assert {v["subject_id"]: v["reasons"] for v in res["violations"]} == {
        "acc-2": ["MFA_NOT_PERFORMED"], "acc-3": ["ACCESS_GRANTED_AFTER_FAILED_MFA"], "acc-4": ["MFA_METHOD_NOT_ACCEPTED"]}
    assert run([access(1, "UNKNOWN")])["status"] == "INSUFFICIENT_EVIDENCE"
    r = client.post("/api/v1/evaluate", headers=auth(), json=request(
        "tenant-a", "PAM-MFAACC-001", "privileged_access_authentication", [access(1, "VERIFIED")], period=P,
        policy_settings={"parameters": METHODS}))
    assert r.status_code == 422  # VERIFIED needs the method


def test_session_idle_configuration(client):
    def run(records):
        return evaluate(client, request("tenant-a", "PAM-SESSIDLE-001", "session_policy_configuration", records,
                                        period=P, policy_settings={"parameters": {"max_idle_minutes": 15}}))

    assert run([policy(1, True, 15)])["status"] == "PASS"
    bad = run([policy(1, True, 16), policy(2, False, None)])
    assert {v["subject_id"]: v["reasons"] for v in bad["violations"]} == {
        "sp-1": ["IDLE_TIMEOUT_EXCEEDS_MAXIMUM"], "sp-2": ["IDLE_TIMEOUT_DISABLED"]}
    assert run([])["undetermined"][0]["reasons"] == ["NO_SESSION_POLICY_SUPPLIED"]


def test_session_duration_history(client):
    def run(records):
        return evaluate(client, request("tenant-a", "PAM-SESSDUR-001", "privileged_session", records, period=P,
                                        policy_settings={"parameters": {"max_session_minutes": 30}}))

    assert run([session(1, started=END - timedelta(days=2))])["status"] == "PASS"  # exactly 30 minutes
    long = session(2, started=END - timedelta(days=2))
    long["ended_at"] = z(END - timedelta(days=2) + timedelta(minutes=31))
    still_open = {**session(3, started=END - timedelta(hours=3)), "ended_at": None}
    res = run([long, still_open])
    assert {v["subject_id"]: v["reasons"] for v in res["violations"]} == {
        "s-00002": ["SESSION_DURATION_EXCEEDED"], "s-00003": ["OPEN_SESSION_EXCEEDS_MAXIMUM"]}
    assert res["metrics"]["longest_session_minutes"] == 180


def test_au14_session_recording_execution_is_deterministic(client):
    """The PC-SESSION-RECORDING execution behind NIST AU-14 a (partial coverage): same evidence and
    stated parameters give the same decision; partial and missing recordings never pass."""
    def run(records, accept_partial=False):
        return evaluate(client, request("tenant-a", "PAM-SESSREC-001", "privileged_session", records, period=P,
                                        policy_settings={"parameters": {"accept_partial_recordings": accept_partial}}))

    at = END - timedelta(days=2)
    records = [session(1, started=at), session(2, started=at, status="PARTIAL"),
               session(3, started=at, status="MISSING"), session(4, started=at, required=False, status="MISSING")]
    first, second = run(records), run(list(reversed(records)))
    assert first["status"] == second["status"] == "FAIL"
    assert sorted(map(str, first["violations"])) == sorted(map(str, second["violations"]))
    assert {v["subject_id"]: v["reasons"] for v in first["violations"]} == {
        "s-00002": ["RECORDING_PARTIAL"], "s-00003": ["RECORDING_MISSING"]}
    assert first["metrics"]["sessions_requiring_recording"] == 3  # not-required sessions are outside the test
    assert run([session(5, started=at, status="PROCESSING")])["status"] != "PASS"
    assert run([session(1, started=at), session(2, started=at, status="PARTIAL")], accept_partial=True)["status"] == "PASS"
