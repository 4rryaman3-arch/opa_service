#!/usr/bin/env python3
"""Regenerate docs/examples/*.json by running synthetic requests against the
real API + OPA (no TLS; transport is covered by the HTTPS tests).

  python scripts/generate_examples.py --opa /path/to/opa
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def z(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--opa", default=os.environ.get("OPM_TEST_OPA_BINARY", "opa"))
    args = p.parse_args()

    from fastapi.testclient import TestClient

    from app.config import Settings
    from app.main import create_app

    tmp = Path(tempfile.mkdtemp(prefix="opm-examples-"))
    token, secret = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    (tmp / "clients.json").write_text(json.dumps({"clients": [{
        "key_id": "securden-example", "secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
        "tenants": ["acme"], "scopes": ["evaluate", "rules:read", "rules:write", "rules:admin", "metrics:read"]}]}))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    opa = subprocess.Popen([args.opa, "run", "--server", f"--addr=127.0.0.1:{port}", "--authentication=token",
                            "--authorization=basic", "--disable-telemetry", "--log-level=error", "policy-bundle"],
                           cwd=ROOT, env={**os.environ, "OPA_AUTH_TOKEN": token},
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    out = ROOT / "docs" / "examples"
    out.mkdir(parents=True, exist_ok=True)
    try:
        app = create_app(Settings(opa_url=f"http://127.0.0.1:{port}", opa_token=token,
                                  policy_bundle_dir=ROOT / "policy-bundle", db_path=tmp / "opm.db",
                                  api_clients_file=tmp / "clients.json", log_level="WARNING"))
        h = {"Authorization": "Bearer securden-example.<redacted>", "X-Correlation-ID": "securden-example-0001"}
        real = {**h, "Authorization": f"Bearer securden-example.{secret}"}
        end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        start = end - timedelta(days=30)
        period = {"start": z(start), "end": z(end)}

        def save(name, method, path, body, resp):
            doc = {"request": {"method": method, "path": path, "headers": h, **({"body": body} if body else {})},
                   "response": {"status": resp.status_code, "body": resp.json()}}
            (out / f"{name}.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
            print(f"docs/examples/{name}.json -> {resp.status_code}")

        with TestClient(app) as c:
            rotation = {
                "tenant_id": "acme",
                "rule_id": "PAM-ROTATION-001",
                "reporting_period": period,
                "evidence": {
                    "evidence_type": "credential_rotation",
                    "records": [
                        {"record_id": "rotation-event-example-001", "account_id": "acct-db-admin-01", "privileged": True,
                         "last_rotated_at": z(end - timedelta(days=95)), "last_rotation_status": "SUCCESS"},
                        {"record_id": "rotation-event-example-002", "account_id": "acct-win-admin-07", "privileged": True,
                         "last_rotated_at": z(end - timedelta(days=12)), "last_rotation_status": "SUCCESS"},
                    ],
                    "completeness": {"expected_record_count": 2, "received_record_count": 2,
                                     "source_complete": True, "collection_errors": 0},
                },
                "policy_settings": {"policy_version": "acme-pam-policy-2026.10",
                                    "effective_from": z(start - timedelta(days=10)),
                                    "parameters": {"max_rotation_age_days": 90}},
            }
            save("evaluate_fail", "POST", "/api/v1/evaluate", rotation,
                 c.post("/api/v1/evaluate", json=rotation, headers=real))

            excepted = json.loads(json.dumps(rotation))
            excepted["exceptions"] = [{"exception_id": "exc-example-001", "rule_id": "PAM-ROTATION-001",
                                       "subject_ids": ["acct-db-admin-01"], "approved_by": "ciso-example",
                                       "approved_at": z(start), "expires_at": z(end + timedelta(days=30))}]
            save("evaluate_pass_with_exception", "POST", "/api/v1/evaluate", excepted,
                 c.post("/api/v1/evaluate", json=excepted, headers=real))

            incomplete = json.loads(json.dumps(rotation))
            incomplete["evidence"]["records"] = incomplete["evidence"]["records"][1:]
            incomplete["evidence"]["completeness"].update({"expected_record_count": 2, "received_record_count": 1})
            save("evaluate_insufficient_evidence", "POST", "/api/v1/evaluate", incomplete,
                 c.post("/api/v1/evaluate", json=incomplete, headers=real))

            batch = {"tenant_id": "acme", "items": [
                {k: v for k, v in rotation.items() if k != "tenant_id"} | {"item_reference": "rotation-acme"},
                {"item_reference": "breakglass-acme", "rule_id": "PAM-BREAKGLASS-001", "reporting_period": period,
                 "evidence": {"evidence_type": "break_glass_event", "records": [
                     {"record_id": "bg-example-001", "event_id": "bge-001", "user_id": "user-oncall-3",
                      "account_id": "acct-root-01", "activated_at": z(end - timedelta(days=3)),
                      "justification_provided": True, "justification_length": 64, "ticket_reference": "INC-20931",
                      "post_review_completed": True, "post_review_at": z(end - timedelta(days=2))}],
                     "completeness": {"expected_record_count": 1, "received_record_count": 1,
                                      "source_complete": True, "collection_errors": 0}}},
                {"item_reference": "bad-rule", "rule_id": "PAM-UNKNOWN-001", "reporting_period": period,
                 "evidence": {"evidence_type": "credential_rotation", "records": [],
                              "completeness": {"received_record_count": 0, "source_complete": True}}},
            ]}
            save("evaluate_batch", "POST", "/api/v1/evaluate/batch", batch,
                 c.post("/api/v1/evaluate/batch", json=batch, headers=real))

            rule = {
                "rule_id": "CUST-ACME-SESSREC-001", "version": "1.0",
                "title": "Production sessions must be recorded",
                "description": "Any privileged session on prod-tagged accounts without an AVAILABLE recording.",
                "severity": "CRITICAL", "evidence_type": "privileged_session", "subject_field": "session_id",
                "scope": {"all": [{"field": "scope_tags", "op": "contains", "value": "prod"}]},
                "violation_when": {"all": [{"field": "recording_status", "op": "ne", "value": "AVAILABLE"}]},
                "tolerance": 0, "effective_from": "2026-01-01T00:00:00Z",
                "framework_mappings": [{"framework": "ISO27001:2022", "control": "8.15", "title": "Logging"}],
                "remediation": "Investigate the recording gateway.",
            }
            body = {"tenant_id": "acme", "rule": rule}
            save("rules_validate", "POST", "/api/v1/rules/validate", body,
                 c.post("/api/v1/rules/validate", json=body, headers=real))
            bad = {"tenant_id": "acme", "rule": {**rule, "violation_when": {"all": [
                {"field": "password_hash", "op": "eq", "value": "x"},
                {"field": "recording_required", "op": "gt", "value": 1}]}}}
            save("rules_validate_invalid", "POST", "/api/v1/rules/validate", bad,
                 c.post("/api/v1/rules/validate", json=bad, headers=real))
            test = {"tenant_id": "acme", "rule": rule, "reporting_period": period, "evidence": {
                "evidence_type": "privileged_session", "records": [
                    {"record_id": "sess-example-1", "session_id": "s-1", "account_id": "acct-1", "user_id": "u-1",
                     "started_at": z(end - timedelta(days=5)), "recording_required": True,
                     "recording_status": "FAILED", "scope_tags": ["prod"]},
                    {"record_id": "sess-example-2", "session_id": "s-2", "account_id": "acct-2", "user_id": "u-2",
                     "started_at": z(end - timedelta(days=4)), "recording_required": True,
                     "recording_status": "AVAILABLE", "recording_reference": "rec-2", "scope_tags": ["prod"]}],
                "completeness": {"expected_record_count": 2, "received_record_count": 2, "source_complete": True}}}
            save("rules_test", "POST", "/api/v1/rules/test", test, c.post("/api/v1/rules/test", json=test, headers=real))
            save("version", "GET", "/api/v1/version", None, c.get("/api/v1/version", headers=real))
            save("error_tenant_forbidden", "POST", "/api/v1/evaluate", {**rotation, "tenant_id": "globex"},
                 c.post("/api/v1/evaluate", json={**rotation, "tenant_id": "globex"}, headers=real))
            spoof = {**rotation, "evaluated_at": "2020-01-01T00:00:00Z"}
            save("error_spoofed_field", "POST", "/api/v1/evaluate", spoof,
                 c.post("/api/v1/evaluate", json=spoof, headers=real))
    finally:
        opa.terminate()


if __name__ == "__main__":
    main()
