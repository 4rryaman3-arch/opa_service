"""A rule generated from a RuleSpec (regintel.generated_rules) evaluates through the public /evaluate API and the
real OPA server exactly like a custom rule, for its own tenant only. Synthetic records only."""
from __future__ import annotations

from datetime import timedelta

import pytest

from regintel import generated_rules as gr

from .helpers import auth, item, recent_period, z

START, END = recent_period()
SPEC = {"spec_version": "1.0", "title": "Emergency access references a ticket", "description": "",
        "pam_control_id": "PAMC-EMERGENCY-ACCESS", "evidence_type": "break_glass_event",
        "evidence_schema_version": "1.0", "assessment_mode": "EVENT_HISTORY", "subject_field": "event_id",
        "population": {"type": "ORGANIZATION_SUPPORTED_ENTITIES", "period_field": "activated_at", "where": []},
        "parameters": {}, "condition": {"field": "ticket_reference", "operator": "exists"},
        "missing_evidence_result": "INSUFFICIENT_EVIDENCE", "coverage": "PARTIAL", "source_requirement_ids": [1],
        "limitations": ["Tests that a ticket is referenced, not that the ticket was approved."]}


def event(n, at, ticket):
    return {"record_id": f"r{n}", "event_id": f"bg-{n}", "user_id": "u1", "account_id": "a1", "activated_at": z(at),
            "justification_provided": True, "justification_length": 40, "ticket_reference": ticket,
            "post_review_completed": False, "post_review_at": None, "scope_tags": []}


@pytest.mark.opa
def test_generated_rule_evaluates_for_its_tenant_only(client, tmp_path):
    from pathlib import Path
    bundle = Path(__file__).resolve().parents[1] / "policy-bundle"
    spec = gr.RuleSpec.model_validate(SPEC)
    compiled = gr.compile_spec(spec, [], scope="org-test", tenant="tenant-a", bundle_dir=bundle)
    gr._store_activate(tmp_path / "opm.db", "tenant-a", compiled, "test")  # what activation does
    rid = compiled["rule_id"]
    records = [event(1, START + timedelta(days=2), "CHG-1"), event(2, START + timedelta(days=3), None),
               event(3, START - timedelta(days=5), None)]  # outside the reporting period
    ev = {"tenant_id": "tenant-a", "rule_version": "1.0",
          **item(rid, "break_glass_event", records, period=(START, END))}
    res = client.post("/api/v1/evaluate", json=ev, headers=auth())
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "FAIL" and body["decision_details"]["rule_source"] == "GENERATED"
    assert [v["subject_id"] for v in body["violations"]] == ["bg-2"]
    # another tenant cannot evaluate it
    other = client.post("/api/v1/evaluate", json={**ev, "tenant_id": "tenant-b"}, headers=auth("securden-b"))
    assert other.status_code == 404
