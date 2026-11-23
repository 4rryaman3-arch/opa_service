"""Coverage fixes of 2026-11-20 (NIST gpt-4.1 run): review-v2 label corrections, matrix-based vetted-rule candidates
and rule-quality-v1 gates. Synthetic inputs only; control identifiers are used as identifiers."""
from __future__ import annotations

from regintel import automation as au, generated_rules as gr, llm_mapping as lm
from .test_rule_generation import _spec


def derived(cid, clause=None, location="CONTROL_STATEMENT"):
    return {"status": "DERIVED", "canonical_id": cid, "control_id": cid.split("(")[0], "clause": clause,
            "location": location}


def review(**over):
    checks = {"quote_supported": True, "is_requirement": True, "obligation_type_correct": True,
              "thresholds_grounded": True, "domains_relevant": True, **over.pop("checks", {})}
    return au._Review.model_validate({"verdict": "APPROVE", "reasons": [], "checks": checks, **over})


# ------------------------------------------------------------------------------------- review-v2

def test_wrong_domain_label_is_corrected_not_rejected():
    r = review(verdict="REJECT", checks={"domains_relevant": False}, corrected_pam_domains=["access_control"])
    assert r.approves() and r.corrections() == {"pam_domains": ["access_control"]}
    # a wrong label without a correction still rejects
    assert not review(checks={"domains_relevant": False}).approves()


def test_imperative_wording_correction_and_real_rejections():
    r = review(checks={"obligation_type_correct": False}, corrected_obligation_type="MANDATORY")
    assert r.approves() and r.corrections() == {"obligation_type": "MANDATORY"}
    # headings, unsupported quotes and invented thresholds are never approved, whatever the verdict says
    for bad in ({"is_requirement": False}, {"quote_supported": False}, {"thresholds_grounded": False}):
        assert not review(checks=bad).approves(), bad
    # a correction for a check that passed is ignored
    assert review(corrected_pam_domains=["authentication"]).corrections() == {}


def test_review_v1_attempts_still_parse():
    old = au._Review.model_validate({"verdict": "APPROVE", "checks": {
        "quote_supported": True, "obligation_type_correct": True, "thresholds_grounded": True,
        "domains_relevant": True}})
    assert old.approves()
    assert "is_requirement" in au.SYSTEM_REVIEW and au.REVIEW_PROMPT_VERSION == "review-v2"


# ----------------------------------------------------------------------- matrix-based candidates

def test_matrix_controls_offer_their_vetted_rule():
    assert lm.candidates_for(derived("AC-12"), "") == ["PAM-SESSIDLE-001"]
    assert lm.candidates_for(derived("AC-17"), "") == ["PAM-SESSREC-001"]
    # the hard-coded table still wins where it has an entry
    assert lm.candidates_for(derived("AC-2", "j"), "") == ["PAM-REVIEW-001"]


def test_matrix_candidates_never_for_discussion_or_unlisted_controls():
    assert lm.candidates_for(derived("AC-12", location="DISCUSSION"), "") == []
    assert lm.candidates_for(derived("PE-4"), "") == []
    # an evidence type without a vetted rule (audit_event, lookup-only types) offers nothing
    assert lm.matrix_candidates(derived("AU-4(1)")) == []


# --------------------------------------------------------------------------------- quality gates

AUDIT = dict(evidence_type="audit_event", pam_control_id="PAMC-AUDIT-LOGGING", subject_field="event_id",
             population={"type": "ORGANIZATION_SUPPORTED_ENTITIES", "period_field": "occurred_at", "where": []})


def test_optional_audit_context_may_not_be_required():
    spec = gr.RuleSpec.model_validate(_spec(1, **AUDIT, condition={"operator": "all", "where": [
        {"field": f, "operator": "exists"} for f in ("event_type", "outcome", "actor_id", "target_id")]}))
    assert "target_id" in gr.rule_quality_gap(spec)
    content = gr.RuleSpec.model_validate(_spec(1, **AUDIT, condition={"operator": "all", "where": [
        {"field": f, "operator": "exists"} for f in ("event_type", "outcome", "actor_id", "source_id")]}))
    assert gr.rule_quality_gap(content) is None


def test_presence_only_audit_rule_and_running_sessions_are_rejected():
    only = gr.RuleSpec.model_validate(_spec(1, **AUDIT, condition={"field": "event_type", "operator": "exists"}))
    assert "any evidence feed passes" in gr.rule_quality_gap(only)
    ended = gr.RuleSpec.model_validate(_spec(1, evidence_type="privileged_session", subject_field="session_id",
                                             pam_control_id="PAMC-SESSION-RECORDING",
                                             population={"type": "ORGANIZATION_SUPPORTED_ENTITIES",
                                                         "period_field": "started_at", "where": []},
                                             condition={"field": "ended_at", "operator": "exists"}))
    assert "still running" in gr.rule_quality_gap(ended)
    # a specific evidence type with one presence test is fine (break-glass event references a ticket)
    assert gr.rule_quality_gap(gr.RuleSpec.model_validate(_spec(1))) is None


def test_a_vetted_candidate_that_cannot_be_assigned_falls_back_to_generation():
    for code in ("NO_EXECUTABLE_RULE", "LLM_NO_MAP", "LLM_MAPPING_AMBIGUOUS", "LLM_OUTPUT_INVALID", "VALIDATION_FAILED"):
        assert code in gr.TRIGGER_CODES
    # obligations that are not mandatory, or whose quote is not grounded, never reach generation
    for code in ("NOT_MANDATORY", "SOURCE_GROUNDING_FAILED", "PARTIALLY_PARSED"):
        assert code not in gr.TRIGGER_CODES


def test_every_vetted_rule_offered_by_the_matrix_is_seeded():
    import json
    from pathlib import Path
    seeded = {r for c in json.loads((Path(__file__).resolve().parents[2] / "regintel/data/pam_controls.json")
                                    .read_text("utf-8"))["controls"] for r in c["predefined_rules"]}
    offered = {r for rules in lm.VETTED_BY_EVIDENCE.values() for r in rules} | set(lm._SESSION_BY_FIELD.values())
    assert offered <= seeded


# ------------------------------------------------------------------------------------ lookup fields

def _cap(**over):
    from regintel import policy_contexts as pc
    body = {"tenant_id": "default", "collector": {"name": "synthetic-collector", "version": "1.0"},
            "evidence": [{"evidence_type": "privileged_account", "schema_version": "1.0",
                          "assessment_modes": ["EVENT_HISTORY"],
                          "supported_fields": ["record_id", "account_id", "privileged", "enabled", "created_at",
                                               "last_used_at"], **over}]}
    return pc.CollectorCapabilitiesIn.model_validate(body)


def test_lookup_fields_are_declared_beside_supported_fields():
    import pytest
    assert _cap(lookup_fields=["owner_id"]).evidence[0].lookup_fields == ["owner_id"]
    with pytest.raises(ValueError):
        _cap(lookup_fields=["enabled"])  # a field is sent or held, not both
    with pytest.raises(ValueError):
        _cap(lookup_fields=["owner_id"], collection_status="LOOKUP_AVAILABLE")


def test_a_rule_on_a_lookup_field_waits_for_the_collector():
    cap = {"evidence_detail": {"privileged_account": {"supported_fields": ["account_id", "owner_id", "created_at"],
                                                      "lookup_fields": ["owner_id"]}}}
    spec = gr.RuleSpec.model_validate(_spec(1, evidence_type="privileged_account", subject_field="account_id",
                                            pam_control_id="PAMC-DORMANT-ACCOUNTS",
                                            population={"type": "ORGANIZATION_SUPPORTED_ENTITIES",
                                                        "period_field": "created_at", "where": []},
                                            condition={"field": "owner_id", "operator": "exists"}))
    assert gr.lookup_fields_used(cap, spec) == ["owner_id"]
    cap["evidence_detail"]["privileged_account"]["lookup_fields"] = []
    assert gr.lookup_fields_used(cap, spec) == []
