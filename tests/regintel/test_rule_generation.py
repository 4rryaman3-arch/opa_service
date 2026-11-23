"""Bounded automatic rule generation (RuleSpec 1.0) end to end through prepare_catalog.

SYNTHETIC FIXTURES ONLY: the framework is the synthetic SYN-EU-ACT; every requirement passage below is
invented test text (not a real standard). The scripted "rule designer" stands in for the local LLM and
deliberately also returns Rego, unknown operators, invented thresholds and undeclared evidence, which the
deterministic gates must reject. Generated cases run against the real OPA binary. No human approval click
happens anywhere in these tests, and nothing here claims that any real framework is fully assessable."""
from __future__ import annotations

import json
from contextlib import nullcontext
from pathlib import Path

import pytest

from app.engine.store import RuleStore
from regintel import catalog, extraction, generated_rules as gr, llm_mapping as lm, registry
from . import support as s
from .test_rewrite_contract import ADMIN, CATALOG, SCOPE_A, SCOPE_B, env  # noqa: F401  (fixture)

FW = "SYN-EU-ACT"
Q = {
    "ticket": "Each activation of emergency privileged access shall reference an approved change ticket.",
    "idle": "Privileged session policies shall lock an idle session after 15 minutes of inactivity.",
    "gap": "Privileged audit logging shall have no collection gap longer than the organization-defined period.",
    "rego": "Emergency privileged access shall be justified by the person who activates it.",
    "unknown_op": "Emergency privileged access tickets shall match the approved naming pattern.",
    "invented": "Privileged session policies shall enforce a short idle timeout.",
    "mfa": "Privileged access shall be granted only after multi-factor authentication succeeded.",
    "review": "Every emergency privileged access activation shall be reviewed after use.",
    "decline": "The organization shall appoint a person responsible for emergency privileged access governance.",
}
PAGE = ("<html><body><h1>SYNTHETIC TEST FIXTURE - invented PAM obligations (not a real standard)</h1>"
        + "".join(f"<p>Article {n}. {q}</p>" for n, q in enumerate(Q.values(), 1)) + s.FILLER + "</body></html>")
UPLOAD = ("<html><body><h1>SYNTHETIC TEST FIXTURE - organization copy (not a real standard)</h1>"
          f"<p>Article 1. {Q['ticket']}</p>{s.FILLER}</body></html>")

BG_FIELDS = ["event_id", "user_id", "account_id", "activated_at", "ticket_reference", "justification_provided"]
HANDSHAKE = [
    {"evidence_type": "break_glass_event", "schema_version": "1.0", "assessment_modes": ["EVENT_HISTORY"],
     "supported_fields": BG_FIELDS},  # post_review_completed is NOT populated by this collector
    {"evidence_type": "session_policy_configuration", "schema_version": "1.0",
     "assessment_modes": ["CONFIGURATION_SNAPSHOT"],
     "supported_fields": ["policy_id", "applies_to_privileged", "idle_timeout_enabled", "idle_timeout_minutes",
                          "captured_at"]},
    {"evidence_type": "audit_log_coverage", "schema_version": "1.0", "assessment_modes": ["EVENT_HISTORY"],
     "supported_fields": ["source_id", "coverage_start", "coverage_end", "max_gap_seconds"]},
    {"evidence_type": "privileged_session", "schema_version": "1.0"},
]


def _spec(rid, **over):
    base = {"spec_version": "1.0", "title": "Synthetic generated test", "description": "",
            "pam_control_id": "PAMC-EMERGENCY-ACCESS", "evidence_type": "break_glass_event",
            "evidence_schema_version": "1.0", "assessment_mode": "EVENT_HISTORY", "subject_field": "event_id",
            "population": {"type": "ORGANIZATION_SUPPORTED_ENTITIES", "period_field": "activated_at", "where": []},
            "parameters": {}, "condition": {"field": "ticket_reference", "operator": "exists"},
            "missing_evidence_result": "INSUFFICIENT_EVIDENCE", "coverage": "PARTIAL",
            "source_requirement_ids": [rid],
            "limitations": ["Tests that a ticket is referenced, not that the ticket was approved."]}
    return {**base, **over}


IDLE = dict(title="Idle session lock configured", pam_control_id="PAMC-SESSION-LIMITS",
            evidence_type="session_policy_configuration", assessment_mode="CONFIGURATION_SNAPSHOT",
            subject_field="policy_id",
            population={"type": "ORGANIZATION_SUPPORTED_ENTITIES", "period_field": "captured_at",
                        "where": [{"field": "applies_to_privileged", "operator": "equals", "value": True}]},
            parameters={"max_idle": {"type": "integer", "unit": "minutes",
                                     "policy_control": {"control_id": "PC-SESSION-IDLE-LIMIT",
                                                        "parameter": "max_idle_minutes"}}},
            condition={"operator": "all", "where": [
                {"field": "idle_timeout_enabled", "operator": "equals", "value": True},
                {"field": "idle_timeout_minutes", "operator": "less_than_or_equal", "parameter": "max_idle"}]},
            limitations=["Tests the configured timeout, not its enforcement on endpoints."])


def designer(system, prompt):
    if system == lm.SYSTEM_MAP:  # no existing rule fits any of these synthetic obligations
        ctx = json.loads(prompt)
        return {"requirement_id": ctx["requirement_id"], "decision": "NO_MAP", "confidence": 0.9,
                "rationale": "No candidate rule tests what this requirement mandates.", "limitations": []}
    if not system.startswith(gr.SYSTEM_RULESPEC):  # the worked example is appended to the system prompt
        return {"requirements": []}
    ctx = json.loads(prompt)
    rid, text = ctx["requirement_id"], ctx["requirement_text"]

    def propose(spec, confidence=0.9):
        return {"requirement_id": rid, "decision": "PROPOSE", "confidence": confidence,
                "rationale": "The collector's records can test this obligation directly.", "rule_spec": spec}

    if text == Q["ticket"]:
        return propose(_spec(rid, title="Emergency access references a ticket"))
    if text == Q["idle"]:
        return propose(_spec(rid, **IDLE))
    if text == Q["gap"]:
        return propose(_spec(rid, title="Audit collection gap bounded", pam_control_id="PAMC-AUDIT-LOG-COMPLETENESS",
                             evidence_type="audit_log_coverage", subject_field="source_id",
                             population={"type": "ORGANIZATION_SUPPORTED_ENTITIES", "period_field": "coverage_end",
                                         "where": []},
                             parameters={"max_gap": {"type": "integer", "unit": "seconds"}},
                             condition={"field": "max_gap_seconds", "operator": "less_than_or_equal",
                                        "parameter": "max_gap"}))
    if text == Q["rego"]:
        return ('{"requirement_id": %d, "decision": "PROPOSE", "confidence": 0.9, "rationale": "package '
                'securden.gen\\nviolation contains x if { x := input.evidence.records[_] }", "rule_spec": null}' % rid)
    if text == Q["unknown_op"]:
        return propose(_spec(rid, condition={"field": "ticket_reference", "operator": "matches_regex",
                                             "value": "CHG-.*"}))
    if text == Q["invented"]:  # the model invents "15" instead of declaring a parameter
        return propose(_spec(rid, **{**IDLE, "parameters": {}, "condition": {
            "field": "idle_timeout_minutes", "operator": "less_than_or_equal", "value": 15}}))
    if text == Q["mfa"]:
        return propose(_spec(rid, title="MFA before privileged access", pam_control_id="PAMC-MFA-PRIVILEGED",
                             evidence_type="privileged_access_authentication", subject_field="access_id",
                             population={"type": "ORGANIZATION_SUPPORTED_ENTITIES", "period_field": "accessed_at",
                                         "where": []},
                             condition={"field": "mfa_status", "operator": "in", "value": ["SUCCESS"]}))
    if text == Q["review"]:
        return propose(_spec(rid, condition={"field": "post_review_completed", "operator": "equals", "value": True}))
    return {"requirement_id": rid, "decision": "MANUAL_ASSESSMENT", "confidence": 0.9,
            "rationale": "An appointment of a person is judged by an assessor, not by PAM evidence."}


def official(env):
    db = env.db
    s.setup_synthetic(db)
    s.sync(db, {f"https://{s.DOMAIN}/act/en": PAGE}, Path(db.path).parent)
    vid = db.scalar("SELECT MAX(id) FROM regulatory_document_version")
    catalog.review_document_version(db, vid, reviewer="bob", decision="APPROVED", published_on="2024-01-15",
                                    effective_from="2025-01-01")
    registry.verify_framework(db, FW, reviewer="bob", evidence_version_id=vid, lifecycle="IN_FORCE",
                              published_on="2024-01-15", effective_from="2025-01-01")
    ids = {}
    for key, quote in Q.items():
        section = db.scalar("SELECT id FROM document_section WHERE version_id=? AND text LIKE ?", (vid, f"%{quote}%"))
        ids[key] = extraction.add_manual_requirement(db, section_id=section, quote=quote,
                                                     pam_domains=["access_control"], obligation_type="MANDATORY",
                                                     actor="alice")
        catalog.review(db, "requirement", ids[key], reviewer="bob", decision="APPROVED")
    catalog.publish_catalog(db, "bob")
    return ids


def declare(env, scope, evidence=HANDSHAKE):
    r = env.admin.put(ADMIN + "/collector-capabilities", headers=env.h(scope), json={
        "tenant_id": "acme", "collector": {"name": "securden-django", "version": "1.0"}, "evidence": evidence})
    assert r.status_code == 200, r.text
    return r.json()["collector_capabilities"]["digest"]


@pytest.fixture
def gen(env, tmp_path, monkeypatch):  # noqa: F811
    from regintel import __main__ as cli
    monkeypatch.setenv(gr.FLAG_GENERATE, "true")
    monkeypatch.setenv(gr.FLAG_PUBLISH, "true")
    env.jobs.rule_store_path = tmp_path / "opm.db"  # the evaluator's store of the public app in this env
    ids = official(env)
    digest = declare(env, SCOPE_A)
    model = s.FakeLlm(designer)
    up = env.upload(UPLOAD.encode(), scope=SCOPE_A, key="gen-upload-1", framework_id=FW, filename="act.html")
    assert up.status_code == 201, up.text
    doc_ids = up.json()["document_ids"]

    def submit(key, scope=SCOPE_A, **extra):
        body = dict(document_ids=doc_ids, requested_framework_ids=[FW], tenant_id="acme", auto_rule_generation=True,
                    auto_publish_validated_rules=True, collector_capability_digest=digest)
        return env.prepare(scope=scope, key=key, **{k: v for k, v in {**body, **extra}.items() if v is not None})

    def run(key, **extra):
        with pytest.MonkeyPatch.context() as m:
            m.setattr(cli, "_llm", lambda: nullcontext(model))
            r = submit(key, **extra)
            assert r.status_code == 202, r.text
            env.run_all()
        job = env.admin.get(ADMIN + f"/jobs/{r.json()['job']['id']}", headers=env.h(SCOPE_A)).json()["job"]
        assert job["status"] in ("SUCCEEDED", "PARTIAL"), (job["status"], job["error"])
        return job["result"]

    return env, ids, run, submit, model, digest, tmp_path / "opm.db"


def by_req(result):
    return {d["requirement_id"]: d for d in result["rule_generation_decisions"]}


def spec_calls(model):
    return sum(1 for system, _ in model.calls if system == gr.SYSTEM_RULESPEC)


def test_submission_is_gated_by_flags_tenant_and_pinned_digest(gen, monkeypatch):
    env, _ids, _run, submit, _model, digest, _store = gen
    assert submit("gate-key-1", auto_publish_validated_rules=True, auto_rule_generation=False).status_code == 422
    r = submit("gate-key-2", tenant_id=None)
    assert r.status_code == 422 and r.json()["error"]["code"] == "TENANT_REQUIRED"
    r = submit("gate-key-3", collector_capability_digest=None)
    assert r.status_code == 422 and r.json()["error"]["code"] == "CAPABILITY_DIGEST_REQUIRED"
    r = submit("gate-key-4", collector_capability_digest="sha256:" + "0" * 64)
    assert r.status_code == 409 and r.json()["error"]["code"] == "STALE_CAPABILITY_DIGEST"
    monkeypatch.setenv(gr.FLAG_PUBLISH, "false")
    r = submit("gate-key-5")
    assert r.status_code == 422 and r.json()["error"]["code"] == "RULE_PUBLICATION_DISABLED"
    monkeypatch.setenv(gr.FLAG_GENERATE, "false")
    r = submit("gate-key-6", auto_publish_validated_rules=False, collector_capability_digest=None)
    assert r.status_code == 422 and r.json()["error"]["code"] == "RULE_GENERATION_DISABLED"
    assert digest.startswith("sha256:")


def test_generated_rules_are_validated_tested_activated_and_gaps_stay_explicit(gen):
    env, ids, run, _submit, model, _digest, store_path = gen
    result = run("gen-run-1")
    d = by_req(result)
    # grounded, collector-compatible, compiled and tested against the real OPA binary -> activated + mapped
    t = d[ids["ticket"]]
    assert t["outcome"] == gr.GENERATED_RULE_ACTIVATED, t
    assert t["rule_id"].startswith("PAM-GEN-") and t["coverage"] == "PARTIAL"
    from pydantic import TypeAdapter  # the id is accepted by the public evaluate API
    from app.models.common import RuleId
    TypeAdapter(RuleId).validate_python(t["rule_id"])
    row = env.db.one("SELECT * FROM generated_rule_version WHERE rule_id=?", (t["rule_id"],))
    assert row["status"] == "ACTIVE" and row["organization_scope"] == SCOPE_A and row["tenant_id"] == "acme"
    assert row["compiler_version"] == gr.COMPILER_VERSION and row["rego_digest"].startswith("sha256:")
    names = {c["name"] for c in row["tests"]}
    assert {"passing_evidence", "failing_evidence", "empty_evidence", "empty_incomplete_evidence",
            "outside_reporting_period", "out_of_scope_tag"} <= names
    assert row["test_results"] and all(r["passed"] for r in row["test_results"])
    m = env.db.one("SELECT * FROM framework_control_mapping WHERE id=?", (t["mapping_id"],))
    assert (m["organization_scope"], m["coverage"], m["status"]) == (SCOPE_A, "PARTIAL", "APPROVED")
    assert m["published_seq"] is not None and m["rule_version_min"] == m["rule_version_max"] == "1.0"
    review = env.db.one("SELECT * FROM review_approval WHERE entity_type='mapping' AND entity_id=?", (str(m["id"]),))
    assert review["decision_origin"] == "AUTOMATED_LLM"
    assert review["attestations"]["generated_rule"]["rule_origin"] == "GENERATED"
    # the evaluator's tenant store holds exactly this active version
    store = RuleStore(store_path)
    try:
        stored = store.get_custom("acme", t["rule_id"], "1.0")
    finally:
        store.close()
    assert stored is not None and stored["status"] == "ACTIVE" and stored["compiled"]["period_field"] == "activated_at"

    # the threshold comes from the regulatory text (15 minutes), never from the model
    idle = d[ids["idle"]]
    assert idle["outcome"] == gr.GENERATED_RULE_ACTIVATED, idle
    irow = env.db.one("SELECT * FROM generated_rule_version WHERE rule_id=?", (idle["rule_id"],))
    [p] = irow["parameter_resolution"]
    assert (p["value"], p["source_type"]) == (15, "REGULATORY_TEXT") and "15 minutes" in p["quotation"]
    # every rejection is explicit and nothing is mapped for it
    expect = {"gap": "PARAMETER_SOURCE_MISSING", "rego": "RULE_SPEC_INVALID", "unknown_op": "RULE_SPEC_INVALID",
              "invented": "RULE_SPEC_INVALID", "mfa": "COLLECTOR_MISSING", "review": "EVIDENCE_SCHEMA_INCOMPATIBLE",
              "decline": "MANUAL_ASSESSMENT_REQUIRED"}
    for key, code in expect.items():
        assert d[ids[key]]["outcome"] == code, (key, d[ids[key]])
        assert env.db.scalar("SELECT COUNT(*) FROM framework_control_mapping WHERE requirement_id=? AND "
                             "status IN ('DRAFT','APPROVED')", (ids[key],)) == 0, key
    rego = env.db.one("SELECT * FROM rule_generation_decision WHERE id=?", (d[ids["rego"]]["decision_id"],))
    assert "EXECUTABLE_CODE" in rego["llm_validation"]["forbidden"] and rego["raw_output"].count("package") == 1
    c = result["counts"]
    assert (c["rules_activated"], c["missing_parameters"], c["missing_collectors"]) == (2, 1, 1)
    assert c["rule_proposals_created"] >= 6 and c["requirements_processed"] >= len(Q)
    outcomes = {m["requirement_id"]: m["orchestration_outcome"] for m in result["mapping_decisions"]}
    assert outcomes[ids["ticket"]] == "GENERATED_RULE_ACTIVATED" and outcomes[ids["mfa"]] == "COLLECTOR_MISSING"
    stages = [st["orchestration_stage"] for st in result["stages"]]
    for stage in ("match_existing_rules", "propose_missing_rules", "test_generated_rules",
                  "publish_generated_rules", "publish_mappings", "recompute_readiness", "complete"):
        assert stage in stages, stage

    # read APIs: mapping-gaps and the plan show the generated decision and provenance; scope B sees none of it
    gaps = env.public.get(CATALOG + f"/frameworks/{FW}/mapping-gaps", params={"tenant_id": "acme"},
                          headers=env.h(SCOPE_A)).json()
    item = {i["requirement_id"]: i for i in gaps["items"]}
    assert item[ids["ticket"]]["rule_generation"]["outcome"] == "PUBLISHABLE"
    assert t["rule_id"] in item[ids["ticket"]]["executable_rules"]
    assert item[ids["mfa"]]["rule_generation"]["gap_code"] == "COLLECTOR_MISSING"
    plan = env.public.get(CATALOG + f"/evaluation-templates/{FW}/plan", params={"tenant_id": "acme"},
                          headers=env.h(SCOPE_A))
    assert plan.status_code == 200, plan.text
    gen_exec = [e for e in plan.json()["executions"] if e["rule_id"] == t["rule_id"]]
    assert gen_exec and gen_exec[0]["generated_rule"]["rule_origin"] == "GENERATED"
    assert gen_exec[0]["generated_rule"]["required_fields"]
    assert gen_exec[0]["rule_source"] == "GENERATED"
    gaps_b = env.public.get(CATALOG + f"/frameworks/{FW}/mapping-gaps", headers=env.h(SCOPE_B)).json()
    assert all("rule_generation" not in i and not any(r.startswith("PAM-GEN-") for r in i["executable_rules"])
               for i in gaps_b["items"])
    rules = env.public.get(CATALOG + "/rules", headers=env.h(SCOPE_B)).json()
    assert not any(r["rule_id"].startswith("PAM-GEN-") for r in rules["items"])
    cat = env.admin.get(ADMIN + "/rule-catalog", headers=env.h(SCOPE_A)).json()["items"]
    origins = {r["rule_id"]: r["origin"] for r in cat}
    assert origins[t["rule_id"]] == "GENERATED" and origins["PAM-SESSREC-001"] == "BUILT_IN"
    assert not any(r["rule_id"].startswith("PAM-GEN-")
                   for r in env.admin.get(ADMIN + "/rule-catalog", headers=env.h(SCOPE_B)).json()["items"])

    # an identical retry reuses every proposal and rule: no model call, no duplicate rule or mapping
    calls = spec_calls(model)
    again = by_req(run("gen-run-2"))
    assert spec_calls(model) == calls
    assert again[ids["ticket"]]["outcome"] == gr.GENERATED_RULE_ACTIVATED
    assert again[ids["ticket"]]["mapping_id"] == t["mapping_id"]
    assert env.db.scalar("SELECT COUNT(*) FROM generated_rule_version") == 2
    assert env.db.scalar("SELECT COUNT(*) FROM framework_control_mapping WHERE rule_id LIKE 'PAM-GEN-%' AND "
                         "status IN ('DRAFT','APPROVED')") == 2


def test_validated_only_without_auto_publish(gen):
    env, ids, run, _submit, _model, _digest, store_path = gen
    d = by_req(run("gen-validate-1", auto_publish_validated_rules=False, collector_capability_digest=None))
    t = d[ids["ticket"]]
    assert t["outcome"] == gr.GENERATED_RULE_VALIDATED and t["mapping_id"] is None, t
    assert env.db.scalar("SELECT status FROM generated_rule_version WHERE rule_id=?", (t["rule_id"],)) == "VALIDATED"
    assert env.db.scalar("SELECT COUNT(*) FROM framework_control_mapping WHERE requirement_id=?", (ids["ticket"],)) == 0
    assert not store_path.exists() or RuleStore(store_path).get_custom("acme", t["rule_id"], "1.0") is None


def test_lookup_available_evidence_is_validated_and_waits_then_activates_when_collected(gen):
    env, ids, run, _submit, model, _digest, store_path = gen
    lookup = [dict(e, collection_status="LOOKUP_AVAILABLE", caveats=["Synthetic: lookup over PAM configuration."])
              if e["evidence_type"] == "session_policy_configuration" else e for e in HANDSHAKE]
    d = by_req(run("gen-lookup-1", collector_capability_digest=declare(env, SCOPE_A, lookup)))
    idle = d[ids["idle"]]
    assert idle["outcome"] == gr.GENERATED_RULE_VALIDATED and idle["mapping_id"] is None, idle
    assert idle["waiting_for_collector"]["evidence_type"] == "session_policy_configuration"
    assert env.db.scalar("SELECT status FROM generated_rule_version WHERE rule_id=?", (idle["rule_id"],)) == "VALIDATED"
    assert not store_path.exists() or RuleStore(store_path).get_custom("acme", idle["rule_id"], "1.0") is None
    assert "session_policy_configuration" not in gr.pctx.capabilities(env.db, SCOPE_A, "acme")["evidence"]
    calls = spec_calls(model)
    d = by_req(run("gen-lookup-2", collector_capability_digest=declare(env, SCOPE_A)))  # Django now sends it
    assert d[ids["idle"]]["outcome"] == gr.GENERATED_RULE_ACTIVATED and d[ids["idle"]]["rule_id"] == idle["rule_id"]
    assert spec_calls(model) == calls  # the stored proposal was re-checked, the model was not asked again


class ReasoningLlm(s.FakeLlm):
    """A fake model that also reasons in plain text (analyse, then judge), like OllamaClient.generate_text."""

    def __init__(self, script, thinker):
        super().__init__(script)
        self.thinker = thinker
        self.text_calls: list[tuple[str, str]] = []

    def generate_text(self, system, prompt, *, max_tokens=400):
        from regintel.llm import RawOutput
        self.text_calls.append((system, prompt))
        return RawOutput(self.thinker(system, prompt))


def thinker(system, prompt):
    if system == gr.SYSTEM_ANALYSE:
        if Q["decline"] in prompt:
            return "Obligation: appoint a responsible person. No record shows that.\nVERDICT: PERSON_JUDGES"
        if Q["ticket"] in prompt:
            assert "the incident or change ticket" in prompt  # the field's meaning reaches the model
            return "A violating activation has no ticket.\nVERDICT: TESTABLE break_glass_event.ticket_reference"
        return "Unclear which field applies."
    assert system == gr.SYSTEM_JUDGE
    assert "Stated limitations" not in prompt  # the review does not weigh coverage
    if Q["idle"] in prompt:
        return "Neither record is about this.\nANSWER: NEITHER"
    # answer with the record whose ticket is empty, wherever OPM placed it
    return "The activation without a ticket breaks it.\nANSWER: " + (
        "A" if "Record A: " in prompt and "ticket_reference is empty" in prompt.split("Record B:")[0] else "B")


def test_model_analyses_then_writes_then_reviews_and_reuses_its_reasoning(gen):
    env, ids, run, _submit, model, _digest, _store = gen
    model.text_calls = []
    model.generate_text = lambda system, prompt, *, max_tokens=400: ReasoningLlm.generate_text(
        model, system, prompt, max_tokens=max_tokens)
    model.thinker = thinker
    go = run
    d = by_req(go("gen-reason-1"))
    decline = d[ids["decline"]]
    assert decline["outcome"] == "MANUAL_ASSESSMENT_REQUIRED" and "analysis" in decline["message"]
    written = [p for sy, p in model.calls if sy.startswith(gr.SYSTEM_RULESPEC)]
    assert not any(Q["decline"] in p for p in written)  # a person-judged requirement is never written as a rule
    t = d[ids["ticket"]]
    assert t["outcome"] == gr.GENERATED_RULE_ACTIVATED, t
    row = env.db.one("SELECT llm_validation FROM rule_generation_decision WHERE id=?", (t["decision_id"],))
    v = row["llm_validation"]
    assert v["analysis"]["verdict"] == "TESTABLE" and v["review"]["verdict"] == "YES"
    assert "judged_by_model" in v["checks"]
    assert any(Q["ticket"] in p and "your_analysis" in p for p in written)  # the writing step sees the analysis
    idle = d[ids["idle"]]
    assert idle["outcome"] == "RULE_SPEC_INVALID" and "review (NO)" in idle["message"], idle
    # an identical retry re-checks the stored reasoning: no new plain-text call
    calls = len(model.text_calls)
    again = by_req(go("gen-reason-2"))
    assert len(model.text_calls) == calls
    assert again[ids["ticket"]]["outcome"] == gr.GENERATED_RULE_ACTIVATED


def test_generate_rules_job_runs_generation_only_and_reports_progress(gen):
    env, ids, _run, _submit, model, digest, _store = gen
    from regintel import __main__ as cli
    extracted = env.db.scalar("SELECT COUNT(*) FROM regulatory_requirement")
    with pytest.MonkeyPatch.context() as m:
        m.setattr(cli, "_llm", lambda: nullcontext(model))
        r = env.admin.post(ADMIN + "/jobs", headers=env.h(SCOPE_A), json={
            "action": "generate_rules", "requested_framework_ids": [FW], "tenant_id": "acme",
            "auto_publish_validated_rules": True, "collector_capability_digest": digest,
            "request_key": "gen-only-job-1"})
        assert r.status_code == 202, r.text
        env.run_all()
    jid = r.json()["job"]["id"]
    job = env.admin.get(ADMIN + f"/jobs/{jid}", headers=env.h(SCOPE_A)).json()["job"]
    assert job["status"] in ("SUCCEEDED", "PARTIAL"), job["error"]
    d = by_req(job["result"])
    assert d[ids["ticket"]]["outcome"] == gr.GENERATED_RULE_ACTIVATED
    assert env.db.scalar("SELECT COUNT(*) FROM regulatory_requirement") == extracted  # nothing re-extracted
    p = env.admin.get(ADMIN + f"/jobs/{jid}/progress", headers=env.h(SCOPE_A)).json()["progress"]
    assert p["action"] == "generate_rules" and p["eta"]["percent"] == 100.0
    steps = {s["stage"]: s for s in p["completed_steps"]}
    assert steps["llm_mapping"]["unit"] == "requirements" and steps["llm_mapping"]["total"] >= len(Q)
    assert steps["propose_missing_rules"]["done"] == steps["propose_missing_rules"]["total"] > 0
    # the same gates as prepare_catalog: activation needs the pinned digest
    r = env.admin.post(ADMIN + "/jobs", headers=env.h(SCOPE_A), json={
        "action": "generate_rules", "requested_framework_ids": [FW], "tenant_id": "acme",
        "auto_publish_validated_rules": True, "request_key": "gen-only-job-2"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "CAPABILITY_DIGEST_REQUIRED"


def test_review_accepts_a_partial_rule_and_rejects_wrong_or_over_strict_ones():
    from regintel.llm import RawOutput

    class _M:
        def __init__(self, text):
            self.text = text

        def generate_text(self, *_a, **_k):
            return RawOutput(self.text)
    spec = gr.RuleSpec.model_validate(_spec(1))
    req = {"original_text": "Every emergency activation must reference a ticket."}
    passing, failing = gr.example_records(spec, {})
    assert "ticket_reference is filled in" in passing and "ticket_reference is empty" in failing
    first = gr.judge(_M("ANSWER: A"), req, spec, {}, grounded=True)
    fail_label, pass_label = first["failing_record"], "B" if first["failing_record"] == "A" else "A"
    assert first["records"][fail_label] == failing  # the order is fixed by the spec digest, not always A/B
    v = lambda t: gr.judge(_M(t), req, spec, {}, grounded=True)["verdict"]  # noqa: E731
    assert v(f"It checks one part; that record breaks it.\nANSWER: {fail_label}") == "YES"
    assert v(f"The passing one breaks it.\n**ANSWER:** {pass_label}") == "FLAGS_COMPLIANT"  # inverted rule
    assert v("Unrelated.\nANSWER: NEITHER") == "NO"
    assert v("JUDGE: YES") == "UNCLEAR"


def test_a_rule_requiring_every_account_disabled_is_rejected_but_dormant_ones_may_be():
    base = dict(pam_control_id="PAMC-ACCOUNT-LIFECYCLE", evidence_type="privileged_account",
                assessment_mode="CONFIGURATION_SNAPSHOT", subject_field="account_id",
                population={"type": "ORGANIZATION_SUPPORTED_ENTITIES", "period_field": "last_used_at", "where": []})
    alone = gr.RuleSpec.model_validate(_spec(1, **base, condition={"field": "enabled", "operator": "equals",
                                                                  "value": False}))
    assert gr.disables_every_account(alone)
    dormant = gr.RuleSpec.model_validate(_spec(1, **base, parameters={"dormant_after_days": {
        "type": "integer", "unit": "days"}}, condition={"operator": "any", "where": [
            {"field": "enabled", "operator": "equals", "value": False},
            {"field": "last_used_at", "operator": "within_last_days", "parameter": "dormant_after_days"}]}))
    assert not gr.disables_every_account(dormant)


def test_a_not_testable_analysis_that_names_a_test_field_is_written_and_judged():
    cap = {"evidence_detail": {"access_authorization": {
        "supported_fields": ["access_id", "user_id", "accessed_at", "entitlement_status"]}}}

    class _M:
        def __init__(self, text):
            self.text = text

        def generate_text(self, *_a, **_k):
            from regintel.llm import RawOutput
            return RawOutput(self.text)
    req = {"id": 1, "original_text": "Authorize access based on a valid access authorization."}
    contradicts = "A compliant record shows `entitlement_status = AUTHORIZED`.\nVERDICT: NOT_TESTABLE"
    assert gr.analyse(_M(contradicts), req, cap, ["access_authorization"])["verdict"] == "UNCLEAR"
    as_worded = ("A compliant record would show `entitlement_status` as `AUTHORIZED` alongside `access_id`.\n"
                 "VERDICT: NOT_TESTABLE")  # AC-2 i, gemma3:4b, 2026-11-20
    assert gr.analyse(_M(as_worded), req, cap, ["access_authorization"])["verdict"] == "UNCLEAR"
    declines = "This needs a documented procedure; no record shows it.\nVERDICT: NOT_TESTABLE"
    assert gr.analyse(_M(declines), req, cap, ["access_authorization"])["verdict"] == "NOT_TESTABLE"


def test_field_meanings_cover_every_field_and_a_collector_can_override_them():
    from app.models.evidence import CUSTOM_RULE_FIELDS
    for etype, fields in CUSTOM_RULE_FIELDS.items():
        missing = sorted(f for f in fields if f not in ("record_id", "scope_tags")
                         and not gr.FIELD_MEANINGS.get(etype, {}).get(f, {}).get("meaning"))
        assert not missing, (etype, missing)
    cap = {"evidence_detail": {"privileged_account": {"field_meanings": {"enabled": {"meaning": "may log in today"}}}}}
    assert gr.field_meaning(cap, "privileged_account", "enabled") == {"meaning": "may log in today"}
    assert "dormant" in gr.field_meaning({}, "privileged_account", "enabled")["shows"]


def test_screen_offers_only_evidence_types_the_requirement_speaks_to():
    detail = {"assessment_modes": ["EVENT_HISTORY"]}
    cap = {"source": "HANDSHAKE", "evidence": {"privileged_account": "1.0"}, "evidence_detail": {
        "privileged_account": {**detail, "supported_fields": ["account_id", "created_at", "enabled"]},
        "session_policy_configuration": {"assessment_modes": ["CONFIGURATION_SNAPSHOT"],
                                         "supported_fields": ["policy_id", "captured_at"],
                                         "collection_status": "LOOKUP_AVAILABLE", "schema_version": "1.0"}}}
    assert gr.relevant_evidence({"original_text": "Define and document the types of accounts allowed."}, cap) == [
        "privileged_account"]  # v1 also offered every type without keywords, here session_policy_configuration
    assert gr.relevant_evidence({"original_text": "Lock the session after 15 minutes of inactivity."}, cap) == [
        "privileged_account", "session_policy_configuration"]
    assert gr.relevant_evidence({"original_text": "Appoint a privacy officer."}, cap) == []
    from app.models.evidence import EVIDENCE_MODELS
    assert set(EVIDENCE_MODELS) <= set(gr.EVIDENCE_KEYWORDS)


def test_grammar_pairs_fields_only_with_operators_their_type_allows():
    cap = {"source": "HANDSHAKE", "evidence": {"privileged_account": "1.0"}, "evidence_detail": {"privileged_account": {
        "assessment_modes": ["EVENT_HISTORY"],
        "supported_fields": ["account_id", "scope_tags", "created_at", "enabled", "last_used_at"]}}}

    class _Db:
        def q(self, *_a, **_k):
            return [{"id": "PAMC-ACCOUNT-LIFECYCLE"}]
    branch = gr._spec_grammar(_Db(), {"id": 1}, cap, "privileged_account")

    def ops_by_field(node) -> dict[str, set[str]]:
        seen: dict[str, set[str]] = {}

        def walk(n):
            if isinstance(n, dict):
                props = n.get("properties") or {}
                if "field" in props and "operator" in props:
                    for f in props["field"].get("enum") or [props["field"]["const"]]:
                        seen.setdefault(f, set()).update(props["operator"]["enum"])
                for v in n.values():
                    walk(v)
            elif isinstance(n, list):
                for v in n:
                    walk(v)
        walk(node)
        return seen
    cond = ops_by_field(branch["properties"]["condition"])
    pop = ops_by_field(branch["properties"]["population"])
    assert "scope_tags" not in cond and "scope_tags" not in pop  # org-defined tags: the model cannot know them
    assert cond["enabled"] == {"equals", "not_equals"}
    assert not set(pop) & set(cond)  # filter and condition fields are disjoint: a filter can never be repeated
    assert set(pop) <= {"privileged"}  # population filters: scope flags only, never statuses or timestamps
    assert "account_id" not in cond  # never-null identifier: no operator tests anything on it
    assert {"older_than_days", "exists"} <= cond["last_used_at"] and "exists" not in cond["created_at"]
    assert branch["properties"]["subject_field"]["enum"] == ["account_id"]
    # datetime/integer thresholds only through a declared parameter; exists takes no value
    variants = branch["properties"]["condition"]["anyOf"][0]["anyOf"]
    def names(v):
        return v["properties"]["field"].get("enum") or [v["properties"]["field"]["const"]]
    assert all("value" not in v["required"] for v in variants if "last_used_at" in names(v))
    # a date threshold only takes a parameter in days
    [dated] = [v for v in variants if "parameter" in v["required"] and names(v) == ["last_used_at"]]
    assert dated["properties"]["parameter"]["enum"] and all(
        n.endswith("_days") for n in dated["properties"]["parameter"]["enum"])
    assert "older_than_days" not in pop.get("last_used_at", set())  # population filters take no parameters


def test_condition_that_repeats_a_population_filter_is_rejected():
    spec = gr.RuleSpec.model_validate(_spec(1, population={
        "type": "ORGANIZATION_SUPPORTED_ENTITIES", "period_field": "activated_at",
        "where": [{"field": "justification_provided", "operator": "equals", "value": True}]},
        condition={"field": "justification_provided", "operator": "equals", "value": True}))
    cap = {"source": "HANDSHAKE", "evidence": {"break_glass_event": "1.0"}, "evidence_detail": {"break_glass_event": {
        "assessment_modes": ["EVENT_HISTORY"], "supported_fields": BG_FIELDS}}}
    class _Db:
        def one(self, *_a, **_k):
            return {"id": spec.pam_control_id}
    with pytest.raises(gr.Gap, match="repeats the population filter"):
        gr.validate(spec, req={"id": 1, "original_text": "Emergency access shall be justified."}, cap=cap, db=_Db())


def test_population_filter_repeating_the_condition_is_rejected_not_repaired():
    raw = json.dumps({"requirement_id": 1, "decision": "PROPOSE", "confidence": 0.9, "rationale": "ok",
                      "rule_spec": _spec(1, population={
                          "type": "ORGANIZATION_SUPPORTED_ENTITIES", "period_field": "activated_at",
                          "where": [{"field": "justification_provided", "operator": "equals", "value": True}]},
                          condition={"field": "justification_provided", "operator": "equals", "value": True})})
    proposal_json, gap = gr._parse(raw, truncated=False)
    # left as written: removing the filter would make a stricter rule the model never stated; validate() rejects it
    assert gap is None and proposal_json["rule_spec"]["population"]["where"] != []


def test_unreferenced_parameters_are_dropped_before_schema_validation():
    params = {f"max_count_{i}": {"type": "integer", "unit": "count"} for i in range(10)}
    raw = json.dumps({"requirement_id": 1, "decision": "PROPOSE", "confidence": 0.9, "rationale": "ok",
                      "rule_spec": _spec(1, parameters=params)})
    proposal_json, _gap = gr._parse(raw, truncated=False)
    assert proposal_json is not None and proposal_json["rule_spec"]["parameters"] == {}, _gap


def test_condition_requiring_accounts_to_be_enabled_is_rejected():
    spec = gr.RuleSpec.model_validate(_spec(1, evidence_type="privileged_account", subject_field="account_id",
                                            population={"type": "ORGANIZATION_SUPPORTED_ENTITIES",
                                                        "period_field": "created_at", "where": []},
                                            condition={"field": "enabled", "operator": "equals", "value": True}))
    cap = {"source": "HANDSHAKE", "evidence": {"privileged_account": "1.0"}, "evidence_detail": {"privileged_account": {
        "assessment_modes": ["EVENT_HISTORY"], "supported_fields": ["account_id", "created_at", "enabled"]}}}

    class _Db:
        def one(self, *_a, **_k):
            return {"id": spec.pam_control_id}
    with pytest.raises(gr.Gap, match="requires accounts to be enabled"):
        gr.validate(spec, req={"id": 1, "original_text": "Create, enable, modify, disable and remove accounts."},
                    cap=cap, db=_Db())


def test_limitation_copied_from_the_worked_example_is_rejected():
    copied = next(iter(gr._EXAMPLE_LIMITATIONS))
    spec = gr.RuleSpec.model_validate(_spec(1, limitations=[copied]))
    cap = {"source": "HANDSHAKE", "evidence": {"break_glass_event": "1.0"}, "evidence_detail": {"break_glass_event": {
        "assessment_modes": ["EVENT_HISTORY"], "supported_fields": BG_FIELDS}}}

    class _Db:
        def one(self, *_a, **_k):
            return {"id": spec.pam_control_id}
    with pytest.raises(gr.Gap, match="copied from the prompt's worked example"):
        gr.validate(spec, req={"id": 1, "original_text": "Emergency access shall reference a ticket."},
                    cap=cap, db=_Db())


def test_audit_records_do_not_ground_recording_fields():
    rec = gr.RuleSpec.model_validate(_spec(1, evidence_type="privileged_session", subject_field="session_id",
                                           population={"type": "ORGANIZATION_SUPPORTED_ENTITIES",
                                                       "period_field": "started_at", "where": []},
                                           condition={"field": "recording_status", "operator": "equals",
                                                      "value": "AVAILABLE"}))
    assert gr.grounded_fields(rec, {"original_text": "Audit records contain the type of event."}) == []
    assert gr.grounded_fields(rec, {"original_text": "Record privileged sessions."}) == ["recording_status"]
    au7 = "Provide an audit record reduction and report generation capability."
    assert gr.grounded_fields(rec, {"original_text": au7}) == []
    au14 = "Provide the capability to [Selection (one or more): record; view; hear; log] the content of a session."
    assert gr.grounded_fields(rec, {"original_text": au14}) == ["recording_status"]
    assert gr.grounded_fields(rec, {"original_text": "Capture comprehensive session recordings."}) == ["recording_status"]
    ac5 = "Identify and document duties of individuals requiring separation; define access authorizations."
    assert gr.grounded_fields(auth_spec := gr.RuleSpec.model_validate(_spec(
        1, evidence_type="access_authorization", subject_field="access_id",
        population={"type": "ORGANIZATION_SUPPORTED_ENTITIES", "period_field": "accessed_at", "where": []},
        condition={"field": "entitlement_status", "operator": "equals", "value": "AUTHORIZED"})),
        {"original_text": ac5}) == [] and auth_spec
    auth = gr.RuleSpec.model_validate(_spec(1, evidence_type="access_authorization", subject_field="access_id",
                                            population={"type": "ORGANIZATION_SUPPORTED_ENTITIES",
                                                        "period_field": "accessed_at", "where": []},
                                            condition={"field": "entitlement_status", "operator": "equals",
                                                       "value": "AUTHORIZED"}))
    ia52 = "Enforce authorized access to the corresponding private key;"
    assert gr.grounded_fields(auth, {"original_text": ia52}) == []
    ac2i = "Authorize access to the system based on a valid access authorization;"
    assert gr.grounded_fields(auth, {"original_text": ac2i}) == ["entitlement_status"]


def test_inventory_file_is_accepted_as_the_handshake():
    body = json.loads((Path(__file__).resolve().parents[2] / "pam_capability_inventory.json").read_text("utf-8"))
    parsed = gr.pctx.CollectorCapabilitiesIn.model_validate(body)
    assert {e.collection_status for e in parsed.evidence} == {"COLLECTED", "LOOKUP_AVAILABLE"}


def test_interruption_between_activation_and_mapping_resumes_without_duplicates(gen, monkeypatch):
    env, ids, run, submit, _model, _digest, _store = gen
    real = catalog.create_mapping
    calls = {"n": 0}

    def crash_once(*a, **k):
        if (k.get("rule_id") or "").startswith("PAM-GEN-") and calls["n"] == 0:
            calls["n"] += 1
            raise RuntimeError("simulated worker crash after activation")
        return real(*a, **k)

    monkeypatch.setattr(catalog, "create_mapping", crash_once)
    from regintel import __main__ as cli
    with pytest.MonkeyPatch.context() as m:
        m.setattr(cli, "_llm", lambda: nullcontext(s.FakeLlm(designer)))
        r = submit("gen-crash-1")
        env.run_all()
    job = env.admin.get(ADMIN + f"/jobs/{r.json()['job']['id']}", headers=env.h(SCOPE_A)).json()["job"]
    assert job["status"] == "FAILED"
    active = env.db.q("SELECT rule_id FROM generated_rule_version WHERE status='ACTIVE'")
    assert active and env.db.scalar("SELECT COUNT(*) FROM framework_control_mapping WHERE rule_id LIKE 'PAM-GEN-%'") == 0
    d = by_req(run("gen-crash-2"))  # the retry finds the active rule and creates only the missing mapping
    assert d[ids["ticket"]]["outcome"] == gr.GENERATED_RULE_ACTIVATED
    assert env.db.scalar("SELECT COUNT(*) FROM generated_rule_version") == 2


def test_stale_collector_digest_at_activation_refuses_activation(gen, monkeypatch):
    env, ids, run, _submit, _model, digest, _store = gen
    # the declaration changes between submission and activation (Django re-declared the collector)
    real = gr.pctx.capabilities
    seen = {"n": 0}

    def drifting(db, scope, tenant):
        cap = dict(real(db, scope, tenant))
        if cap.get("digest") == digest and seen["n"] > 0:  # the submission check still sees the pinned one
            cap["digest"] = "sha256:" + "f" * 64
        seen["n"] += 1
        return cap
    monkeypatch.setattr(gr.pctx, "capabilities", drifting)
    d = by_req(run("gen-stale-1"))
    assert d[ids["ticket"]]["outcome"] == "EVIDENCE_SCHEMA_INCOMPATIBLE"
    assert "stale" in d[ids["ticket"]]["message"]
    assert env.db.scalar("SELECT COUNT(*) FROM generated_rule_version WHERE status='ACTIVE'") == 0


def test_rule_ids_are_tenant_and_value_bound():
    spec = gr.RuleSpec.model_validate(_spec(1))
    bundle = Path(__file__).resolve().parents[2] / "policy-bundle"
    a = gr.compile_spec(spec, [], scope="org-a", tenant="acme", bundle_dir=bundle)
    b = gr.compile_spec(spec, [], scope="org-b", tenant="acme", bundle_dir=bundle)
    again = gr.compile_spec(spec, [], scope="org-a", tenant="acme", bundle_dir=bundle)
    assert a["rule_id"] != b["rule_id"] and a["rule_id"] == again["rule_id"] and a["rego_digest"] == again["rego_digest"]
    idle = gr.RuleSpec.model_validate(_spec(1, **IDLE))
    v15 = gr.compile_spec(idle, [{"name": "max_idle", "value": 15}], scope="org-a", tenant="acme", bundle_dir=bundle)
    v30 = gr.compile_spec(idle, [{"name": "max_idle", "value": 30}], scope="org-a", tenant="acme", bundle_dir=bundle)
    assert v15["rule_id"] != v30["rule_id"] and v15["structure_digest"] == v30["structure_digest"]


@pytest.mark.parametrize("raw, code", [
    ('{"x": "https://example.invalid/a"}', "URL"),
    ('{"x": "{{ input.records }}"}', "TEMPLATE"),
    ('{"x": "api_key: abc123"}', "CREDENTIAL_MATERIAL"),
    ('{"x": "this rule provides full coverage"}', "COVERAGE_CLAIM"),
    ('{"x": "import data.lib"}', "EXECUTABLE_CODE"),
])
def test_forbidden_content_is_detected(raw, code):
    assert code in gr.forbidden_content(raw)


def test_valid_nested_proposals_are_not_flagged():
    raw = json.dumps({"requirement_id": 1, "decision": "PROPOSE", "confidence": 0.9, "rationale": "ok",
                      "rule_spec": _spec(1, **IDLE)})
    assert gr.forbidden_content(raw) == []
    assert "EXECUTABLE_CODE" in gr.forbidden_content("package x\nallow := true")


def test_condition_must_test_what_the_requirement_says():
    idle = gr.RuleSpec.model_validate(_spec(1, **IDLE))
    assert gr.grounded_fields(idle, {"original_text": Q["idle"]}) == ["idle_timeout_enabled", "idle_timeout_minutes"]
    # synthetic stand-in for the live failure: an account-attribute obligation "tested" by the enabled flag
    enabled = gr.RuleSpec.model_validate(_spec(1, evidence_type="privileged_account", subject_field="account_id",
                                               population={"type": "ORGANIZATION_SUPPORTED_ENTITIES",
                                                           "period_field": "created_at", "where": []},
                                               condition={"field": "enabled", "operator": "equals", "value": True}))
    assert gr.grounded_fields(enabled, {"original_text": "Specify the authorized users of each account."}) == []
    assert gr.grounded_fields(enabled, {"original_text": "Disable accounts of departed users."}) == ["enabled"]


def test_unused_parameters_are_dropped_without_changing_the_condition():
    spec = gr.RuleSpec.model_validate(_spec(1, parameters={"unused_minutes": {"type": "integer", "unit": "minutes"}}))
    out, dropped = gr.drop_unused_parameters(spec)
    assert dropped == ["unused_minutes"] and out.parameters == {} and out.condition == spec.condition
    used = gr.RuleSpec.model_validate(_spec(1, **IDLE))
    assert gr.drop_unused_parameters(used) == (used, [])


def test_trailing_model_output_after_the_first_object_is_ignored():
    # live gemma3:4b behaviour: one valid object, then a markdown repeat and prose until the output limit
    first = {"requirement_id": 7, "decision": "NO_RULE", "confidence": 0.8, "rationale": "not testable"}
    raw = json.dumps(first) + "\n```json\n{\"requirement_id\": 7}}\n```\nThe response is valid.\n" * 3
    proposal, gap = gr._parse(raw, truncated=True)
    assert gap is None and proposal["decision"] == "NO_RULE"
    # forbidden content inside the object that would be used is still caught
    bad = dict(first, rationale="use {{ input.user }} here")
    assert gr._parse(json.dumps(bad) + "\nmore", truncated=False)[1]["gap_code"] == "RULE_SPEC_INVALID"
    # a decline's filler rule_spec is ignored, not validated
    filler = dict(first, rule_spec={"description": "No rule available", "assessment_mode": ["EVENT_HISTORY"]})
    assert gr._parse(json.dumps(filler), truncated=False)[0]["decision"] == "NO_RULE"
    assert gr._parse(json.dumps(dict(filler, decision="PROPOSE")), truncated=False)[1]["gap_code"] == \
        "RULE_SPEC_INVALID"
    # an object cut off by the output limit is still rejected as truncated
    assert gr._parse(json.dumps(first)[:-5], truncated=True)[1]["gap_code"] == "LLM_OUTPUT_INVALID"


def test_generated_cases_cover_boundaries_against_real_opa():
    idle = gr.RuleSpec.model_validate(_spec(1, **IDLE))
    bundle = Path(__file__).resolve().parents[2] / "policy-bundle"
    c = gr.compile_spec(idle, [{"name": "max_idle", "value": 15}], scope="org-a", tenant="acme", bundle_dir=bundle)
    cases = gr.build_cases(idle, c["values"])
    names = {x["name"] for x in cases}
    assert "boundary_idle_timeout_minutes_less_than_or_equal" in names and "out_of_scope_entity_1" in names
    results = gr.run_cases(c["definition"], c["compiled"], cases, bundle_dir=bundle)
    assert results and all(r["passed"] for r in results), results
    # a broken compilation (inverted violation) is caught by the same cases
    broken = json.loads(json.dumps(c["compiled"]))
    for cond in broken["violation"]["conditions"]:
        cond["op"] = {"ne": "eq", "gt": "lte"}.get(cond["op"], cond["op"])
    assert not all(r["passed"] for r in gr.run_cases(c["definition"], broken, cases, bundle_dir=bundle))


def test_vector_db_interprets_and_drives_collector_capabilities(tmp_path):
    from regintel.pam_vector_db import PamVectorDatabase, generate_test_vectors, validate_test_vectors
    from .test_pam_vector_db import fixture_db
    db_path = fixture_db(tmp_path)
    with PamVectorDatabase(db_path) as database:
        # 1. Interprets metadata, models, and constants
        context = database.capability_context("password_policy_configuration")
        assert context["collection_status"] == "COLLECTED"
        assert context["model_context"][0]["present"] is True

        # 2. Generates and validates deterministic schema test vectors
        vectors = generate_test_vectors(database)
        validation = validate_test_vectors(vectors)
        assert validation["failed"] == 0
        assert validation["passed"] > 0

        # 3. Formats capabilities for OPM collector handshake
        handshake = database.to_collector_handshake()
        assert len(handshake) == 1
        assert handshake[0]["evidence_type"] == "password_policy_configuration"
        assert "min_length" in handshake[0]["supported_fields"]
