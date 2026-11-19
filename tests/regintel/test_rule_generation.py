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
    "unknown_op": "Privileged accounts shall carry an owner identifier matching the approved naming pattern.",
    "invented": "Privileged session policies shall enforce a short idle timeout.",
    "mfa": "Privileged access shall be granted only after multi-factor authentication succeeded.",
    "review": "Every emergency privileged access activation shall be reviewed after use.",
    "decline": "The organization shall appoint a person responsible for privileged access governance.",
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
