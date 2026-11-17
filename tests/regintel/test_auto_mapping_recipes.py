"""prepare_catalog end to end with deterministic mapping recipes (policy auto-v3).

SYNTHETIC FIXTURE: a tailored baseline in NIST SP 800-53 layout in which an organization has
filled in some of its organization-defined values. It is not the official standard (the official
text leaves these values as [Assignment: ...]) and is never published as real coverage.
No human approval click happens anywhere in these tests."""
from __future__ import annotations

from contextlib import nullcontext

import pytest

from regintel import automation, mapping_recipes as mr
from . import support as s
from .test_rewrite_contract import ADMIN, CATALOG, SCOPE_A, SCOPE_B, env  # noqa: F401  (fixture)

Q = {
    "ia5f": "Changing or refreshing authenticators of privileged accounts every 60 days;",
    "au14": "Provide and implement the capability for security administrators to record the content of every "
            "privileged user session;",
    "ac2_3": "Disable accounts within 1 day when the accounts: (a) Have expired; (b) Are no longer associated with a "
             "user or individual; (c) Are in violation of organizational policy; or (d) Have been inactive for 90 days.",
    "ac2j": "Review privileged accounts for compliance with account management requirements every 90 days;",
    "ac7a": "Enforce a limit of [Assignment: organization-defined number] consecutive invalid logon attempts by a user "
            "during a [Assignment: organization-defined time period];",
    "ia21": "Implement multi-factor authentication for access to privileged accounts.",
    "licence": "This publication is available free of charge from the issuing organization.",
}
THRESHOLDS = {"ia5f": ["60 days"], "ac2j": ["90 days"]}
DOC = f"""<html><body>
<h1>SYNTHETIC TEST FIXTURE - tailored control baseline in NIST SP 800-53 layout (not the official standard)</h1>
<h2>Notices</h2>
<p>{Q['licence']}</p>
<h2>AC family</h2>
<p>AC-2 ACCOUNT MANAGEMENT Control: a. Define and document the types of accounts allowed; and j. {Q['ac2j']} k.
Establish a process for changing shared account authenticators.</p>
<p>Control Enhancements: (3) ACCOUNT MANAGEMENT | DISABLE ACCOUNTS {Q['ac2_3']} Discussion: Disabling expired
accounts.</p>
<p>AC-7 UNSUCCESSFUL LOGON ATTEMPTS Control: a. {Q['ac7a']} and b. Automatically lock the account.</p>
<h2>AU family</h2>
<p>AU-14 SESSION AUDIT Control: a. {Q['au14']} and b. Develop session auditing activities with legal counsel.</p>
<h2>IA family</h2>
<p>IA-2 IDENTIFICATION AND AUTHENTICATION (ORGANIZATIONAL USERS) Control: Uniquely identify and authenticate
organizational users.</p>
<p>Control Enhancements: (1) IDENTIFICATION AND AUTHENTICATION (ORGANIZATIONAL USERS) | MULTI-FACTOR AUTHENTICATION
TO PRIVILEGED ACCOUNTS {Q['ia21']} Discussion: Multi-factor authentication.</p>
<p>IA-5 AUTHENTICATOR MANAGEMENT Control: Manage system authenticators by: e. Changing default authenticators prior to
first use; f. {Q['ia5f']} and g. Protecting authenticator content.</p>
{s.FILLER}
</body></html>"""


def llm() -> s.FakeLlm:
    def script(system, prompt):
        if system == automation.SYSTEM_REVIEW:
            return {"verdict": "APPROVE", "reasons": [],
                    "checks": {"quote_supported": True, "obligation_type_correct": True,
                               "thresholds_grounded": True, "domains_relevant": True}}
        return {"requirements": [s.candidate(q, domains=("access_control",), thresholds=THRESHOLDS.get(k, ()))
                                 for k, q in Q.items() if q in prompt]}
    return s.FakeLlm(script)


@pytest.fixture
def prepared(env):  # noqa: F811
    from regintel import __main__ as cli
    with pytest.MonkeyPatch.context() as m:
        m.setattr(cli, "_llm", lambda: nullcontext(llm()))
        ids = env.upload(DOC.encode(), scope=SCOPE_A, key="nist-auto-up", filename="baseline.html").json()["document_ids"]
        r = env.prepare(scope=SCOPE_A, key="nist-auto-1", document_ids=ids)
        assert r.status_code == 202, r.text
        env.run_all()
    job = env.admin.get(ADMIN + f"/jobs/{r.json()['job']['id']}", headers=env.h(SCOPE_A)).json()["job"]
    assert job["status"] in ("SUCCEEDED", "PARTIAL"), (job["status"], job["error"])
    return env, job["result"]


def req_ids(env, quote_keys):
    return {k: env.db.scalar("SELECT id FROM regulatory_requirement WHERE original_text=?", (Q[k],)) for k in quote_keys}


def test_prepare_catalog_publishes_only_fully_grounded_mappings(prepared):
    env, result = prepared
    ids = req_ids(env, Q)
    licence = env.db.one("SELECT status, published_seq FROM regulatory_requirement WHERE id=?", (ids["licence"],))
    assert licence["published_seq"] is None and licence["status"] != "APPROVED"  # licensing text: never published
    assert env.db.scalar("SELECT COUNT(*) FROM framework_control_mapping WHERE requirement_id=?", (ids["licence"],)) == 0
    assert result["counts"]["requirements_published"] == 6
    mappings = result["mappings"]
    assert mappings["policy_version"] == "auto-v3" and mappings["recipe_set_version"] == mr.RECIPE_SET_VERSION
    made = {m["requirement_id"]: m for m in mappings["prepared"] if not m.get("existing")}
    assert set(made) == {ids["ia5f"], ids["au14"]}
    rot, rec = made[ids["ia5f"]], made[ids["au14"]]
    assert (rot["recipe_id"], rot["rule_id"], rot["rule_version"], rot["parameters"]) == (
        "NIST-IA-5-f", "PAM-ROTATION-001", "1.1", {"max_rotation_age_days": 60})
    assert (rec["recipe_id"], rec["rule_id"], rec["parameters"]) == (
        "NIST-AU-14-a", "PAM-SESSREC-001", {"accept_partial_recordings": False})
    assert all(m["coverage"] == "PARTIAL" and m["decision_origin"] == "AUTOMATED" for m in made.values())
    # every other requirement is a structured NOT_MAPPED decision
    decisions = {d["requirement_id"]: d for d in mappings["decisions"]}
    assert decisions[ids["ac2_3"]]["code"] == mr.PARAMETER_NOT_SOURCE_GROUNDED  # 1 day AND 90 days: ambiguous value
    assert decisions[ids["ac2j"]]["code"] == "COLLECTOR_MISSING" and decisions[ids["ac2j"]]["rule_id"] == "PAM-REVIEW-001"
    assert decisions[ids["ac7a"]]["code"] == "COLLECTOR_MISSING"  # then POLICY_CONTEXT_REQUIRED once collected
    assert decisions[ids["au14"]]["decision"] == "PROPOSED"
    assert decisions[ids["ia21"]]["code"] == "COLLECTOR_MISSING" and decisions[ids["ia21"]]["rule_id"] == "PAM-MFAACC-001"
    recipes = {x["recipe_id"]: x["support_status"] for x in mappings["recipes"]}
    assert recipes["NIST-IA-5-f"] == recipes["NIST-AU-14-a"] == "SUPPORTED"
    assert recipes["NIST-IA-2-MFA"] == "COLLECTOR_UNAVAILABLE"  # support is never claimed without a collector
    gaps = {g["requirement_id"]: g for g in result["mapping_gaps"]}
    assert gaps[ids["ac2j"]]["auto_mapping"]["code"] == "COLLECTOR_MISSING"
    assert gaps[ids["ia5f"]]["auto_mapping"]["decision"] == "EXISTING"
    # recorded decision: AUTOMATED origin, policy version, source requirement, rule version, parameters, limitations
    review = env.db.one("SELECT * FROM review_approval WHERE entity_type='mapping' AND entity_id=?",
                        (str(rot["mapping_id"]),))
    assert (review["decision"], review["decision_origin"], review["policy_version"]) == ("APPROVED", "AUTOMATED",
                                                                                         "auto-v3")
    att = review["attestations"]
    assert att["source_requirement"]["requirement_id"] == ids["ia5f"]
    assert (att["source_requirement"]["canonical_id"], att["source_requirement"]["clause"]) == ("IA-5", "f")
    assert att["rule_version"] == "1.1" and att["parameter_provenance"][0]["source_text"] == "60 days"
    assert att["coverage"] == "PARTIAL" and att["limitations"].startswith("PARTIAL")
    row = env.db.one("SELECT * FROM framework_control_mapping WHERE id=?", (rot["mapping_id"],))
    assert row["published_seq"] is not None and row["rule_version_min"] == row["rule_version_max"] == "1.1"
    assert [r["readiness"] for r in result["readiness"]] == ["PARTIAL"]


def test_published_mappings_appear_in_the_plan_without_approval_clicks(prepared):
    env, result = prepared
    ids = req_ids(env, ("ia5f", "au14", "ac2j"))
    fw_id = result["frameworks"][0]["framework_id"]
    plan = env.public.get(CATALOG + f"/evaluation-templates/{fw_id}/plan", params={"tenant_id": "acme"},
                          headers=env.h(SCOPE_A))
    assert plan.status_code == 200, plan.text
    body = plan.json()
    assert body["readiness"] == "PARTIAL"
    by_rule = {e["rule_id"]: e for e in body["executions"]}
    assert set(by_rule) == {"PAM-ROTATION-001", "PAM-SESSREC-001"}
    assert by_rule["PAM-ROTATION-001"]["rule_version"] == "1.1"
    reqs = {r["requirement_id"]: r for r in body["requirements"]}
    assert reqs[ids["ia5f"]]["assessment"] == "AUTOMATED" and reqs[ids["au14"]]["assessment"] == "AUTOMATED"
    assert reqs[ids["ac2j"]]["assessment"] == "UNMAPPED"
    assert reqs[ids["ia5f"]]["technical_coverage"] == "PARTIAL" and reqs[ids["ia5f"]]["execution_ids"]
    mapping = reqs[ids["ia5f"]]["mappings"][0]
    assert mapping["execution_id"] in reqs[ids["ia5f"]]["execution_ids"] and mapping["mapping_id"]
    # never human: no review row of these mappings has a human origin
    assert env.db.scalar("SELECT COUNT(*) FROM review_approval WHERE entity_type='mapping' "
                         "AND decision_origin<>'AUTOMATED'") == 0
    # scoped: another organization sees neither the framework nor its plan
    assert env.public.get(CATALOG + f"/evaluation-templates/{fw_id}/plan", params={"tenant_id": "acme"},
                          headers=env.h(SCOPE_B)).status_code == 404


def test_rerun_is_idempotent_and_conflicts_are_kept(prepared):
    env, result = prepared
    ids = req_ids(env, ("ia5f",))
    again = automation.prepare_mappings(env.db, env.admin.app.state.engine, [ids["ia5f"]], actor="bot")
    assert [m.get("existing") for m in again["prepared"]] == [True]
    # a different live mapping on the same requirement (here a person's MANUAL draft) is a conflict, never replaced
    from regintel import catalog
    control = env.db.scalar("SELECT pam_control_id FROM opa_rule_definition WHERE rule_id='PAM-REVIEW-001'")
    manual = catalog.create_mapping(env.db, requirement_id=ids["ia5f"], assessment="MANUAL", pam_control_id=control,
                                    rationale="Synthetic reviewer note: assessed by interview.",
                                    limitations="Manual assessment only.", actor="alice")
    conflict = automation.prepare_mappings(env.db, env.admin.app.state.engine, [ids["ia5f"]], actor="bot")
    [d] = conflict["decisions"]
    assert d["code"] == mr.MAPPING_CONFLICT and d["conflicting_mapping_ids"] == [manual]
    assert conflict["prepared"] == []
