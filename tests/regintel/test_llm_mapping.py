"""LLM-assisted PAM rule assignment (llm-auto-v1) end to end through prepare_catalog.

SYNTHETIC FIXTURES: the official framework here is the synthetic SYN-EU-ACT whose page uses the
NIST SP 800-53 control layout. The control passages in ``Q`` are verbatim NIST SP 800-53 Rev. 5 text
(public domain); the capability matrix rows are short excerpts of the Securden NIST SP 800-53 control
mapping matrix (vendor capability text). The scripted model below stands in for the local LLM; it
deliberately also proposes fabricated values, which the deterministic gate must reject.
No human approval click happens anywhere in these tests."""
from __future__ import annotations

import json
import os
from contextlib import nullcontext
from datetime import timedelta
from pathlib import Path

import pytest

from regintel import catalog, extraction, llm_mapping as lm, registry
from regintel import capability_tables as ct
from . import support as s
from .test_rewrite_contract import ADMIN, CATALOG, SCOPE_A, SCOPE_B, env  # noqa: F401  (fixture)

FW = "SYN-EU-ACT"
Q = {
    "au14": "Provide and implement the capability for [Assignment: organization-defined users or roles] to "
            "[Selection (one or more): record; view; hear; log] the content of a user session under "
            "[Assignment: organization-defined circumstances];",
    "ia5f": "Changing or refreshing authenticators [Assignment: organization-defined time period by authenticator "
            "type] or when [Assignment: organization-defined events] occur;",
    "ac2_3": "Disable accounts within [Assignment: organization-defined time period] when the accounts: (a) Have "
             "expired; (b) Are no longer associated with a user or individual; (c) Are in violation of "
             "organizational policy; or (d) Have been inactive for [Assignment: organization-defined time period].",
    "ac7a": "Enforce a limit of [Assignment: organization-defined number] consecutive invalid logon attempts by a user "
            "during a [Assignment: organization-defined time period];",
    "ia21": "Implement multi-factor authentication for access to privileged accounts.",
    "ac2a": "Define and document the types of accounts allowed and specifically prohibited for use within the system;",
}
PAGE = f"""<html><body>
<h1>SYNTHETIC TEST FIXTURE - control catalog layout (not a real standard)</h1>
<p>AC-2 ACCOUNT MANAGEMENT Control: a. {Q['ac2a']} b. Assign account managers.</p>
<p>Control Enhancements: (3) ACCOUNT MANAGEMENT | DISABLE ACCOUNTS {Q['ac2_3']} Discussion: Disabling expired
accounts.</p>
<p>AC-7 UNSUCCESSFUL LOGON ATTEMPTS Control: a. {Q['ac7a']} and b. Automatically lock the account.</p>
<p>AC-11 DEVICE LOCK Control: a. Prevent further access to the system by initiating a device lock.</p>
{s.FILLER}
<p>AU-14 SESSION AUDIT Control: a. {Q['au14']} and b. Develop, integrate, and use session auditing activities in
consultation with legal counsel.</p>
<p>IA-2 IDENTIFICATION AND AUTHENTICATION (ORGANIZATIONAL USERS) Control: Uniquely identify and authenticate
organizational users.</p>
<p>Control Enhancements: (1) IDENTIFICATION AND AUTHENTICATION (ORGANIZATIONAL USERS) | MULTI-FACTOR AUTHENTICATION
TO PRIVILEGED ACCOUNTS {Q['ia21']} Discussion: Multi-factor authentication.</p>
<p>IA-5 AUTHENTICATOR MANAGEMENT Control: Manage system authenticators by: e. Changing default authenticators prior to
first use; f. {Q['ia5f']} and g. Protecting authenticator content.</p>
</body></html>"""

ROWS = [
    ("Access Control (AC)", "AC-2 Account Management", "Manage information system accounts.",
     "Automates account lifecycle management and flags dormant/abandoned accounts. Accounts that have not been used "
     "for a while can be disabled."),
    ("Access Control (AC)", "AC-7 Unsuccessful Login Attempts", "Enforce limits on consecutive invalid logon attempts.",
     "It can track invalid logon attempts, and take actions such as automatically locking accounts."),
    ("Access Control (AC)", "AC-11 Session Lock", "Lock sessions after inactivity.",
     "Idle sessions can be terminated automatically."),
    ("Identification and Authentication (IA)", "IA-2 Identification and Authentication",
     "Uniquely identify and authenticate users.", "Supports multi-factor authentication for privileged access."),
    ("Identification and Authentication (IA)", "IA-5 Authenticator Management", "Manage system authenticators.",
     "Securden enforces complex password generation and automated rotation schedules across servers, databases, "
     "and network devices."),
    ("Audit and Accountability (AU)", "AU-14 Session Audit", "Capture comprehensive session recordings.",
     "Securden records full video playbacks of RDP/VNC/Web sessions and text logs of SSH/Telnet sessions."),
    ("System and Communications Protection (SC)", "SC-8 Transmission Confidentiality", "Protect transmitted data.",
     "All traffic is encrypted with TLS."),
]
MATRIX = ("<html><body><h1>Securden Compliance Matrix: NIST SP 800-53 Control Mapping (excerpt, test fixture)</h1>"
          "<p>Securden Capability Alignment with NIST SP 800-53 controls.</p><table>"
          "<tr><th>Control Family</th><th>Control ID &amp; Title</th><th>NIST SP 800-53 Requirement</th>"
          "<th>Securden Capability Alignment</th></tr>"
          + "".join(f"<tr><td>{a}</td><td>{b}</td><td>{c}</td><td>{d}</td></tr>" for a, b, c, d in ROWS)
          + "</table>" + s.FILLER + "</body></html>")

KEYWORDS = {"PAM-SESSREC-001": "session", "PAM-ROTATION-001": "authenticators", "PAM-DORMANT-001": "inactive",
            "PAM-AUTHFAIL-001": "invalid logon", "PAM-MFAACC-001": "multi-factor"}
# What the scripted analyst "wants" to bind: honest where a source exists, fabricated where none does.
FABRICATED = {"max_rotation_age_days": (90, "REGULATORY_TEXT", "automated rotation schedules"),
              "dormant_after_days": (90, "CAPABILITY_MAPPING", "Accounts that have not been used for a while")}


def analyst(system, prompt):
    if system != lm.SYSTEM_MAP:
        return {"requirements": []}
    ctx = json.loads(prompt)
    text = ctx["requirement_text"].lower()
    rule = next((r for r in ctx["candidate_rules"] if KEYWORDS.get(r["rule_id"], "\0") in text), None)
    if rule is None:
        return {"requirement_id": ctx["requirement_id"], "decision": "NO_MAP", "confidence": 0.9,
                "rationale": "No candidate rule tests what this requirement mandates.", "limitations": []}
    offered = {v["name"]: v for v in rule["available_parameter_values"]}
    bindings = []
    for name in rule["parameters"]:
        if name in offered:
            v = offered[name]
            bindings.append({"name": name, "value": v["value"], "source_type": v["source_type"],
                             "source_document_id": v.get("source_document_id"), "quotation": v.get("quotation")})
        elif name in FABRICATED:
            value, source, quote = FABRICATED[name]
            bindings.append({"name": name, "value": value, "source_type": source, "quotation": quote})
    return {"requirement_id": ctx["requirement_id"], "decision": "MAP", "rule_id": rule["rule_id"],
            "rule_version": rule["rule_version"], "coverage": "FULL", "confidence": 0.92,
            "parameter_bindings": bindings, "evidence_type": rule["evidence_type"],
            "rationale": f"{rule['rule_id']} tests the PAM behaviour this control statement mandates for privileged "
                         "access.",
            "limitations": ["Covers privileged access managed by the PAM only."],
            "applicable_population": "Privileged accounts and sessions managed by Securden PAM."}


class Counting(s.FakeLlm):
    def map_calls(self):
        return sum(1 for system, _ in self.calls if system == lm.SYSTEM_MAP)


def official(env):
    """Global framework with reviewed official text and published requirements (no organization scope)."""
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
        section = db.scalar("SELECT id FROM document_section WHERE version_id=? AND text LIKE ?", (vid, f"%{quote[:50]}%"))
        ids[key] = extraction.add_manual_requirement(db, section_id=section, quote=quote, pam_domains=["access_control"],
                                                     obligation_type="MANDATORY", actor="alice")
        catalog.review(db, "requirement", ids[key], reviewer="bob", decision="APPROVED")
    catalog.publish_catalog(db, "bob")
    return ids


def handshake(env, scope):
    r = env.admin.put(ADMIN + "/collector-capabilities", headers=env.h(scope), json={
        "tenant_id": "acme", "collector": {"name": "securden-django", "version": "1.0"},
        "evidence": [{"evidence_type": t, "schema_version": "1.0"}
                     for t in ("credential_rotation", "privileged_account", "privileged_session")]})
    assert r.status_code == 200, r.text


@pytest.fixture
def prepared(env):  # noqa: F811
    from regintel import __main__ as cli
    ids = official(env)
    handshake(env, SCOPE_A)
    model = Counting(analyst)
    up = env.upload(MATRIX.encode(), scope=SCOPE_A, key="matrix-up-1", filename="securden-matrix.html")
    assert up.status_code == 201, up.text
    doc_ids = up.json()["document_ids"]
    requirements_before = env.db.scalar("SELECT COUNT(*) FROM regulatory_requirement")

    def run(key):
        with pytest.MonkeyPatch.context() as m:
            m.setattr(cli, "_llm", lambda: nullcontext(model))
            r = env.prepare(scope=SCOPE_A, key=key, document_ids=doc_ids, requested_framework_ids=[FW],
                            tenant_id="acme")
            assert r.status_code == 202, r.text
            env.run_all()
        job = env.admin.get(ADMIN + f"/jobs/{r.json()['job']['id']}", headers=env.h(SCOPE_A)).json()["job"]
        assert job["status"] in ("SUCCEEDED", "PARTIAL"), (job["status"], job["error"])
        return job["result"]

    return env, ids, run, model, doc_ids, requirements_before


def decisions(result):
    return {d["requirement_id"]: d for d in result["llm_mapping"]["decisions"]}


def test_matrix_rows_attach_to_official_controls_and_are_never_requirements(prepared):
    env, ids, run, _model, doc_ids, before = prepared
    result = run("llm-map-1")
    [cap] = result["capability_documents"]
    assert cap["role"] == "CAPABILITY_MAPPING" and cap["source_origin"] == "VENDOR_CAPABILITY_MAPPING"
    assert cap["framework_id"] == FW and cap["rows"] == len(ROWS)
    # no regulatory requirement, no organization framework was created from the matrix
    assert env.db.scalar("SELECT COUNT(*) FROM regulatory_requirement") == before
    assert env.db.scalar("SELECT COUNT(*) FROM regulatory_framework WHERE id LIKE 'ORG-%'") == 0
    rows = {r["control_id"]: r for r in env.db.q("SELECT * FROM capability_mapping_row WHERE organization_scope=?",
                                                  (SCOPE_A,))}
    assert len(rows) == len(ROWS)  # one row per control: no duplicates
    assert rows["AU-14"]["requirement_ids"] == [ids["au14"]] and rows["IA-5"]["requirement_ids"] == [ids["ia5f"]]
    assert set(rows["AC-2"]["requirement_ids"]) == {ids["ac2a"], ids["ac2_3"]}  # base control covers enhancements
    assert rows["AU-14"]["official_control_title"] == "SESSION AUDIT"
    assert rows["AC-11"]["resolution_status"] == "OFFICIAL_CONTROL_WITHOUT_PUBLISHED_REQUIREMENT"
    assert rows["SC-8"]["resolution_status"] == "CANONICAL_CONTROL_UNRESOLVED"
    assert all(r["source_origin"] == ct.SOURCE_ORIGIN and r["document_id"] == doc_ids[0] for r in rows.values())


def test_only_grounded_mappings_publish_and_gaps_stay_explicit(prepared):
    env, ids, run, _model, _docs, _before = prepared
    result = run("llm-map-1")
    d = decisions(result)
    # AU-14 a: boolean grounded by "full video playbacks" -> PARTIAL, organization-scoped, auto-published
    au = d[ids["au14"]]
    assert au["outcome"] == "PUBLISHABLE" and au["rule_id"] == "PAM-SESSREC-001"
    m = env.db.one("SELECT * FROM framework_control_mapping WHERE id=?", (au["mapping_id"],))
    assert m["organization_scope"] == SCOPE_A and m["published_seq"] is not None and m["coverage"] == "PARTIAL"
    assert m["rule_parameters"] == {"accept_partial_recordings": False} and m["rule_version_min"] == m["rule_version_max"]
    # no fabricated rotation or dormancy interval: the model's values are rejected
    assert d[ids["ia5f"]]["gap_code"] == "PARAMETER_SOURCE_MISSING"
    assert d[ids["ac2_3"]]["gap_code"] == "PARAMETER_SOURCE_MISSING"
    assert env.db.scalar("SELECT COUNT(*) FROM framework_control_mapping WHERE requirement_id IN (?, ?)",
                         (ids["ia5f"], ids["ac2_3"])) == 0
    # collectors not declared by Django stay explicit gaps (no MFA mapping without a collector)
    assert d[ids["ac7a"]]["gap_code"] == "COLLECTOR_MISSING" and d[ids["ia21"]]["gap_code"] == "COLLECTOR_MISSING"
    assert d[ids["ac2a"]]["gap_code"] == "LLM_NO_MAP"
    c = result["counts"]
    assert (c["mappings_published"], c["missing_parameters"], c["missing_collectors"]) == (1, 2, 2)
    assert c["llm_candidates"] >= 2 and c["capability_rows"] == len(ROWS)
    # create, review and publication are separate audit records; review origin AUTOMATED_LLM with the model
    review = env.db.one("SELECT * FROM review_approval WHERE entity_type='mapping' AND entity_id=?", (str(m["id"]),))
    assert (review["decision_origin"], review["policy_version"]) == ("AUTOMATED_LLM", lm.POLICY_VERSION)
    att = review["attestations"]
    assert att["model"] == "fake-multilingual:test" and att["model_digest"] == "sha256:fixture-weights"
    assert att["prompt_version"] == lm.PROMPT_VERSION and att["coverage_adjusted_from_full"] is True
    [prov] = att["parameter_provenance"]
    assert prov["source_type"] == "CAPABILITY_MAPPING" and prov["quotation"].lower().startswith("full video playback")
    events = [e["action"] for e in env.db.q("SELECT action FROM audit_event WHERE entity_type IN ('mapping',"
                                            "'framework_control_mapping') AND entity_id=? ORDER BY id", (str(m["id"]),))]
    assert len(events) >= 2
    assert env.db.scalar("SELECT COUNT(*) FROM catalog_publication WHERE seq=?", (m["published_seq"],)) == 1
    # every decision is visible in mapping-gaps for this organization
    gaps = env.public.get(CATALOG + f"/frameworks/{FW}/mapping-gaps", params={"tenant_id": "acme"},
                          headers=env.h(SCOPE_A)).json()
    by = {i["requirement_id"]: i for i in gaps["items"]}
    assert by[ids["ia5f"]]["llm_mapping"]["gap_code"] == "PARAMETER_SOURCE_MISSING"
    assert by[ids["au14"]]["executable_rules"] == ["PAM-SESSREC-001"]


def test_plan_isolation_and_idempotent_reruns(prepared):
    env, ids, run, model, _docs, _before = prepared
    first = run("llm-map-1")
    calls = model.map_calls()
    again = run("llm-map-2")
    assert model.map_calls() == calls  # same inputs: recorded decisions reused, no new model call
    assert again["counts"]["mappings_published"] == 0
    assert decisions(again)[ids["au14"]]["outcome"] == "EXISTING"
    assert env.db.scalar("SELECT COUNT(*) FROM framework_control_mapping WHERE requirement_id=?", (ids["au14"],)) == 1
    plan = env.public.get(CATALOG + f"/evaluation-templates/{FW}/plan", params={"tenant_id": "acme"},
                          headers=env.h(SCOPE_A))
    assert plan.status_code == 200, plan.text
    reqs = {r["requirement_id"]: r for r in plan.json()["requirements"]}
    published = env.db.q("SELECT id, requirement_id FROM framework_control_mapping WHERE organization_scope=? AND "
                         "published_seq IS NOT NULL", (SCOPE_A,))
    assert published and all(any(x["mapping_id"] == p["id"] for x in reqs[p["requirement_id"]]["mappings"])
                             for p in published)
    assert reqs[ids["au14"]]["assessment"] == "AUTOMATED"
    # another organization sees none of it: global framework, but no mapping and no LLM decision
    other = env.public.get(CATALOG + f"/evaluation-templates/{FW}/plan", params={"tenant_id": "acme"},
                           headers=env.h(SCOPE_B))
    if other.status_code == 200:
        assert {r["requirement_id"]: r for r in other.json()["requirements"]}[ids["au14"]]["assessment"] == "UNMAPPED"
    gaps_b = env.public.get(CATALOG + f"/frameworks/{FW}/mapping-gaps", headers=env.h(SCOPE_B)).json()
    assert all("llm_mapping" not in i and i["executable_rules"] == [] for i in gaps_b["items"])
    assert first["llm_mapping"]["model_digest"] == "sha256:fixture-weights"


def test_pam_configuration_grounds_customer_policy_thresholds(prepared):
    env, ids, run, _model, _docs, _before = prepared
    run("llm-map-1")
    body = {"tenant_id": "acme", "collector": {"name": "securden-django", "version": "1.0"},
            "captured_at": "2026-11-10T08:00:00Z", "verified": True,
            "settings": [{"rule_id": "PAM-ROTATION-001", "parameter": "max_rotation_age_days", "value": 30,
                          "setting_reference": "Rotation policy 'Privileged default' > interval"}]}
    assert env.admin.put(ADMIN + "/pam-configuration", headers=env.h(SCOPE_A),
                         json={**body, "verified": False}).status_code == 422  # typed-in values are not evidence
    bad = {**body, "settings": [{**body["settings"][0], "value": 5000}]}
    assert env.admin.put(ADMIN + "/pam-configuration", headers=env.h(SCOPE_A), json=bad).status_code == 422
    snap = env.admin.put(ADMIN + "/pam-configuration", headers=env.h(SCOPE_A), json=body)
    assert snap.status_code == 201, snap.text
    assert snap.json()["pam_configuration"]["provenance"] == "CUSTOMER_POLICY"
    assert env.admin.get(ADMIN + "/pam-configuration", params={"tenant_id": "acme"},
                         headers=env.h(SCOPE_B)).status_code in (403, 404)
    result = run("llm-map-3")  # new inputs (configuration snapshot): a new decision is taken
    rot = decisions(result)[ids["ia5f"]]
    assert rot["outcome"] == "PUBLISHABLE" and rot["rule_version"] == "1.1"
    m = env.db.one("SELECT * FROM framework_control_mapping WHERE id=?", (rot["mapping_id"],))
    assert m["rule_parameters"] == {"max_rotation_age_days": 30} and m["organization_scope"] == SCOPE_A
    assert "not a regulatory threshold" in m["limitations"]
    review = env.db.one("SELECT attestations FROM review_approval WHERE entity_type='mapping' AND entity_id=?",
                        (str(m["id"]),))
    [prov] = review["attestations"]["parameter_provenance"]
    assert (prov["provenance"], prov["source_type"]) == ("CUSTOMER_POLICY", "PAM_CONFIGURATION")
    assert prov["assessment_basis"] == "CONFIGURATION_OBSERVED_AT_CAPTURE"
    assert result["counts"]["mappings_published"] == 1  # AU-14 from the first run is reused, not re-created


def test_a_value_that_differs_from_the_verifiable_source_is_rejected(prepared):
    env, ids, _run, _model, _docs, _before = prepared
    snap = env.admin.put(ADMIN + "/pam-configuration", headers=env.h(SCOPE_A), json={
        "tenant_id": "acme", "collector": {"name": "securden-django", "version": "1.0"},
        "captured_at": "2026-11-10T08:00:00Z", "verified": True,
        "settings": [{"rule_id": "PAM-ROTATION-001", "parameter": "max_rotation_age_days", "value": 30,
                      "setting_reference": "Rotation policy 'Privileged default' > interval"}]})
    assert snap.status_code == 201, snap.text

    def stubborn(system, prompt):  # ignores the offered 30 and binds 90 "from the regulation"
        out = analyst(system, prompt)
        for b in out.get("parameter_bindings", []):
            if b["name"] in FABRICATED:
                b["value"], b["source_type"], b["quotation"] = FABRICATED[b["name"]]
        return out

    from regintel import __main__ as cli
    with pytest.MonkeyPatch.context() as m:
        m.setattr(cli, "_llm", lambda: nullcontext(Counting(stubborn)))
        r = env.prepare(scope=SCOPE_A, key="llm-map-stubborn", document_ids=_docs, requested_framework_ids=[FW],
                        tenant_id="acme")
        env.run_all()
    job = env.admin.get(ADMIN + f"/jobs/{r.json()['job']['id']}", headers=env.h(SCOPE_A)).json()["job"]
    rot = decisions(job["result"])[ids["ia5f"]]
    assert rot["gap_code"] == "SOURCE_GROUNDING_FAILED"
    assert env.db.scalar("SELECT COUNT(*) FROM framework_control_mapping WHERE requirement_id=?", (ids["ia5f"],)) == 0


SETTINGS = {"tenant_id": "acme", "title": "Organization PAM settings",
            "policy_reference": {"title": "Organization PAM settings (synthetic test fixture)"},
            "effective_from": "2026-01-01T00:00:00.000000Z"}


def _rotation(days):
    return [{"control_id": "PC-CRED-ROTATION", "control_version": "1.0",
             "parameters": {"max_rotation_age_days": days}, "targets": [{"type": "ORGANIZATION"}]}]


def _live(env, rid):
    return env.db.q("SELECT * FROM framework_control_mapping WHERE requirement_id=? AND status IN ('DRAFT','APPROVED')",
                    (rid,))


def test_organization_settings_ground_values_and_a_settings_change_reassigns(prepared):
    """DJANGO_CONTRACT §5.3: the settings form is an organization policy context. A confirmed section's value
    grounds an organization-defined parameter; an unconfirmed (absent) one stays PARAMETER_SOURCE_MISSING; a
    new settings version replaces the automatic mapping instead of conflicting with it."""
    env, ids, run, _model, _docs, _before = prepared
    assert decisions(run("llm-map-1"))[ids["ia5f"]]["gap_code"] == "PARAMETER_SOURCE_MISSING"
    r = env.admin.post(ADMIN + "/policy-contexts", headers=env.h(SCOPE_A),
                       json={**SETTINGS, "request_key": "org-settings-0001", "controls": _rotation(60)})
    assert r.status_code == 201, r.text
    ctx, v1 = r.json()["policy_version"]["policy_context_id"], r.json()["policy_version"]["policy_version_id"]

    rot = decisions(run("llm-map-2"))[ids["ia5f"]]
    assert rot["outcome"] == "PUBLISHABLE", rot
    [m] = _live(env, ids["ia5f"])
    assert m["rule_parameters"] == {"max_rotation_age_days": 60} and m["organization_scope"] == SCOPE_A
    review = env.db.one("SELECT attestations FROM review_approval WHERE entity_type='mapping' AND entity_id=?",
                        (str(m["id"]),))
    [prov] = review["attestations"]["parameter_provenance"]
    assert (prov["provenance"], prov["source_type"], prov["policy_version_id"]) == ("CUSTOMER_POLICY",
                                                                                    "POLICY_DOCUMENT", v1)
    # the dormancy section was never confirmed (not in the policy): still an explicit gap, nothing invented
    assert decisions(run("llm-map-2b"))[ids["ac2_3"]]["gap_code"] == "PARAMETER_SOURCE_MISSING"

    r = env.admin.post(ADMIN + f"/policy-contexts/{ctx}/versions", headers=env.h(SCOPE_A),
                       json={**SETTINGS, "request_key": "org-settings-0002", "supersedes_version": 1,
                             "controls": _rotation(45)})
    assert r.status_code == 201, r.text
    rot = decisions(run("llm-map-3"))[ids["ia5f"]]
    assert rot["outcome"] == "PUBLISHABLE", rot
    [m2] = _live(env, ids["ia5f"])
    assert m2["rule_parameters"] == {"max_rotation_age_days": 45} and m2["id"] != m["id"]
    old = env.db.one("SELECT status FROM framework_control_mapping WHERE id=?", (m["id"],))
    assert old["status"] == "WITHDRAWN"
    gaps = env.public.get(CATALOG + f"/frameworks/{FW}/mapping-gaps", params={"tenant_id": "acme"},
                          headers=env.h(SCOPE_A)).json()
    item = {i["requirement_id"]: i for i in gaps["items"]}[ids["ia5f"]]
    assert item["executable_rules"] == ["PAM-ROTATION-001"]
    assert item["llm_mapping"]["outcome"] == "PUBLISHABLE"
    assert rot["replaced_mapping_ids"] == [m["id"]]

    # the passwords section is un-confirmed (left out of the next version): the mapping is withdrawn, not kept
    review_only = [{"control_id": "PC-ACCESS-REVIEW", "control_version": "1.0",
                    "parameters": {"review_interval_days": 90}, "targets": [{"type": "ORGANIZATION"}]}]
    r = env.admin.post(ADMIN + f"/policy-contexts/{ctx}/versions", headers=env.h(SCOPE_A),
                       json={**SETTINGS, "request_key": "org-settings-0003", "supersedes_version": 2,
                             "controls": review_only})
    assert r.status_code == 201, r.text
    rot = decisions(run("llm-map-4"))[ids["ia5f"]]
    assert rot["gap_code"] == "PARAMETER_SOURCE_MISSING" and rot["withdrawn_mapping_ids"] == [m2["id"]]
    assert _live(env, ids["ia5f"]) == []


def test_stated_values_constrain_overrides_in_the_stricter_direction():
    """A value stated by the standard caps 'max_*' limits and floors 'min_*' and window parameters."""
    spec = type("P", (), {"minimum": 1, "maximum": 2000})()
    assert lm.override_constraint("max_rotation_age_days", 60, spec) == {"min": 1, "max": 60}
    assert lm.override_constraint("min_justification_length", 40, spec) == {"min": 40, "max": 2000}
    assert lm.override_constraint("window_minutes", 15, spec) == {"min": 15, "max": 2000}
    # parameters with no reliable unit in prose are never read from the text
    assert lm.TEXT_UNITS.get("min_justification_length") is None
    assert lm.TEXT_UNITS.get("min_completeness_percent") is None
    assert lm.TEXT_UNITS["max_idle_minutes"] == "minutes"


@pytest.mark.opa
def test_published_llm_mapping_executes_deterministically_in_opa(prepared, client):
    """The AU-14 mapping's bound parameters drive the real OPA rule: same evidence, same decision."""
    from ..helpers import auth, recent_period, request, session

    env, ids, run, _model, _docs, _before = prepared
    result = run("llm-map-1")
    m = env.db.one("SELECT * FROM framework_control_mapping WHERE id=?", (decisions(result)[ids["au14"]]["mapping_id"],))
    start, end = recent_period()
    at = end - timedelta(days=2)
    records = [session(1, started=at), session(2, started=at, status="PARTIAL")]

    def evaluate(recs):
        r = client.post("/api/v1/evaluate", headers=auth(), json=request(
            "tenant-a", m["rule_id"], m["evidence_type"], recs, period=(start, end),
            policy_settings={"parameters": m["rule_parameters"]}))
        assert r.status_code == 200, r.text
        return r.json()

    first, second = evaluate(records), evaluate(list(reversed(records)))
    assert first["status"] == second["status"] == "FAIL"  # partial recording rejected: strict reading bound
    assert sorted(map(str, first["violations"])) == sorted(map(str, second["violations"]))


@pytest.mark.skipif(not os.environ.get("OPM_TEST_SECURDEN_MATRIX"), reason="set OPM_TEST_SECURDEN_MATRIX to the PDF")
def test_real_securden_matrix_pdf_extracts_official_rows():
    rows = ct.extract_rows(Path(os.environ["OPM_TEST_SECURDEN_MATRIX"]).read_bytes(), "pdf")
    ids = [r["control_id"] for r in rows]
    assert len(ids) == len(set(ids)) and {"AC-2", "AC-7", "IA-5", "AU-14"} <= set(ids)
    au = next(r for r in rows if r["control_id"] == "AU-14")
    assert "full video playbacks" in au["capability_text"]
    assert next(r for r in rows if r["control_id"] == "AC-7")["control_title"] == "Unsuccessful Login Attempts"


def test_validation_rejects_arbitrary_rules_and_versions():
    class Spec:
        status, evidence_type, parameters = "ACTIVE", "privileged_session", {}

    class Engine:
        rules = {"PAM-SESSREC-001": {"1.0": Spec()}}

    req = {"id": 7, "original_text": "x", "organization_scope": None}
    base = dict(requirement_id=7, decision="MAP", confidence=0.95, rationale="r" * 50, limitations=["l"],
                applicable_population="p", coverage="PARTIAL")
    kw = dict(req=req, ref={"canonical_id": "AU-14", "clause": "a"}, cands=["PAM-SESSREC-001"], engine=Engine(),
              cap={"source": "HANDSHAKE"}, collected=("PAM-SESSREC-001",), resolved={"PAM-SESSREC-001": []},
              rows=[], existing=[], scope=SCOPE_A)
    gate = lambda **p: lm.validate(None, proposal=lm.Proposal(**{**base, **p}), **kw)  # noqa: E731
    assert gate(rule_id="PAM-EVIL-001", rule_version="1.0")["gap_code"] == "NO_EXECUTABLE_RULE"
    assert gate(rule_id="PAM-SESSREC-001", rule_version="9.9")["gap_code"] == "RULE_VERSION_INVALID"
    assert gate(rule_id="PAM-SESSREC-001", rule_version="1.0", confidence=0.5)["gap_code"] == "LLM_MAPPING_AMBIGUOUS"
    assert gate(rule_id="PAM-SESSREC-001", rule_version="1.0", requirement_id=8)["gap_code"] == "LLM_OUTPUT_INVALID"
    assert gate(rule_id="PAM-SESSREC-001", rule_version="1.0", applicable_population=None)["gap_code"] == \
        "VALIDATION_FAILED"
    with pytest.raises(Exception):
        lm.Proposal(**{**base, "rule_id": "PAM-SESSREC-001", "rego": "allow { true }"})  # no code fields exist
