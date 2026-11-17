"""Catalog-style standards (NIST SP 800-53 layout): canonical control references derived from
source headings, organization-defined parameters, honest gap codes, and the public
mapping-gaps / control-coverage reads. SYNTHETIC FIXTURE page modelled on the layout only;
the quoted passages in ``Q`` are verbatim NIST SP 800-53 Rev. 5 control text (public domain,
same wording as the published catalog requirements 299, 304, 326, 354, 360, 372), but the
fixture framework is synthetic and is never published as real coverage."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.models.common import format_utc
from regintel import automation, catalog, control_ids, extraction, mapping_policy as mp, registry
from regintel.admin_api import create_admin_app
from ..conftest import BUNDLE, OPA_TOKEN
from . import support as s
from .test_policy_contexts import CATALOG, P_START, PERIOD, SCOPE_A, SCOPE_B, Env, control, credentials

FW = "SYN-EU-ACT"  # the synthetic source document belongs to this framework
Q = {
    "ac2a": "Define and document the types of accounts allowed and specifically prohibited for use within the system;",
    "ac2i": "Authorize access to the system based on: 1. A valid access authorization; 2. Intended system usage; and "
            "3. [Assignment: organization-defined attributes (as required)];",
    "ac2disc": "Examples of system account types include individual, shared, group, system, guest, and temporary.",
    "ac2_2": "Automatically [Selection: remove; disable] temporary and emergency accounts after [Assignment: "
             "organization-defined time period for each type of account].",
    "ac7a": "Enforce a limit of [Assignment: organization-defined number] consecutive invalid logon attempts by a user "
            "during a [Assignment: organization-defined time period];",
    "au14": "Provide and implement the capability for [Assignment: organization-defined users or roles] to "
            "[Selection (one or more): record; view; hear; log] the content of a user session under "
            "[Assignment: organization-defined circumstances];",
    "ia5i": "Changing authenticators for group or role accounts when membership to those accounts changes.",
    "ia26": "Implement multi-factor authentication for [Selection (one or more): local; network; remote] access to "
            "[Selection (one or more): privileged accounts; non-privileged accounts] such that: (a) One of the factors "
            "is provided by a device separate from the system gaining access; and (b) The device meets [Assignment: "
            "organization-defined strength of mechanism requirements].",
}
PAGE = f"""<html><body>
<h1>SYNTHETIC TEST FIXTURE - control catalog layout (not a real standard)</h1>
<h2>page 46</h2>
<p>AC-2 ACCOUNT MANAGEMENT Control: a. {Q['ac2a']} b. Assign account managers; and i. {Q['ac2i']} j. Review
accounts for compliance with account management requirements.</p>
<p>Discussion: {Q['ac2disc']} Related Controls: AC-3.</p>
{s.FILLER}
<h2>page 47</h2>
<p>Control Enhancements: (1) ACCOUNT MANAGEMENT | AUTOMATED SYSTEM ACCOUNT MANAGEMENT Support the management of
system accounts using automated mechanisms. (2) ACCOUNT MANAGEMENT | AUTOMATED TEMPORARY AND EMERGENCY ACCOUNT
MANAGEMENT {Q['ac2_2']} Discussion: Management of temporary accounts.</p>
<h2>page 66</h2>
<p>AC-7 UNSUCCESSFUL LOGON ATTEMPTS Control: a. {Q['ac7a']} and b. Automatically lock the account when the maximum
number of unsuccessful attempts is exceeded.</p>
<p>AC-11 DEVICE LOCK Control: a. Prevent further access to the system by initiating a device lock after a period of
inactivity.</p>
<h2>page 107</h2>
<p>AU-14 SESSION AUDIT Control: a. {Q['au14']} and b. Develop, integrate, and use session auditing activities in
consultation with legal counsel.</p>
<h2>page 159</h2>
<p>IA-2 IDENTIFICATION AND AUTHENTICATION (ORGANIZATIONAL USERS) Control: Uniquely identify and authenticate
organizational users and associate that unique identification with processes acting on behalf of those users.</p>
<h2>page 160</h2>
<p>Control Enhancements: (6) IDENTIFICATION AND AUTHENTICATION (ORGANIZATIONAL USERS) | ACCESS TO ACCOUNTS —
SEPARATE DEVICE {Q['ia26']} Discussion: The purpose of requiring a device that is separate from the system.</p>
<h2>page 165</h2>
<p>IA-5 AUTHENTICATOR MANAGEMENT Control: Manage system authenticators by: h. Requiring individuals to protect
authenticators; and i. {Q['ia5i']}</p>
</body></html>"""


def build(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db)
    s.sync(db, {f"https://{s.DOMAIN}/act/en": PAGE}, tmp_path)
    vid = db.scalar("SELECT MAX(id) FROM regulatory_document_version")
    catalog.review_document_version(db, vid, reviewer="bob", decision="APPROVED", published_on="2024-01-15",
                                    effective_from="2025-01-01")
    registry.verify_framework(db, FW, reviewer="bob", evidence_version_id=vid, lifecycle="IN_FORCE",
                              published_on="2024-01-15", effective_from="2025-01-01")
    ids = {}
    for key, quote in Q.items():
        section = db.scalar("SELECT id FROM document_section WHERE version_id=? AND text LIKE ?",
                            (vid, f"%{quote[:50]}%"))
        assert section, key
        ids[key] = extraction.add_manual_requirement(db, section_id=section, quote=quote, pam_domains=["access_control"],
                                                     obligation_type="MANDATORY", actor="alice")
        catalog.review(db, "requirement", ids[key], reviewer="bob", decision="APPROVED")
    catalog.publish_catalog(db, "bob")
    path, headers = credentials(tmp_path)
    common = dict(api_clients_file=path, catalog_db_path=Path(db.path), policy_bundle_dir=BUNDLE)
    admin = create_admin_app(Settings(**common, catalog_jobs_db_path=tmp_path / "jobs.db",
                                      catalog_upload_dir=tmp_path / "uploads"), start_worker=False)
    public = create_app(Settings(**common, opa_url="http://127.0.0.1:9", opa_token=OPA_TOKEN,
                                 db_path=tmp_path / "opm.db", log_level="WARNING", trust_proxy_headers=False,
                                 opa_connect_timeout_seconds=0.5))
    return admin, public, db, ids, headers


@pytest.fixture
def env(tmp_path):
    admin, public, db, ids, headers = build(tmp_path)
    with TestClient(admin) as a, TestClient(public) as p:
        yield Env(a, p, db, ids, headers)
    db.close()


def gaps_of(body, rid):
    item = next(i for i in body["items"] if i["requirement_id"] == rid)
    return item, [(g["code"], g.get("rule_id")) for g in item["gaps"]]


def test_canonical_references_come_from_source_headings(env):
    reqs = env.db.q("SELECT * FROM regulatory_requirement WHERE framework_id=?", (FW,))
    refs = {r["id"]: r for r in reqs}
    got = control_ids.annotate(env.db, reqs)
    by_key = {k: got[env.ids[k]] for k in Q}
    assert {k: (v["canonical_id"], v["clause"], v["location"]) for k, v in by_key.items()} == {
        "ac2a": ("AC-2", "a", "CONTROL_STATEMENT"), "ac2i": ("AC-2", "i", "CONTROL_STATEMENT"),
        "ac2disc": ("AC-2", None, "DISCUSSION"), "ac2_2": ("AC-2(2)", None, "CONTROL_STATEMENT"),
        "ac7a": ("AC-7", "a", "CONTROL_STATEMENT"), "au14": ("AU-14", "a", "CONTROL_STATEMENT"),
        "ia5i": ("IA-5", "i", "CONTROL_STATEMENT"), "ia26": ("IA-2(6)", None, "CONTROL_STATEMENT")}
    assert by_key["ac2_2"]["enhancement_title"] == "AUTOMATED TEMPORARY AND EMERGENCY ACCOUNT MANAGEMENT"
    # derived only: the stored page references are untouched
    assert all(refs[env.ids[k]]["section_ref"].startswith("#") for k in Q)
    report = control_ids.coverage_report(env.db, FW)
    [v] = report["versions"]
    assert "AC-11" in v["omitted_controls_in_families"] and "AC-2(1)" in v["omitted_controls_in_families"]
    assert "AC-2" not in v["omitted_controls_in_families"]
    assert report["discussion_text_requirements"] == [env.ids["ac2disc"]] and report["unresolved"] == []
    assert v["content_sha256"] and "subset" in report["statement"]


def test_gap_codes_are_honest_for_catalog_text(env):
    r = env.public.get(f"{CATALOG}/frameworks/{FW}/mapping-gaps", headers=env.h(None))
    assert r.status_code == 200, r.text
    body = r.json()
    item, codes = gaps_of(body, env.ids["au14"])
    assert item["canonical_reference"]["canonical_id"] == "AU-14"
    # recording is collected, but users/roles and circumstances are organization-defined: policy first
    assert codes == [("POLICY_CONTEXT_REQUIRED", "PAM-SESSREC-001")]
    gap = item["gaps"][0]
    assert gap["parameters"] == [] and len(gap["organization_defined"]) == 3
    # invalid logon attempts -> failed-attempt rule, collector missing (never MFA)
    assert gaps_of(body, env.ids["ac7a"])[1] == [("COLLECTOR_MISSING", "PAM-AUTHFAIL-001")]
    # valid access authorization -> entitlement-at-access rule, collector missing
    assert gaps_of(body, env.ids["ac2i"])[1] == [("COLLECTOR_MISSING", "PAM-UNAUTH-001")]
    # not mapped to look-alike rules: temporary-account expiry is not dormancy, membership-change
    # authenticator change is not age-based rotation
    assert gaps_of(body, env.ids["ac2_2"])[1] == [("NO_EXECUTABLE_RULE", None)]
    assert gaps_of(body, env.ids["ia5i"])[1] == [("NO_EXECUTABLE_RULE", None)]
    assert gaps_of(body, env.ids["ac2a"])[1] == [("MAPPING_MISSING", None)]
    assert body["counts"]["requirements"] == len(Q) and body["collector_capability_source"] == "LEGACY_BRIDGE_DEFAULT"
    # automation never binds a passage whose values are organization-defined
    prepared = automation.prepare_mappings(env.db, env.admin.app.state.engine, list(env.ids.values()), actor="bot")
    assert prepared["prepared"] == []
    assert env.db.scalar("SELECT COUNT(*) FROM framework_control_mapping") == 0
    assert env.public.get(f"{CATALOG}/frameworks/NOPE/mapping-gaps", headers=env.h(None)).status_code == 404


def test_mapping_gaps_follow_the_collector_handshake(env):
    params = {"tenant_id": "acme"}
    before = env.public.get(f"{CATALOG}/frameworks/{FW}/mapping-gaps", params=params, headers=env.h()).json()
    assert gaps_of(before, env.ids["ac2i"])[1] == [("COLLECTOR_MISSING", "PAM-UNAUTH-001")]
    env.handshake({"access_authorization": "1.0", "privileged_session": "1.0"})
    after = env.public.get(f"{CATALOG}/frameworks/{FW}/mapping-gaps", params=params, headers=env.h()).json()
    assert after["collector_capability_source"] == "HANDSHAKE"
    item, codes = gaps_of(after, env.ids["ac2i"])
    assert codes == [("POLICY_CONTEXT_REQUIRED", "PAM-UNAUTH-001")]
    assert item["gaps"][0]["organization_defined"] == ["[Assignment: organization-defined attributes (as required)]"]
    # another organization still sees its own (legacy) collector state
    other = env.public.get(f"{CATALOG}/frameworks/{FW}/mapping-gaps", params=params, headers=env.h(SCOPE_B)).json()
    assert gaps_of(other, env.ids["ac2i"])[1] == [("COLLECTOR_MISSING", "PAM-UNAUTH-001")]


def test_policy_resolves_au14_selectors_with_partial_coverage(env):
    env.handshake({"privileged_session": "1.0"})
    v = env.saved("pol-au14-0001", [control("PC-SESSION-RECORDING", {"accept_partial_recordings": False},
                                            [{"type": "USER_GROUP", "id": "grp-auditors"}])],
                  start=P_START - timedelta(days=1))
    r = env.public.post(f"{CATALOG}/evaluation-templates/{FW}/plan", headers=env.h(), json={
        "tenant_id": "acme", "policy_version_ids": [v["policy_version_id"]], "reporting_period": PERIOD})
    assert r.status_code == 200, r.text
    plan = r.json()
    req = next(x for x in plan["requirements"] if x["requirement_id"] == env.ids["au14"])
    codes = [(g["code"], g["status"]) for g in req["policy_resolution"]["gaps"]]
    assert codes == [("POLICY_CONTEXT_REQUIRED", "PARTIALLY_RESOLVED"), ("PARTIAL_COVERAGE", "OPEN")]
    assert req["policy_resolution"]["gaps"][0]["target_coverage"] == "SELECTED_TARGETS"
    [execution] = plan["policy_context"]["executions"]
    assert execution["targets"] == [{"id": "grp-auditors", "type": "USER_GROUP"}]
    assert execution["evaluate_request"]["reporting_period"] == PERIOD
    assert req["assessment"] == "UNMAPPED" and req["execution_ids"] == []  # no regulatory mapping was invented
    assert format_utc(P_START) == PERIOD["start"]


def test_organization_defined_detection():
    assert mp.organization_defined("Retain for [Assignment: organization-defined time period].") == [
        "[Assignment: organization-defined time period]"]
    assert mp.organization_defined("Rotate every 90 days.") == []
    names = [t[0] for t in mp.topics(Q["ia5i"])]
    assert names == ["event-triggered authenticator change (age-based rotation does not test it)"]
    assert "PAM-ROTATION-001" not in {t[1] for t in mp.topics(Q["ia5i"])}
    assert "PAM-DORMANT-001" not in {t[1] for t in mp.topics(Q["ac2_2"])}
    assert [t[1] for t in mp.topics(Q["au14"])] == ["PAM-SESSREC-001"]
    assert SCOPE_A != SCOPE_B
