"""Framework -> requirement -> rule mapping -> execution plan, over real HTTP apps.

SYNTHETIC FIXTURE ONLY. The mappings below bind a fictitious act to Securden
rules purely to exercise the workflow; they are not legal interpretation.
One credential ("deploy") drafts, reviews and publishes, as a single-credential
deployment does.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from client.securden_opm_client import OpmError, effective_parameters, plan_digest
from regintel import catalog
from regintel.admin_api import PREFIX as ADMIN, create_admin_app
from regintel.db import CatalogDb

from .. import helpers
from ..conftest import BUNDLE, OPA_TOKEN, ROOT
from . import support as s

CATALOG = "/api/v1/catalog"
FRAMEWORK = "SYN-EU-ACT"
EXAMPLES = ROOT / "docs" / "examples" / "framework_evaluation"
ROTATION = {"assessment": "AUTOMATED", "rule_id": "PAM-ROTATION-001", "rule_version_min": "1.1", "coverage": "PARTIAL",
            "parameters": {"max_rotation_age_days": 90},
            "override_constraints": {"max_rotation_age_days": {"min": 1, "max": 90}},
            "rationale": "Synthetic fixture: the rule measures the rotation interval the passage states.",
            "limitations": "Synthetic fixture: covers accounts managed in Securden only."}


def credentials(tmp_path: Path) -> tuple[Path, dict[str, dict[str, str]]]:
    entries, headers = [], {}
    for name, tenants, scopes in [
        ("deploy", ["acme"], ["catalog:read", "catalog:operate", "catalog:review", "catalog:publish", "evaluate",
                              "rules:read", "rules:admin"]),
        ("other", ["tenant-b"], ["catalog:read"]),
    ]:
        secret = "synthetic-test-secret-" + name
        headers[name] = {"Authorization": f"Bearer {name}.{secret}"}
        entries.append({"key_id": name, "secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
                        "scopes": scopes, "tenants": tenants, "enabled": True})
    path = tmp_path / "clients.json"
    path.write_text(json.dumps({"clients": entries}))
    return path, headers


class Env:
    def __init__(self, admin, public, db, ids, headers):
        self.admin, self.public, self.db, self.ids, self.headers = admin, public, db, ids, headers
        self.h = headers["deploy"]

    def draft(self, requirement: str, **body):
        return self.admin.post(ADMIN + "/mappings", json={"requirement_id": self.ids[requirement], **body}, headers=self.h)

    def publish_mapping(self, requirement: str, **body) -> int:
        response = self.draft(requirement, **body)
        assert response.status_code == 201, response.text
        mapping_id = response.json()["mapping"]["id"]
        review = self.admin.post(ADMIN + f"/reviews/mapping/{mapping_id}", headers=self.h,
                                 json={"decision": "APPROVED", "comment": "Synthetic fixture review."})
        assert review.status_code == 200, review.text
        assert self.admin.post(ADMIN + "/publish", headers=self.h).status_code == 200
        return mapping_id

    def plan(self, framework: str = FRAMEWORK, who: str = "deploy", **params):
        return self.public.get(f"{CATALOG}/evaluation-templates/{framework}/plan",
                               params={"tenant_id": "acme", **params}, headers=self.headers[who])

    def templates(self, **params) -> dict[str, dict]:
        response = self.public.get(f"{CATALOG}/evaluation-templates", params=params, headers=self.h)
        assert response.status_code == 200, response.text
        return {item["framework_id"]: item for item in response.json()["items"]}


def build(tmp_path, opa_url="http://127.0.0.1:9"):
    db = s.make_db(tmp_path)
    ids = s.reviewed_requirements(db, tmp_path)  # SYN-EU-ACT approved, three approved requirements
    catalog.publish_catalog(db, "bob")
    path, headers = credentials(tmp_path)
    common = dict(api_clients_file=path, catalog_db_path=Path(db.path), policy_bundle_dir=BUNDLE)
    admin = create_admin_app(Settings(**common, catalog_jobs_db_path=tmp_path / "jobs.db",
                                      catalog_upload_dir=tmp_path / "uploads"), start_worker=False)
    public = create_app(Settings(**common, opa_url=opa_url, opa_token=OPA_TOKEN, db_path=tmp_path / "opm.db",
                                 log_level="WARNING", trust_proxy_headers=False, opa_connect_timeout_seconds=0.5))
    return admin, public, db, ids, headers


@pytest.fixture
def env(tmp_path):
    admin, public, db, ids, headers = build(tmp_path)
    with TestClient(admin) as a, TestClient(public) as p:
        yield Env(a, p, db, ids, headers)
    db.close()


def by_assessment(plan: dict) -> dict[int, str]:
    return {r["requirement_id"]: r["assessment"] for r in plan["requirements"]}


# ---------------------------------------------------------------- acceptance 1, 2


def test_approved_framework_without_requirements_is_visible_but_not_runnable(env):
    assert "SYN-STD" not in env.templates()  # not review-approved yet
    assert env.templates(include_unapproved=True)["SYN-STD"]["review_status"] == "PENDING"
    approve = env.admin.post(ADMIN + "/frameworks/SYN-STD/verify", json={"decision": "APPROVED"}, headers=env.h)
    assert approve.status_code == 200, approve.text  # plain approval needs no document
    item = env.templates()["SYN-STD"]
    assert item["readiness"] == "NOT_READY" and item["published_requirements"] == 0 and item["lifecycle"] == "UNKNOWN"
    assert [b["code"] for b in item["blockers"]] == ["NO_PUBLISHED_REQUIREMENTS"]
    plan = env.plan("SYN-STD").json()
    assert plan["readiness"] == "NOT_READY" and plan["requirements"] == [] and plan["executions"] == []
    assert [b["code"] for b in plan["blockers"]] == ["NO_PUBLISHED_REQUIREMENTS"]


def test_published_requirements_without_mappings_are_unmapped_not_invented(env):
    plan = env.plan().json()
    assert plan["totals"]["published_requirements"] == 3 and plan["totals"]["unmapped_requirements"] == 3
    assert set(by_assessment(plan).values()) == {"UNMAPPED"} and plan["executions"] == []
    assert plan["readiness"] == "NOT_READY" and [b["code"] for b in plan["blockers"]] == ["NO_EXECUTABLE_MAPPINGS"]
    assert all(r["execution_ids"] == [] and r["requires_manual_assessment"] for r in plan["requirements"])
    item = env.templates()[FRAMEWORK]
    assert (item["automated_requirements"], item["unmapped_requirements"], item["readiness"]) == (0, 3, "NOT_READY")


# ---------------------------------------------------------------- acceptance 3


def test_draft_and_rejected_mappings_are_never_executed(env):
    draft = env.draft("rotation", **ROTATION)
    assert draft.status_code == 201 and draft.json()["mapping"]["status"] == "DRAFT"
    mapping_id = draft.json()["mapping"]["id"]
    assert env.plan().json()["executions"] == []
    assert env.public.get(f"{CATALOG}/mappings", params={"framework_id": FRAMEWORK}, headers=env.h).json()["items"] == []
    listed = env.admin.get(ADMIN + "/mappings", params={"framework_id": FRAMEWORK, "status": "DRAFT"}, headers=env.h).json()
    assert [m["id"] for m in listed["items"]] == [mapping_id]
    reject = env.admin.post(ADMIN + f"/reviews/mapping/{mapping_id}", headers=env.h,
                            json={"decision": "REJECTED", "comment": "Synthetic fixture: wrong rule."})
    assert reject.status_code == 200
    env.admin.post(ADMIN + "/publish", headers=env.h)
    plan = env.plan().json()
    assert plan["executions"] == [] and by_assessment(plan)[env.ids["rotation"]] == "UNMAPPED"
    detail = env.admin.get(ADMIN + f"/mappings/{mapping_id}", headers=env.h).json()
    assert detail["mapping"]["status"] == "REJECTED" and detail["reviews"][0]["comment"] == "Synthetic fixture: wrong rule."
    # Approved but unpublished is not executed either.
    second = env.draft("rotation", **ROTATION).json()["mapping"]
    assert second["mapping_version"] == 2 and second["mapping_key"] == detail["mapping"]["mapping_key"]
    env.admin.post(ADMIN + f"/reviews/mapping/{second['id']}", headers=env.h,
                   json={"decision": "APPROVED", "comment": "Synthetic fixture review."})
    assert env.plan().json()["executions"] == []


# ---------------------------------------------------------------- acceptance 4, 7, 13


def test_published_rotation_mapping_produces_a_pinned_traceable_execution(env):
    mapping_id = env.publish_mapping("rotation", **ROTATION)
    env.publish_mapping("scope", assessment="MANUAL", pam_control_id="PAMC-ACCESS-AUTHORIZATION",
                        rationale="Synthetic fixture: scope provisions need an organizational assessment.",
                        limitations="Synthetic fixture: no technical evidence exists for this passage.")
    response = env.plan()
    assert response.status_code == 200, response.text
    plan = response.json()
    assert by_assessment(plan) == {env.ids["rotation"]: "AUTOMATED", env.ids["session"]: "UNMAPPED", env.ids["scope"]: "MANUAL"}
    assert plan["readiness"] == "PARTIAL" and plan["blockers"] == []
    assert plan["totals"] == {"published_requirements": 3, "automated_requirements": 1, "manual_requirements": 1,
                              "unmapped_requirements": 1, "blocked_requirements": 0, "mapping_count": 2, "execution_count": 1}
    execution, = plan["executions"]
    assert (execution["rule_id"], execution["rule_version"], execution["evidence_type"]) == \
        ("PAM-ROTATION-001", "1.1", "credential_rotation")
    assert execution["parameters"] == ROTATION["parameters"]
    assert execution["override_constraints"] == ROTATION["override_constraints"]
    assert execution["requirement_ids"] == [env.ids["rotation"]] and execution["mapping_ids"] == [mapping_id]
    assert execution["evaluate_request"] == {"rule_id": "PAM-ROTATION-001", "rule_version": "1.1",
                                             "policy_settings": {"parameters": ROTATION["parameters"]}}
    assert set(execution["parameter_schema"]) == set(ROTATION["parameters"])
    rotation = next(r for r in plan["requirements"] if r["requirement_id"] == env.ids["rotation"])
    assert rotation["execution_ids"] == [execution["execution_id"]] and rotation["technical_coverage"] == "PARTIAL"
    assert rotation["aggregation"] == "ALL" and rotation["original_text"] == s.ROTATION_QUOTE
    assert rotation["source_reference"]["content_sha256"] == plan["framework"]["documents"][0]["content_sha256"]
    link, = rotation["mappings"]
    assert (link["mapping_id"], link["mapping_version"], link["reviewer"], link["coverage"]) == (mapping_id, 1, "deploy", "PARTIAL")
    assert plan_digest(plan["digest_input"]) == plan["plan_digest"]  # reproducible by the caller
    assert env.plan().json()["plan_digest"] == plan["plan_digest"]  # deterministic
    # Local PAM values are accepted only inside the reviewed constraint; nothing is clamped.
    assert effective_parameters(execution, {"max_rotation_age_days": 60})["max_rotation_age_days"] == 60
    for weaker in ({"max_rotation_age_days": 120}, {"max_violations": 5}, {"unknown": 1}):
        with pytest.raises(OpmError, match="OVERRIDE_NOT_PERMITTED"):
            effective_parameters(execution, weaker)
    published = env.public.get(f"{CATALOG}/mappings", params={"requirement_id": env.ids["rotation"]}, headers=env.h).json()["items"]
    assert published[0]["mapping_version"] == 1 and published[0]["mapped_rule_id"] == "PAM-ROTATION-001"
    assert published[0]["assessment"] == "AUTOMATED" and published[0]["parameters"] == ROTATION["parameters"]
    item = env.templates(jurisdiction="EU")[FRAMEWORK]
    assert (item["readiness"], item["jurisdiction_match"], item["automated_requirements"]) == ("PARTIAL", "EXACT", 1)
    assert FRAMEWORK not in env.templates(jurisdiction="DE")  # registration for the EU is not inherited by default
    inherited = env.templates(jurisdiction="DE", include_inherited=True)[FRAMEWORK]
    assert inherited["jurisdiction_match"] == "INHERITED" and inherited["jurisdiction_path"] == "MEMBER:DE"
    if os.environ.get("OPM_WRITE_EXAMPLES"):
        EXAMPLES.mkdir(parents=True, exist_ok=True)
        templates = env.public.get(f"{CATALOG}/evaluation-templates", params={"jurisdiction": "EU"}, headers=env.h).json()
        mapping = env.admin.get(ADMIN + f"/mappings/{mapping_id}", headers=env.h).json()
        for name, body in (("evaluation_plan.json", plan), ("evaluation_templates.json", templates),
                           ("mapping_create_request.json", {"requirement_id": env.ids["rotation"], **ROTATION}),
                           ("mapping.json", mapping)):
            (EXAMPLES / name).write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def test_one_rule_mapped_to_two_requirements_is_one_execution_with_two_links(env):
    first = env.publish_mapping("rotation", **ROTATION)
    second = env.publish_mapping("session", **ROTATION)
    plan = env.plan().json()
    execution, = plan["executions"]
    assert execution["requirement_ids"] == [env.ids["rotation"], env.ids["session"]]
    assert execution["mapping_ids"] == [first, second] and plan["totals"]["mapping_count"] == 2
    # Different reviewed parameters are a different execution identity, never merged.
    env.admin.post(ADMIN + f"/mappings/{second}/withdraw", headers=env.h,
                   json={"reason": "Synthetic fixture: replace with a stricter interval."})
    env.publish_mapping("session", **{**ROTATION, "parameters": {"max_rotation_age_days": 30},
                                      "override_constraints": {}})
    plan = env.plan().json()
    assert len(plan["executions"]) == 2
    assert {e["parameters"]["max_rotation_age_days"] for e in plan["executions"]} == {30, 90}
    assert len({e["execution_id"] for e in plan["executions"]}) == 2


# ---------------------------------------------------------------- mapping validation


def test_mapping_creation_rejects_unknown_rules_and_bad_parameters(env):
    cases = [
        ({"rule_id": "PAM-NOPE-001"}, "UNKNOWN_RULE"),
        ({"rule_version_min": "9.0"}, "RULE_VERSION_UNAVAILABLE"),
        ({"rule_version_min": "1.1", "rule_version_max": "1.0"}, "INVALID_RULE_VERSION"),
        ({"evidence_type": "privileged_session"}, "EVIDENCE_TYPE_MISMATCH"),
        ({"parameters": {}}, "MISSING_PARAMETER"),
        ({"parameters": {**ROTATION["parameters"], "invented": 1}}, "INVALID_PARAMETER"),
        ({"parameters": {"max_rotation_age_days": 100000}}, "INVALID_PARAMETER"),
        ({"override_constraints": {"max_rotation_age_days": {"min": 1, "max": 30}}}, "INVALID_OVERRIDE_CONSTRAINT"),
        ({"override_constraints": {"max_rotation_age_days": {"min": 1, "max": 100000}}}, "INVALID_OVERRIDE_CONSTRAINT"),
        ({"pam_control_id": "PAMC-SESSION-RECORDING"}, "INVALID_MAPPING"),
        ({"coverage": None}, "INVALID_MAPPING"),
    ]
    for change, code in cases:
        response = env.draft("rotation", **{**ROTATION, **change})
        assert response.status_code == 422, (change, response.text)
        body = response.json()
        assert body["error"]["code"] == code, change
        if code in ("MISSING_PARAMETER", "INVALID_PARAMETER", "INVALID_OVERRIDE_CONSTRAINT"):
            problems = body["error"]["details"]["problems"]  # structured, actionable parameter problems
            assert problems and all(p["code"] and p["message"] for p in problems), change
    manual = dict(assessment="MANUAL", pam_control_id="PAMC-MFA-PRIVILEGED",
                  rationale="Synthetic fixture: no collector exists for this control.",
                  limitations="Synthetic fixture: needs a new collector.")
    assert env.draft("rotation", **{**manual, "rule_id": "PAM-ROTATION-001"}).json()["error"]["code"] == "INVALID_MAPPING"
    assert env.draft("rotation", **{**manual, "pam_control_id": None}).json()["error"]["code"] == "INVALID_MAPPING"
    assert env.draft("rotation", **{**manual, "actor": "someone"}).status_code == 422
    missing = env.admin.post(ADMIN + "/mappings", json={"requirement_id": 999999, **ROTATION}, headers=env.h)
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "NOT_FOUND"
    assert env.db.scalar("SELECT COUNT(*) FROM framework_control_mapping") == 0  # nothing was silently stored
    assert env.draft("rotation", **ROTATION).status_code == 201
    assert env.draft("rotation", **ROTATION).status_code == 409  # one live mapping per requirement and control
    rules = env.admin.get(ADMIN + "/rule-catalog", headers=env.h).json()
    rotation = next(r for r in rules["items"] if r["rule_id"] == "PAM-ROTATION-001")
    assert rotation["pam_control_id"] == "PAMC-CRED-ROTATION" and {v["version"] for v in rotation["versions"]} >= {"1.0", "1.1"}


# ---------------------------------------------------------------- acceptance 6, 8, 9, tenant isolation


def test_plans_are_per_framework_and_stale_plans_are_reported(env):
    env.publish_mapping("rotation", **ROTATION)
    saved = env.plan().json()
    assert env.plan(expected_digest=saved["plan_digest"], catalog_version=saved["catalog_version"]).status_code == 200
    env.admin.post(ADMIN + "/frameworks/SYN-STD/verify", json={"decision": "APPROVED"}, headers=env.h)
    other = env.plan("SYN-STD").json()
    assert other["framework"]["framework_id"] == "SYN-STD" and other["executions"] == [] and other["requirements"] == []
    # An unrelated publication moves catalog_version but not this framework's digest.
    assert env.plan(expected_digest=saved["plan_digest"]).status_code == 200
    stale_version = env.plan(catalog_version=saved["catalog_version"])
    assert stale_version.status_code == 409 and stale_version.json()["error"]["code"] == "PLAN_STALE"
    # A published change to this framework's mappings makes the saved plan stale.
    env.publish_mapping("session", assessment="MANUAL", pam_control_id="PAMC-SESSION-RECORDING",
                        rationale="Synthetic fixture: retention is assessed by a person.",
                        limitations="Synthetic fixture: recording retention is not collected.")
    stale = env.plan(expected_digest=saved["plan_digest"])
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "PLAN_STALE"
    assert stale.json()["error"]["details"]["plan_digest"] == env.plan().json()["plan_digest"] != saved["plan_digest"]
    assert env.plan(who="other").status_code == 403  # tenant comes from the credential
    assert env.public.get(f"{CATALOG}/evaluation-templates/NOPE/plan", params={"tenant_id": "acme"},
                          headers=env.h).json()["error"]["code"] == "UNSUPPORTED_FRAMEWORK"
    assert env.public.get(f"{CATALOG}/evaluation-templates").status_code == 401


def test_unavailable_or_deactivated_rules_block_instead_of_falling_back(env):
    # Reviewed for the retired 1.0 only: the plan must not substitute the active 1.1.
    env.publish_mapping("rotation", **{**ROTATION, "rule_version_min": "1.0", "rule_version_max": "1.0",
                                       "parameters": {"max_rotation_age_days": 90}, "override_constraints": {}})
    plan = env.plan().json()
    assert by_assessment(plan)[env.ids["rotation"]] == "BLOCKED" and plan["executions"] == []
    assert plan["readiness"] == "NOT_READY" and plan["totals"]["blocked_requirements"] == 1
    blocker = next(b for b in plan["blockers"] if b["code"] == "RULE_VERSION_UNAVAILABLE")
    assert blocker["affected"] == {"requirement_ids": [env.ids["rotation"]], "mapping_ids": [1], "rule_ids": ["PAM-ROTATION-001"]}
    env.publish_mapping("session", **ROTATION)
    assert len(env.plan().json()["executions"]) == 1
    off = env.public.post("/api/v1/rules/predefined/PAM-ROTATION-001/deactivate", json={"tenant_id": "acme"}, headers=env.h)
    assert off.status_code == 200, off.text
    plan = env.plan().json()
    assert plan["executions"] == [] and "RULE_INACTIVE_FOR_TENANT" in [b["code"] for b in plan["blockers"]]


def test_withdrawn_mapping_leaves_the_plan_and_a_new_version_replaces_it(env):
    mapping_id = env.publish_mapping("rotation", **ROTATION)
    key = env.admin.get(ADMIN + f"/mappings/{mapping_id}", headers=env.h).json()["mapping"]["mapping_key"]
    assert env.admin.post(ADMIN + f"/mappings/{mapping_id}/withdraw", json={"reason": "short"}, headers=env.h).status_code == 422
    done = env.admin.post(ADMIN + f"/mappings/{mapping_id}/withdraw", headers=env.h,
                          json={"reason": "Synthetic fixture: superseded by a stricter mapping."})
    assert done.status_code == 200, done.text
    assert env.plan().json()["executions"] == []
    replacement = env.publish_mapping("rotation", **{**ROTATION, "coverage": "FULL"})
    row = env.admin.get(ADMIN + f"/mappings/{replacement}", headers=env.h).json()["mapping"]
    assert (row["mapping_key"], row["mapping_version"]) == (key, 2)
    rotation = next(r for r in env.plan().json()["requirements"] if r["requirement_id"] == env.ids["rotation"])
    assert rotation["technical_coverage"] == "FULL" and rotation["mappings"][0]["mapping_version"] == 2
    with pytest.raises(Exception, match="immutable"):
        env.db.x("UPDATE framework_control_mapping SET rule_parameters='{}' WHERE id=?", (replacement,))


def test_existing_catalog_database_is_migrated_in_place(tmp_path):
    import sqlite3
    path = tmp_path / "old" / "catalog.db"
    db = CatalogDb(path)
    db.close()
    raw = sqlite3.connect(path)
    raw.execute("DROP TRIGGER trg_mapping_execution_immutable")
    for column in ("assessment", "rule_id", "rule_version_min", "rule_version_max", "evidence_type", "rule_parameters",
                   "override_constraints", "coverage", "control_reference", "mapping_key", "version"):
        raw.execute(f"ALTER TABLE framework_control_mapping DROP COLUMN {column}")
    raw.commit()
    raw.close()
    from regintel import plan
    old = CatalogDb(path, read_only=True)
    assert not plan.schema_ready(old)
    old.close()
    migrated = CatalogDb(path)
    assert plan.schema_ready(migrated)
    migrated.close()


# ---------------------------------------------------------------- plan -> real evaluation (needs OPA)


@pytest.mark.opa
def test_plan_execution_runs_through_the_existing_evaluate_api(tmp_path, opa_url):
    admin, public, db, ids, headers = build(tmp_path, opa_url)
    with TestClient(admin) as a, TestClient(public) as p:
        env = Env(a, p, db, ids, headers)
        env.publish_mapping("rotation", **ROTATION)
        plan = env.plan().json()
        execution, = plan["executions"]
        now = datetime.now(timezone.utc)
        records = [helpers.rotation(1, rotated_at=now - timedelta(days=10)), helpers.rotation(2, rotated_at=now - timedelta(days=75))]
        body = helpers.request("acme", execution["rule_id"], execution["evidence_type"], records,
                               item_reference=execution["execution_id"])
        body.update(rule_version=execution["rule_version"],
                    policy_settings={"parameters": effective_parameters(execution, {"max_rotation_age_days": 60})})
        result = p.post("/api/v1/evaluate", json=body, headers=env.h)
        assert result.status_code == 200, result.text
        result = result.json()
        assert result["status"] == "FAIL" and [v["subject_id"] for v in result["violations"]] == ["acct-00002"]
        assert (result["rule_id"], result["rule_version"], result["item_reference"]) == \
            (execution["rule_id"], execution["rule_version"], execution["execution_id"])
        assert result["policy_bundle_version"] == plan["policy_bundle_version"]
        assert result["decision_details"]["parameters"]["max_rotation_age_days"] == 60
        # A version that is not in the bundle is an explicit error, never a silent substitute.
        body["rule_version"] = "9.9"
        missing = p.post("/api/v1/evaluate", json=body, headers=env.h)
        assert missing.status_code == 404 and missing.json()["error"]["code"] == "RULE_VERSION_NOT_FOUND"
    db.close()
