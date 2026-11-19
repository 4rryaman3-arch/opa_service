"""Automated requirements pipeline (automation.build_framework, run inside prepare_catalog), automation policy,
decision origins and scoped publication. Synthetic fixtures only."""
from __future__ import annotations

import hashlib
import json
from contextlib import nullcontext

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from regintel import automation, catalog, extraction
from regintel.admin_api import PREFIX, create_admin_app
from regintel.db import CatalogDb
from regintel.sources import registry as sources
from . import support as s

EN_URL = f"https://{s.DOMAIN}/act/en"
DE_URL = f"https://{s.DOMAIN}/act/de"


def pipeline_llm(review=None, translation_review=None) -> s.FakeLlm:
    """good_llm plus scripted answers for the second-pass review prompts."""
    base = s.good_llm().script

    def script(system: str, prompt: str):
        if system == automation.SYSTEM_REVIEW:
            return review(prompt) if review else {
                "verdict": "APPROVE", "reasons": [],
                "checks": {"quote_supported": True, "obligation_type_correct": True,
                           "thresholds_grounded": True, "domains_relevant": True}}
        if system == automation.SYSTEM_TRANSLATION_REVIEW:
            return translation_review(prompt) if translation_review else {"verdict": "APPROVE", "reasons": []}
        return base(system, prompt)

    return s.FakeLlm(script)


def build(db: CatalogDb, tmp_path, llm=None, pages=None, framework_id="SYN-EU-ACT", **kw):
    return automation.build_framework(
        db, actor="opm-ops", framework_id=framework_id, llm=llm or pipeline_llm(),
        blob_dir=tmp_path / "blobs", transport=s.transport(pages if pages is not None else {EN_URL: s.ACT_EN_V1}),
        **kw)


def approved_framework(db: CatalogDb, framework_id="SYN-EU-ACT") -> None:
    """The two declared human inputs: framework identity approval. Source
    configuration exists from setup_synthetic (left PROPOSED for the policy)."""
    from regintel import registry
    registry.verify_framework(db, framework_id, reviewer="bob")


def origins(db: CatalogDb, entity_type: str) -> list[tuple[str, str | None]]:
    return [(r["decision_origin"], r["policy_version"]) for r in
            db.q("SELECT * FROM review_approval WHERE entity_type=? ORDER BY id", (entity_type,))]


def test_source_eligibility_policy(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)
    src = db.one("SELECT * FROM source WHERE id='syn-gazette'")
    ok, reason = automation.source_eligibility(db, src)
    assert ok and "official domain" in reason
    # file provenance is never machine-verified
    ok, reason = automation.source_eligibility(db, {**src, "adapter_type": "file_drop"})
    assert not ok and "file_drop" in reason
    # a fetch domain outside the authority's registered official domains is ineligible
    bad = {**src, "config": {**src["config"], "allowed_domains": ["cdn.unrelated.example"]}}
    ok, reason = automation.source_eligibility(db, bad)
    assert not ok and "cdn.unrelated.example" in reason
    db.close()


def test_pipeline_reaches_publication_without_human_review_actions(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)  # the source stays PROPOSED: the policy must verify it
    approved_framework(db)
    from ..conftest import BUNDLE
    from app.engine.catalog import Catalog
    result = build(db, tmp_path, engine=Catalog.load(BUNDLE))

    assert result["status"] == "SUCCESS" and result["outcome"] == "PUBLISHED"
    # the PROPOSED source was verified by the policy, with the decision recorded as AUTOMATED
    assert [v["source_id"] for v in result["sources"]["auto_verified"]] == ["syn-gazette"]
    verification = db.one("SELECT * FROM source_verification WHERE source_id='syn-gazette' ORDER BY id DESC")
    assert verification["decision_origin"] == "AUTOMATED"
    assert verification["policy_version"] == automation.POLICY_VERSION
    assert verification["verifier"] == "engine:opm-ops"
    # document completeness review, extraction, candidate review, publication
    assert len(result["documents"]["auto_reviewed"]) == 1
    assert result["extraction"]["drafted"] == 2
    assert len(result["review"]["approved"]) == 2 and result["review"]["rejected"] == []
    assert result["publication"]["published"] is True
    published = result["publication"]["requirement_ids"]
    assert len(published) == 2 and result["counts"]["published"] == 2
    for rid in published:
        row = db.one("SELECT status, published_seq FROM regulatory_requirement WHERE id=?", (rid,))
        assert row["status"] == "APPROVED" and row["published_seq"] is not None
    # every decision is AUTOMATED with the policy version; none pretends to be human
    assert origins(db, "document_version") == [("AUTOMATED", automation.POLICY_VERSION)]
    assert origins(db, "requirement") == [("AUTOMATED", automation.POLICY_VERSION)] * 2
    approvals = db.q("SELECT * FROM review_approval WHERE entity_type='requirement'")
    assert all(a["reviewer"] == "engine:opm-ops" and a["attempt_id"] for a in approvals)
    assert all(a["attestations"]["review_attempt_id"] == a["attempt_id"] for a in approvals)
    # the second-pass model reviews were persisted as attempts
    reviews = db.q("SELECT * FROM extraction_attempt WHERE kind='REVIEW'")
    assert len(reviews) == 2 and all(r["status"] == "SUCCEEDED" and r["requirement_id"] for r in reviews)
    # missing mappings still yield honest readiness
    assert result["readiness"]["readiness"] == "NOT_READY"
    assert {b["code"] for b in result["readiness"]["blockers"]} == {"NO_EXECUTABLE_MAPPINGS"}
    assert any(a["action"] == "draft_mapping" for a in result["next_actions"])
    # coverage agrees with the publication (same catalog database)
    assert result["coverage"]["requirements"]["published"] == 2
    assert result["statement"].startswith("Decisions marked decision_origin=AUTOMATED")
    db.close()


def test_retries_do_not_duplicate_records_decisions_or_publications(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)
    approved_framework(db)
    first = build(db, tmp_path)
    version_before = first["publication"]["catalog_version"]
    again = build(db, tmp_path)
    # sections with a completed extraction attempt are not sent to the model again
    assert again["extraction"]["drafted"] == 0 and again["extraction"]["model_calls"] == 0
    assert again["extraction"]["already_extracted"] == first["extraction"]["model_calls"] > 0
    assert again["review"]["approved"] == [] and again["publication"]["published"] is False
    assert again["publication"]["catalog_version"] == version_before
    assert db.scalar("SELECT COUNT(*) FROM review_approval WHERE entity_type='requirement'") == 2
    assert db.scalar("SELECT COUNT(*) FROM regulatory_requirement") == 2
    assert db.scalar("SELECT COUNT(*) FROM catalog_publication") == version_before
    db.close()


def test_model_rejections_and_failures_cannot_enter_the_published_set(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)
    approved_framework(db)

    def review(prompt):
        if s.SESSION_QUOTE in prompt.split("PROPOSAL:")[-1]:  # the section text above contains both quotes
            return {"verdict": "REJECT", "reasons": ["the passage is about recording, not the claimed domain"],
                    "checks": {"quote_supported": True, "obligation_type_correct": True,
                               "thresholds_grounded": True, "domains_relevant": False}}
        return {"verdict": "APPROVE", "reasons": [],
                "checks": {"quote_supported": True, "obligation_type_correct": True,
                           "thresholds_grounded": True, "domains_relevant": True}}

    result = build(db, tmp_path, llm=pipeline_llm(review=review))
    assert result["status"] == "PARTIAL"
    assert len(result["review"]["approved"]) == 1 and len(result["review"]["rejected"]) == 1
    rejected = result["review"]["rejected"][0]
    assert rejected["disposition"] == "LEFT_DRAFT_FOR_HUMAN_REVIEW"
    assert rejected["problems"][0]["code"] == "REVIEW_REJECTED"
    assert "recording" in rejected["problems"][0]["message"]
    row = db.one("SELECT status, published_seq FROM regulatory_requirement WHERE id=?",
                 (rejected["requirement_id"],))
    assert row["status"] == "DRAFT" and row["published_seq"] is None  # recoverable by a human, never published
    assert len(result["publication"]["requirement_ids"]) == 1
    assert any(a["action"] == "review_requirement" and rejected["requirement_id"] in a["ids"]
               for a in result["next_actions"])
    db.close()


def test_unsupported_translation_blocks_automated_approval(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False, languages=("de",))
    approved_framework(db)

    def translation_review(prompt):
        return {"verdict": "REJECT", "reasons": ["the translation drops the 90-day interval"]}

    result = build(db, tmp_path, llm=pipeline_llm(translation_review=translation_review),
                   pages={DE_URL: s.ACT_DE})
    assert result["status"] == "PARTIAL" and result["outcome"] == "NOTHING_TO_PUBLISH"
    assert result["review"]["approved"] == []
    problems = {p["code"] for r in result["review"]["rejected"] for p in r["problems"]}
    assert "TRANSLATION_REJECTED" in problems
    req = db.one("SELECT * FROM regulatory_requirement")
    assert req["status"] == "DRAFT" and req["translation_status"] == "UNREVIEWED"
    attempts = {r["kind"] for r in db.q("SELECT kind FROM extraction_attempt")}
    assert "TRANSLATION_REVIEW" in attempts
    db.close()


def test_translation_approval_is_automated_and_grounded(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False, languages=("de",))
    approved_framework(db)
    result = build(db, tmp_path, pages={DE_URL: s.ACT_DE})
    assert result["outcome"] == "PUBLISHED" and len(result["publication"]["requirement_ids"]) == 1
    req = db.one("SELECT * FROM regulatory_requirement")
    assert req["translation_status"] == "REVIEWED" and req["original_text"] == s.ROTATION_QUOTE_DE
    assert origins(db, "translation") == [("AUTOMATED", automation.POLICY_VERSION)]
    db.close()


def test_invented_numbers_in_translation_are_rejected_in_code(tmp_path):
    assert automation._translation_numbers_ok("alle 90 Tage", "every 90 days") == []
    assert automation._translation_numbers_ok("alle 90 Tage", "every 30 days") == ["30"]
    assert automation._translation_numbers_ok("1.000 Stunden", "1,000 hours") == []


def test_scoped_publication_never_publishes_unrelated_pending_content(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)
    approved_framework(db)
    first = build(db, tmp_path)
    assert first["outcome"] == "PUBLISHED"
    # a human approves an unrelated manual draft but does not publish it
    scope_section = db.scalar("SELECT id FROM document_section WHERE text LIKE '%applies to operators%'")
    manual = extraction.add_manual_requirement(
        db, section_id=scope_section, quote=s.SCOPE_QUOTE, pam_domains=["access_control"],
        obligation_type="UNDETERMINED", actor="alice")
    catalog.review(db, "requirement", manual, reviewer="bob", decision="APPROVED")
    again = build(db, tmp_path)
    assert again["publication"]["published"] is False  # the human-approved item is not this pipeline's to publish
    row = db.one("SELECT status, published_seq FROM regulatory_requirement WHERE id=?", (manual,))
    assert row["status"] == "APPROVED" and row["published_seq"] is None
    assert catalog.pending_publication(db)["requirement"] == [manual]
    assert origins(db, "requirement")[-1] == ("HUMAN", None)  # distinguishable from the automated ones
    db.close()


def test_framework_approval_and_source_configuration_remain_inputs(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)
    # not approved: the pipeline must not approve the framework itself
    result = build(db, tmp_path, framework_id="SYN-STD")
    assert result["status"] == "FAILED" and result["outcome"] == "FRAMEWORK_NOT_APPROVED"
    assert result["blockers"][0]["supply"]["verify_framework"]["required_scope"] == "catalog:review"
    # approved but without any usable or eligible source: actionable blocker
    approved_framework(db, "SYN-DE-IMPL")
    result = build(db, tmp_path, framework_id="SYN-DE-IMPL")
    assert result["status"] == "FAILED" and result["outcome"] == "SOURCE_CONFIGURATION_REQUIRED"
    assert set(result["blockers"][0]["supply"]) == {"register_source", "upload_document", "verify_source"}
    assert db.scalar("SELECT COUNT(*) FROM regulatory_requirement") == 0
    db.close()


def test_incomplete_documents_become_blockers_not_approvals(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)
    approved_framework(db)
    result = build(db, tmp_path, pages={EN_URL: s.TRUNCATED})
    assert result["status"] == "PARTIAL"
    assert len(result["documents"]["incomplete"]) == 1
    assert {b["code"] for b in result["blockers"]} == {"INCOMPLETE_DOCUMENTS"}
    vid = result["documents"]["incomplete"][0]["version_id"]
    assert db.one("SELECT status FROM regulatory_document_version WHERE id=?", (vid,))["status"] == "AWAITING_REVIEW"
    assert db.scalar("SELECT COUNT(*) FROM review_approval WHERE entity_type='document_version'") == 0
    db.close()


# ------------------------------------------------------------------ API level


@pytest.fixture
def env(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)
    entries = []
    tokens = {}
    for name, scopes in [('automated', ['catalog:operate', 'catalog:review', 'catalog:automate']),
                         ('operator', ['catalog:operate', 'catalog:review', 'catalog:publish']),
                         ('reader', ['catalog:read'])]:
        secret = 'synthetic-test-secret-' + name
        tokens[name] = f'{name}.{secret}'
        entries.append({'key_id': name, 'secret_sha256': hashlib.sha256(secret.encode()).hexdigest(),
                        'scopes': scopes, 'tenants': ['acme'], 'enabled': True})
    (tmp_path / 'clients.json').write_text(json.dumps({'clients': entries}))
    from ..conftest import BUNDLE
    settings = Settings(api_clients_file=tmp_path / 'clients.json', catalog_db_path=db.path,
                        catalog_jobs_db_path=tmp_path / 'jobs.db', catalog_upload_dir=tmp_path / 'uploads',
                        policy_bundle_dir=BUNDLE)
    app = create_admin_app(settings, start_worker=False)
    with TestClient(app) as client:
        yield client, db, tokens, app.state.jobs
    db.close()


def auth(tokens, name):
    return {'Authorization': 'Bearer ' + tokens[name]}


def test_build_framework_action_is_removed_and_prepare_catalog_needs_the_automation_scope(env):
    client, db, tokens, jobs = env
    removed = client.post(PREFIX + '/jobs', headers=auth(tokens, 'automated'),
                          json={'action': 'build_framework', 'framework_id': 'SYN-EU-ACT',
                                'request_key': 'auto-key-removed'})
    assert removed.status_code == 422  # use prepare_catalog
    denied = client.post(PREFIX + '/jobs', headers=auth(tokens, 'operator'),
                         json={'action': 'prepare_catalog', 'mode': 'discovery', 'jurisdictions': ['EU'],
                               'request_key': 'auto-key-denied'})
    assert denied.status_code == 403 and "catalog:automate" in denied.json()['error']['message']
    assert jobs.list() == []
    # the capability is advertised so Django can show or hide the trigger
    health = client.get(PREFIX + '/health', headers=auth(tokens, 'automated')).json()
    assert health['automation'] == {'scope': 'catalog:automate', 'policy_version': automation.POLICY_VERSION,
                                    'enabled': True}
    assert client.get(PREFIX + '/health', headers=auth(tokens, 'operator')).json()['automation']['enabled'] is False
    # ordinary job actions still work with catalog:operate alone (backward compatible)
    assert client.post(PREFIX + '/jobs', headers=auth(tokens, 'operator'),
                       json={'action': 'sync', 'source_id': 'syn-gazette',
                             'request_key': 'sync-key-compat'}).status_code == 202
