"""Local-LLM extraction, multilingual handling, review workflow, publication."""

from __future__ import annotations

import pytest

from regintel import catalog, coverage, extraction, registry
from regintel.db import CatalogError
from regintel.llm import LlmError, OllamaClient, assert_local_endpoint

from . import support as s


def code(exc) -> str:
    return exc.value.code


def synced(db, tmp_path, page=s.ACT_EN_V1, lang="en", review=True) -> int:
    s.setup_synthetic(db, languages=(lang,))
    s.sync(db, {f"https://{s.DOMAIN}/act/{lang}": page}, tmp_path)
    vid = db.scalar("SELECT MAX(id) FROM regulatory_document_version")
    if review:
        catalog.review_document_version(db, vid, reviewer="bob", decision="APPROVED", effective_from="2025-01-01")
    return vid


# ---------------------------------------------------------------- local LLM only


@pytest.mark.parametrize("url", ["https://api.openai.com/v1", "https://api.anthropic.com", "http://8.8.8.8:11434"])
def test_external_llm_endpoints_are_refused(url):
    with pytest.raises(LlmError, match="public address|does not resolve"):
        assert_local_endpoint(url)
    with pytest.raises(LlmError):
        OllamaClient(url, "any-model")


def test_local_endpoint_accepted_and_model_version_recorded():
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/version":
            return httpx.Response(200, json={"version": "0.0-test"})
        if path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "multi:4b", "digest": "abc123"}]})
        if path == "/api/ps":
            return httpx.Response(200, json={"models": [{"name": "multi:4b", "size": 10, "size_vram": 10}]})
        body = __import__("json").loads(request.content)
        assert body["options"]["temperature"] == 0 and body["format"]["type"] == "object" and body["stream"] is False
        return httpx.Response(200, json={"message": {"content": '{"requirements": []}'}})

    llm = OllamaClient("http://127.0.0.1:11434", "multi:4b", transport=httpx.MockTransport(handler), require_gpu=True)
    assert (llm.info.model, llm.info.version, llm.info.runtime) == ("multi:4b", "abc123", "ollama 0.0-test")
    assert llm.generate_json("s", "p", extraction.EXTRACTION_SCHEMA) == {"requirements": []}
    with pytest.raises(LlmError, match="not installed"):
        OllamaClient("http://127.0.0.1:11434", "missing:1b", transport=httpx.MockTransport(handler))


# ---------------------------------------------------------------- strict validation / grounding


SECTION = "Operators shall rotate the credentials of privileged accounts at least every 90 days. Other text."


@pytest.mark.parametrize("raw, reason", [
    ("not json", "not an object"),
    ({"requirements": [s.candidate("Operators shall rotate privileged credentials every 30 days, without exception.")]}, "UNGROUNDED_QUOTE"),
    ({"requirements": [s.candidate(s.ROTATION_QUOTE, thresholds=["30 days"])]}, "INVENTED_THRESHOLD"),
    ({"requirements": [{**s.candidate(s.ROTATION_QUOTE), "pam_domains": ["made_up_domain"]}]}, "schema"),
    ({"requirements": [{**s.candidate(s.ROTATION_QUOTE), "source_document": "Some Other Act"}]}, "schema"),
    ({"requirements": [{**s.candidate(s.ROTATION_QUOTE), "obligation_type": "LEGALLY_BINDING"}]}, "schema"),
    ({"requirements": [s.candidate("too short")]}, "schema"),
])
def test_model_output_is_rejected_unless_strictly_valid_and_grounded(raw, reason):
    accepted, rejected = extraction.validate_candidates(raw, SECTION)
    assert accepted == [] and reason in rejected[0]


def test_grounding_tolerates_whitespace_and_typographic_quotes_only():
    section = "Operators  shall keep the “privileged” credential log for 12 months."
    ok, _ = extraction.validate_candidates(
        {"requirements": [s.candidate('Operators shall keep the "privileged" credential log for 12 months.', thresholds=["12 months"])]}, section)
    assert len(ok) == 1
    bad, rejected = extraction.validate_candidates(
        {"requirements": [s.candidate('Operators shall keep the "privileged" credential log for 21 months.')]}, section)
    assert not bad and "UNGROUNDED_QUOTE" in rejected[0]


def test_extraction_creates_grounded_drafts_with_provenance(tmp_path):
    db = s.make_db(tmp_path)
    vid = synced(db, tmp_path)
    stats = extraction.extract_version(db, vid, s.good_llm())
    assert (stats["drafted"], stats["rejected"], stats["sections"]) == (2, [], 3)
    rot = db.one("SELECT * FROM regulatory_requirement WHERE original_text=?", (s.ROTATION_QUOTE,))
    assert rot["status"] == "DRAFT" and rot["section_ref"] == "#2 Article 7 Privileged credentials"
    assert rot["framework_id"] == "SYN-EU-ACT" and rot["thresholds"][0]["value_text"] == "90 days"
    assert rot["extraction"] == {"method": "LOCAL_LLM", "model": "fake-multilingual:test", "model_version": "sha256:fixture-weights",
                                 "runtime": "fake-runtime 0", "prompt_version": extraction.PROMPT_VERSION}
    assert rot["translation_status"] == "NOT_REQUIRED" and rot["created_by"] == "llm:fake-multilingual:test"
    assert extraction.extract_version(db, vid, s.good_llm())["duplicates"] == 2  # re-running is idempotent
    assert coverage.metrics(db)["verified_requirements"] == 0  # drafts are not verified requirements


def test_incorrect_source_attribution_from_the_model_is_discarded(tmp_path):
    """The model quotes real text, but for the wrong section / a different act."""
    db = s.make_db(tmp_path)
    vid = synced(db, tmp_path)

    def script(system, prompt):
        if "Article 9" in prompt or "review privileged access" in prompt:
            return {"requirements": [s.candidate(s.ROTATION_QUOTE, thresholds=["90 days"])]}  # belongs to Article 7
        if "applies to operators" in prompt:
            return {"requirements": [s.candidate("Financial entities shall rotate cryptographic keys at least every 12 months.")]}
        return {"requirements": []}

    stats = extraction.extract_version(db, vid, s.FakeLlm(script))
    assert stats["drafted"] == 0 and len(stats["rejected"]) == 2
    assert all("UNGROUNDED_QUOTE" in r for r in stats["rejected"])


def test_llm_failure_on_one_section_is_reported_not_swallowed(tmp_path):
    db = s.make_db(tmp_path)
    vid = synced(db, tmp_path)

    def script(system, prompt):
        if "Article 9" in prompt or "review privileged" in prompt:
            raise LlmError("gpu out of memory")
        return s.good_llm().script(system, prompt)

    stats = extraction.extract_version(db, vid, s.FakeLlm(script))
    assert stats["llm_errors"] == 1 and stats["drafted"] == 2


def test_extraction_refuses_unassigned_or_rejected_documents(tmp_path):
    db = s.make_db(tmp_path)
    vid = synced(db, tmp_path, review=False)
    catalog.review_document_version(db, vid, reviewer="bob", decision="REJECTED", comment="wrong consolidated version")
    with pytest.raises(CatalogError) as exc:
        extraction.extract_version(db, vid, s.good_llm())
    assert code(exc) == "DOCUMENT_NOT_USABLE"


# ---------------------------------------------------------------- multilingual


def test_multilingual_extraction_preserves_original_and_labels_translation(tmp_path):
    db = s.make_db(tmp_path)
    vid = synced(db, tmp_path, page=s.ACT_DE, lang="de")
    llm = s.good_llm()
    assert extraction.extract_version(db, vid, llm)["drafted"] == 1
    r = db.one("SELECT * FROM regulatory_requirement")
    assert r["original_language"] == "de" and r["original_text"] == s.ROTATION_QUOTE_DE  # verbatim, umlauts intact
    assert r["section_ref"] == "#1 Artikel 7 Privilegierte Zugangsdaten"
    assert r["thresholds"][0]["value_text"] == "90 Tage"
    assert r["translation_en"].startswith("Operators must change")
    assert (r["translation_status"], r["translation_model"], r["translation_model_version"]) == (
        "UNREVIEWED", "fake-multilingual:test", "sha256:fixture-weights")
    assert "Document language: de" in llm.calls[0][1]


def test_unreviewed_translation_blocks_approval_until_reviewed_or_attested(tmp_path):
    db = s.make_db(tmp_path)
    vid = synced(db, tmp_path, page=s.ACT_DE, lang="de")
    extraction.extract_version(db, vid, s.good_llm())
    rid = db.scalar("SELECT id FROM regulatory_requirement")
    with pytest.raises(CatalogError) as exc:
        catalog.review(db, "requirement", rid, reviewer="bob", decision="APPROVED")
    assert code(exc) == "TRANSLATION_UNREVIEWED"
    assert db.one("SELECT status FROM regulatory_requirement WHERE id=?", (rid,))["status"] == "DRAFT"
    catalog.review_translation(db, rid, reviewer="carla", decision="REVIEWED",
                               corrected_translation="Operators must change the access credentials of privileged accounts at least every 90 days.")
    catalog.review(db, "requirement", rid, reviewer="bob", decision="APPROVED")
    r = db.one("SELECT * FROM regulatory_requirement WHERE id=?", (rid,))
    assert r["translation_status"] == "REVIEWED" and r["translation_reviewer"] == "carla"
    assert r["original_text"] == s.ROTATION_QUOTE_DE


def test_original_language_attestation_is_an_explicit_alternative(tmp_path):
    db = s.make_db(tmp_path)
    vid = synced(db, tmp_path, page=s.ACT_DE, lang="de")
    extraction.extract_version(db, vid, s.good_llm(), translate=False)
    rid = db.scalar("SELECT id FROM regulatory_requirement")
    assert db.one("SELECT translation_en, translation_status FROM regulatory_requirement") == {
        "translation_en": None, "translation_status": "UNREVIEWED"}
    catalog.review(db, "requirement", rid, reviewer="bob", decision="APPROVED",
                   attestations={"reviewed_in_original_language": True})
    assert db.one("SELECT attestations FROM review_approval WHERE entity_type='requirement'")["attestations"] == {
        "reviewed_in_original_language": True}
    assert coverage.metrics(db)["translations_unreviewed"] == 1  # still visible as unreviewed


def test_failed_translation_is_stored_as_missing_not_invented(tmp_path):
    db = s.make_db(tmp_path)
    vid = synced(db, tmp_path, page=s.ACT_DE, lang="de")

    def script(system, prompt):
        if system == extraction.SYSTEM_TRANSLATE:
            return {"text": "wrong shape"}
        return s.good_llm().script(system, prompt)

    extraction.extract_version(db, vid, s.FakeLlm(script))
    assert db.one("SELECT translation_en, translation_model FROM regulatory_requirement") == {
        "translation_en": None, "translation_model": None}


# ---------------------------------------------------------------- review rules


def test_review_requires_reviewed_document_and_a_second_human(tmp_path):
    db = s.make_db(tmp_path)
    vid = synced(db, tmp_path, review=False)
    extraction.extract_version(db, vid, s.good_llm())
    rid = db.scalar("SELECT MIN(id) FROM regulatory_requirement")
    with pytest.raises(CatalogError) as exc:
        catalog.review(db, "requirement", rid, reviewer="bob", decision="APPROVED")
    assert code(exc) == "DOCUMENT_NOT_REVIEWED"
    catalog.review_document_version(db, vid, reviewer="bob", decision="APPROVED")
    with pytest.raises(CatalogError) as exc:
        catalog.review(db, "requirement", rid, reviewer="llm:fake-multilingual:test", decision="APPROVED")
    assert code(exc) == "SELF_APPROVAL"
    catalog.review(db, "requirement", rid, reviewer="bob", decision="APPROVED")
    with pytest.raises(Exception, match="immutable"):
        db.x("UPDATE regulatory_requirement SET original_text='Operators shall rotate every 30 days.' WHERE id=?", (rid,))


def test_manual_requirement_must_also_be_grounded(tmp_path):
    db = s.make_db(tmp_path)
    vid = synced(db, tmp_path)
    section = db.scalar("SELECT id FROM document_section WHERE version_id=? AND ordinal=3", (vid,))
    with pytest.raises(CatalogError) as exc:
        extraction.add_manual_requirement(db, section_id=section, quote=s.ROTATION_QUOTE, pam_domains=["credential_lifecycle"],
                                          obligation_type="MANDATORY", actor="alice")
    assert code(exc) == "REQUIREMENT_REJECTED"  # that sentence is in Article 7, not Article 9
    rid = extraction.add_manual_requirement(
        db, section_id=section, quote="Operators shall review privileged access rights periodically.",
        pam_domains=["access_reviews"], obligation_type="MANDATORY", actor="alice")
    catalog.review(db, "requirement", rid, reviewer="alice", decision="APPROVED")  # a person may review their own draft


def test_requirement_cannot_be_approved_after_its_source_loses_verification(tmp_path):
    from regintel.sources import registry as sources

    db = s.make_db(tmp_path)
    vid = synced(db, tmp_path)
    extraction.extract_version(db, vid, s.good_llm())
    sources.verify_source(db, "syn-gazette", verifier="carla", outcome="REJECTED",
                          evidence="Fixture: domain turned out to be an unofficial mirror of the gazette.")
    with pytest.raises(CatalogError) as exc:
        catalog.review(db, "requirement", db.scalar("SELECT MIN(id) FROM regulatory_requirement"), reviewer="bob", decision="APPROVED")
    assert code(exc) == "SOURCE_NOT_VERIFIED"


# ---------------------------------------------------------------- mappings, remediation, publication


def test_mapping_validation(tmp_path):
    db = s.make_db(tmp_path)
    ids = s.reviewed_requirements(db, tmp_path)
    good = dict(requirement_id=ids["rotation"], pam_control_id="PAMC-CRED-ROTATION", strength="DIRECT",
                rationale="The control test measures the rotation interval the passage requires.",
                limitations="Covers accounts managed in Securden only.", actor="alice")
    for change, expected in (({"pam_control_id": "PAMC-NOPE"}, "UNKNOWN_PAM_CONTROL"), ({"requirement_id": 9999}, "NOT_FOUND")):
        with pytest.raises(CatalogError) as exc:
            catalog.create_mapping(db, **{**good, **change})
        assert code(exc) == expected
    for change in ({"rationale": "because"}, {"limitations": ""}, {"strength": "TOTAL"}):
        with pytest.raises(Exception, match="CHECK constraint"):
            catalog.create_mapping(db, **{**good, **change})
    mid = catalog.create_mapping(db, **good)
    with pytest.raises(Exception, match="UNIQUE"):
        catalog.create_mapping(db, **good)
    with pytest.raises(CatalogError) as exc:
        catalog.review(db, "mapping", mid, reviewer="llm:fake-multilingual:test", decision="APPROVED")
    assert code(exc) == "SELF_APPROVAL"
    catalog.review(db, "mapping", mid, reviewer="alice", decision="APPROVED")
    with pytest.raises(Exception, match="immutable"):
        db.x("UPDATE framework_control_mapping SET rationale='rewritten after approval, no review' WHERE id=?", (mid,))


def test_mapping_to_a_draft_requirement_is_refused(tmp_path):
    db = s.make_db(tmp_path)
    vid = synced(db, tmp_path)
    extraction.extract_version(db, vid, s.good_llm())
    with pytest.raises(CatalogError) as exc:
        catalog.create_mapping(db, requirement_id=db.scalar("SELECT MIN(id) FROM regulatory_requirement"),
                               pam_control_id="PAMC-CRED-ROTATION", strength="DIRECT", rationale="x" * 30,
                               limitations="y" * 20, actor="alice")
    assert code(exc) == "REQUIREMENT_NOT_APPROVED"


def test_one_control_supports_many_frameworks_and_one_requirement_many_controls(tmp_path):
    db = s.make_db(tmp_path)
    ids = s.reviewed_requirements(db, tmp_path)
    kw = dict(strength="PARTIAL", rationale="Fixture rationale long enough to pass.", limitations="Fixture limitation.", actor="alice")
    catalog.create_mapping(db, requirement_id=ids["rotation"], pam_control_id="PAMC-CRED-ROTATION", **kw)
    catalog.create_mapping(db, requirement_id=ids["rotation"], pam_control_id="PAMC-AUDIT-LOG-COMPLETENESS", **kw)
    catalog.create_mapping(db, requirement_id=ids["session"], pam_control_id="PAMC-AUDIT-LOG-COMPLETENESS", **kw)
    assert db.scalar("SELECT COUNT(DISTINCT pam_control_id) FROM framework_control_mapping WHERE requirement_id=?", (ids["rotation"],)) == 2
    assert db.scalar("SELECT COUNT(DISTINCT requirement_id) FROM framework_control_mapping WHERE pam_control_id='PAMC-AUDIT-LOG-COMPLETENESS'") == 2


def remediation(db, ids, **over):
    kw = dict(finding_category="ROTATION_AGE_EXCEEDED", pam_control_id="PAMC-CRED-ROTATION",
              corrective_actions=["Rotate the credentials of the listed accounts."],
              securden_capabilities=["Scheduled remote password reset"],
              customer_responsibilities=["Maintain connectivity and permissions for remote reset on target systems"],
              source_citations=[{"requirement_id": ids["rotation"]}], actor="alice")
    kw.update(over)
    return catalog.create_remediation(db, **kw)


def test_remediation_templates_are_complete_cited_and_never_auto_executed(tmp_path):
    db = s.make_db(tmp_path)
    ids = s.reviewed_requirements(db, tmp_path)
    for over, expected in (({"source_citations": []}, "CITATION_REQUIRED"), ({"customer_responsibilities": []}, "INCOMPLETE_REMEDIATION"),
                           ({"source_citations": [{"url": "https://blog.example"}]}, "INVALID_CITATION"),
                           ({"finding_category": "rotate now"}, "INVALID_FINDING_CATEGORY")):
        with pytest.raises(CatalogError) as exc:
            remediation(db, ids, **over)
        assert code(exc) == expected
    tid = remediation(db, ids)
    with pytest.raises(Exception, match="CHECK constraint"):
        db.x("UPDATE remediation_template SET auto_execute=1 WHERE id=?", (tid,))


def test_publication_only_contains_approved_entities_and_is_immutable(tmp_path):
    db = s.make_db(tmp_path)
    ids = s.reviewed_requirements(db, tmp_path)
    draft = catalog.create_mapping(db, requirement_id=ids["session"], pam_control_id="PAMC-SESSION-RECORDING", strength="DIRECT",
                                   rationale="Fixture rationale long enough to pass.", limitations="Fixture limitation.", actor="alice")
    out = catalog.publish_catalog(db, "bob")
    assert out["published"] and out["counts"] == {"requirement": 3}
    assert db.one("SELECT published_seq FROM framework_control_mapping WHERE id=?", (draft,))["published_seq"] is None
    assert catalog.publish_catalog(db, "bob")["published"] is False  # nothing new
    with pytest.raises(Exception, match="immutable"):
        db.x("UPDATE catalog_publication SET summary='{}'")
    m = coverage.metrics(db)
    assert m["verified_requirements"] == 3 and m["approved_pam_mappings"] == 0
    eu = coverage.jurisdiction_coverage(db, "EU")[0]
    assert eu["stage"] == "REQUIREMENTS_PUBLISHED" and eu["fully_supported"] is None
    assert coverage.jurisdiction_coverage(db, "DE")[0]["stage"] == "REGISTERED_ONLY"  # EU coverage is not German coverage


def test_publication_is_blocked_if_a_reference_broke_after_approval(tmp_path):
    from regintel.sources import registry as sources

    db = s.make_db(tmp_path)
    s.reviewed_requirements(db, tmp_path)
    sources.verify_source(db, "syn-gazette", verifier="carla", outcome="REJECTED",
                          evidence="Fixture: verification withdrawn before publication took place.")
    with pytest.raises(CatalogError) as exc:
        catalog.publish_catalog(db, "bob")
    assert code(exc) == "PUBLICATION_BLOCKED"
    assert db.catalog_version() == 1  # only the framework verification; no partial catalog publication


def test_withdrawal_cascades_to_mappings_and_flags_rules(tmp_path):
    db = s.make_db(tmp_path)
    ids = s.reviewed_requirements(db, tmp_path)
    mid = catalog.create_mapping(db, requirement_id=ids["rotation"], pam_control_id="PAMC-CRED-ROTATION", strength="DIRECT",
                                 rationale="Fixture rationale long enough to pass.", limitations="Fixture limitation.", actor="alice")
    catalog.review(db, "mapping", mid, reviewer="bob", decision="APPROVED")
    s.draft_rule(db, ids["rotation"])
    catalog.publish_catalog(db, "bob")
    out = catalog.withdraw(db, "requirement", ids["rotation"], actor="bob", reason="Fixture: passage was mis-transcribed.")
    assert set(out["withdrawn"]) == {f"requirement:{ids['rotation']}", f"mapping:{mid}"}
    assert out["rule_versions_to_review"] == ["REG-SYN-ROTATION-001 1.0"]
    assert db.one("SELECT status FROM framework_control_mapping WHERE id=?", (mid,))["status"] == "WITHDRAWN"


# ---------------------------------------------------------------- supersession / history


def test_superseded_regulation_keeps_history_and_stops_applying(tmp_path):
    db = s.make_db(tmp_path)
    ids = s.reviewed_requirements(db, tmp_path)
    catalog.publish_catalog(db, "bob")
    s.sync(db, {f"https://{s.DOMAIN}/act/en": s.ACT_EN_V2}, tmp_path)
    v2 = db.scalar("SELECT MAX(id) FROM regulatory_document_version")
    assert db.one("SELECT supersedes_version_id FROM regulatory_document_version WHERE id=?", (v2,))["supersedes_version_id"] == ids["version"]
    # Detecting a change alters nothing by itself.
    assert db.one("SELECT status FROM regulatory_requirement WHERE id=?", (ids["rotation"],))["status"] == "APPROVED"
    with pytest.raises(CatalogError) as exc:
        catalog.review_document_version(db, v2, reviewer="bob", decision="APPROVED", supersede_previous=True)
    assert code(exc) == "MISSING_START_DATE"
    catalog.review_document_version(db, v2, reviewer="bob", decision="APPROVED", effective_from="2026-07-01", supersede_previous=True)
    old = db.one("SELECT status, effective_from, effective_to FROM regulatory_requirement WHERE id=?", (ids["rotation"],))
    assert old == {"status": "SUPERSEDED", "effective_from": "2025-01-01", "effective_to": "2026-07-01"}
    assert db.one("SELECT status, effective_to FROM regulatory_document_version WHERE id=?", (ids["version"],)) == {
        "status": "SUPERSEDED", "effective_to": "2026-07-01"}
    assert db.scalar("SELECT COUNT(*) FROM regulatory_change WHERE status='OPEN'") == 0
    # The 60-day text is a new requirement that needs its own extraction and review.
    assert db.scalar("SELECT COUNT(*) FROM regulatory_requirement WHERE document_version_id=?", (v2,)) == 0
    with pytest.raises(CatalogError) as exc:  # the old text can no longer back a new mapping
        catalog.create_mapping(db, requirement_id=ids["rotation"], pam_control_id="PAMC-CRED-ROTATION", strength="DIRECT",
                               rationale="Fixture rationale long enough to pass.", limitations="Fixture limitation.", actor="alice")
    assert code(exc) == "REQUIREMENT_NOT_APPROVED"


def test_framework_dates_require_reviewed_official_evidence(tmp_path):
    db = s.make_db(tmp_path)
    vid = synced(db, tmp_path, review=False)
    kw = dict(reviewer="bob", evidence_version_id=vid, lifecycle="IN_FORCE", effective_from="2025-01-01")
    with pytest.raises(CatalogError) as exc:
        registry.verify_framework(db, "SYN-EU-ACT", **kw)
    assert code(exc) == "EVIDENCE_NOT_REVIEWED"
    catalog.review_document_version(db, vid, reviewer="bob", decision="APPROVED")
    with pytest.raises(CatalogError) as exc:  # evidence belongs to a different framework
        registry.verify_framework(db, "SYN-DE-IMPL", **kw)
    assert code(exc) == "EVIDENCE_NOT_REVIEWED"
    with pytest.raises(CatalogError) as exc:
        registry.verify_framework(db, "SYN-EU-ACT", **{**kw, "lifecycle": "SUPERSEDED", "effective_to": "2026-01-01"})
    assert code(exc) == "MISSING_SUCCESSOR"
    registry.verify_framework(db, "SYN-EU-ACT", **kw)
    assert db.one("SELECT verification_status, lifecycle FROM regulatory_framework WHERE id='SYN-EU-ACT'") == {
        "verification_status": "VERIFIED", "lifecycle": "IN_FORCE"}
