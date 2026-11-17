"""Bounding automated work: PAM keyword screening, language selection, resume
without repeated model calls, and preloading the offline staging package.
Synthetic fixtures only."""
from __future__ import annotations

import json

from regintel import automation, extraction, preload, screening
from regintel.sources import registry as sources
from . import support as s
from .test_automation import DE_URL, EN_URL, approved_framework, build, pipeline_llm


def extraction_prompts(llm: s.FakeLlm) -> list[str]:
    return [prompt for system, prompt in llm.calls if system == extraction.SYSTEM_EXTRACT]


def test_screening_sends_only_pam_sections_and_excerpts(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)
    approved_framework(db)
    llm = pipeline_llm()
    result = build(db, tmp_path, llm=llm, screening=screening.SCREENING_VERSION)

    ex = result["extraction"]
    assert result["options"]["screening"] == screening.SCREENING_VERSION
    assert ex["screened_out"] > 0 and ex["model_calls"] == ex["sections"] - ex["screened_out"]
    prompts = extraction_prompts(llm)
    assert len(prompts) == ex["model_calls"]
    assert not any(s.SCOPE_QUOTE in p for p in prompts)  # the non-PAM scope article never reaches the model
    # grounding still uses the full section: both PAM obligations were drafted, approved and published
    assert ex["drafted"] == 2 and len(result["publication"]["requirement_ids"]) == 2
    drafts = db.q("SELECT extraction FROM regulatory_requirement")
    assert all(d["extraction"]["screening"] == screening.SCREENING_VERSION for d in drafts)
    assert result["counts"]["sections_screened_out"] == ex["screened_out"]
    db.close()


def test_language_selection_excludes_other_versions(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False, languages=("en", "de"))
    approved_framework(db)
    result = build(db, tmp_path, pages={EN_URL: s.ACT_EN_V1, DE_URL: s.ACT_DE}, languages=["en"])
    de = db.one("SELECT v.id, v.status FROM regulatory_document_version v JOIN regulatory_document d "
                "ON d.id=v.document_id WHERE d.language='de'")
    assert result["documents"]["language_excluded"] == [de["id"]]
    assert de["status"] == "AWAITING_REVIEW"  # not auto-reviewed either
    assert db.scalar("SELECT COUNT(*) FROM regulatory_requirement WHERE original_language='de'") == 0
    assert result["extraction"]["drafted"] == 2
    db.close()


def test_operator_settings_are_the_default(tmp_path, monkeypatch):
    monkeypatch.setenv("OPM_REGINTEL_AUTOMATION_LANGUAGES", "en")
    monkeypatch.setenv("OPM_REGINTEL_AUTOMATION_SCREENING", screening.SCREENING_VERSION)
    assert automation.pipeline_options(None, None) == (["en"], screening.SCREENING_VERSION)
    assert automation.pipeline_options(["de"], "none") == (["de"], "none")  # explicit job values win
    monkeypatch.delenv("OPM_REGINTEL_AUTOMATION_LANGUAGES")
    monkeypatch.delenv("OPM_REGINTEL_AUTOMATION_SCREENING")
    assert automation.pipeline_options(None, None) == (None, "none")


def test_unscreened_drafts_are_left_for_humans(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)
    approved_framework(db)

    def scope_too(system, prompt):  # an unscreened earlier run also drafted the non-PAM scope sentence
        if system == extraction.SYSTEM_EXTRACT and s.SCOPE_QUOTE in prompt:
            return {"requirements": [s.candidate(s.SCOPE_QUOTE, domains=["access_control"])]}
        return pipeline_llm().script(system, prompt)

    sources.verify_source(db, "syn-gazette", verifier="bob", outcome="VERIFIED", evidence="x" * 40)
    sources.sync_source(db, "syn-gazette", blob_dir=tmp_path / "blobs", transport=s.transport({EN_URL: s.ACT_EN_V1}))
    vid = db.scalar("SELECT id FROM regulatory_document_version")
    from regintel import catalog
    catalog.review_document_version(db, vid, reviewer="bob", decision="APPROVED", comment="complete text")
    extraction.extract_version(db, vid, s.FakeLlm(scope_too), actor="w")  # unscreened: drafts the scope sentence too
    result = build(db, tmp_path, screening=screening.SCREENING_VERSION)
    scope_id = db.scalar("SELECT id FROM regulatory_requirement WHERE original_text LIKE 'This synthetic act%'")
    assert scope_id in result["review"]["not_screened"]
    assert db.scalar("SELECT status FROM regulatory_requirement WHERE id=?", (scope_id,)) == "DRAFT"
    assert result["extraction"]["model_calls"] == 0  # everything was already extracted
    assert len(result["review"]["approved"]) == 2
    db.close()


def test_staging_package_is_preloaded_and_never_reextracted(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)
    approved_framework(db)
    sources.verify_source(db, "syn-gazette", verifier="bob", outcome="VERIFIED", evidence="x" * 40)
    sources.sync_source(db, "syn-gazette", blob_dir=tmp_path / "blobs", transport=s.transport({EN_URL: s.ACT_EN_V1}))
    v = db.one("SELECT v.*, d.framework_id, d.language FROM regulatory_document_version v "
               "JOIN regulatory_document d ON d.id=v.document_id")
    sections = db.q("SELECT ordinal, section_ref, heading, text FROM document_section WHERE version_id=? "
                    "ORDER BY ordinal", (v["id"],))
    rot = next(x for x in sections if s.ROTATION_QUOTE in x["text"])
    staged = {
        "framework_id": v["framework_id"], "language": "en", "sha256": v["content_sha256"],
        "prompt_version": extraction.PROMPT_VERSION, "screening": screening.SCREENING_VERSION,
        "model": {"model": "gemma3:4b", "version": "sha256:staged", "runtime": "ollama staged"},
        "sections": sections,
        "extractions": {str(x["ordinal"]): ({"section_ref": x["section_ref"], "screened_out": False, "rejected": [],
                                             "requirements": [
                                                 s.candidate(s.ROTATION_QUOTE, thresholds=["90 days"]),
                                                 s.candidate("Operators shall never be audited by anyone at all.")]}
                                            if x["ordinal"] == rot["ordinal"] else
                                            {"section_ref": x["section_ref"], "screened_out": True,
                                             "requirements": [], "rejected": []})
                        for x in sections},
    }
    (tmp_path / "stage").mkdir()
    (tmp_path / "stage" / "SYN-EU-ACT-en.json").write_text(json.dumps(staged), encoding="utf-8")
    (tmp_path / "stage" / "summary.json").write_text("[]", encoding="utf-8")

    report = preload.import_staging(db, tmp_path / "stage", actor="opm-ops")
    assert report["drafted"] == 1  # the ungrounded staged candidate is rejected again on import
    assert report["files"][0]["rejected"] == [f"#{rot['ordinal']}: UNGROUNDED_QUOTE"]
    draft = db.one("SELECT * FROM regulatory_requirement")
    assert draft["status"] == "DRAFT" and draft["created_by"] == "llm:gemma3:4b"
    assert draft["extraction"]["imported_from"] == "staging:SYN-EU-ACT-en.json"
    attempt = db.one("SELECT * FROM extraction_attempt WHERE kind='EXTRACTION'")
    assert attempt["raw_response"] is None and "staging package" in attempt["raw_unavailable_reason"]
    assert preload.import_staging(db, tmp_path / "stage", actor="opm-ops")["drafted"] == 0  # idempotent

    llm = pipeline_llm()
    result = build(db, tmp_path, llm=llm, screening=screening.SCREENING_VERSION)
    assert not any(s.ROTATION_QUOTE in p for p in extraction_prompts(llm))  # preloaded section not re-sent
    assert result["extraction"]["already_extracted"] == 1
    assert draft["id"] in result["publication"]["requirement_ids"]  # reviewed by the policy like any draft
    db.close()


def test_source_section_screen_replaces_keyword_screen(tmp_path):
    import re

    import pytest

    from regintel.db import CatalogError
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)
    approved_framework(db)
    cfg = db.one("SELECT config FROM source WHERE id='syn-gazette'")["config"]
    with pytest.raises(CatalogError) as bad:
        sources.update_source_config(db, "syn-gazette", {**cfg, "section_screen": {"include": ["(unclosed"]}}, "t")
    assert bad.value.code == "INVALID_SOURCE_CONFIG"
    sources.update_source_config(db, "syn-gazette", {**cfg, "section_screen": {
        "include": [r"rotate the credentials"], "excerpt": [re.escape(s.ROTATION_QUOTE)]}}, "t")

    llm = pipeline_llm()
    result = build(db, tmp_path, llm=llm, screening=screening.SCREENING_VERSION)
    ex = result["extraction"]
    prompts = extraction_prompts(llm)
    assert ex["model_calls"] == len(prompts) >= 1
    assert all(s.ROTATION_QUOTE in p for p in prompts)
    assert not any(s.SESSION_QUOTE in p or s.SCOPE_QUOTE in p for p in prompts)  # only the matched span is sent
    assert ex["drafted"] == 1
    draft = db.one("SELECT * FROM regulatory_requirement")
    assert draft["extraction"]["screening"] == "pam-keyword-screen-v1+source"
    assert result["publication"]["requirement_ids"] == [draft["id"]]
    db.close()


def test_job_payload_omits_unset_bounds():
    from regintel.admin_api import OPTIONAL_JOB_FIELDS, BuildFramework
    body = BuildFramework(action="build_framework", framework_id="X", request_key="k" * 8)
    payload = body.model_dump(mode="json", exclude={"request_key"})
    assert set(OPTIONAL_JOB_FIELDS) <= set(payload)  # present on the model, stripped by submit()
