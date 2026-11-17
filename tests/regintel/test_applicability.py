"""Deterministic applicability engine."""

from __future__ import annotations

import pytest

from regintel import applicability, catalog, registry
from regintel.applicability import OrganizationProfile
from regintel.db import CatalogError

from . import support as s


def outcomes(db, **profile) -> dict[str, dict]:
    result = applicability.evaluate(db, OrganizationProfile(**profile))
    return {r["framework_id"]: r for r in result["results"]}


def criteria(db, ids, crit, framework="SYN-EU-ACT") -> int:
    cid = catalog.create_applicability_criteria(
        db, framework_id=framework, criteria=crit, requirement_ids=[ids["scope"]] if framework == "SYN-EU-ACT" else [],
        rationale="Fixture: derived from the scope article of the synthetic act.", actor="alice")
    catalog.review(db, "applicability_criteria", cid, reviewer="bob", decision="APPROVED")
    catalog.publish_catalog(db, "bob")
    return cid


@pytest.fixture
def cat(tmp_path):
    db = s.make_db(tmp_path, subdivisions=True)
    return db, s.reviewed_requirements(db, tmp_path)


def test_country_alone_never_makes_a_framework_applicable(cat):
    db, ids = cat
    r = outcomes(db, countries_of_operation=["DE"])
    assert r["SYN-EU-ACT"]["outcome"] == "REQUIRES_LEGAL_REVIEW" and "NO_REVIEWED_CRITERIA" in r["SYN-EU-ACT"]["basis"]
    criteria(db, ids, {"nexus": ["OPERATION"]})  # reviewed criteria that add nothing beyond jurisdiction
    r = outcomes(db, countries_of_operation=["DE"])
    assert r["SYN-EU-ACT"]["outcome"] == "POTENTIALLY_APPLICABLE" and "COUNTRY_MATCH_ONLY" in r["SYN-EU-ACT"]["basis"]


def test_overlapping_jurisdictions_for_a_german_organization(cat):
    db, _ = cat
    result = applicability.evaluate(db, OrganizationProfile(countries_of_operation=["DE-BY"], as_of="2026-03-01"))
    assert set(result["jurisdictions_considered"]) == {"DE-BY", "DE", "EU"}
    by_id = {r["framework_id"]: r for r in result["results"]}
    assert by_id["SYN-EU-ACT"]["jurisdiction_paths"] == ["OPERATION:DE-BY via MEMBER:DE"]
    assert by_id["SYN-DE-IMPL"]["implements_framework_id"] == "SYN-EU-ACT"
    # German implementing act was never verified: it is flagged, not asserted.
    assert by_id["SYN-DE-IMPL"]["outcome"] == "REQUIRES_LEGAL_REVIEW" and "FRAMEWORK_UNVERIFIED" in by_id["SYN-DE-IMPL"]["basis"]
    assert "SYN-STD" not in by_id  # voluntary standard nobody selected: not a candidate at all


def test_criteria_matrix(cat):
    db, ids = cat
    criteria(db, ids, {"nexus": ["OPERATION"], "industries": ["payments", "banking"], "organization_types": ["operator"]})
    base = dict(countries_of_operation=["FR"], as_of="2026-03-01")
    assert outcomes(db, **base, industries=["payments"], organization_types=["operator"])["SYN-EU-ACT"]["outcome"] == "APPLICABLE"
    partial = outcomes(db, **base, industries=["payments"])["SYN-EU-ACT"]
    assert partial["outcome"] == "POTENTIALLY_APPLICABLE" and "organization_types" in partial["reasons"][-1]
    no = outcomes(db, **base, industries=["retail"], organization_types=["operator"])["SYN-EU-ACT"]
    assert no["outcome"] == "NOT_APPLICABLE" and "CRITERION_NOT_MET" in no["basis"]
    explicit_none = outcomes(db, **base, industries=[], organization_types=["operator"])["SYN-EU-ACT"]
    assert explicit_none["outcome"] == "NOT_APPLICABLE"  # [] means "none", unlike not stated
    assert "SYN-EU-ACT" not in outcomes(db, countries_of_operation=["IN"], industries=["payments"], as_of="2026-03-01")


def test_data_processing_nexus_and_legal_review_flags(cat):
    db, ids = cat
    cid = criteria(db, ids, {"nexus": ["OPERATION"], "industries": ["payments"]})
    r = outcomes(db, countries_of_operation=["IN"], data_processing_jurisdictions=["IE"], industries=["payments"], as_of="2026-03-01")
    assert r["SYN-EU-ACT"]["outcome"] == "REQUIRES_LEGAL_REVIEW" and "NEXUS_TYPE_NOT_COVERED" in r["SYN-EU-ACT"]["basis"]
    catalog.withdraw(db, "applicability_criteria", cid, actor="bob", reason="Fixture: replacing criteria.")
    criteria(db, ids, {"nexus": ["OPERATION", "DATA_PROCESSING"], "legal_review_required": True,
                       "legal_review_note": "Thresholds depend on entity size; counsel must confirm."})
    r = outcomes(db, countries_of_operation=["DE"], industries=["payments"], as_of="2026-03-01")["SYN-EU-ACT"]
    assert r["outcome"] == "REQUIRES_LEGAL_REVIEW" and "counsel must confirm" in r["reasons"][-1]


def test_historical_effective_dates(cat):
    db, ids = cat
    criteria(db, ids, {"nexus": ["OPERATION"], "all_entities_in_jurisdiction": True})
    profile = dict(countries_of_operation=["DE"])
    before = outcomes(db, **profile, as_of="2024-06-01")["SYN-EU-ACT"]
    assert before["outcome"] == "NOT_APPLICABLE" and "not yet in force on 2024-06-01" in before["reasons"][0]
    assert outcomes(db, **profile, as_of="2025-01-01")["SYN-EU-ACT"]["outcome"] == "APPLICABLE"
    # GB was an EU member on the first date and not on the second.
    assert outcomes(db, countries_of_operation=["GB"], as_of="2025-06-01") == {}
    registry.verify_framework(db, "SYN-EU-ACT", reviewer="bob", evidence_version_id=ids["version"], lifecycle="REPEALED",
                              effective_from="2019-01-01", effective_to="2026-01-01")
    assert outcomes(db, countries_of_operation=["GB"], as_of="2019-06-01")["SYN-EU-ACT"]["outcome"] == "APPLICABLE"
    assert "SYN-EU-ACT" not in outcomes(db, countries_of_operation=["GB"], as_of="2021-06-01")
    after = outcomes(db, **profile, as_of="2026-01-01")["SYN-EU-ACT"]
    assert after["outcome"] == "NOT_APPLICABLE" and "repealed from 2026-01-01" in after["reasons"][0]


def test_customer_selected_and_contractual_frameworks(cat):
    db, _ = cat
    r = outcomes(db, countries_of_operation=["IN"])
    assert "SYN-STD" not in r
    r = outcomes(db, countries_of_operation=["IN"], selected_frameworks=["SYN-STD"], contractual_frameworks=["SYN-EU-ACT"])
    assert r["SYN-STD"]["outcome"] == "APPLICABLE" and r["SYN-STD"]["basis"] == ["CUSTOMER_SELECTED"]
    assert "dates are unverified" in " ".join(r["SYN-STD"]["reasons"])
    assert r["SYN-EU-ACT"]["basis"] == ["CONTRACTUAL"]


def test_unsupported_frameworks_are_reported_not_guessed(cat):
    db, _ = cat
    result = applicability.evaluate(db, OrganizationProfile(countries_of_operation=["DE"], selected_frameworks=["NOT-IN-CATALOG"]))
    assert result["unsupported_frameworks"] == [{
        "framework_id": "NOT-IN-CATALOG", "outcome": "REQUIRES_LEGAL_REVIEW",
        "reasons": ["framework is not registered in the catalog; no assessment is possible"]}]
    assert "not legal advice" in result["disclaimer"]


def test_cross_border_framework_without_nexus_needs_legal_review(cat):
    db, _ = cat
    registry.add_framework(db, "SYN-XB", "Synthetic extraterritorial act (fixture)", "LAW", "STATUTORY", "BR", cross_border=True)
    r = outcomes(db, countries_of_operation=["JP"])
    assert r["SYN-XB"]["outcome"] == "REQUIRES_LEGAL_REVIEW" and r["SYN-XB"]["basis"] == ["CROSS_BORDER_SCOPE"]


def test_engine_is_deterministic_and_rejects_unknown_input(cat):
    db, ids = cat
    criteria(db, ids, {"nexus": ["OPERATION"], "industries": ["payments"]})
    profile = OrganizationProfile(countries_of_operation=["DE", "FR", "US-CA"], industries=["payments"], as_of="2026-03-01")
    assert applicability.evaluate(db, profile) == applicability.evaluate(db, profile)
    with pytest.raises(CatalogError) as exc:
        applicability.evaluate(db, OrganizationProfile(countries_of_operation=["ZZ"]))
    assert exc.value.code == "UNKNOWN_JURISDICTION"
    with pytest.raises(Exception):
        OrganizationProfile(countries_of_operation=["DE"], llm_opinion="applies")
    import regintel.applicability as mod

    assert "llm" not in {name.lower() for name in vars(mod)}  # no model anywhere in this module


def test_criteria_must_be_structured_reviewed_and_cited(cat):
    db, ids = cat
    for bad in ({"free_text": "applies to big banks"}, {"nexus": []}, {"industries": ["Banking Sector!"]},
                {"all_entities_in_jurisdiction": True, "industries": ["payments"]}):
        with pytest.raises(CatalogError) as exc:
            catalog.create_applicability_criteria(db, framework_id="SYN-EU-ACT", criteria=bad, requirement_ids=[],
                                                  rationale="Fixture rationale long enough.", actor="alice")
        assert exc.value.code == "INVALID_CRITERIA"
    cid = catalog.create_applicability_criteria(db, framework_id="SYN-EU-ACT", criteria={"industries": ["payments"]},
                                                requirement_ids=[ids["scope"]], rationale="Fixture rationale long enough.", actor="alice")
    # approved-but-unpublished criteria are not used
    catalog.review(db, "applicability_criteria", cid, reviewer="bob", decision="APPROVED")
    assert outcomes(db, countries_of_operation=["DE"], industries=["payments"])["SYN-EU-ACT"]["outcome"] == "REQUIRES_LEGAL_REVIEW"
