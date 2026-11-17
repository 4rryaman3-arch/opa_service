"""Catalog API consumed by the Securden Django application: auth, filtering,
pagination, versioning, incremental synchronization, coverage dashboard."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from regintel import catalog, extraction, registry
from regintel.db import CatalogDb

from .. import helpers
from ..conftest import ROOT, make_settings
from . import support as s

sys.path.insert(0, str(ROOT / "client"))
from securden_opm_client import OpmClient, OpmRequestError, OpmResponseError, RetryPolicy  # noqa: E402

H = lambda: helpers.auth("catalog-sync")  # noqa: E731
BASE = "/api/v1/catalog"


def mapping(db, req, control="PAMC-CRED-ROTATION") -> int:
    mid = catalog.create_mapping(db, requirement_id=req, pam_control_id=control, strength="DIRECT",
                                 rationale="Fixture rationale long enough to pass.", limitations="Fixture limitation.", actor="alice")
    catalog.review(db, "mapping", mid, reviewer="bob", decision="APPROVED")
    return mid


@pytest.fixture
def env(tmp_path, clients_file):
    """Populated catalog + API app (OPA unreachable: the catalog does not need it)."""
    db = s.make_db(tmp_path, subdivisions=True)
    ids = s.reviewed_requirements(db, tmp_path)
    ids["mapping"] = mapping(db, ids["rotation"])
    ids["evidence"] = catalog.create_evidence_requirement(
        db, pam_control_id="PAMC-CRED-ROTATION", evidence_type="credential_rotation",
        description="One record per privileged account with its last successful rotation time.",
        fields=["account_id", "privileged", "last_rotated_at"], actor="alice")
    catalog.review(db, "evidence_requirement", ids["evidence"], reviewer="bob", decision="APPROVED")
    ids["remediation"] = catalog.create_remediation(
        db, finding_category="ROTATION_AGE_EXCEEDED", pam_control_id="PAMC-CRED-ROTATION",
        corrective_actions=["Rotate the credentials of the listed accounts."],
        securden_capabilities=["Scheduled remote password reset"],
        customer_responsibilities=["Keep target systems reachable for remote reset"],
        source_citations=[{"requirement_id": ids["rotation"]}], actor="alice")
    catalog.review(db, "remediation", ids["remediation"], reviewer="bob", decision="APPROVED")
    ids["catalog_version"] = catalog.publish_catalog(db, "bob")["catalog_version"]
    settings = make_settings(tmp_path, clients_file, "http://127.0.0.1:9", catalog_db_path=Path(db.path),
                             opa_connect_timeout_seconds=0.5)
    with TestClient(create_app(settings)) as client:
        yield client, db, ids


# ---------------------------------------------------------------- auth / availability


def test_catalog_requires_authentication_and_scope(env):
    client, _, _ = env
    for path in ("meta", "jurisdictions", "frameworks", "requirements", "mappings", "rules", "remediations", "changes",
                 "coverage", "coverage/unverified", "sources", "pam-controls", "evidence-requirements"):
        assert client.get(f"{BASE}/{path}").status_code == 401, path
        r = client.get(f"{BASE}/{path}", headers=helpers.auth("readonly-a"))
        assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN", path
        assert client.get(f"{BASE}/{path}", headers=H()).status_code == 200, path
    assert client.post(f"{BASE}/applicability", json={"countries_of_operation": ["DE"]}).status_code == 401


def test_catalog_api_is_read_only(env):
    client, _, _ = env
    for method in ("post", "put", "delete", "patch"):
        for path in ("requirements", "mappings", "rules", "frameworks/SYN-EU-ACT"):
            assert getattr(client, method)(f"{BASE}/{path}", headers=H()).status_code in (404, 405)


def test_missing_catalog_database_is_503_and_does_not_break_the_service(tmp_path, clients_file):
    settings = make_settings(tmp_path, clients_file, "http://127.0.0.1:9", catalog_db_path=tmp_path / "absent.db")
    with TestClient(create_app(settings)) as client:
        r = client.get(f"{BASE}/meta", headers=H())
        assert r.status_code == 503 and r.json()["error"]["code"] == "CATALOG_UNAVAILABLE"
        assert client.get("/health").json() == {"status": "ok"}
        assert client.get("/api/v1/rules", params={"tenant_id": "tenant-a"}, headers=helpers.auth()).status_code == 200


def test_every_response_is_versioned(env):
    client, _, ids = env
    for path in ("meta", "jurisdictions?limit=1", "frameworks", "requirements", "changes", "coverage"):
        body = client.get(f"{BASE}/{path}", headers=H()).json()
        assert body["schema_version"] == "1.0" and body["catalog_version"] == ids["catalog_version"], path
    meta = client.get(f"{BASE}/meta", headers=H()).json()
    assert meta["layers"] == ["CUSTOMER_POLICY", "EXECUTABLE_RULE", "EXPLICIT_OBLIGATION", "INTERPRETIVE_MAPPING"]
    assert len(meta["pam_domains"]) == 11


# ---------------------------------------------------------------- jurisdictions / frameworks


def test_jurisdiction_listing_paginates_through_the_whole_registry(env):
    client, _, _ = env
    seen, after, pages = [], "", 0
    while True:
        page = client.get(f"{BASE}/jurisdictions", params={"kind": "COUNTRY_OR_TERRITORY", "limit": 100, "after": after}, headers=H()).json()
        seen += [j["code"] for j in page["items"]]
        pages += 1
        if not page["has_more"]:
            break
        after = page["next_cursor"]
    assert len(seen) == len(set(seen)) == 249 and pages == 3 and seen == sorted(seen)
    de = next(j for j in client.get(f"{BASE}/jurisdictions", params={"after": "DD", "limit": 1}, headers=H()).json()["items"])
    assert de["code"] == "DE" and de["coverage"]["stage"] == "REGISTERED_ONLY" and de["coverage"]["fully_supported"] is None
    subs = client.get(f"{BASE}/jurisdictions", params={"parent": "DE", "limit": 500}, headers=H()).json()
    assert len(subs["items"]) == 16
    assert client.get(f"{BASE}/jurisdictions", params={"limit": 501}, headers=H()).status_code == 422


def test_jurisdiction_detail_shows_overlap_and_per_jurisdiction_coverage(env):
    client, _, _ = env
    body = client.get(f"{BASE}/jurisdictions/DE-BY", headers=H()).json()
    assert [c["code"] for c in body["overlapping_jurisdictions"]] == ["DE-BY", "DE", "EU"]
    assert body["coverage"]["EU"]["stage"] == "MAPPINGS_PUBLISHED" and body["coverage"]["DE"]["stage"] == "REGISTERED_ONLY"
    gb = client.get(f"{BASE}/jurisdictions/GB", params={"as_of": "2019-01-01"}, headers=H()).json()
    assert [c["code"] for c in gb["overlapping_jurisdictions"]] == ["GB", "EU"]
    assert client.get(f"{BASE}/jurisdictions/ZZ", headers=H()).json()["error"]["code"] == "UNKNOWN_JURISDICTION"


def test_framework_discovery_with_country_and_industry_filters(env):
    client, _, _ = env
    de = client.get(f"{BASE}/frameworks", params={"jurisdiction": "DE"}, headers=H()).json()
    assert {f["id"]: f["jurisdiction_path"] for f in de["items"]} == {"SYN-DE-IMPL": "SELF", "SYN-EU-ACT": "MEMBER:DE"}
    assert "does not mean a framework applies" in de["note"]
    own = client.get(f"{BASE}/frameworks", params={"jurisdiction": "DE", "include_overlapping": False}, headers=H()).json()
    assert [f["id"] for f in own["items"]] == ["SYN-DE-IMPL"]
    assert client.get(f"{BASE}/frameworks", params={"jurisdiction": "IN"}, headers=H()).json()["items"] == []
    pay = client.get(f"{BASE}/frameworks", params={"jurisdiction": "FR", "industry": "payments"}, headers=H()).json()["items"]
    assert [(f["id"], f["industry_filter_match"]) for f in pay] == [("SYN-EU-ACT", "LISTED")]
    health = client.get(f"{BASE}/frameworks", params={"jurisdiction": "DE", "industry": "healthcare"}, headers=H()).json()["items"]
    assert [(f["id"], f["industry_filter_match"]) for f in health] == [("SYN-DE-IMPL", "NO_INDUSTRY_RESTRICTION_RECORDED")]
    verified = client.get(f"{BASE}/frameworks", params={"verified_only": True}, headers=H()).json()["items"]
    assert [f["id"] for f in verified] == ["SYN-EU-ACT"]
    by_id = {f["id"]: f for f in client.get(f"{BASE}/frameworks", headers=H()).json()["items"]}
    assert by_id["SYN-EU-ACT"]["in_force_on_as_of"] is True and by_id["SYN-EU-ACT"]["published_requirements"] == 3
    assert by_id["SYN-DE-IMPL"]["in_force_on_as_of"] is None  # unverified: unknown, not "in force"
    assert by_id["SYN-DE-IMPL"]["coverage_note"].startswith("No source-verified requirements")
    past = client.get(f"{BASE}/frameworks", params={"as_of": "2024-06-01"}, headers=H()).json()["items"]
    assert {f["id"]: f["in_force_on_as_of"] for f in past}["SYN-EU-ACT"] is False


def test_framework_detail_has_source_references_and_unsupported_is_explicit(env):
    client, _, ids = env
    body = client.get(f"{BASE}/frameworks/SYN-EU-ACT", headers=H()).json()
    ref = body["source_references"][0]
    assert ref["authority"] == "Synthetic Regulator (fixture)" and ref["url"] == f"https://{s.DOMAIN}/act/en"
    assert ref["version_id"] == ids["version"] and len(ref["content_sha256"]) == 64 and ref["source_status"] == "VERIFIED"
    r = client.get(f"{BASE}/frameworks/PCI-DSS", headers=H())
    assert r.status_code == 404 and r.json()["error"]["code"] == "UNSUPPORTED_FRAMEWORK"
    assert client.get(f"{BASE}/requirements", params={"framework_id": "PCI-DSS"}, headers=H()).json()["error"]["code"] == "UNSUPPORTED_FRAMEWORK"


# ---------------------------------------------------------------- requirements / mappings


def test_requirements_carry_layer_original_text_and_full_citation(env):
    client, _, ids = env
    items = client.get(f"{BASE}/requirements", params={"framework_id": "SYN-EU-ACT", "pam_domain": "credential_lifecycle"}, headers=H()).json()["items"]
    assert len(items) == 1
    r = items[0]
    assert r["layer"] == "EXPLICIT_OBLIGATION" and r["original_text"] == s.ROTATION_QUOTE and r["original_language"] == "en"
    assert r["thresholds_stated_in_text"] == [{"value_text": "90 days", "meaning": "interval"}]
    assert r["translation_en"] is None and r["extraction_method"] == "LOCAL_LLM"
    assert r["source_reference"]["section"] == "#2 Article 7 Privileged credentials"
    assert r["source_reference"]["document"] == "SYN-ACT" and r["source_reference"]["authority_jurisdiction"] == "EU"


def test_drafts_and_unpublished_approvals_are_never_served(env):
    client, db, ids = env
    section = db.scalar("SELECT id FROM document_section WHERE version_id=? AND ordinal=3", (ids["version"],))
    rid = extraction.add_manual_requirement(db, section_id=section, quote="Operators shall review privileged access rights periodically.",
                                            pam_domains=["access_reviews"], obligation_type="MANDATORY", actor="alice")
    assert len(client.get(f"{BASE}/requirements", headers=H()).json()["items"]) == 3
    catalog.review(db, "requirement", rid, reviewer="bob", decision="APPROVED")
    assert len(client.get(f"{BASE}/requirements", headers=H()).json()["items"]) == 3  # approved, not yet published
    catalog.publish_catalog(db, "bob")
    assert len(client.get(f"{BASE}/requirements", headers=H()).json()["items"]) == 4


def test_unreviewed_translation_text_is_not_served(tmp_path, clients_file):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, languages=("de",))
    s.sync(db, {f"https://{s.DOMAIN}/act/de": s.ACT_DE})
    catalog.review_document_version(db, 1, reviewer="bob", decision="APPROVED")
    extraction.extract_version(db, 1, s.good_llm())
    catalog.review(db, "requirement", 1, reviewer="bob", decision="APPROVED", attestations={"reviewed_in_original_language": True})
    catalog.publish_catalog(db, "bob")
    settings = make_settings(tmp_path, clients_file, "http://127.0.0.1:9", catalog_db_path=Path(db.path))
    with TestClient(create_app(settings)) as client:
        r = client.get(f"{BASE}/requirements", headers=H()).json()["items"][0]
        assert r["original_text"] == s.ROTATION_QUOTE_DE and r["original_language"] == "de"
        t = r["translation_en"]
        assert t["status"] == "UNREVIEWED" and t["text"] is None and t["authoritative"] is False
        assert t["model"] == "fake-multilingual:test" and t["model_version"] == "sha256:fixture-weights"
        assert client.get(f"{BASE}/coverage/unverified", headers=H()).json()["unreviewed_translations"] == 1
        catalog.review_translation(db, 1, reviewer="carla", decision="REVIEWED")
        t = client.get(f"{BASE}/requirements", headers=H()).json()["items"][0]["translation_en"]
        assert t["status"] == "REVIEWED" and t["text"].startswith("Operators must") and t["authoritative"] is False


def test_licensing_restriction_withholds_text_but_keeps_citation(tmp_path, clients_file):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, redistribute=False)
    s.sync(db, {f"https://{s.DOMAIN}/act/en": s.ACT_EN_V1})
    catalog.review_document_version(db, 1, reviewer="bob", decision="APPROVED")
    extraction.extract_version(db, 1, s.good_llm())
    catalog.review(db, "requirement", 1, reviewer="bob", decision="APPROVED")
    catalog.publish_catalog(db, "bob")
    settings = make_settings(tmp_path, clients_file, "http://127.0.0.1:9", catalog_db_path=Path(db.path))
    with TestClient(create_app(settings)) as client:
        r = client.get(f"{BASE}/requirements", headers=H()).json()["items"][0]
        assert r["original_text"] is None and "licensing" in r["text_withheld_reason"] and r["thresholds_stated_in_text"] == []
        assert r["source_reference"]["section"] and r["source_reference"]["url"]


def test_historical_requirements_by_as_of_date(env):
    client, db, ids = env
    s.sync(db, {f"https://{s.DOMAIN}/act/en": s.ACT_EN_V2})
    v2 = db.scalar("SELECT MAX(id) FROM regulatory_document_version")
    catalog.review_document_version(db, v2, reviewer="bob", decision="APPROVED", effective_from="2026-07-01", supersede_previous=True)
    current = client.get(f"{BASE}/requirements", headers=H()).json()["items"]
    assert current == []  # superseded text is no longer current; the new text is not reviewed yet
    past = client.get(f"{BASE}/requirements", params={"as_of": "2026-03-01"}, headers=H()).json()["items"]
    assert {r["status"] for r in past} == {"SUPERSEDED"} and len(past) == 3
    assert past[0]["effective_to"] == "2026-07-01"
    assert client.get(f"{BASE}/requirements", params={"as_of": "2024-06-01"}, headers=H()).json()["items"] == []
    assert len(client.get(f"{BASE}/requirements", params={"include_historical": True}, headers=H()).json()["items"]) == 3
    # mappings to superseded text drop out of the current mapping list
    assert client.get(f"{BASE}/mappings", headers=H()).json()["items"] == []


def test_mappings_include_rationale_limitations_sources_and_disclaimer(env):
    client, _, ids = env
    body = client.get(f"{BASE}/mappings", params={"framework_id": "SYN-EU-ACT"}, headers=H()).json()
    m = body["items"][0]
    assert m["layer"] == "INTERPRETIVE_MAPPING" and m["approval_status"] == "APPROVED" and m["approved_at"]
    assert m["rationale"] and m["limitations"] and m["source_references"][0]["section"].startswith("#2 Article 7")
    assert "not legal advice" in body["mapping_disclaimer"]
    by_rule = client.get(f"{BASE}/mappings", params={"rule_id": "PAM-ROTATION-001"}, headers=H()).json()["items"]
    assert [x["id"] for x in by_rule] == [ids["mapping"]]
    assert client.get(f"{BASE}/mappings", params={"rule_id": "PAM-SESSREC-001"}, headers=H()).json()["items"] == []
    controls = {c["id"]: c for c in client.get(f"{BASE}/pam-controls", headers=H()).json()["items"]}
    assert controls["PAMC-CRED-ROTATION"]["frameworks_mapped"] == ["SYN-EU-ACT"]
    assert controls["PAMC-CRED-ROTATION"]["rule_ids"] == ["PAM-ROTATION-001"]
    assert controls["PAMC-MFA-PRIVILEGED"]["frameworks_mapped"] == []


def test_evidence_rules_and_remediation_endpoints(env):
    client, _, ids = env
    ev = client.get(f"{BASE}/evidence-requirements", params={"pam_control_id": "PAMC-CRED-ROTATION"}, headers=H()).json()["items"]
    assert ev[0]["evidence_type"] == "credential_rotation" and ev[0]["fields"] == ["account_id", "last_rotated_at", "privileged"]
    rules_body = client.get(f"{BASE}/rules", headers=H()).json()
    assert rules_body["bundle_consistent"] is True and rules_body["active_policy_bundle"] is None
    rot = next(r for r in rules_body["items"] if r["rule_id"] == "PAM-ROTATION-001")
    assert rot["layer"] == "EXECUTABLE_RULE" and [v["version"] for v in rot["versions"]] == ["1.0", "1.1"]
    assert rot["versions"][0]["threshold_provenance"][0]["origin"] == "CUSTOMER_POLICY"
    assert len(rules_body["items"]) == 14  # 10 original + MFA configuration/at-access, session idle/duration
    rem = client.get(f"{BASE}/remediations", params={"finding_category": "ROTATION_AGE_EXCEEDED"}, headers=H()).json()
    t = rem["items"][0]
    assert t["automatic_execution"] is False and t["review_status"] == "APPROVED"
    assert t["framework_references"] == [{"framework_id": "SYN-EU-ACT", "section_ref": "#2 Article 7 Privileged credentials",
                                          "requirement_id": ids["rotation"]}]
    assert t["customer_responsibilities"] and t["securden_supported_capabilities"] and t["source_citations"]
    assert "Nothing is executed automatically" in rem["note"]


# ---------------------------------------------------------------- applicability over HTTP


def test_applicability_endpoint(env):
    client, _, _ = env
    r = client.post(f"{BASE}/applicability", headers=H(), json={
        "countries_of_operation": ["DE"], "industries": ["payments"], "selected_frameworks": ["SYN-STD", "NOPE-1"],
        "as_of": "2026-03-01"})
    body = r.json()
    assert r.status_code == 200 and body["catalog_version"] and "not legal advice" in body["disclaimer"]
    by_id = {x["framework_id"]: x["outcome"] for x in body["results"]}
    assert by_id == {"SYN-DE-IMPL": "REQUIRES_LEGAL_REVIEW", "SYN-EU-ACT": "REQUIRES_LEGAL_REVIEW", "SYN-STD": "APPLICABLE"}
    assert body["unsupported_frameworks"][0]["framework_id"] == "NOPE-1"
    assert client.post(f"{BASE}/applicability", headers=H(), json={"countries_of_operation": ["ZZ"]}).json()["error"]["code"] == "UNKNOWN_JURISDICTION"
    assert client.post(f"{BASE}/applicability", headers=H(), json={"countries_of_operation": ["DE"], "verdict": "APPLICABLE"}).status_code == 422
    assert client.post(f"{BASE}/applicability", headers=H(), json={"countries_of_operation": []}).status_code == 422


# ---------------------------------------------------------------- coverage dashboard


def test_coverage_dashboard_metrics(env):
    client, _, _ = env
    body = client.get(f"{BASE}/coverage", headers=H()).json()
    m = body["metrics"]
    assert m["jurisdictions_registered"]["by_kind"]["COUNTRY_OR_TERRITORY"] == 249
    assert m["official_sources_configured"] == {"total": 1, "by_status": {"VERIFIED": 1}, "verified": 1}
    assert m["sources_successfully_synchronized"] == 1 and m["stale_regulatory_sources"] == 0
    assert m["documents_retrieved"] == 1 and m["documents_awaiting_review"] == 0
    assert m["verified_requirements"] == 3 and m["approved_pam_mappings"] == 1
    assert m["published_opa_rules"] == {"catalog_rules_in_active_bundle": 0, "active_bundle_version": None, "predefined_rules_registered": 14}
    assert m["regulatory_changes_detected"] == {"total": 0, "open": 0}
    # Published EU requirements do not make any *country* supported.
    assert m["unsupported_jurisdictions"] == 249 and m["countries_and_territories_by_stage"]["REGISTERED_ONLY"] == 249
    assert "fully supported" in m["statement"]
    assert body["source_freshness"][0]["freshness"] == "FRESH"
    src = client.get(f"{BASE}/sources", headers=H()).json()["items"][0]
    assert src["official_domains"] == [s.DOMAIN] and src["verification"]["verifier"] == "bob" and src["licensing"]["redistribute_text"] is True


def test_unverified_coverage_is_listed_explicitly(env):
    client, db, _ = env
    registry.seed_starter_sources(db)
    body = client.get(f"{BASE}/coverage/unverified", params={"limit": 5}, headers=H()).json()
    assert body["has_more"] and len(body["items"]) == 5 and all(i["stage"] == "REGISTERED_ONLY" for i in body["items"])
    assert {f["id"] for f in body["unverified_frameworks"]} == {"EU-DORA", "EU-GDPR", "EU-NIS2", "SYN-DE-IMPL", "SYN-STD"}
    assert [x["id"] for x in body["unverified_sources"]] == ["eurlex-core"]


# ---------------------------------------------------------------- Django synchronization


def django_client(test_client: TestClient) -> OpmClient:
    """The real integration client, with its transport pointed at the test app."""
    client = OpmClient.__new__(OpmClient)
    test_client.headers.update(H())
    client._http = test_client  # noqa: SLF001
    client.retry = RetryPolicy(max_attempts=1)
    return client


def test_incremental_synchronization_with_the_django_client(env):
    test_client, db, ids = env
    client = django_client(test_client)

    # first sync: full history from 0
    changes, version = client.catalog_changes(0)
    assert version == ids["catalog_version"]
    kinds = [(c["entity_type"], c["change_type"]) for c in changes]
    assert kinds.count(("requirement", "UPSERT")) == 3 and ("mapping", "UPSERT") in kinds and ("framework", "UPSERT") in kinds
    assert [c["seq"] for c in changes] == sorted(c["seq"] for c in changes)
    assert client.catalog_changes(version) == ([], version)  # nothing new

    local = {r["id"]: r for r in client.catalog_iter("requirements", page_size=2)}  # 2 pages
    assert set(local) == {ids["rotation"], ids["session"], ids["scope"]}

    # server-side change: a withdrawal becomes a tombstone for the client
    catalog.withdraw(db, "requirement", ids["rotation"], actor="bob", reason="Fixture: withdrawn after re-review.")
    changes, new_version = client.catalog_changes(version)
    assert new_version == version + 1
    assert {(c["entity_type"], int(c["entity_id"]), c["change_type"]) for c in changes} == {
        ("requirement", ids["rotation"], "WITHDRAW"), ("mapping", ids["mapping"], "WITHDRAW")}
    for c in changes:
        if c["entity_type"] == "requirement" and c["change_type"] == "WITHDRAW":
            local.pop(int(c["entity_id"]))
    assert set(local) == {r["id"] for r in client.catalog_iter("requirements")}  # local copy == server

    with pytest.raises(OpmRequestError) as exc:
        client.catalog_changes(new_version + 50)
    assert exc.value.code == "CATALOG_VERSION_AHEAD"


def test_change_feed_pages_never_split_a_publication(env):
    test_client, db, ids = env
    page = test_client.get(f"{BASE}/changes", params={"since": 0, "limit": 2}, headers=H()).json()
    # publication 1 (framework verification) fits; publication 2 has more rows than the limit
    assert [c["publication_seq"] for c in page["items"]] == [1] and page["synced_to"] == 1 and page["has_more"]
    page = test_client.get(f"{BASE}/changes", params={"since": 1, "limit": 2}, headers=H()).json()
    assert {c["publication_seq"] for c in page["items"]} == {2} and len(page["items"]) > 2 and page["synced_to"] == 2
    client = django_client(test_client)
    changes, version = client.catalog_changes(0, page_size=2)
    assert version == ids["catalog_version"] and len(changes) == db.scalar("SELECT COUNT(*) FROM catalog_change")


def test_client_rejects_unknown_schema_versions(env):
    test_client, _, _ = env
    client = django_client(test_client)
    import regintel.api as api

    original = api.SCHEMA_VERSION
    api.SCHEMA_VERSION = "2.0"
    try:
        with pytest.raises(OpmResponseError) as exc:
            client.catalog_get("meta")
        assert exc.value.code == "UNSUPPORTED_SCHEMA"
    finally:
        api.SCHEMA_VERSION = original


def test_api_opens_the_catalog_read_only(env):
    _, db, _ = env
    ro = CatalogDb(db.path, read_only=True)
    with pytest.raises(Exception, match="readonly"):
        ro.x("DELETE FROM regulatory_requirement")
    ro.close()
