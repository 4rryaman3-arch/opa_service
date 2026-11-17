"""Jurisdiction registry, source adapters, verification and synchronization."""

from __future__ import annotations

import pytest

from regintel import catalog, coverage, registry, textproc
from regintel.db import CatalogDb, CatalogError
from regintel.sources import registry as sources
from regintel.sources.base import ADAPTERS, Fetcher, SourceConfig, SourceError

from . import support as s


def code(exc) -> str:
    return exc.value.code


# ---------------------------------------------------------------- registry


def test_registry_covers_all_iso_3166_1_entries_and_subdivisions(tmp_path):
    db = s.make_db(tmp_path, subdivisions=True)
    assert db.scalar("SELECT COUNT(*) FROM jurisdiction WHERE kind='COUNTRY_OR_TERRITORY'") == 249
    assert db.scalar("SELECT COUNT(*) FROM jurisdiction WHERE kind='SUBDIVISION'") > 4000
    # territories and small states are first-class, not just a handful of large countries
    for c in ("DE", "IN", "US", "BR", "NG", "JP", "TV", "GL", "HK", "PR", "AQ"):
        assert db.one("SELECT 1 FROM jurisdiction WHERE code=?", (c,)), c
    assert db.one("SELECT parent_code FROM jurisdiction WHERE code='US-CA'")["parent_code"] == "US"
    registry.seed_registry(db, subdivisions=True)  # idempotent
    assert db.scalar("SELECT COUNT(*) FROM jurisdiction WHERE kind='COUNTRY_OR_TERRITORY'") == 249


def test_country_region_mapping_and_overlap(tmp_path):
    db = s.make_db(tmp_path, subdivisions=True)
    closure = registry.jurisdiction_closure(db, "DE-BY", "2026-01-01")
    assert [c["code"] for c in closure] == ["DE-BY", "DE", "EU"]
    assert closure[2]["via"] == "MEMBER:DE"
    assert [c["code"] for c in registry.jurisdiction_closure(db, "IN", "2026-01-01")] == ["IN"]
    with pytest.raises(CatalogError) as exc:
        registry.jurisdiction_closure(db, "ZZ", "2026-01-01")
    assert code(exc) == "UNKNOWN_JURISDICTION"


def test_membership_is_date_dependent(tmp_path):
    db = s.make_db(tmp_path)
    assert "EU" in [c["code"] for c in registry.jurisdiction_closure(db, "GB", "2019-06-01")]
    assert "EU" not in [c["code"] for c in registry.jurisdiction_closure(db, "GB", "2020-02-01")]
    assert "EU" not in [c["code"] for c in registry.jurisdiction_closure(db, "HR", "2013-06-30")]
    assert "EU" in [c["code"] for c in registry.jurisdiction_closure(db, "HR", "2013-07-01")]


def test_registry_is_extensible_without_code_changes(tmp_path):
    db = s.make_db(tmp_path)
    registry.add_jurisdiction(db, "GCC", "SUPRANATIONAL", "Fixture regional body")
    registry.add_membership(db, "GCC", "SA", "1981-05-25")
    assert "GCC" in [c["code"] for c in registry.jurisdiction_closure(db, "SA", "2026-01-01")]


def test_registered_jurisdiction_is_never_reported_as_supported(tmp_path):
    db = s.make_db(tmp_path)
    m = coverage.metrics(db)
    assert m["unsupported_jurisdictions"] == 249
    assert m["countries_and_territories_by_stage"]["REGISTERED_ONLY"] == 249
    row = coverage.jurisdiction_coverage(db, "DE")[0]
    assert row["stage"] == "REGISTERED_ONLY" and row["fully_supported"] is None


def test_starter_sources_load_unverified_with_no_dates(tmp_path):
    db = s.make_db(tmp_path)
    registry.seed_starter_sources(db)
    assert {r["status"] for r in db.q("SELECT status FROM source")} == {"PROPOSED"}
    for fw in db.q("SELECT * FROM regulatory_framework"):
        assert fw["verification_status"] == "UNVERIFIED" and fw["effective_from"] is None and fw["lifecycle"] == "UNKNOWN"
    assert db.scalar("SELECT COUNT(*) FROM regulatory_requirement") == 0
    assert coverage.metrics(db)["unsupported_jurisdictions"] == 249


# ---------------------------------------------------------------- adapters


def test_every_adapter_declares_the_contract():
    assert {"static_list", "index_page", "eurlex", "file_drop"} <= set(ADAPTERS)
    for cls in ADAPTERS.values():
        assert cls.discovery_methods and cls.supported_formats
    required = set(SourceConfig.model_json_schema()["required"])
    assert {"allowed_domains", "formats", "discovery", "version_identification", "change_detection", "licensing",
            "verification_method"} <= required


def test_source_domains_must_belong_to_the_authority(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db)
    cfg = s.source_config([{"external_id": "X", "url": "https://compliance-blog.example/x", "language": "en"}],
                          allowed_domains=["compliance-blog.example"])
    with pytest.raises(CatalogError) as exc:
        sources.propose_source(db, "third-party", "static_list", "A summary site", "syn-regulator", "EU", cfg,
                               languages=["en"])
    assert code(exc) == "DOMAIN_NOT_REGISTERED"


@pytest.mark.parametrize("bad", [
    {"allowed_domains": ["https://x.example/path"]}, {"allowed_domains": ["*.example"]},
    {"formats": []}, {"licensing": {"license": ""}}, {"unknown_key": 1},
])
def test_invalid_source_config_is_rejected(tmp_path, bad):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db)
    with pytest.raises(CatalogError) as exc:
        sources.propose_source(db, "bad", "static_list", "bad", "syn-regulator", "EU", s.source_config([], **bad),
                               languages=["en"])
    assert code(exc) == "INVALID_SOURCE_CONFIG"


def test_document_language_is_never_guessed(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db)
    cfg = s.source_config([{"external_id": "X", "url": f"https://{s.DOMAIN}/x"}])
    with pytest.raises(CatalogError) as exc:
        sources.propose_source(db, "nolang", "static_list", "n", "syn-regulator", "EU", cfg, languages=["en"])
    assert code(exc) == "LANGUAGE_REQUIRED"


def test_fetcher_refuses_off_allowlist_hosts_http_and_redirects():
    cfg = SourceConfig.model_validate(s.source_config([]))
    pages = {f"https://{s.DOMAIN}/moved": (302, {"location": "https://mirror.example/doc"}, ""),
             "https://mirror.example/doc": "<html>mirror</html>"}
    t = s.transport(pages)
    f = Fetcher(cfg, transport=t, sleep=lambda x: None)
    for url, expected in ((f"http://{s.DOMAIN}/a", "INSECURE_URL"), ("https://mirror.example/doc", "DOMAIN_NOT_ALLOWED"),
                          (f"https://user:pw@{s.DOMAIN}/a", "FORBIDDEN_URL"), (f"https://{s.DOMAIN}/moved", "DOMAIN_NOT_ALLOWED")):
        with pytest.raises(SourceError) as exc:
            f.get(url)
        assert exc.value.code == expected, url
    assert "https://mirror.example/doc" not in t.calls  # the off-domain hop was never requested


def test_fetcher_enforces_rate_limit_and_run_budget():
    cfg = SourceConfig.model_validate(s.source_config([], rate_limit={"min_interval_seconds": 5, "max_requests_per_run": 2}))
    slept: list[float] = []
    now = [100.0]
    f = Fetcher(cfg, transport=s.transport({f"https://{s.DOMAIN}/a": "<html></html>"}), sleep=slept.append,
                clock=lambda: now[0])
    f.get(f"https://{s.DOMAIN}/a")
    f.get(f"https://{s.DOMAIN}/a")
    assert slept == [5.0]
    with pytest.raises(SourceError) as exc:
        f.get(f"https://{s.DOMAIN}/a")
    assert exc.value.code == "RUN_BUDGET_EXCEEDED"


def test_non_200_responses_are_not_documents():
    cfg = SourceConfig.model_validate(s.source_config([]))
    f = Fetcher(cfg, transport=s.transport({f"https://{s.DOMAIN}/c": (202, {}, "<html>challenge</html>")}), sleep=lambda x: None)
    with pytest.raises(SourceError) as exc:
        f.get(f"https://{s.DOMAIN}/c")
    assert exc.value.code == "UNEXPECTED_STATUS"


def test_index_page_adapter_ignores_links_outside_the_allowlist(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db)
    index = (f'<html><body><a href="/gazette/2026-01">Issue 1</a><a href="https://summaries.example/gazette/2026-01">'
             f'Summary</a><a href="/about">About</a></body></html>')
    cfg = s.source_config([], discovery={"method": "index_page", "index_url": f"https://{s.DOMAIN}/gazette",
                                         "link_pattern": r"/gazette/\d{4}-\d{2}$", "language": "en",
                                         "framework_id": "SYN-EU-ACT"})
    sources.propose_source(db, "syn-index", "index_page", "idx", "syn-regulator", "EU", cfg, languages=["en"], actor="alice")
    sources.verify_source(db, "syn-index", verifier="bob", outcome="VERIFIED", evidence="Fixture verification of the index page domain.")
    out = sources.sync_source(db, "syn-index", sleep=lambda x: None, transport=s.transport({
        f"https://{s.DOMAIN}/gazette": index, f"https://{s.DOMAIN}/gazette/2026-01": s.ACT_EN_V1}))
    assert out["documents_seen"] == 1 and out["versions_new"] == 1


def test_eurlex_adapter_builds_per_language_urls_and_is_domain_locked(tmp_path):
    db = s.make_db(tmp_path)
    registry.seed_starter_sources(db)
    adapter = sources.build_adapter(db.one("SELECT * FROM source WHERE id='eurlex-core'"))
    refs = list(adapter.discover(None))  # type: ignore[arg-type]
    assert len(refs) == 9 and {r.language for r in refs} == {"en", "de", "fr"}
    assert refs[0].url == "https://publications.europa.eu/resource/celex/32022L2555"
    bad = dict(db.one("SELECT * FROM source WHERE id='eurlex-core'"))
    bad["config"] = {**bad["config"], "allowed_domains": ["publications.europa.eu", "mirror.example"]}
    with pytest.raises(CatalogError):
        sources.build_adapter(bad)


def test_file_drop_adapter_for_licensed_standards(tmp_path):
    db = s.make_db(tmp_path)
    registry.add_authority(db, "syn-standards-body", "Synthetic standards body (fixture)", "INT", [])
    registry.add_framework(db, "SYN-STD", "Synthetic standard (fixture)", "STANDARD", "VOLUNTARY", "INT")
    drop = tmp_path / "drop"
    drop.mkdir()
    (drop / "standard.txt").write_text("SYNTHETIC STANDARD (fixture)\n\n" + "Control text for the fixture. " * 20, encoding="utf-8")
    cfg = s.source_config([], allowed_domains=[], formats=["txt"], discovery={
        "method": "file_drop", "directory": str(drop),
        "documents": [{"external_id": "SYN-STD-2026", "file": "standard.txt", "language": "en", "framework_id": "SYN-STD"}]})
    cfg["licensing"] = {"license": "Licensed copy; redistribution prohibited", "redistribute_text": False}
    cfg["verification_method"] = "HUMAN_ATTESTATION_OF_PURCHASE"
    sources.propose_source(db, "syn-std-drop", "file_drop", "licensed", "syn-standards-body", "INT", cfg, languages=["en"], actor="alice")
    sources.verify_source(db, "syn-std-drop", verifier="bob", outcome="VERIFIED",
                          evidence="Fixture: file obtained from the standards body's own web store, order 0000.")
    assert sources.sync_source(db, "syn-std-drop")["versions_new"] == 1


# ---------------------------------------------------------------- verification & sync


def test_missing_or_unverified_official_source_blocks_sync(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)
    with pytest.raises(CatalogError) as exc:
        s.sync(db, {})
    assert code(exc) == "SOURCE_NOT_VERIFIED"
    with pytest.raises(CatalogError) as exc:
        sources.sync_source(db, "does-not-exist")
    assert code(exc) == "UNKNOWN_SOURCE"
    assert coverage.jurisdiction_coverage(db, "EU")[0]["stage"] == "SOURCE_PROPOSED"


def test_source_verification_needs_evidence(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)
    with pytest.raises(CatalogError) as exc:
        sources.verify_source(db, "syn-gazette", verifier="bob", outcome="VERIFIED", evidence="looks ok")
    assert code(exc) == "EVIDENCE_REQUIRED"


def test_changing_source_config_voids_verification(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db)
    cfg = db.one("SELECT config FROM source WHERE id='syn-gazette'")["config"]
    cfg["discovery"]["documents"].append({"external_id": "NEW", "url": f"https://{s.DOMAIN}/new", "language": "en"})
    sources.update_source_config(db, "syn-gazette", cfg, actor="alice")
    with pytest.raises(CatalogError) as exc:
        s.sync(db, {})
    assert code(exc) == "SOURCE_NOT_VERIFIED"


def test_sync_versions_by_content_hash_and_detects_change(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db)
    url = f"https://{s.DOMAIN}/act/en"
    first = s.sync(db, {url: s.ACT_EN_V1}, tmp_path)
    assert (first["status"], first["versions_new"]) == ("SUCCESS", 1)
    again = s.sync(db, {url: s.ACT_EN_V1}, tmp_path)
    assert (again["versions_new"], again["versions_changed"]) == (0, 0)
    changed = s.sync(db, {url: s.ACT_EN_V2}, tmp_path)
    assert changed["versions_changed"] == 1
    assert db.scalar("SELECT COUNT(*) FROM regulatory_change WHERE status='OPEN'") == 1
    assert db.scalar("SELECT COUNT(*) FROM regulatory_document_version") == 2
    assert len(list((tmp_path / "blobs").iterdir())) == 2
    m = coverage.metrics(db)
    assert m["regulatory_changes_detected"] == {"total": 1, "open": 1} and m["documents_awaiting_review"] == 2
    with pytest.raises(Exception, match="immutable"):
        db.x("UPDATE regulatory_document_version SET content_sha256='0' WHERE id=1")


def test_failed_sync_is_recorded_and_source_becomes_stale(tmp_path):
    from datetime import datetime, timedelta, timezone

    db = s.make_db(tmp_path)
    s.setup_synthetic(db)
    out = s.sync(db, {})  # 404
    assert out["status"] == "FAILED" and out["errors"]
    src = coverage.stale_sources(db)[0]
    assert src["freshness"] == "NEVER_SYNCHRONIZED" and src["consecutive_failures"] == 1
    s.sync(db, {f"https://{s.DOMAIN}/act/en": s.ACT_EN_V1})
    assert coverage.stale_sources(db)[0]["freshness"] == "FRESH"
    later = datetime.now(timezone.utc) + timedelta(days=30)
    assert coverage.stale_sources(db, later)[0]["freshness"] == "STALE"
    assert coverage.metrics(db, later)["stale_regulatory_sources"] == 1


def test_incomplete_documents_are_stored_but_unusable(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db)
    s.sync(db, {f"https://{s.DOMAIN}/act/en": s.TRUNCATED})
    v = db.one("SELECT * FROM regulatory_document_version")
    assert v["complete"] == 0 and "truncated" in v["incomplete_reason"]
    with pytest.raises(CatalogError) as exc:
        catalog.review_document_version(db, v["id"], reviewer="bob", decision="APPROVED")
    assert code(exc) == "DOCUMENT_INCOMPLETE"
    from regintel import extraction

    with pytest.raises(CatalogError) as exc:
        extraction.extract_version(db, v["id"], s.good_llm())
    assert code(exc) == "DOCUMENT_INCOMPLETE"
    m = coverage.metrics(db)
    assert m["documents_incomplete"] == 1 and m["documents_awaiting_review"] == 0


def test_incompleteness_detection():
    assert textproc.parse_document(s.ACT_EN_V1.encode(), "html").complete
    short = textproc.parse_document(b"<html><body><p>tiny</p></body></html>", "html")
    assert not short.complete and "characters" in short.incomplete_reason
    mismatch = textproc.parse_document(s.ACT_EN_V1.encode(), "html", declared_length=10)
    assert not mismatch.complete and "declared" in mismatch.incomplete_reason
    assert not textproc.parse_document(b"\xc3\x28 broken " * 100, "txt").complete


def test_declared_legacy_encodings_are_decoded_strictly_never_guessed():
    legacy = "<html><head><meta charset='shift_jis'></head><body><p>" + "特権アカウントの認証情報 " * 30 + "</p></body></html>"
    assert "特権" in textproc.parse_document(legacy.encode("shift_jis"), "html").sections[0].text
    assert textproc.parse_document(("Ünïcode text " * 30).encode("latin-1"), "txt", charset="iso-8859-1").complete
    wrong = textproc.parse_document(legacy.encode("shift_jis"), "html", charset="utf-8")
    assert not wrong.complete and "declared encoding" in wrong.incomplete_reason
    assert not textproc.parse_document(b"x" * 500, "docx").complete


def test_sections_come_from_document_structure():
    parsed = textproc.parse_document(s.ACT_EN_V1.encode(), "html")
    refs = [x.section_ref for x in parsed.sections]
    assert refs == ["#1 Article 1 Scope", "#2 Article 7 Privileged credentials", "#3 Article 9 Reviews"]
    assert "ignored()" not in "".join(x.text for x in parsed.sections)  # scripts are dropped


def test_eurlex_adapter_negotiates_language_and_never_follows_plaintext_redirects(tmp_path):
    import httpx

    db = s.make_db(tmp_path)
    registry.seed_starter_sources(db)
    adapter = sources.build_adapter(db.one("SELECT * FROM source WHERE id='eurlex-core'"))
    seen: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.headers.get("accept-language")))
        if request.url.path.startswith("/resource/celex/"):
            return httpx.Response(303, headers={"location": "http://publications.europa.eu/resource/cellar/abc.0004.03/DOC_1"})
        return httpx.Response(200, headers={"content-type": "application/xhtml+xml;charset=UTF-8", "etag": '"v1"'},
                              content=s.ACT_DE.replace("<h2>", '<p class="oj-ti-art">').replace("</h2>", "</p>").encode())

    fetcher = Fetcher(adapter.config, transport=httpx.MockTransport(handler), sleep=lambda x: None)
    ref = next(r for r in adapter.discover(fetcher) if r.language == "de")
    doc = adapter.fetch(fetcher, ref)
    assert seen == [("https://publications.europa.eu/resource/celex/32022L2555", "deu"),
                    ("https://publications.europa.eu/resource/cellar/abc.0004.03/DOC_1", "deu")]  # upgraded to https
    assert doc.etag == '"v1"' and doc.retrieved_url.startswith("https://")
    parsed = textproc.parse_document(doc.content, doc.format, charset=doc.charset, heading_classes=adapter.heading_classes)
    assert parsed.sections[0].heading == "Artikel 7 Privilegierte Zugangsdaten"
    bad = dict(db.one("SELECT * FROM source WHERE id='eurlex-core'"))
    bad["languages"] = ["en", "ja"]
    with pytest.raises(CatalogError, match="not EU official languages"):
        sources.build_adapter(bad)
