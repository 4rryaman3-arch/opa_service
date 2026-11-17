"""Synthetic fixtures for the regulatory-intelligence tests.

EVERYTHING HERE IS FICTITIOUS. The "Synthetic Access Security Act", its
articles, thresholds, authority and the ``*.example`` domains do not exist and
must never be loaded into a real catalog. Real jurisdiction codes (DE, EU, GB)
are used only to exercise the registry's inheritance logic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import httpx

from regintel import catalog, extraction, registry, rules
from regintel.db import CatalogDb
from regintel.llm import ModelInfo
from regintel.sources import registry as sources

DOMAIN = "gazette.regulator.example"
FILLER = "<p>" + "This synthetic paragraph exists only to give the fixture a realistic length. " * 4 + "</p>"

ACT_EN_V1 = f"""<html><head><title>fixture</title><script>ignored()</script></head><body>
<h1>SYNTHETIC TEST FIXTURE - Synthetic Access Security Act (not a real regulation)</h1>
<h2>Article 1 Scope</h2>
<p>This synthetic act applies to operators of synthetic payment services established in the territory.</p>
{FILLER}
<h2>Article 7 Privileged credentials</h2>
<p>Operators shall rotate the credentials of privileged accounts at least every 90 days.</p>
<p>Operators shall record every privileged session and retain the recording.</p>
<h2>Article 9 Reviews</h2>
<p>Operators shall review privileged access rights periodically.</p>
</body></html>"""
ACT_EN_V2 = ACT_EN_V1.replace("at least every 90 days", "at least every 60 days")
ACT_DE = f"""<html><body>
<h1>SYNTHETISCHE TESTDATEN - Synthetisches Zugangssicherheitsgesetz (keine echte Vorschrift)</h1>
<h2>Artikel 7 Privilegierte Zugangsdaten</h2>
<p>Betreiber müssen die Zugangsdaten privilegierter Konten mindestens alle 90 Tage ändern.</p>
{FILLER}
</body></html>"""
TRUNCATED = ACT_EN_V1[: ACT_EN_V1.index("<h2>Article 9")]

ROTATION_QUOTE = "Operators shall rotate the credentials of privileged accounts at least every 90 days."
SESSION_QUOTE = "Operators shall record every privileged session and retain the recording."
SCOPE_QUOTE = "This synthetic act applies to operators of synthetic payment services established in the territory."
ROTATION_QUOTE_DE = "Betreiber müssen die Zugangsdaten privilegierter Konten mindestens alle 90 Tage ändern."


def make_db(tmp_path: Path, subdivisions: bool = False) -> CatalogDb:
    db = CatalogDb(tmp_path / "regintel" / "catalog.db")
    registry.seed_registry(db, subdivisions=subdivisions)
    return db


def transport(pages: dict[str, Any]) -> httpx.MockTransport:
    """pages: url -> str body | (status, headers, body)."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        page = pages.get(str(request.url))
        if page is None:
            return httpx.Response(404, text="not found")
        if isinstance(page, str):
            return httpx.Response(200, headers={"content-type": "text/html; charset=utf-8"}, content=page.encode("utf-8"))
        status, headers, body = page
        return httpx.Response(status, headers=headers, content=body.encode("utf-8") if isinstance(body, str) else body)

    t = httpx.MockTransport(handler)
    t.calls = calls  # type: ignore[attr-defined]
    return t


def source_config(documents: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    cfg = {
        "allowed_domains": [DOMAIN], "formats": ["html"],
        "discovery": {"method": "static_list", "documents": documents},
        "version_identification": "content_sha256", "change_detection": "content_sha256",
        "rate_limit": {"min_interval_seconds": 0}, "verification_method": "TLS_DOMAIN_ALLOWLIST+HUMAN_ATTESTATION",
        "licensing": {"license": "synthetic fixture - freely redistributable", "redistribute_text": True},
    }
    cfg.update(overrides)
    return cfg


def setup_synthetic(db: CatalogDb, *, verify: bool = True, redistribute: bool = True,
                    languages: tuple[str, ...] = ("en",)) -> None:
    """Authority, three frameworks and one source for the synthetic act."""
    registry.add_authority(db, "syn-regulator", "Synthetic Regulator (fixture)", "EU", [DOMAIN])
    registry.add_framework(db, "SYN-EU-ACT", "Synthetic Access Security Act (fixture)", "REGULATION", "STATUTORY", "EU",
                           authority_id="syn-regulator", industries=["payments"])
    registry.add_framework(db, "SYN-DE-IMPL", "Synthetic German implementing act (fixture)", "LAW", "STATUTORY", "DE",
                           implements_framework_id="SYN-EU-ACT")
    registry.add_framework(db, "SYN-STD", "Synthetic voluntary standard (fixture)", "STANDARD", "VOLUNTARY", "INT")
    docs = [{"external_id": "SYN-ACT", "url": f"https://{DOMAIN}/act/{lang}", "language": lang,
             "framework_id": "SYN-EU-ACT"} for lang in languages]
    cfg = source_config(docs)
    cfg["licensing"]["redistribute_text"] = redistribute
    sources.propose_source(db, "syn-gazette", "static_list", "Synthetic gazette (fixture)", "syn-regulator", "EU", cfg,
                           languages=list(languages), actor="alice")
    if verify:
        sources.verify_source(db, "syn-gazette", verifier="bob", outcome="VERIFIED",
                              evidence="Fixture: domain confirmed against the synthetic regulator's own imprint page.")


def sync(db: CatalogDb, pages: dict[str, Any], tmp_path: Path | None = None) -> dict[str, Any]:
    return sources.sync_source(db, "syn-gazette", transport=transport(pages), sleep=lambda s: None,
                               blob_dir=(tmp_path / "blobs") if tmp_path else None)


class FakeLlm:
    """Stands in for the local GPU model. ``script(system, prompt) -> object``.
    A script may return a ``str`` to simulate raw, non-JSON model output; any
    other value is serialized to JSON like the real runtime would return it."""

    def __init__(self, script: Callable[[str, str], Any], model: str = "fake-multilingual:test") -> None:
        self.script = script
        self.info = ModelInfo(model, "sha256:fixture-weights", "fake-runtime 0")
        self.calls: list[tuple[str, str]] = []

    def generate_json(self, system: str, prompt: str, schema: dict[str, Any]) -> Any:
        self.calls.append((system, prompt))
        return self.script(system, prompt)

    def generate_raw(self, system: str, prompt: str, schema: dict[str, Any]) -> Any:
        import json

        from regintel.llm import RawOutput

        self.calls.append((system, prompt))
        out = self.script(system, prompt)
        return RawOutput(out if isinstance(out, str) else json.dumps(out, ensure_ascii=False))


def candidate(quote: str, domains=("credential_lifecycle",), thresholds=(), obligation="MANDATORY") -> dict[str, Any]:
    return {"quote": quote, "pam_domains": list(domains), "obligation_type": obligation,
            "thresholds": [{"value_text": t, "meaning": "interval"} for t in thresholds]}


def good_llm() -> FakeLlm:
    def script(system: str, prompt: str) -> Any:
        if system == extraction.SYSTEM_TRANSLATE:
            return {"translation": "Operators must change the credentials of privileged accounts at least every 90 days."}
        out = []
        if ROTATION_QUOTE in prompt:
            out.append(candidate(ROTATION_QUOTE, thresholds=["90 days"]))
        if SESSION_QUOTE in prompt:
            out.append(candidate(SESSION_QUOTE, domains=["session_monitoring"]))
        if ROTATION_QUOTE_DE in prompt:
            out.append(candidate(ROTATION_QUOTE_DE, thresholds=["90 Tage"]))
        return {"requirements": out}

    return FakeLlm(script)


def reviewed_requirements(db: CatalogDb, tmp_path: Path | None = None, page: str = ACT_EN_V1) -> dict[str, int]:
    """Synthetic source -> reviewed document -> approved requirements. Returns ids by key."""
    setup_synthetic(db)
    sync(db, {f"https://{DOMAIN}/act/en": page}, tmp_path)
    vid = db.scalar("SELECT MAX(id) FROM regulatory_document_version")
    catalog.review_document_version(db, vid, reviewer="bob", decision="APPROVED", published_on="2024-01-15",
                                    effective_from="2025-01-01")
    registry.verify_framework(db, "SYN-EU-ACT", reviewer="bob", evidence_version_id=vid, lifecycle="IN_FORCE",
                              published_on="2024-01-15", effective_from="2025-01-01")
    extraction.extract_version(db, vid, good_llm())
    ids = {"version": vid}
    for row in db.q("SELECT id, original_text FROM regulatory_requirement"):
        catalog.review(db, "requirement", row["id"], reviewer="bob", decision="APPROVED")
        ids["rotation" if "rotate" in row["original_text"] else "session"] = row["id"]
    scope_section = db.scalar("SELECT id FROM document_section WHERE version_id=? AND text LIKE '%applies to operators%'", (vid,))
    ids["scope"] = extraction.add_manual_requirement(
        db, section_id=scope_section, quote=SCOPE_QUOTE, pam_domains=["access_control"], obligation_type="UNDETERMINED",
        actor="alice")
    catalog.review(db, "requirement", ids["scope"], reviewer="bob", decision="APPROVED")
    return ids


def rule_definition(days: int = 90, version: str = "1.0", rule_id: str = "REG-SYN-ROTATION-001") -> dict[str, Any]:
    return {
        "rule_id": rule_id, "version": version, "title": "Synthetic rotation interval (fixture)",
        "severity": "HIGH", "evidence_type": "credential_rotation", "subject_field": "account_id",
        "effective_from": "2025-01-01T00:00:00Z",
        "violation_when": {"all": [
            {"field": "privileged", "op": "eq", "value": True},
            {"any": [{"field": "last_rotated_at", "op": "is_null"},
                     {"field": "last_rotated_at", "op": "older_than_days", "value": days}]},
        ]},
    }


def rotation_record(i: int, rotated_at: str | None) -> dict[str, Any]:
    return {"record_id": f"rot-{i}", "account_id": f"acct-{i}", "privileged": True, "last_rotated_at": rotated_at,
            "last_rotation_status": "SUCCESS" if rotated_at else None}


def rule_tests(expect_old: str = "FAIL") -> list[dict[str, Any]]:
    return [
        {"name": "fresh credential passes", "as_of": "2026-06-01T00:00:00Z",
         "records": [rotation_record(1, "2026-05-20T00:00:00Z")], "expected_status": "PASS"},
        {"name": "100-day-old credential fails", "as_of": "2026-06-01T00:00:00Z",
         "records": [rotation_record(1, "2026-05-20T00:00:00Z"), rotation_record(2, "2026-02-21T00:00:00Z")],
         "expected_status": expect_old, "expected_violation_subjects": ["acct-2"]},
    ]


def draft_rule(db: CatalogDb, requirement_id: int, **kw: Any) -> int:
    return rules.draft_rule_version(
        db, definition=rule_definition(**kw), pam_control_id="PAMC-CRED-ROTATION",
        threshold_provenance=[{"condition": "g1.c2", "origin": "REGULATORY", "requirement_id": requirement_id}],
        tests=rule_tests(), actor="alice")
