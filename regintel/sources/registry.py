"""Source lifecycle: propose -> verify (human) -> synchronize.

Anyone (seed data, an operator, a discovery provider) can *propose* a source.
Only a source a human has verified against the authority can be synchronized,
and the verification is bound to the exact configuration that was reviewed:
editing the allowlist or discovery settings voids it.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol

import httpx
from pydantic import ValidationError

from .. import textproc
from ..db import CatalogDb, CatalogError, canonical, digest_of, now_iso
from ..registry import LANG_RE, SLUG_RE, require_jurisdiction
from . import adapters as _adapters  # noqa: F401 - registers built-in adapters
from .base import ADAPTERS, Fetcher, SourceAdapter, SourceConfig, SourceError


def _config(raw: dict[str, Any]) -> SourceConfig:
    try:
        return SourceConfig.model_validate(raw)
    except ValidationError as exc:
        raise CatalogError("INVALID_SOURCE_CONFIG", "; ".join(
            f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors(include_input=False))) from exc


def build_adapter(source: dict[str, Any]) -> SourceAdapter:
    cls = ADAPTERS.get(source["adapter_type"])
    if cls is None:
        raise CatalogError("UNKNOWN_ADAPTER", f"no adapter registered for '{source['adapter_type']}'")
    try:
        return cls(source, _config(source["config"]))
    except SourceError as exc:
        raise CatalogError(exc.code, exc.message) from exc
    except (KeyError, TypeError, AttributeError, ValueError, re.error) as exc:
        # Adapter-specific discovery settings are free-form JSON supplied by the caller.
        raise CatalogError("INVALID_SOURCE_CONFIG",
                           f"discovery settings are malformed for '{source['adapter_type']}' ({type(exc).__name__})") from exc


def propose_source(db: CatalogDb, id: str, adapter_type: str, name: str, authority_id: str, jurisdiction: str,
                   config: dict[str, Any], *, languages: list[str], origin: str = "MANUAL",
                   actor: str = "operator", freshness_sla_hours: int = 168) -> None:
    if not SLUG_RE.match(id):
        raise CatalogError("INVALID_ID", "source id must be a lowercase slug")
    require_jurisdiction(db, jurisdiction)
    authority = db.one("SELECT * FROM regulatory_authority WHERE id=?", (authority_id,))
    if authority is None:
        raise CatalogError("UNKNOWN_AUTHORITY", authority_id)
    if not languages or any(not LANG_RE.match(lang) for lang in languages):
        raise CatalogError("INVALID_LANGUAGE", "languages must be BCP 47 codes such as 'en', 'de', 'pt-BR'")
    cfg = _config(config)
    # A source may only fetch from domains registered for its authority.
    stray = set(cfg.allowed_domains) - set(authority["official_domains"])
    if stray:
        raise CatalogError("DOMAIN_NOT_REGISTERED",
                           f"{sorted(stray)} are not registered official domains of authority '{authority_id}'")
    source = {"id": id, "adapter_type": adapter_type, "languages": languages, "config": cfg.model_dump(mode="json")}
    build_adapter(source)  # validates adapter-specific configuration
    with db.tx():
        db.insert("source", id=id, adapter_type=adapter_type, name=name, authority_id=authority_id,
                  jurisdiction_code=jurisdiction, languages=languages, config=source["config"],
                  proposal_origin=origin, proposed_by=actor, freshness_sla_hours=freshness_sla_hours,
                  created_at=now_iso())
        db.audit(actor, "PROPOSE", "source", id, origin=origin)


class DiscoveryProvider(Protocol):
    """Search / discovery mechanisms plug in here. They only ever *propose*."""

    name: str

    def candidates(self) -> Iterable[dict[str, Any]]: ...


def propose_from_provider(db: CatalogDb, provider: DiscoveryProvider, actor: str) -> dict[str, list[str]]:
    proposed, skipped = [], []
    for c in provider.candidates():
        try:
            propose_source(db, c["id"], c["adapter_type"], c["name"], c["authority_id"], c["jurisdiction"],
                           c["config"], languages=c["languages"], origin=f"DISCOVERY:{provider.name}", actor=actor)
            proposed.append(c["id"])
        except (CatalogError, KeyError, TypeError) as exc:  # one bad candidate must not stop the rest
            skipped.append(f"{c.get('id', '?')}: {exc}")
    return {"proposed": proposed, "skipped": skipped}


def verify_source(db: CatalogDb, source_id: str, *, verifier: str, outcome: str, evidence: str,
                  method: str | None = None, origin: str = "HUMAN", policy_version: str | None = None) -> None:
    """Attestation that the source's domains really are the authority's
    official publication channel (or, for file_drop, that the files came from
    an authorized repository). ``origin`` is ``HUMAN`` for the review endpoint;
    the automation policy (``regintel.automation``) records ``AUTOMATED``
    decisions for sources that satisfy its domain-restriction criteria."""
    source = db.one("SELECT * FROM source WHERE id=?", (source_id,))
    if source is None:
        raise CatalogError("UNKNOWN_SOURCE", source_id)
    if outcome not in ("VERIFIED", "REJECTED"):
        raise CatalogError("INVALID_OUTCOME", outcome)
    if len(evidence.strip()) < 30:
        raise CatalogError("EVIDENCE_REQUIRED",
                           "describe how the source was confirmed as authoritative (at least 30 characters)")
    with db.tx():
        db.insert("source_verification", source_id=source_id, method=method or source["config"]["verification_method"],
                  outcome=outcome, verifier=verifier, evidence=evidence.strip(),
                  config_digest=digest_of(source["config"]), verified_at=now_iso(),
                  decision_origin=origin, policy_version=policy_version)
        db.x("UPDATE source SET status=? WHERE id=?", (outcome, source_id))
        if outcome == "VERIFIED":
            db.x("UPDATE regulatory_authority SET verification_status='VERIFIED' WHERE id=?", (source["authority_id"],))
        db.audit(verifier, f"SOURCE_{outcome}", "source", source_id)


def update_source_config(db: CatalogDb, source_id: str, config: dict[str, Any], actor: str) -> None:
    """Changing what a source fetches sends it back to PROPOSED."""
    source = db.one("SELECT * FROM source WHERE id=?", (source_id,))
    if source is None:
        raise CatalogError("UNKNOWN_SOURCE", source_id)
    cfg = _config(config).model_dump(mode="json")
    build_adapter({**source, "config": cfg})
    with db.tx():
        db.x("UPDATE source SET config=?, status='PROPOSED' WHERE id=?", (canonical(cfg), source_id))
        db.audit(actor, "CONFIG_CHANGED", "source", source_id)


def is_verified(db: CatalogDb, source: dict[str, Any]) -> bool:
    if source["status"] != "VERIFIED":
        return False
    last = db.one("SELECT * FROM source_verification WHERE source_id=? ORDER BY id DESC LIMIT 1", (source["id"],))
    return bool(last and last["outcome"] == "VERIFIED" and last["config_digest"] == digest_of(source["config"]))


def sync_source(db: CatalogDb, source_id: str, *, blob_dir: Path | None = None,
                transport: httpx.BaseTransport | None = None,
                sleep: Callable[[float], None] | None = None, actor: str = "worker") -> dict[str, Any]:
    """Discover and retrieve documents from one verified source. Each distinct
    content hash becomes an immutable document version awaiting human review."""
    source = db.one("SELECT * FROM source WHERE id=?", (source_id,))
    if source is None:
        raise CatalogError("UNKNOWN_SOURCE", source_id)
    if not is_verified(db, source):
        raise CatalogError("SOURCE_NOT_VERIFIED",
                           f"source '{source_id}' is {source['status']}; only verified sources are synchronized")
    adapter = build_adapter(source)
    kwargs = {"sleep": sleep} if sleep else {}
    fetcher = Fetcher(adapter.config, transport=transport, **kwargs)
    run_id = db.insert("sync_run", source_id=source_id, started_at=now_iso(), status="RUNNING")
    seen = new = changed = unchanged = 0
    errors: list[str] = []
    warnings: list[str] = []
    versions: list[dict[str, Any]] = []
    heading_classes = adapter.heading_classes | frozenset(adapter.config.discovery.get("heading_classes", []))
    try:
        try:
            refs = list(adapter.discover(fetcher))
        except SourceError as exc:
            refs = []
            errors.append(f"discovery: {exc}")
        for ref in refs:
            seen += 1
            try:
                if ref.framework_id and not db.one("SELECT 1 FROM regulatory_framework WHERE id=?", (ref.framework_id,)):
                    raise SourceError("UNKNOWN_FRAMEWORK", f"framework '{ref.framework_id}' is not registered")
                doc = adapter.fetch(fetcher, ref)
                outcome, info = _store(db, source, doc, heading_classes, blob_dir)
                new += outcome == "NEW"
                changed += outcome == "CHANGED"
                unchanged += outcome == "UNCHANGED"
                versions.append({"external_id": ref.external_id, "language": ref.language, "outcome": outcome, **info})
                if info.get("complete") is False:
                    warnings.append(f"{ref.external_id}[{ref.language}]: version {info['version_id']} stored INCOMPLETE: "
                                    f"{info.get('incomplete_reason')}")
                elif outcome != "UNCHANGED" and not info.get("sections"):
                    warnings.append(f"{ref.external_id}[{ref.language}]: version {info['version_id']} parsed into 0 sections")
            except SourceError as exc:
                errors.append(f"{ref.external_id}[{ref.language}]: {exc}")
    except Exception as exc:
        # An unexpected failure must not leave the sync_run row RUNNING forever.
        errors.append(f"internal: {type(exc).__name__}: {exc}"[:500])
        with db.tx():
            db.x("UPDATE sync_run SET finished_at=?, status='FAILED', documents_seen=?, versions_new=?, "
                 "versions_changed=?, errors=? WHERE id=?",
                 (now_iso(), seen, new, changed, canonical(errors[:50]), run_id))
        raise
    finally:
        fetcher.close()
    if errors:
        status = "FAILED" if seen <= len(errors) else "PARTIAL"
    elif not seen:
        # A successful search with no results is not a failure, and it is not coverage either.
        status = "SUCCESS"
        warnings.append("Discovery completed but matched no documents. An empty result is not evidence that no "
                        "regulations exist; check the source's discovery configuration if documents were expected.")
    else:
        status = "SUCCESS"
    at = now_iso()
    with db.tx():
        db.x("UPDATE sync_run SET finished_at=?, status=?, documents_seen=?, versions_new=?, versions_changed=?, errors=? "
             "WHERE id=?", (at, status, seen, new, changed, canonical(errors[:50]), run_id))  # type: ignore[arg-type]
        db.x(
            "UPDATE source SET last_sync_at=?, last_sync_status=?, "
            "last_success_at=CASE WHEN ?='SUCCESS' THEN ? ELSE last_success_at END, "
            "last_change_at=CASE WHEN ?>0 THEN ? ELSE last_change_at END, "
            "consecutive_failures=CASE WHEN ?='SUCCESS' THEN 0 ELSE consecutive_failures+1 END WHERE id=?",
            (at, status, status, at, new + changed, at, status, source_id),
        )
        db.audit(actor, "SYNC", "source", source_id, status=status, seen=seen, new=new, changed=changed)
    return {"source_id": source_id, "status": status, "documents_seen": seen, "versions_new": new,
            "versions_changed": changed, "versions_unchanged": unchanged, "errors": errors,
            "warnings": warnings, "versions": versions}


def _store(db: CatalogDb, source: dict[str, Any], doc, heading_classes: frozenset[str],
           blob_dir: Path | None) -> tuple[str, dict[str, Any]]:
    """Returns (outcome, info): outcome NEW|CHANGED|UNCHANGED, info identifies the stored version."""
    ref = doc.ref
    parsed = textproc.parse_document(doc.content, doc.format, declared_length=doc.declared_length, charset=doc.charset,
                                     heading_classes=heading_classes)
    with db.tx():
        row = db.one("SELECT * FROM regulatory_document WHERE source_id=? AND external_id=? AND language=?",
                     (source["id"], ref.external_id, ref.language))
        doc_id = row["id"] if row else db.insert(
            "regulatory_document", source_id=source["id"], framework_id=ref.framework_id, external_id=ref.external_id,
            title=ref.title, url=ref.url, language=ref.language, created_at=now_iso())
        sha = doc.sha256
        existing = db.one("SELECT id, complete, incomplete_reason FROM regulatory_document_version "
                          "WHERE document_id=? AND content_sha256=?", (doc_id, sha))
        if existing:
            return "UNCHANGED", {"document_id": doc_id, "version_id": existing["id"],
                                 "complete": bool(existing["complete"]),
                                 "incomplete_reason": existing["incomplete_reason"], "content_sha256": sha}
        previous = db.one(
            "SELECT id FROM regulatory_document_version WHERE document_id=? AND complete=1 ORDER BY id DESC LIMIT 1",
            (doc_id,))
        path = None
        if blob_dir is not None:
            blob_dir.mkdir(parents=True, exist_ok=True)
            target = blob_dir / f"{sha}.{doc.format}"
            if not target.exists():
                target.write_bytes(doc.content)
            path = target.name
        label = doc.version_label or f"retrieved-{datetime.now(timezone.utc):%Y%m%d}-{sha[:12]}"
        vid = db.insert(
            "regulatory_document_version", document_id=doc_id, version_label=label, content_sha256=sha,
            format=doc.format, byte_length=len(doc.content), retrieved_at=now_iso(), retrieved_url=doc.retrieved_url,
            etag=doc.etag, last_modified=doc.last_modified, complete=int(parsed.complete),
            incomplete_reason=parsed.incomplete_reason, storage_path=path,
            supersedes_version_id=previous["id"] if previous and parsed.complete else None)
        for s in parsed.sections:
            db.insert("document_section", version_id=vid, ordinal=s.ordinal, section_ref=s.section_ref,
                      heading=s.heading, text=s.text)
        info = {"document_id": doc_id, "version_id": vid, "complete": parsed.complete,
                "incomplete_reason": parsed.incomplete_reason, "sections": len(parsed.sections),
                "content_sha256": sha}
        if previous and parsed.complete:
            # New text for a known document: a regulatory change to triage. Nothing
            # derived from the old version is altered automatically.
            db.insert("regulatory_change", source_id=source["id"], document_id=doc_id,
                      old_version_id=previous["id"], new_version_id=vid, detected_at=now_iso())
            return "CHANGED", info
    return "NEW", info
