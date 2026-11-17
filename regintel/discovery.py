"""Jurisdiction-scoped regulatory-intelligence coordinator ("Start Regulatory
Intelligence" for a selected country/subdivision/group).

A discover job never fetches arbitrary URLs and never invents content. It only:

  1. resolves the jurisdiction scope (the selection itself plus, when
     ``include_inherited``, its parents and dated group memberships),
  2. inventories what is configured for that scope (authorities, frameworks,
     sources with their verification status),
  3. submits child ``sync`` jobs for the sources a human has already verified
     (each sync is bounded by the source's domain allowlist and rate limit),
  4. reports the exact human review checkpoints as ``next_actions``.

The job always finishes: it never waits for a human. Review states are
expressed as ``next_actions`` in the result; polling the coverage endpoint
returns the same list recomputed from current state. Registration of a
jurisdiction (or membership of a group) never implies coverage: counts are
computed from verified sources, reviewed documents and published artifacts.
"""

from __future__ import annotations

from typing import Any

from . import coverage
from .db import CatalogDb, CatalogError, today
from .registry import jurisdiction_closure, require_jurisdiction

PREFIX = "/api/v1/catalog/admin"
MAX_IDS = 100  # ids listed per next_action; the paginated listings hold the rest


def _ids(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    values = [r[key] for r in rows]
    out: dict[str, Any] = {"count": len(values), "ids": values[:MAX_IDS]}
    if len(values) > MAX_IDS:
        out["truncated"] = True
    return out


def _action(action: str, method: str, path: str, scope: str, description: str, **extra: Any) -> dict[str, Any]:
    return {"action": action, "method": method, "path": path, "required_scope": scope,
            "description": description, **extra}


def resolve_scope(db: CatalogDb, jurisdiction: str, include_inherited: bool, as_of: str) -> list[dict[str, Any]]:
    """The jurisdictions whose content can apply to the selection, with the path
    that explains each entry and, for group memberships, the membership dates."""
    if include_inherited:
        entries = jurisdiction_closure(db, jurisdiction, as_of)
    else:
        require_jurisdiction(db, jurisdiction)
        entries = [{"code": jurisdiction, "via": "SELF"}]
    out = []
    for e in entries:
        row = db.one("SELECT code, kind, name FROM jurisdiction WHERE code=?", (e["code"],))
        entry: dict[str, Any] = {**row, "via": e["via"], "inherited": e["via"] != "SELF"}
        if e["via"].startswith("MEMBER:"):
            member = e["via"].split(":", 1)[1]
            m = db.one("SELECT valid_from, valid_to FROM jurisdiction_membership WHERE group_code=? AND member_code=? "
                       "AND valid_from<=? AND (valid_to IS NULL OR valid_to>?) ORDER BY valid_from DESC LIMIT 1",
                       (e["code"], member, as_of, as_of))
            if m:
                entry["membership"] = {"member": member, "valid_from": m["valid_from"], "valid_to": m["valid_to"]}
        out.append(entry)
    return out


def next_actions(db: CatalogDb, codes: list[str]) -> list[dict[str, Any]]:
    """Human/operator checkpoints currently open for a jurisdiction scope, in
    pipeline order, with the exact call and target ids."""
    ph = ",".join("?" * len(codes))
    actions: list[dict[str, Any]] = []

    proposed = db.q(f"SELECT id FROM source WHERE status='PROPOSED' AND jurisdiction_code IN ({ph}) ORDER BY id", codes)
    if proposed:
        actions.append(_action(
            "verify_source", "POST", PREFIX + "/sources/{source_id}/verify", "catalog:review",
            "A human must confirm each proposed source is the authority's official publication channel "
            "(or attest file provenance for uploads) before it can be synchronized.",
            source_ids=_ids(proposed, "id")))

    unsynced = db.q(f"SELECT id FROM source WHERE status='VERIFIED' AND last_sync_at IS NULL "
                    f"AND jurisdiction_code IN ({ph}) ORDER BY id", codes)
    if unsynced:
        actions.append(_action(
            "submit_sync_job", "POST", PREFIX + "/jobs", "catalog:operate",
            "Submit {\"action\":\"sync\",\"source_id\":...,\"request_key\":...} to retrieve and parse documents "
            "from each verified source.", source_ids=_ids(unsynced, "id")))

    incomplete = db.q(
        f"SELECT v.id FROM regulatory_document_version v JOIN regulatory_document d ON d.id=v.document_id "
        f"JOIN source s ON s.id=d.source_id WHERE v.complete=0 AND v.status='AWAITING_REVIEW' "
        f"AND s.jurisdiction_code IN ({ph}) ORDER BY v.id", codes)
    if incomplete:
        actions.append(_action(
            "resolve_incomplete_document", "GET", PREFIX + "/documents/{version_id}", "catalog:review",
            "These retrieved versions parsed as incomplete (see incomplete_reason); obtain the complete official "
            "text (re-upload or fix the source) - incomplete documents are never extracted.",
            version_ids=_ids(incomplete, "id")))

    unreviewed_docs = db.q(
        f"SELECT v.id FROM regulatory_document_version v JOIN regulatory_document d ON d.id=v.document_id "
        f"JOIN source s ON s.id=d.source_id WHERE v.complete=1 AND v.status='AWAITING_REVIEW' "
        f"AND s.jurisdiction_code IN ({ph}) ORDER BY v.id", codes)
    if unreviewed_docs:
        actions.append(_action(
            "review_document", "POST", PREFIX + "/documents/{version_id}/review", "catalog:review",
            "A human must confirm each retrieved version is the complete official text and record its dates.",
            version_ids=_ids(unreviewed_docs, "id")))

    unextracted = db.q(
        f"SELECT v.id FROM regulatory_document_version v JOIN regulatory_document d ON d.id=v.document_id "
        f"JOIN source s ON s.id=d.source_id WHERE v.status='REVIEWED' AND s.jurisdiction_code IN ({ph}) "
        f"AND NOT EXISTS (SELECT 1 FROM regulatory_requirement r WHERE r.document_version_id=v.id) "
        f"AND NOT EXISTS (SELECT 1 FROM extraction_attempt a WHERE a.version_id=v.id) ORDER BY v.id", codes)
    if unextracted:
        actions.append(_action(
            "submit_extract_job", "POST", PREFIX + "/jobs", "catalog:operate",
            "Submit {\"action\":\"extract\",\"version_id\":...,\"request_key\":...} to draft PAM requirements "
            "from each reviewed version with the local model. Drafts still require human review.",
            version_ids=_ids(unextracted, "id")))

    draft_reqs = db.q(
        f"SELECT r.id FROM regulatory_requirement r JOIN regulatory_framework f ON f.id=r.framework_id "
        f"WHERE r.status='DRAFT' AND f.jurisdiction_code IN ({ph}) ORDER BY r.id", codes)
    if draft_reqs:
        actions.append(_action(
            "review_requirement", "POST", PREFIX + "/reviews/requirement/{requirement_id}", "catalog:review",
            "A human must approve or reject each drafted requirement against the source text.",
            requirement_ids=_ids(draft_reqs, "id")))

    translations = db.q(
        f"SELECT r.id FROM regulatory_requirement r JOIN regulatory_framework f ON f.id=r.framework_id "
        f"WHERE r.translation_status='UNREVIEWED' AND r.status IN ('DRAFT','APPROVED') "
        f"AND f.jurisdiction_code IN ({ph}) ORDER BY r.id", codes)
    if translations:
        actions.append(_action(
            "review_translation", "POST", PREFIX + "/requirements/{requirement_id}/translation-review",
            "catalog:review", "A human must review (and may correct) each machine working translation.",
            requirement_ids=_ids(translations, "id")))

    unverified_fw = db.q(f"SELECT id FROM regulatory_framework WHERE verification_status='UNVERIFIED' "
                         f"AND jurisdiction_code IN ({ph}) ORDER BY id", codes)
    if unverified_fw:
        actions.append(_action(
            "verify_framework", "POST", PREFIX + "/frameworks/{framework_id}/verify", "catalog:review",
            "A human must approve each registered framework (lifecycle and dates only from a reviewed document).",
            framework_ids=_ids(unverified_fw, "id")))

    draft_mappings = db.q(
        f"SELECT m.id FROM framework_control_mapping m JOIN regulatory_requirement r ON r.id=m.requirement_id "
        f"JOIN regulatory_framework f ON f.id=r.framework_id WHERE m.status='DRAFT' "
        f"AND f.jurisdiction_code IN ({ph}) ORDER BY m.id", codes)
    if draft_mappings:
        actions.append(_action(
            "review_mapping", "POST", PREFIX + "/reviews/mapping/{mapping_id}", "catalog:review",
            "A human must review each drafted mapping; mappings are legal judgements and are never auto-approved.",
            mapping_ids=_ids(draft_mappings, "id")))

    unmapped = db.q(
        f"SELECT r.id FROM regulatory_requirement r JOIN regulatory_framework f ON f.id=r.framework_id "
        f"WHERE r.status='APPROVED' AND r.published_seq IS NOT NULL AND f.jurisdiction_code IN ({ph}) "
        f"AND NOT EXISTS (SELECT 1 FROM framework_control_mapping m WHERE m.requirement_id=r.id "
        f"AND m.status IN ('DRAFT','APPROVED')) ORDER BY r.id", codes)
    if unmapped:
        actions.append(_action(
            "draft_mapping", "POST", PREFIX + "/mappings", "catalog:operate",
            "Published requirements without a mapping stay manual/unmapped in plans; draft a mapping when a PAM "
            "control genuinely addresses the requirement.", requirement_ids=_ids(unmapped, "id")))

    unpublished = (db.scalar(f"SELECT COUNT(*) FROM regulatory_requirement r JOIN regulatory_framework f "
                             f"ON f.id=r.framework_id WHERE r.status='APPROVED' AND r.published_seq IS NULL "
                             f"AND f.jurisdiction_code IN ({ph})", codes) or 0) + \
                  (db.scalar(f"SELECT COUNT(*) FROM framework_control_mapping m JOIN regulatory_requirement r "
                             f"ON r.id=m.requirement_id JOIN regulatory_framework f ON f.id=r.framework_id "
                             f"WHERE m.status='APPROVED' AND m.published_seq IS NULL "
                             f"AND f.jurisdiction_code IN ({ph})", codes) or 0)
    if unpublished:
        actions.append(_action(
            "publish", "POST", PREFIX + "/publish", "catalog:publish",
            "Approved items are invisible to the read-only catalog and to plans until published.",
            approved_unpublished=unpublished))
    return actions


def configuration_required(scope_codes: list[str]) -> dict[str, Any]:
    """What an operator must supply before discovery can run for this scope."""
    return {
        "code": "SOURCE_CONFIGURATION_REQUIRED",
        "message": "No official regulatory sources are configured for "
                   f"{', '.join(scope_codes)}. Discovery only reads sources a human has registered and verified; "
                   "it never searches the open internet or fetches arbitrary URLs.",
        "supply": {
            "register_authority": {
                "method": "POST", "path": PREFIX + "/authorities", "required_scope": "catalog:operate",
                "fields": ["id", "name", "jurisdiction", "official_domains", "languages"],
                "note": "The regulator/publisher and its official domains for one of the scope jurisdictions."},
            "register_framework": {
                "method": "POST", "path": PREFIX + "/frameworks", "required_scope": "catalog:operate",
                "fields": ["id", "title", "kind", "adoption", "jurisdiction", "authority_id"]},
            "register_source": {
                "method": "POST", "path": PREFIX + "/sources", "required_scope": "catalog:operate",
                "adapter_types": ["static_list", "index_page", "eurlex"],
                "note": "config.allowed_domains must be registered official domains of the authority; "
                        "the source starts PROPOSED and must be verified by a human (catalog:review)."},
            "upload_document": {
                "method": "POST", "path": PREFIX + "/uploads", "required_scope": "catalog:operate",
                "note": "For official texts obtained offline: creates a proposed file source; provenance and "
                        "license note are mandatory and a human must verify them."},
        },
    }


def discover(db: CatalogDb, jobs: Any, *, actor: str, jurisdiction: str, include_inherited: bool = True,
             as_of: str | None = None, job_id: str | None = None) -> dict[str, Any]:
    """Execute one discover job (runs on the worker, outside any HTTP request)."""
    require_jurisdiction(db, jurisdiction)
    when = as_of or today()
    scope = resolve_scope(db, jurisdiction, include_inherited, when)
    codes = [e["code"] for e in scope]
    ph = ",".join("?" * len(codes))
    sources = db.q(f"SELECT id, status, adapter_type, jurisdiction_code, name FROM source "
                   f"WHERE jurisdiction_code IN ({ph}) ORDER BY id", codes)
    frameworks = db.q(f"SELECT id, verification_status, jurisdiction_code FROM regulatory_framework "
                      f"WHERE jurisdiction_code IN ({ph}) ORDER BY id", codes)
    authorities = db.q(f"SELECT id, jurisdiction_code FROM regulatory_authority "
                       f"WHERE jurisdiction_code IN ({ph}) ORDER BY id", codes)
    by_status: dict[str, list[str]] = {}
    for src in sources:
        by_status.setdefault(src["status"], []).append(src["id"])

    result: dict[str, Any] = {
        "action": "discover", "jurisdiction": jurisdiction, "include_inherited": include_inherited, "as_of": when,
        "scope": scope,
        "authorities": [a["id"] for a in authorities],
        "frameworks": {"registered": len(frameworks), "verified": sum(f["verification_status"] == "VERIFIED" for f in frameworks),
                       "ids": [f["id"] for f in frameworks]},
        "sources": {status.lower(): ids for status, ids in sorted(by_status.items())},
        "sync_jobs": [], "blockers": [], "errors": [],
        "statement": coverage.STATEMENT,
    }

    if not sources:
        blocker = configuration_required(codes)
        result.update(status="FAILED", outcome="SOURCE_CONFIGURATION_REQUIRED", blockers=[blocker],
                      error=f"SOURCE_CONFIGURATION_REQUIRED: no official sources are configured for {', '.join(codes)}",
                      next_actions=next_actions(db, codes))
        return result

    for source_id in by_status.get("VERIFIED", []):
        key = f"discover:{job_id or 'adhoc'}:sync:{source_id}"
        try:
            child = jobs.submit(actor, key, {"action": "sync", "source_id": source_id})
            result["sync_jobs"].append({"source_id": source_id, "job_id": child["id"], "status": child["status"],
                                        "request_key": key})
        except CatalogError as exc:  # e.g. QUEUE_FULL: report, do not abort the inventory
            result["errors"].append(f"{source_id}: {exc.code}: {exc.message}")

    actions = next_actions(db, codes)
    result["next_actions"] = actions
    if result["sync_jobs"]:
        outcome = "SYNC_TRIGGERED"
    elif by_status.get("PROPOSED"):
        outcome = "AWAITING_HUMAN_REVIEW"
    elif by_status.get("VERIFIED"):
        outcome = "SYNC_TRIGGERED" if not result["errors"] else "PARTIAL"
        # verified sources that were all previously synced submit dedup-ed jobs above,
        # so this branch only means every submit failed; errors say why.
    else:  # only rejected/disabled sources remain: operator must supply a usable one
        blocker = configuration_required(codes)
        blocker["message"] = ("Every configured source for this scope is rejected or disabled. " + blocker["message"])
        result.update(status="FAILED", outcome="SOURCE_CONFIGURATION_REQUIRED", blockers=[blocker],
                      error="SOURCE_CONFIGURATION_REQUIRED: every configured source for this scope is rejected or disabled")
        return result
    result.update(status="PARTIAL" if result["errors"] else "SUCCESS", outcome=outcome)
    return result
