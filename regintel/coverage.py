"""Operational coverage metrics.

Coverage is always computed from evidence in the database: verified sources,
retrieved and reviewed documents, published requirements/mappings and rules in
the active bundle. A jurisdiction that merely exists in the registry is
REGISTERED_ONLY. There is deliberately no "fully supported" state: the catalog
cannot know what it has not ingested.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .db import CatalogDb

STAGES = ("REGISTERED_ONLY", "SOURCE_PROPOSED", "SOURCE_VERIFIED", "DOCUMENTS_RETRIEVED", "DOCUMENTS_REVIEWED",
          "REQUIREMENTS_PUBLISHED", "MAPPINGS_PUBLISHED")
STATEMENT = (
    "Counts describe what has been verified and published so far. They do not indicate that all regulations of a "
    "jurisdiction have been discovered, and no jurisdiction is represented as fully supported."
)

# Coverage always describes the GLOBAL official catalog; organization-scoped
# records (the Django-rewrite workflow's uploads and their artifacts) are
# excluded so no scope can learn about another scope's material.
_PER_JURISDICTION = """
SELECT j.code,
  (SELECT COUNT(*) FROM source s WHERE s.jurisdiction_code=j.code AND s.status='PROPOSED' AND s.organization_scope IS NULL) AS sources_proposed,
  (SELECT COUNT(*) FROM source s WHERE s.jurisdiction_code=j.code AND s.status='VERIFIED' AND s.organization_scope IS NULL) AS sources_verified,
  (SELECT COUNT(*) FROM regulatory_framework f WHERE f.jurisdiction_code=j.code AND f.organization_scope IS NULL) AS frameworks_registered,
  (SELECT COUNT(*) FROM regulatory_framework f WHERE f.jurisdiction_code=j.code AND f.verification_status='VERIFIED' AND f.organization_scope IS NULL) AS frameworks_verified,
  (SELECT COUNT(*) FROM regulatory_document_version v JOIN regulatory_document d ON d.id=v.document_id
     JOIN source s ON s.id=d.source_id WHERE s.jurisdiction_code=j.code AND v.complete=1 AND d.organization_scope IS NULL) AS documents_retrieved,
  (SELECT COUNT(*) FROM regulatory_document_version v JOIN regulatory_document d ON d.id=v.document_id
     JOIN source s ON s.id=d.source_id WHERE s.jurisdiction_code=j.code AND v.status='REVIEWED' AND d.organization_scope IS NULL) AS documents_reviewed,
  (SELECT COUNT(*) FROM regulatory_requirement r JOIN regulatory_framework f ON f.id=r.framework_id
     WHERE f.jurisdiction_code=j.code AND r.status='APPROVED' AND r.published_seq IS NOT NULL AND r.organization_scope IS NULL) AS requirements_published,
  (SELECT COUNT(*) FROM framework_control_mapping m JOIN regulatory_requirement r ON r.id=m.requirement_id
     JOIN regulatory_framework f ON f.id=r.framework_id
     WHERE f.jurisdiction_code=j.code AND m.status='APPROVED' AND m.published_seq IS NOT NULL AND m.organization_scope IS NULL) AS mappings_published
FROM jurisdiction j
"""


def stage_of(c: dict[str, Any]) -> str:
    if c["mappings_published"]:
        return "MAPPINGS_PUBLISHED"
    if c["requirements_published"]:
        return "REQUIREMENTS_PUBLISHED"
    if c["documents_reviewed"]:
        return "DOCUMENTS_REVIEWED"
    if c["documents_retrieved"]:
        return "DOCUMENTS_RETRIEVED"
    if c["sources_verified"]:
        return "SOURCE_VERIFIED"
    if c["sources_proposed"]:
        return "SOURCE_PROPOSED"
    return "REGISTERED_ONLY"


def jurisdiction_coverage(db: CatalogDb, code: str | None = None, *, after: str = "", limit: int = 100,
                          kinds: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    sql, args = _PER_JURISDICTION + " WHERE j.code > ?", [after]
    if code is not None:
        sql, args = _PER_JURISDICTION + " WHERE j.code = ?", [code]
    if kinds:
        sql += f" AND j.kind IN ({','.join('?' * len(kinds))})"
        args += list(kinds)
    rows = db.q(sql + " ORDER BY j.code LIMIT ?", [*args, limit])
    for r in rows:
        r["stage"] = stage_of(r)
        r["fully_supported"] = None  # never asserted; see STATEMENT
    return rows


def coverage_detail(db: CatalogDb, code: str) -> dict[str, Any]:
    """Pipeline-stage counts for ONE jurisdiction's own content (no inheritance),
    computed from the same catalog database that management writes, the public
    API reads and plan resolution uses. Registration never implies coverage."""
    n = db.scalar
    source_status = {r["status"]: r["n"] for r in db.q(
        "SELECT status, COUNT(*) AS n FROM source WHERE jurisdiction_code=? AND organization_scope IS NULL "
        "GROUP BY status", (code,))}
    base = jurisdiction_coverage(db, code)[0]
    docs = "FROM regulatory_document_version v JOIN regulatory_document d ON d.id=v.document_id " \
           "JOIN source s ON s.id=d.source_id WHERE d.organization_scope IS NULL AND s.jurisdiction_code=?"
    reqs = ("FROM regulatory_requirement r JOIN regulatory_framework f ON f.id=r.framework_id "
            "WHERE r.organization_scope IS NULL AND f.jurisdiction_code=?")
    maps = "FROM framework_control_mapping m JOIN regulatory_requirement r ON r.id=m.requirement_id " \
           "JOIN regulatory_framework f ON f.id=r.framework_id WHERE m.organization_scope IS NULL AND f.jurisdiction_code=?"
    return {
        "code": code,
        "stage": base["stage"],
        "fully_supported": None,  # never asserted; see STATEMENT
        "sources": {"proposed": source_status.get("PROPOSED", 0), "verified": source_status.get("VERIFIED", 0),
                    "rejected": source_status.get("REJECTED", 0), "disabled": source_status.get("DISABLED", 0)},
        "frameworks": {"registered": base["frameworks_registered"], "approved": base["frameworks_verified"]},
        "documents": {"retrieved_complete": n(f"SELECT COUNT(*) {docs} AND v.complete=1", (code,)),
                      "incomplete": n(f"SELECT COUNT(*) {docs} AND v.complete=0", (code,)),
                      "awaiting_review": n(f"SELECT COUNT(*) {docs} AND v.complete=1 AND v.status='AWAITING_REVIEW'", (code,)),
                      "reviewed": n(f"SELECT COUNT(*) {docs} AND v.status='REVIEWED'", (code,))},
        "requirements": {"draft": n(f"SELECT COUNT(*) {reqs} AND r.status='DRAFT'", (code,)),
                         "approved_unpublished": n(f"SELECT COUNT(*) {reqs} AND r.status='APPROVED' AND r.published_seq IS NULL", (code,)),
                         "published": n(f"SELECT COUNT(*) {reqs} AND r.status='APPROVED' AND r.published_seq IS NOT NULL", (code,))},
        "mappings": {"draft": n(f"SELECT COUNT(*) {maps} AND m.status='DRAFT'", (code,)),
                     "approved_unpublished": n(f"SELECT COUNT(*) {maps} AND m.status='APPROVED' AND m.published_seq IS NULL", (code,)),
                     "published_executable": n(f"SELECT COUNT(*) {maps} AND m.status='APPROVED' AND m.published_seq IS NOT NULL "
                                               "AND m.assessment='AUTOMATED'", (code,)),
                     "published_manual": n(f"SELECT COUNT(*) {maps} AND m.status='APPROVED' AND m.published_seq IS NOT NULL "
                                           "AND (m.assessment IS NULL OR m.assessment<>'AUTOMATED')", (code,))},
    }


def stale_sources(db: CatalogDb, now: datetime | None = None) -> list[dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    out = []
    for s in db.q("SELECT id, name, jurisdiction_code, status, freshness_sla_hours, last_sync_at, last_sync_status, "
                  "last_success_at, last_change_at, consecutive_failures FROM source "
                  "WHERE organization_scope IS NULL ORDER BY id"):
        if s["status"] != "VERIFIED":
            s["freshness"] = "NOT_SYNCHRONIZED"  # proposed/rejected/disabled sources are never fetched
        elif not s["last_success_at"]:
            s["freshness"] = "NEVER_SYNCHRONIZED"
        else:
            last = datetime.strptime(s["last_success_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
            s["age_hours"] = round((now - last).total_seconds() / 3600, 1)
            s["freshness"] = "STALE" if now - last > timedelta(hours=s["freshness_sla_hours"]) else "FRESH"
        out.append(s)
    return out


def metrics(db: CatalogDb, now: datetime | None = None) -> dict[str, Any]:
    n = db.scalar
    by_kind = {r["kind"]: r["n"] for r in db.q("SELECT kind, COUNT(*) AS n FROM jurisdiction GROUP BY kind")}
    by_status = {r["status"]: r["n"] for r in db.q(
        "SELECT status, COUNT(*) AS n FROM source WHERE organization_scope IS NULL GROUP BY status")}
    stages = dict.fromkeys(STAGES, 0)
    countries = jurisdiction_coverage(db, limit=100_000, kinds=("COUNTRY_OR_TERRITORY",))
    for c in countries:
        stages[c["stage"]] += 1
    freshness = stale_sources(db, now)
    active = db.one("SELECT version FROM bundle_version WHERE active=1")
    published_rules = n("SELECT COUNT(*) FROM bundle_rule br JOIN bundle_version b ON b.version=br.bundle_version "
                        "JOIN rule_version rv ON rv.id=br.rule_version_id WHERE b.active=1 AND rv.status='APPROVED'")
    return {
        "statement": STATEMENT,
        "catalog_version": db.catalog_version(),
        "jurisdictions_registered": {"total": sum(by_kind.values()), "by_kind": by_kind},
        "official_sources_configured": {"total": sum(by_status.values()), "by_status": by_status,
                                        "verified": by_status.get("VERIFIED", 0)},
        "sources_successfully_synchronized": sum(1 for s in freshness if s["status"] == "VERIFIED" and s["last_sync_status"] == "SUCCESS"),
        "stale_regulatory_sources": sum(1 for s in freshness if s["freshness"] in ("STALE", "NEVER_SYNCHRONIZED")),
        "documents_retrieved": n("SELECT COUNT(*) FROM regulatory_document_version v JOIN regulatory_document d "
                                 "ON d.id=v.document_id WHERE d.organization_scope IS NULL"),
        "documents_incomplete": n("SELECT COUNT(*) FROM regulatory_document_version v JOIN regulatory_document d "
                                  "ON d.id=v.document_id WHERE d.organization_scope IS NULL AND v.complete=0"),
        "documents_awaiting_review": n("SELECT COUNT(*) FROM regulatory_document_version v JOIN regulatory_document d "
                                       "ON d.id=v.document_id WHERE d.organization_scope IS NULL "
                                       "AND v.status='AWAITING_REVIEW' AND v.complete=1"),
        "requirements_draft": n("SELECT COUNT(*) FROM regulatory_requirement WHERE status='DRAFT' AND organization_scope IS NULL"),
        "verified_requirements": n("SELECT COUNT(*) FROM regulatory_requirement WHERE status='APPROVED' AND published_seq IS NOT NULL AND organization_scope IS NULL"),
        "translations_unreviewed": n("SELECT COUNT(*) FROM regulatory_requirement WHERE translation_status='UNREVIEWED' AND status IN ('DRAFT','APPROVED') AND organization_scope IS NULL"),
        "approved_pam_mappings": n("SELECT COUNT(*) FROM framework_control_mapping WHERE status='APPROVED' AND published_seq IS NOT NULL AND organization_scope IS NULL"),
        "published_opa_rules": {
            "catalog_rules_in_active_bundle": published_rules,
            "active_bundle_version": active["version"] if active else None,
            "predefined_rules_registered": n("SELECT COUNT(*) FROM opa_rule_definition WHERE kind='PREDEFINED_REGO'"),
        },
        "rule_versions_awaiting_review": n("SELECT COUNT(*) FROM rule_version WHERE status='DRAFT'"),
        "remediation_templates_published": n("SELECT COUNT(*) FROM remediation_template WHERE status='APPROVED' AND published_seq IS NOT NULL"),
        "regulatory_changes_detected": {"total": n("SELECT COUNT(*) FROM regulatory_change"),
                                        "open": n("SELECT COUNT(*) FROM regulatory_change WHERE status='OPEN'")},
        "frameworks": {"registered": n("SELECT COUNT(*) FROM regulatory_framework WHERE organization_scope IS NULL"),
                       "verified": n("SELECT COUNT(*) FROM regulatory_framework WHERE verification_status='VERIFIED' AND organization_scope IS NULL")},
        "countries_and_territories_by_stage": stages,
        # "Unsupported" = no published, source-verified requirement of the jurisdiction's own.
        "unsupported_jurisdictions": sum(v for k, v in stages.items() if k not in ("REQUIREMENTS_PUBLISHED", "MAPPINGS_PUBLISHED")),
    }


def render_text(m: dict[str, Any]) -> str:
    rules = m["published_opa_rules"]
    lines = [
        "Securden regulatory catalog - coverage",
        f"  catalog version                     {m['catalog_version']}",
        f"  jurisdictions registered            {m['jurisdictions_registered']['total']}  {m['jurisdictions_registered']['by_kind']}",
        f"  official sources configured         {m['official_sources_configured']['total']}  {m['official_sources_configured']['by_status']}",
        f"  sources successfully synchronized   {m['sources_successfully_synchronized']}",
        f"  stale regulatory sources            {m['stale_regulatory_sources']}",
        f"  documents retrieved                 {m['documents_retrieved']}  (incomplete: {m['documents_incomplete']})",
        f"  documents awaiting review           {m['documents_awaiting_review']}",
        f"  verified requirements (published)   {m['verified_requirements']}  (drafts: {m['requirements_draft']})",
        f"  approved PAM mappings (published)   {m['approved_pam_mappings']}",
        f"  published OPA rules                 {rules['catalog_rules_in_active_bundle']} catalog rule(s) in bundle "
        f"{rules['active_bundle_version'] or '(base bundle)'}; {rules['predefined_rules_registered']} predefined",
        f"  regulatory changes detected         {m['regulatory_changes_detected']['total']}  (open: {m['regulatory_changes_detected']['open']})",
        f"  unsupported jurisdictions           {m['unsupported_jurisdictions']} of "
        f"{sum(m['countries_and_territories_by_stage'].values())} countries/territories",
        "  countries/territories by stage:",
        *[f"    {k:<24}{v}" for k, v in m["countries_and_territories_by_stage"].items()],
        "",
        m["statement"],
    ]
    return "\n".join(lines)
