"""Global catalog API for the Securden Django application (read-only).

Mounted in the existing FastAPI service, so it inherits the HTTPS + mTLS edge
and bearer-token authentication; every endpoint requires the ``catalog:read``
scope. The catalog is global reference data (not tenant data): no customer
configuration, evidence or assessment result is stored or served here.

Conventions
  * every response carries ``schema_version`` and ``catalog_version`` (the
    sequence number of the latest publication)
  * list endpoints are cursor-paginated: ``limit`` + ``after`` -> ``next_cursor``
  * incremental sync: ``GET /api/v1/catalog/changes?since=<catalog_version>``
  * only reviewed *and published* content is served; drafts never are
  * every item says which layer it belongs to (explicit obligation,
    interpretive mapping, executable rule)
"""

from __future__ import annotations

import hashlib
from datetime import date, datetime
from typing import Any, Iterator

from fastapi import APIRouter, Depends, Query, Request
from pydantic import ValidationError

from app.errors import ServiceError
from app.models.common import TenantId, format_utc
from app.security import Principal, authorize_tenant, require_scope

from . import PAM_DOMAINS, SCHEMA_VERSION, coverage, orgscope, plan as planning
from . import automation, control_ids, mapping_policy, policy_contexts as pctx, policy_controls
from . import generated_rules, policy_plan
from .applicability import OrganizationProfile, evaluate
from .catalog import LAYERS
from .db import CatalogDb, CatalogError, canonical
from .registry import jurisdiction_closure

router = APIRouter(prefix="/api/v1/catalog", tags=["catalog"])
_auth = require_scope("catalog:read")

MAPPING_DISCLAIMER = (
    "Mappings are Securden's reviewed interpretation of how a PAM technical control supports a regulatory "
    "requirement. They are not legal advice, certification, attestation or an audit conclusion."
)
TRANSLATION_NOTICE = "English text is a working translation. Only the original-language official text is authoritative."
Limit = Query(default=100, ge=1, le=500)


def get_db(request: Request) -> Iterator[CatalogDb]:
    path = request.app.state.settings.catalog_db_path
    if not path.exists():
        raise ServiceError(503, "CATALOG_UNAVAILABLE", "The regulatory catalog has not been initialised on this host.")
    db = CatalogDb(path, read_only=True)
    try:
        yield db
    finally:
        db.close()


def _envelope(db: CatalogDb, **body: Any) -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "catalog_version": db.catalog_version(), **body}


def _page(db: CatalogDb, rows: list[dict[str, Any]], limit: int, key: str = "id", **extra: Any) -> dict[str, Any]:
    more = len(rows) > limit
    rows = rows[:limit]
    return _envelope(db, items=rows, has_more=more, next_cursor=str(rows[-1][key]) if more and rows else None, **extra)


def _as_of(value: date | None) -> str:
    return (value or date.today()).isoformat()


def _int_cursor(after: str | None) -> int:
    try:
        return int(after) if after else 0
    except ValueError as exc:
        raise ServiceError(422, "INVALID_CURSOR", "Cursor is not valid for this endpoint.") from exc


def _scope(request: Request, db: CatalogDb, principal: Principal) -> str | None:
    """Validated organization scope of this request (Django rewrite contract 1.0).

    The public catalog connection is read-only; a scope seen here for the first
    time is bound through a short-lived writable connection."""
    raw = request.headers.get(orgscope.HEADER)
    if raw is None:
        return None
    try:
        bound = db.one("SELECT key_id FROM organization_scope_binding WHERE scope=?", (raw,))
        if bound is not None:
            return orgscope.validate_and_bind(db, raw, principal.key_id)  # read-only path: no insert needed
        wdb = CatalogDb(request.app.state.settings.catalog_db_path)
        try:
            return orgscope.validate_and_bind(wdb, raw, principal.key_id)
        finally:
            wdb.close()
    except orgscope.ScopeError as exc:
        raise ServiceError(exc.status, exc.code, exc.message) from exc


def _scope_pred(alias: str, scope: str | None) -> tuple[str, list[str]]:
    col = f"{alias}.organization_scope"
    return (f"{col} IS NULL", []) if scope is None else (f"({col} IS NULL OR {col}=?)", [scope])


# ------------------------------------------------------------------ meta


@router.get("/meta")
def meta(db: CatalogDb = Depends(get_db), _: Principal = Depends(_auth)) -> dict:
    active = db.one("SELECT version, digest FROM bundle_version WHERE active=1")
    last = db.one("SELECT seq, published_at, kind FROM catalog_publication ORDER BY seq DESC LIMIT 1")
    return _envelope(
        db, pam_domains=list(PAM_DOMAINS), layers=sorted(set(LAYERS.values()) | {"CUSTOMER_POLICY"}),
        active_policy_bundle=active, last_publication=last, coverage_statement=coverage.STATEMENT,
        mapping_disclaimer=MAPPING_DISCLAIMER, translation_notice=TRANSLATION_NOTICE)


# ------------------------------------------------------------------ jurisdictions


@router.get("/jurisdictions")
def jurisdictions(
    kind: str | None = Query(default=None, pattern="^(COUNTRY_OR_TERRITORY|SUBDIVISION|SUPRANATIONAL|INTERNATIONAL)$"),
    parent: str | None = Query(default=None, max_length=10), after: str = Query(default="", max_length=10),
    limit: int = Limit, db: CatalogDb = Depends(get_db), _: Principal = Depends(_auth),
) -> dict:
    sql, args = "SELECT code FROM jurisdiction WHERE code > ?", [after]
    if kind:
        sql, args = sql + " AND kind=?", args + [kind]
    if parent:
        sql, args = sql + " AND parent_code=?", args + [parent]
    codes = [r["code"] for r in db.q(sql + " ORDER BY code LIMIT ?", args + [limit + 1])]
    rows = []
    for code in codes:
        j = db.one("SELECT code, kind, name, alpha3, numeric_code, parent_code, subdivision_type, languages "
                   "FROM jurisdiction WHERE code=?", (code,))
        j["coverage"] = coverage.jurisdiction_coverage(db, code)[0]  # type: ignore[index]
        del j["coverage"]["code"]  # type: ignore[index]
        rows.append(j)
    return _page(db, rows, limit, key="code", coverage_statement=coverage.STATEMENT)


@router.get("/jurisdictions/{code}")
def jurisdiction(code: str, as_of: date | None = None, db: CatalogDb = Depends(get_db),
                 _: Principal = Depends(_auth)) -> dict:
    j = db.one("SELECT * FROM jurisdiction WHERE code=?", (code,))
    if j is None:
        raise ServiceError(404, "UNKNOWN_JURISDICTION", "Jurisdiction is not in the registry.")
    when = _as_of(as_of)
    closure = jurisdiction_closure(db, code, when)
    return _envelope(
        db, jurisdiction=j, as_of=when, overlapping_jurisdictions=closure,
        memberships=db.q("SELECT group_code, valid_from, valid_to FROM jurisdiction_membership WHERE member_code=? "
                         "ORDER BY group_code, valid_from", (code,)),
        coverage={c["code"]: coverage.jurisdiction_coverage(db, c["code"])[0] for c in closure},
        coverage_statement=coverage.STATEMENT)


# ------------------------------------------------------------------ frameworks


def _framework_public(db: CatalogDb, fw: dict[str, Any], when: str) -> dict[str, Any]:
    in_force = None
    if fw["verification_status"] == "VERIFIED" and fw["lifecycle"] != "UNKNOWN":
        in_force = bool(fw["effective_from"] and fw["effective_from"] <= when
                        and not (fw["effective_to"] and fw["effective_to"] <= when))
    fw = {k: v for k, v in fw.items() if k not in ("created_at", "updated_seq", "verified_by")}
    fw["cross_border"] = bool(fw["cross_border"])
    fw["in_force_on_as_of"] = in_force  # null = unverified, cannot tell
    fw["published_requirements"] = db.scalar(
        "SELECT COUNT(*) FROM regulatory_requirement WHERE framework_id=? AND status='APPROVED' AND published_seq IS NOT NULL",
        (fw["id"],))
    fw["coverage_note"] = ("No source-verified requirements are published for this framework."
                           if not fw["published_requirements"] else
                           "Published requirements are those reviewed so far; completeness is not asserted.")
    return fw


@router.get("/frameworks")
def frameworks(
    request: Request,
    jurisdiction: str | None = Query(default=None, max_length=10),
    include_overlapping: bool = True, industry: str | None = Query(default=None, max_length=64),
    as_of: date | None = None, verified_only: bool = False,
    after: str = Query(default="", max_length=48), limit: int = Limit,
    db: CatalogDb = Depends(get_db), principal: Principal = Depends(_auth),
) -> dict:
    """Framework discovery with country / industry filters. A jurisdiction
    filter returns frameworks *registered for* that jurisdiction (and, by
    default, for the jurisdictions that overlap it). That is a candidate list,
    not an applicability decision: use POST /applicability for screening."""
    when = _as_of(as_of)
    pred, pred_args = _scope_pred("regulatory_framework", _scope(request, db, principal))
    sql, args = f"SELECT * FROM regulatory_framework WHERE {pred} AND id > ?", [*pred_args, after]
    paths: dict[str, str] = {}
    if jurisdiction:
        try:
            closure = jurisdiction_closure(db, jurisdiction, when) if include_overlapping else [{"code": jurisdiction, "via": "SELF"}]
        except CatalogError as exc:
            raise ServiceError(404, "UNKNOWN_JURISDICTION", "Jurisdiction is not in the registry.") from exc
        paths = {c["code"]: c["via"] for c in closure}
        sql += f" AND jurisdiction_code IN ({','.join('?' * len(paths))})"
        args += list(paths)
    if verified_only:
        sql += " AND verification_status='VERIFIED'"
    rows = db.q(sql + " ORDER BY id", args)
    if industry:  # frameworks with no industry restriction recorded are kept and flagged
        rows = [r for r in rows if not r["industries"] or industry in r["industries"]]
    out = []
    for fw in rows[: limit + 1]:
        item = _framework_public(db, fw, when)
        item["jurisdiction_path"] = paths.get(fw["jurisdiction_code"])
        item["industry_filter_match"] = None if not industry else ("LISTED" if industry in fw["industries"] else "NO_INDUSTRY_RESTRICTION_RECORDED")
        out.append(item)
    return _page(db, out, limit, as_of=when,
                 note="Candidate frameworks only. Presence in this list does not mean a framework applies to an organization.")


@router.get("/frameworks/{framework_id}")
def framework(framework_id: str, request: Request, as_of: date | None = None, db: CatalogDb = Depends(get_db),
              principal: Principal = Depends(_auth)) -> dict:
    fw = db.one("SELECT * FROM regulatory_framework WHERE id=?", (framework_id,))
    if not orgscope.visible(fw, _scope(request, db, principal)):  # cross-scope ids look exactly like unknown ones
        raise ServiceError(404, "UNSUPPORTED_FRAMEWORK", "Framework is not registered in the catalog.")
    doc_pred, doc_args = _scope_pred("d", _scope(request, db, principal))
    docs = db.q(
        "SELECT d.id AS document_id, d.external_id, d.title, d.url, d.language, s.id AS source_id, s.status AS source_status, "
        "a.name AS authority, v.id AS version_id, v.version_label, v.content_sha256, v.retrieved_at, v.published_on, "
        "v.effective_from, v.effective_to, v.status AS version_status, v.complete "
        "FROM regulatory_document d JOIN source s ON s.id=d.source_id JOIN regulatory_authority a ON a.id=s.authority_id "
        "LEFT JOIN regulatory_document_version v ON v.document_id=d.id AND v.status IN ('REVIEWED','SUPERSEDED') "
        f"WHERE d.framework_id=? AND {doc_pred} ORDER BY d.id, v.id", (framework_id, *doc_args))
    criteria = db.one("SELECT id, criteria, rationale, requirement_ids FROM applicability_criteria WHERE framework_id=? "
                      "AND status='APPROVED' AND published_seq IS NOT NULL", (framework_id,))
    return _envelope(db, framework=_framework_public(db, fw, _as_of(as_of)), source_references=docs,
                     applicability_criteria=criteria)


# ------------------------------------------------------------------ sources


@router.get("/sources")
def sources(db: CatalogDb = Depends(get_db), _: Principal = Depends(_auth)) -> dict:
    """Source references and freshness."""
    items = coverage.stale_sources(db)
    for s in items:
        row = db.one("SELECT s.adapter_type, s.languages, s.config, a.name AS authority, a.official_domains "
                     "FROM source s JOIN regulatory_authority a ON a.id=s.authority_id WHERE s.id=?", (s["id"],))
        last = db.one("SELECT method, verifier, verified_at FROM source_verification WHERE source_id=? AND outcome='VERIFIED' "
                      "ORDER BY id DESC LIMIT 1", (s["id"],))
        s.update(adapter_type=row["adapter_type"], languages=row["languages"], authority=row["authority"],  # type: ignore[index]
                 official_domains=row["config"]["allowed_domains"], licensing=row["config"]["licensing"],  # type: ignore[index]
                 verification=last if s["status"] == "VERIFIED" else None)
    return _envelope(db, items=items)


# ------------------------------------------------------------------ requirements


def _requirement_public(db: CatalogDb, r: dict[str, Any], scope: str | None = None) -> dict[str, Any]:
    ref = db.one(
        "SELECT d.external_id, d.title, d.url, v.version_label, v.content_sha256, v.retrieved_at, v.published_on, "
        "s.id AS source_id, s.config, a.name AS authority, a.jurisdiction_code "
        "FROM regulatory_document_version v JOIN regulatory_document d ON d.id=v.document_id "
        "JOIN source s ON s.id=d.source_id JOIN regulatory_authority a ON a.id=s.authority_id WHERE v.id=?",
        (r["document_version_id"],))
    # An organization always sees the text of its own scoped uploads; third-party
    # licensing limits apply to everything else.
    may_redistribute = bool(ref["config"]["licensing"]["redistribute_text"]) or (  # type: ignore[index]
        scope is not None and r.get("organization_scope") == scope)
    reviewed = r["translation_status"] == "REVIEWED"
    translation = None
    if r["translation_status"] != "NOT_REQUIRED":
        translation = {
            "status": r["translation_status"], "authoritative": False, "notice": TRANSLATION_NOTICE,
            # An unreviewed machine translation is never served as text.
            "text": r["translation_en"] if reviewed and may_redistribute else None,
            "model": r["translation_model"], "model_version": r["translation_model_version"],
            "reviewed_by_human": reviewed,
        }
    return {
        "id": r["id"], "layer": LAYERS["requirement"], "framework_id": r["framework_id"], "status": r["status"],
        "obligation_type": r["obligation_type"], "pam_domains": r["pam_domains"],
        "original_language": r["original_language"],
        "original_text": r["original_text"] if may_redistribute else None,
        "text_withheld_reason": None if may_redistribute else "Source licensing does not permit redistribution; consult the cited official text.",
        "thresholds_stated_in_text": r["thresholds"] if may_redistribute else [],
        "translation_en": translation,
        "effective_from": r["effective_from"], "effective_to": r["effective_to"], "superseded_by": r["superseded_by"],
        "source_reference": {
            "authority": ref["authority"], "authority_jurisdiction": ref["jurisdiction_code"], "source_id": ref["source_id"],  # type: ignore[index]
            "document": ref["external_id"], "document_title": ref["title"], "url": ref["url"],  # type: ignore[index]
            "document_version": ref["version_label"], "content_sha256": ref["content_sha256"],  # type: ignore[index]
            "retrieved_at": ref["retrieved_at"], "published_on": ref["published_on"], "section": r["section_ref"],  # type: ignore[index]
        },
        "extraction_method": r["extraction"].get("method"),
        "published_in": r["published_seq"],
    }


_REQ_VISIBLE = "r.published_seq IS NOT NULL AND r.status IN ('APPROVED','SUPERSEDED','REPEALED')"


def _req_date_filter(when: str | None) -> tuple[str, list[Any]]:
    """Historical filter. Requirements with no recorded dates are returned and
    must be treated as undated by the caller."""
    if when is None:
        return "", []
    return (" AND (r.effective_from IS NULL OR r.effective_from<=?) AND (r.effective_to IS NULL OR r.effective_to>?)",
            [when, when])


@router.get("/requirements")
def requirements(
    request: Request,
    framework_id: str | None = Query(default=None, max_length=48), pam_domain: str | None = Query(default=None, max_length=64),
    as_of: date | None = None, include_historical: bool = False,
    after: str | None = Query(default=None, max_length=20), limit: int = Limit,
    db: CatalogDb = Depends(get_db), principal: Principal = Depends(_auth),
) -> dict:
    scope = _scope(request, db, principal)
    when = None if include_historical else _as_of(as_of)
    clause, dargs = _req_date_filter(when)
    if scope is not None and framework_id:
        # Scoped read of one prepared framework (rewrite contract 1.0): the
        # organization's own rows in EVERY status (its working records and
        # gaps) plus the published global catalog - never the DRAFT-only
        # default of the management API, never another scope's rows.
        sql = ("SELECT r.* FROM regulatory_requirement r WHERE r.id > ? AND "
               f"(r.organization_scope=? OR (r.organization_scope IS NULL AND {_REQ_VISIBLE}))")
        args: list[Any] = [_int_cursor(after), scope]
        when = None  # all statuses implies all dates; snapshots are Django's
    else:
        pred, pargs = _scope_pred("r", scope)
        sql = f"SELECT r.* FROM regulatory_requirement r WHERE {pred} AND {_REQ_VISIBLE} AND r.id > ?{clause}"
        args = [*pargs, _int_cursor(after), *dargs]
        if not include_historical:
            sql += " AND r.status='APPROVED'" if as_of is None else ""
    if framework_id:
        if not orgscope.visible(db.one("SELECT organization_scope FROM regulatory_framework WHERE id=?",
                                       (framework_id,)), scope):
            raise ServiceError(404, "UNSUPPORTED_FRAMEWORK", "Framework is not registered in the catalog.")
        sql, args = sql + " AND r.framework_id=?", args + [framework_id]
    rows = db.q(sql + " ORDER BY r.id", args)
    if pam_domain:
        rows = [r for r in rows if pam_domain in r["pam_domains"]]
    extra = {"organization_scope": scope} if scope else {}
    return _page(db, [_requirement_public(db, r, scope) for r in rows[: limit + 1]], limit, as_of=when,
                 translation_notice=TRANSLATION_NOTICE, **extra)


# ------------------------------------------------------------------ controls, mappings, evidence


@router.get("/pam-controls")
def pam_controls(db: CatalogDb = Depends(get_db), _: Principal = Depends(_auth)) -> dict:
    items = db.q("SELECT * FROM pam_control ORDER BY id")
    for c in items:
        c["rule_ids"] = [r["rule_id"] for r in db.q(  # organization-generated rules are not catalog-wide rules
            "SELECT rule_id FROM opa_rule_definition WHERE pam_control_id=? AND rule_id NOT LIKE 'PAM-GEN-%' "
            "ORDER BY rule_id", (c["id"],))]
        c["frameworks_mapped"] = [r["framework_id"] for r in db.q(
            "SELECT DISTINCT r.framework_id FROM framework_control_mapping m JOIN regulatory_requirement r ON r.id=m.requirement_id "
            "WHERE m.pam_control_id=? AND m.status='APPROVED' AND m.published_seq IS NOT NULL AND r.status='APPROVED' "
            "ORDER BY r.framework_id", (c["id"],))]
    return _envelope(db, items=items, mapping_disclaimer=MAPPING_DISCLAIMER)


@router.get("/mappings")
def mappings(
    request: Request,
    framework_id: str | None = Query(default=None, max_length=48), pam_control_id: str | None = Query(default=None, max_length=64),
    rule_id: str | None = Query(default=None, max_length=100), requirement_id: int | None = Query(default=None, ge=1),
    after: str | None = Query(default=None, max_length=20),
    limit: int = Limit, db: CatalogDb = Depends(get_db), principal: Principal = Depends(_auth),
) -> dict:
    """Approved PAM control mappings (many-to-many between requirements and controls)."""
    _require_plan_schema(db)
    pred, pargs = _scope_pred("m", _scope(request, db, principal))
    sql = ("SELECT m.id, m.requirement_id, m.pam_control_id, m.strength, m.rationale, m.limitations, m.published_seq, "
           "m.mapping_key, m.version AS mapping_version, m.assessment, m.rule_id AS mapped_rule_id, m.rule_version_min, "
           "m.rule_version_max, m.evidence_type, m.rule_parameters, m.override_constraints, m.coverage, "
           "m.control_reference, "
           "r.framework_id, r.section_ref FROM framework_control_mapping m JOIN regulatory_requirement r ON r.id=m.requirement_id "
           f"WHERE {pred} AND m.status='APPROVED' AND m.published_seq IS NOT NULL AND r.status='APPROVED' AND r.published_seq IS NOT NULL AND m.id > ?")
    args: list[Any] = [*pargs, _int_cursor(after)]
    if framework_id:
        sql, args = sql + " AND r.framework_id=?", args + [framework_id]
    if requirement_id:
        sql, args = sql + " AND m.requirement_id=?", args + [requirement_id]
    if rule_id:
        pam_control_id = db.scalar("SELECT pam_control_id FROM opa_rule_definition WHERE rule_id=?", (rule_id,)) or "-"
    if pam_control_id:
        sql, args = sql + " AND m.pam_control_id=?", args + [pam_control_id]
    rows = db.q(sql + " ORDER BY m.id LIMIT ?", args + [limit + 1])
    for m in rows:
        m["layer"] = LAYERS["mapping"]
        m["parameters"] = m.pop("rule_parameters")
        m["assessment"] = m["assessment"] or "CONTROL_REFERENCE"
        approval = db.one("SELECT reviewer, decided_at FROM review_approval WHERE entity_type='mapping' AND entity_id=? "
                          "AND decision='APPROVED' ORDER BY id DESC LIMIT 1", (str(m["id"]),))
        m["approval_status"] = "APPROVED"
        m["approved_at"] = approval["decided_at"] if approval else None
        m["source_references"] = [_requirement_public(db, db.one("SELECT * FROM regulatory_requirement WHERE id=?", (m["requirement_id"],)))["source_reference"]]  # type: ignore[arg-type]
    return _page(db, rows, limit, mapping_disclaimer=MAPPING_DISCLAIMER)


@router.get("/evidence-requirements")
def evidence_requirements(pam_control_id: str | None = Query(default=None, max_length=64),
                          db: CatalogDb = Depends(get_db), _: Principal = Depends(_auth)) -> dict:
    sql, args = ("SELECT id, pam_control_id, evidence_type, description, fields, published_seq FROM evidence_requirement "
                 "WHERE status='APPROVED' AND published_seq IS NOT NULL"), []
    if pam_control_id:
        sql, args = sql + " AND pam_control_id=?", [pam_control_id]
    return _envelope(db, items=db.q(sql + " ORDER BY id", args))


# ------------------------------------------------------------------ evaluation templates and plans

TEMPLATE_NOTE = ("Readiness describes which published requirements have a reviewed, executable rule mapping. It is not a "
                 "compliance result and not an applicability decision; a framework listed for a jurisdiction is a candidate only.")


def _require_plan_schema(db: CatalogDb) -> None:
    if not planning.schema_ready(db):
        raise ServiceError(503, "CATALOG_SCHEMA_OUTDATED",
                           "The catalog database predates execution mappings; start the catalog management process once.")


def _require_policy_schema(db: CatalogDb) -> None:
    if db.scalar("SELECT 1 FROM sqlite_master WHERE type='table' AND name='policy_context_version'") is None:
        raise ServiceError(503, "CATALOG_SCHEMA_OUTDATED",
                           "The catalog database predates policy contexts; start the catalog management process once.")


@router.get("/evaluation-templates", response_model=planning.TemplatePage)
def evaluation_templates(
    request: Request, jurisdiction: str | None = Query(default=None, max_length=10), include_inherited: bool = False,
    include_unapproved: bool = False, as_of: date | None = None, after: str = Query(default="", max_length=48),
    limit: int = Limit, db: CatalogDb = Depends(get_db), principal: Principal = Depends(_auth),
) -> dict:
    """Frameworks that can be selected for an assessment, with engine coverage.

    ``jurisdiction`` matches frameworks registered for exactly that code. With
    ``include_inherited=true`` frameworks of its parents and of groups it was a
    member of on ``as_of`` are added and marked INHERITED. Only review-approved
    frameworks are listed unless ``include_unapproved=true``."""
    _require_plan_schema(db)
    scope = _scope(request, db, principal)
    when = _as_of(as_of)
    paths: dict[str, str] = {}
    pred, pargs = _scope_pred("regulatory_framework", scope)
    sql, args = f"SELECT * FROM regulatory_framework WHERE {pred} AND id > ?", [*pargs, after]
    if jurisdiction:
        try:
            closure = jurisdiction_closure(db, jurisdiction, when)
        except CatalogError as exc:
            raise ServiceError(404, "UNKNOWN_JURISDICTION", "Jurisdiction is not in the registry.") from exc
        paths = {c["code"]: c["via"] for c in closure if include_inherited or c["via"] == "SELF"}
        sql += f" AND jurisdiction_code IN ({','.join('?' * len(paths))})"
        args += list(paths)
    if not include_unapproved:
        sql += " AND verification_status='VERIFIED'"
    rows = db.q(sql + " ORDER BY id LIMIT ?", args + [limit + 1])
    engine = generated_rules.engine_for(db, request.app.state.catalog, scope)
    items = []
    for fw in rows[:limit]:
        item = planning.template_summary(planning.build_plan(db, fw, when, engine, org_scope=scope))
        via = paths.get(fw["jurisdiction_code"])
        item["jurisdiction_match"] = None if not jurisdiction else ("EXACT" if via == "SELF" else "INHERITED")
        item["jurisdiction_path"] = via
        # Rewrite contract 1.0 additions (additive for every caller):
        item["assessable_requirements"] = item["automated_requirements"]
        item["source_origin"] = orgscope.source_origin(db, fw["id"], scope)
        latest = db.scalar(
            "SELECT MAX(created_at) FROM regulatory_requirement WHERE framework_id=? AND published_seq IS NOT NULL AND "
            + ("organization_scope IS NULL" if scope is None else "(organization_scope IS NULL OR organization_scope=?)"),
            (fw["id"], *([] if scope is None else [scope])))
        item["updated_at"] = latest or fw["created_at"]
        items.append(item)
    more = len(rows) > limit
    extra = {"organization_scope": scope} if scope else {}
    return _envelope(db, policy_bundle_version=engine.bundle_version, as_of=when, jurisdiction=jurisdiction,
                     include_inherited=include_inherited, items=items, has_more=more,
                     next_cursor=items[-1]["framework_id"] if more and items else None, note=TEMPLATE_NOTE, **extra)


@router.get("/evaluation-templates/{framework_id}/plan", response_model=planning.PlanResponse,
            response_model_exclude_unset=True)
def evaluation_plan(
    framework_id: str, request: Request, tenant_id: TenantId = Query(...), as_of: date | None = None,
    catalog_version: int | None = Query(default=None, ge=0),
    expected_digest: str | None = Query(default=None, pattern=r"^sha256:[0-9a-f]{64}$"),
    policy_version_id: list[str] = Query(default=[], max_length=50,
                                         description="Selected organization policy versions (repeat the parameter)."),
    reporting_period_start: datetime | None = None, reporting_period_end: datetime | None = None,
    db: CatalogDb = Depends(get_db), principal: Principal = Depends(_auth),
) -> dict:
    """Execution plan for one framework: every published requirement in scope
    (including manual and unmapped ones) and the distinct pinned rule executions.
    Pass ``expected_digest`` (or ``catalog_version``) to confirm a saved plan is
    still current; a difference returns 409 PLAN_STALE. Optional, additive:
    ``policy_version_id`` + ``reporting_period_start/end`` bind organization
    policy (CUSTOMER_POLICY) to the plan; POST the same request to also send
    ``target_resolutions``."""
    try:
        period = None
        if reporting_period_start is not None or reporting_period_end is not None:
            period = pctx.Period(start=reporting_period_start, end=reporting_period_end)
        body = pctx.PlanRequest(tenant_id=tenant_id, as_of=as_of, catalog_version=catalog_version,
                                expected_digest=expected_digest, policy_version_ids=policy_version_id,
                                reporting_period=period)
    except ValidationError as exc:
        raise ServiceError(422, "VALIDATION_ERROR", "Invalid plan request.",
                           details=exc.errors(include_input=False, include_url=False)) from exc
    return _plan(framework_id, request, body, db, principal)


@router.post("/evaluation-templates/{framework_id}/plan", response_model=planning.PlanResponse,
             response_model_exclude_unset=True)
def evaluation_plan_post(framework_id: str, request: Request, body: pctx.PlanRequest,
                         db: CatalogDb = Depends(get_db), principal: Principal = Depends(_auth)) -> dict:
    """Same plan as GET; the body can also carry ``target_resolutions`` (Django-resolved,
    frozen group membership) used to decide whether policy bindings overlap."""
    return _plan(framework_id, request, body, db, principal)


def _plan(framework_id: str, request: Request, body: pctx.PlanRequest, db: CatalogDb, principal: Principal) -> dict:
    _require_plan_schema(db)
    tenant_id = body.tenant_id
    authorize_tenant(principal, tenant_id)
    scope = _scope(request, db, principal)
    if body.reporting_period is not None and not body.policy_version_ids:
        raise ServiceError(422, "POLICY_VERSIONS_REQUIRED",
                           "reporting_period is used only together with policy_version_ids.")
    if body.target_resolutions and not body.policy_version_ids:
        raise ServiceError(422, "POLICY_VERSIONS_REQUIRED",
                           "target_resolutions are used only together with policy_version_ids.")
    if body.policy_version_ids:
        if scope is None:
            raise ServiceError(422, "SCOPE_REQUIRED", f"Policy contexts are organization-owned; send {orgscope.HEADER}.")
        if body.reporting_period is None:
            raise ServiceError(422, "REPORTING_PERIOD_REQUIRED",
                               "policy_version_ids need reporting_period bounds (start and end).")
        _require_policy_schema(db)
    as_of = body.as_of
    if as_of is None and body.reporting_period is not None:
        as_of = body.reporting_period.end.date()
    fw = db.one("SELECT * FROM regulatory_framework WHERE id=?", (framework_id,))
    if not orgscope.visible(fw, scope):  # cross-scope frameworks look exactly like unknown ones
        raise ServiceError(404, "UNSUPPORTED_FRAMEWORK", "Framework is not registered in the catalog.")
    state = request.app.state
    store = getattr(state, "store", None)
    rule_active = (lambda rule: store.predefined_active(tenant_id, rule)) if store is not None else None
    # this tenant's activated generated rules (PAM-GEN-*) execute beside the bundle's rules
    engine = generated_rules.engine_for(db, state.catalog, scope, tenant_id)
    result = planning.build_plan(
        db, fw, _as_of(as_of), engine, tenant_id=tenant_id, rule_active=rule_active,
        public_requirement=lambda d, r: _requirement_public(d, r, scope), org_scope=scope)
    if body.policy_version_ids:
        assert scope is not None and body.reporting_period is not None
        period = (format_utc(body.reporting_period.start), format_utc(body.reporting_period.end))
        try:
            result["policy_context"] = policy_plan.resolve(
                db, result, engine=engine, scope=scope, tenant=tenant_id, version_ids=body.policy_version_ids,
                period=period, resolutions=[r.as_dict() for r in body.target_resolutions],
                cap=pctx.capabilities(db, scope, tenant_id), rule_active=rule_active)
        except CatalogError as exc:
            raise ServiceError(404 if exc.code.startswith("UNKNOWN_") else 422, exc.code, exc.message,
                               details=exc.details) from exc
        result["plan_digest"] = "sha256:" + hashlib.sha256(canonical(result["digest_input"]).encode("utf-8")).hexdigest()
    catalog_version, expected_digest = body.catalog_version, body.expected_digest
    current = db.catalog_version()
    if (catalog_version is not None and catalog_version != current) or (
            expected_digest is not None and expected_digest != result["plan_digest"]):
        raise ServiceError(409, "PLAN_STALE", "The catalog or policy bundle changed; resolve a new plan before evaluating.",
                           details={"catalog_version": current, "plan_digest": result["plan_digest"],
                                    "policy_bundle_version": result["policy_bundle_version"]})
    extra = {"organization_scope": scope} if scope else {}
    return _envelope(db, **result, mapping_disclaimer=MAPPING_DISCLAIMER, **extra)


# ------------------------------------------------------------------ organization policy contexts


def _policy_owner(request: Request, db: CatalogDb, principal: Principal, tenant_id: str) -> str:
    authorize_tenant(principal, tenant_id)
    scope = _scope(request, db, principal)
    if scope is None:
        raise ServiceError(422, "SCOPE_REQUIRED", f"Policy contexts are organization-owned; send {orgscope.HEADER}.")
    _require_policy_schema(db)
    return scope


@router.get("/policy-controls")
def policy_control_catalog(request: Request, tenant_id: TenantId | None = None,
                           control_id: str | None = Query(default=None, pattern=r"^PC-[A-Z0-9-]{2,60}$"),
                           include_evidence_schema: bool = True,
                           db: CatalogDb = Depends(get_db), principal: Principal = Depends(_auth)) -> dict:
    """Versioned policy-control definitions. With ``tenant_id`` and the organization-scope
    header, each item's ``assessability`` reflects that organization's collector handshake."""
    cap = None
    if tenant_id is not None:
        authorize_tenant(principal, tenant_id)
        scope = _scope(request, db, principal)
        if scope is not None:
            _require_policy_schema(db)
            cap = pctx.capabilities(db, scope, tenant_id)
    engine = request.app.state.catalog
    items = [policy_controls.public(c, capabilities=cap, engine=engine, include_evidence_schema=include_evidence_schema)
             for (cid, _v), c in sorted(policy_controls.CONTROLS.items()) if control_id in (None, cid)]
    return _envelope(
        db, control_catalog_version=policy_controls.CONTROL_CATALOG_VERSION,
        policy_bundle_version=engine.bundle_version, schema_subset=policy_controls.SCHEMA_SUBSET,
        target_types=policy_controls.TARGET_TYPES, assessment_modes=policy_controls.ASSESSMENT_MODES,
        collector_capabilities=pctx.capabilities_view(cap) if cap else None, items=items)


@router.get("/policy-contexts")
def policy_context_list(request: Request, tenant_id: TenantId = Query(...),
                        after: str = Query(default="", max_length=64), limit: int = Limit,
                        db: CatalogDb = Depends(get_db), principal: Principal = Depends(_auth)) -> dict:
    scope = _policy_owner(request, db, principal, tenant_id)
    rows = pctx.list_contexts(db, scope, tenant_id, after=after, limit=limit)
    more = len(rows) > limit
    rows = rows[:limit]
    return _envelope(db, organization_scope=scope, tenant_id=tenant_id, items=rows, has_more=more,
                     next_cursor=rows[-1]["policy_context_id"] if more and rows else None)


@router.get("/policy-contexts/{context_id}/versions/{version}")
def policy_context_version(context_id: str, version: int, request: Request, tenant_id: TenantId = Query(...),
                           db: CatalogDb = Depends(get_db), principal: Principal = Depends(_auth)) -> dict:
    scope = _policy_owner(request, db, principal, tenant_id)
    try:
        pctx.owned_context(db, context_id, scope, tenant_id)
    except CatalogError as exc:
        raise ServiceError(404, exc.code, exc.message) from exc
    row = db.one("SELECT * FROM policy_context_version WHERE context_id=? AND version=?", (context_id, version))
    if row is None:
        raise ServiceError(404, "UNKNOWN_POLICY_VERSION", "Policy version not found in this organization scope.")
    view = pctx.version_view(db, row, engine=request.app.state.catalog)
    return _envelope(db, organization_scope=scope, policy_version=view)


def _visible_framework(request: Request, db: CatalogDb, principal: Principal, framework_id: str,
                       tenant_id: str | None) -> tuple[dict | None, str | None]:
    if tenant_id is not None:
        authorize_tenant(principal, tenant_id)
    scope = _scope(request, db, principal)
    fw = db.one("SELECT * FROM regulatory_framework WHERE id=?", (framework_id,))
    if not orgscope.visible(fw, scope):  # cross-scope frameworks look exactly like unknown ones
        raise ServiceError(404, "UNSUPPORTED_FRAMEWORK", "Framework is not registered in the catalog.")
    return fw, scope


def _gap_items(request: Request, db: CatalogDb, principal: Principal, framework_id: str, tenant_id: str | None):
    _, scope = _visible_framework(request, db, principal, framework_id, tenant_id)
    engine = generated_rules.engine_for(db, request.app.state.catalog, scope, tenant_id)
    collected, cap = None, None
    if scope is not None and tenant_id is not None:
        _require_policy_schema(db)
        cap = pctx.capabilities(db, scope, tenant_id)
        collected = generated_rules.collected_with_generated(policy_controls.collected_rules(cap, engine), engine, cap)
    ids = [r["id"] for r in db.q(
        "SELECT id FROM regulatory_requirement WHERE framework_id=? AND status='APPROVED' AND published_seq IS NOT NULL "
        "AND (organization_scope IS NULL" + (" OR organization_scope=?" if scope else "") + ") ORDER BY id",
        (framework_id, *([scope] if scope else [])))]
    items = automation.requirement_mapping_gaps(db, engine, ids, collected=collected, scope=scope)
    return scope, engine, items, collected, cap


@router.get("/frameworks/{framework_id}/mapping-gaps")
def framework_mapping_gaps(framework_id: str, request: Request, tenant_id: TenantId | None = None,
                           db: CatalogDb = Depends(get_db), principal: Principal = Depends(_auth)) -> dict:
    """Per published requirement (global plus the caller's scope): executable rules, structured gap
    codes and the canonical control reference derived from the source headings. With ``tenant_id``
    and the scope header, COLLECTOR_MISSING follows that organization's collector handshake."""
    scope, engine, items, collected, cap = _gap_items(request, db, principal, framework_id, tenant_id)
    counts: dict[str, int] = {}
    for it in items:
        for g in it["gaps"]:
            counts[g["code"]] = counts.get(g["code"], 0) + 1
    extra = {"organization_scope": scope} if scope else {}
    return _envelope(db, framework_id=framework_id, items=items, gap_codes=list(mapping_policy.GAP_CODES),
                     counts={"requirements": len(items), "gaps_by_code": dict(sorted(counts.items()))},
                     collected_rules=list(collected if collected is not None else mapping_policy.bridge_collected_rules()),
                     collector_capability_source=(cap or pctx.capabilities(db, None, None))["source"],
                     policy_bundle_version=engine.bundle_version, **extra)


@router.get("/frameworks/{framework_id}/control-coverage")
def framework_control_coverage(framework_id: str, request: Request,
                               family: list[str] = Query(default=["AC", "AU", "IA"], max_length=30),
                               db: CatalogDb = Depends(get_db), principal: Principal = Depends(_auth)) -> dict:
    """Canonical control references of the published requirements, clauses with more than one requirement,
    and control headings of the official text without any published requirement (extraction omissions).
    Derived from the stored source text; nothing is modified."""
    _, scope = _visible_framework(request, db, principal, framework_id, None)
    fams = tuple(sorted({f.upper() for f in family if f.isalpha() and len(f) <= 3}))
    report = control_ids.coverage_report(db, framework_id, families=fams, org_scope=scope)
    extra = {"organization_scope": scope} if scope else {}
    return _envelope(db, **report, **extra)


@router.get("/collector-capabilities")
def collector_capabilities(request: Request, tenant_id: TenantId = Query(...), db: CatalogDb = Depends(get_db),
                           principal: Principal = Depends(_auth)) -> dict:
    scope = _policy_owner(request, db, principal, tenant_id)
    return _envelope(db, organization_scope=scope, tenant_id=tenant_id,
                     collector_capabilities=pctx.capabilities_view(pctx.capabilities(db, scope, tenant_id)))


# ------------------------------------------------------------------ rules


@router.get("/rules")
def rules(request: Request, db: CatalogDb = Depends(get_db), _: Principal = Depends(_auth)) -> dict:
    """OPA rule versions. ``in_running_bundle`` is checked against the bundle
    this service actually loaded, not only against the catalog database."""
    running = request.app.state.catalog
    active = db.one("SELECT version, digest, created_at FROM bundle_version WHERE active=1")
    items = []
    for d in db.q("SELECT * FROM opa_rule_definition WHERE rule_id NOT LIKE 'PAM-GEN-%' ORDER BY rule_id"):
        versions = []
        if d["kind"] == "PREDEFINED_REGO":
            for ver, spec in sorted(running.rules.get(d["rule_id"], {}).items()):
                versions.append({"version": ver, "status": spec.status, "in_running_bundle": True,
                                 "effective_from": spec.public()["effective_from"], "effective_to": spec.public()["effective_to"],
                                 "threshold_provenance": [{"origin": "CUSTOMER_POLICY", "note": "Predefined rule parameters are "
                                                           "supplied by the customer via policy_settings.parameters; defaults are Securden defaults, not regulatory thresholds."}]})
        else:
            for rv in db.q(
                "SELECT rv.* FROM rule_version rv JOIN bundle_rule br ON br.rule_version_id=rv.id "
                "JOIN bundle_version b ON b.version=br.bundle_version WHERE b.active=1 AND rv.rule_id=? ORDER BY rv.id",
                (d["rule_id"],)):
                spec = running.rules.get(d["rule_id"], {}).get(rv["version"])
                versions.append({
                    "version": rv["version"], "status": "ACTIVE" if rv["status"] == "APPROVED" else rv["status"],
                    "definition_digest": f"sha256:{rv['digest']}", "in_running_bundle": spec is not None,
                    "effective_from": rv["definition"]["effective_from"], "effective_to": rv["definition"].get("effective_to"),
                    "evidence_type": rv["definition"]["evidence_type"], "severity": rv["definition"]["severity"],
                    "threshold_provenance": rv["threshold_provenance"], "tests": len(rv["tests"]),
                })
        if versions:
            items.append({"rule_id": d["rule_id"], "layer": LAYERS["rule_version"], "kind": d["kind"], "title": d["title"],
                          "pam_control_id": d["pam_control_id"], "versions": versions})
    running_has_published = any(s.source == "PUBLISHED" for vs in running.rules.values() for s in vs.values())
    consistent = running.bundle_version == active["version"] if active else not running_has_published
    return _envelope(db, items=items, active_policy_bundle=active, running_policy_bundle_version=running.bundle_version,
                     bundle_consistent=consistent)


# ------------------------------------------------------------------ remediation


@router.get("/remediations")
def remediations(pam_control_id: str | None = Query(default=None, max_length=64),
                 finding_category: str | None = Query(default=None, max_length=64),
                 db: CatalogDb = Depends(get_db), _: Principal = Depends(_auth)) -> dict:
    sql, args = "SELECT * FROM remediation_template WHERE status='APPROVED' AND published_seq IS NOT NULL", []
    if pam_control_id:
        sql, args = sql + " AND pam_control_id=?", args + [pam_control_id]
    if finding_category:
        sql, args = sql + " AND finding_category=?", args + [finding_category]
    items = []
    for t in db.q(sql + " ORDER BY id", args):
        refs = db.q(
            "SELECT DISTINCT r.framework_id, r.section_ref, r.id AS requirement_id FROM framework_control_mapping m "
            "JOIN regulatory_requirement r ON r.id=m.requirement_id WHERE m.pam_control_id=? AND m.status='APPROVED' "
            "AND m.published_seq IS NOT NULL AND r.status='APPROVED' ORDER BY r.framework_id, r.id", (t["pam_control_id"],))
        items.append({
            "id": t["id"], "finding_category": t["finding_category"], "pam_control_id": t["pam_control_id"],
            "framework_references": refs, "recommended_corrective_actions": t["corrective_actions"],
            "securden_supported_capabilities": t["securden_capabilities"],
            "customer_responsibilities": t["customer_responsibilities"], "source_citations": t["source_citations"],
            "review_status": "APPROVED", "automatic_execution": False, "published_in": t["published_seq"],
        })
    return _envelope(db, items=items, note="Remediation templates are guidance for people. Nothing is executed automatically.")


# ------------------------------------------------------------------ sync


@router.get("/changes")
def changes(request: Request, since: int = Query(default=0, ge=0), limit: int = Limit, db: CatalogDb = Depends(get_db),
            principal: Principal = Depends(_auth)) -> dict:
    """Incremental synchronization. ``since`` is the last ``catalog_version``
    the client fully applied; changes are ordered and grouped by publication.
    A page never splits a publication unless one publication exceeds ``limit``.
    Publications of another organization scope are served without entity rows."""
    scope = _scope(request, db, principal)
    current = db.catalog_version()
    if since > current:
        raise ServiceError(409, "CATALOG_VERSION_AHEAD", "Client catalog version is newer than the server's; perform a full resync.")

    def own(row: dict[str, Any]) -> bool:
        pub_scope = (row.pop("summary", None) or {}).get("organization_scope")
        return pub_scope is None or pub_scope == scope

    rows = [r for r in db.q(
        "SELECT c.seq, c.publication_seq, c.entity_type, c.entity_id, c.change_type, c.at, p.kind, p.summary "
        "FROM catalog_change c JOIN catalog_publication p ON p.seq=c.publication_seq "
        "WHERE c.publication_seq > ? ORDER BY c.publication_seq, c.seq LIMIT ?", (since, limit + 1)) if own(r)]
    more = len(rows) > limit
    if more:
        last_pub = rows[limit]["publication_seq"]
        whole = [r for r in rows[:limit] if r["publication_seq"] < last_pub]
        rows = whole or [r for r in db.q(
            "SELECT c.seq, c.publication_seq, c.entity_type, c.entity_id, c.change_type, c.at, p.kind, p.summary FROM catalog_change c "
            "JOIN catalog_publication p ON p.seq=c.publication_seq WHERE c.publication_seq=? ORDER BY c.seq", (last_pub,)) if own(r)]
    synced_to = rows[-1]["publication_seq"] if more and rows else current
    return _envelope(db, since=since, items=rows, has_more=synced_to < current, synced_to=synced_to)


# ------------------------------------------------------------------ coverage


@router.get("/coverage")
def coverage_dashboard(db: CatalogDb = Depends(get_db), _: Principal = Depends(_auth)) -> dict:
    return _envelope(db, metrics=coverage.metrics(db), source_freshness=coverage.stale_sources(db))


@router.get("/coverage/unverified")
def unverified(after: str = Query(default="", max_length=10), limit: int = Limit, db: CatalogDb = Depends(get_db),
               _: Principal = Depends(_auth)) -> dict:
    """Unsupported or unverified coverage, stated explicitly."""
    rows = [c for c in coverage.jurisdiction_coverage(db, after=after, limit=100_000, kinds=("COUNTRY_OR_TERRITORY",))
            if not c["requirements_published"]]
    page = _page(db, rows[: limit + 1], limit, key="code")
    page.update(
        unverified_frameworks=db.q("SELECT id, title, jurisdiction_code FROM regulatory_framework WHERE verification_status<>'VERIFIED' AND organization_scope IS NULL ORDER BY id"),
        unverified_sources=db.q("SELECT id, name, jurisdiction_code, status, proposal_origin FROM source WHERE status<>'VERIFIED' AND organization_scope IS NULL ORDER BY id"),
        unreviewed_translations=db.scalar("SELECT COUNT(*) FROM regulatory_requirement WHERE translation_status='UNREVIEWED' AND status='APPROVED' AND organization_scope IS NULL"),
        coverage_statement=coverage.STATEMENT)
    return page


# ------------------------------------------------------------------ applicability


@router.post("/applicability")
def applicability(profile: OrganizationProfile, db: CatalogDb = Depends(get_db), _: Principal = Depends(_auth)) -> dict:
    """Stateless screening; the profile is not stored."""
    try:
        return _envelope(db, **evaluate(db, profile))
    except CatalogError as exc:
        raise ServiceError(422, exc.code, exc.message) from exc
