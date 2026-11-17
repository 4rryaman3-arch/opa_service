"""Framework evaluation templates and execution plans.

A *plan* answers one question for the calling service: for this framework, on
this date, which published requirements exist and which pinned rule executions
were reviewed and published as technical evidence for them. It is derived only
from reviewed, published catalog rows and the rule catalog of the running
policy bundle. Nothing here evaluates evidence or decides compliance, and no
model-generated text is used to select or parameterize a rule.

Vocabulary
  assessment   AUTOMATED  a published mapping binds the requirement to a rule
               MANUAL     a published mapping records that a person must assess it
               UNMAPPED   no published execution mapping exists
               BLOCKED    an automated mapping exists but cannot run (see blockers)
  readiness    engine coverage only (NOT_READY | PARTIAL | READY); it says
               nothing about PASS/FAIL
"""

from __future__ import annotations

import hashlib
from datetime import date, datetime
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field

from .db import CatalogDb, CatalogError, canonical, digest_of, now_iso

AGGREGATION = "ALL"
AGGREGATION_NOTE = (
    "A requirement's automated result is derived from ALL of its execution_ids: any FAIL -> FAIL; otherwise any "
    "error, missing collector or INSUFFICIENT_EVIDENCE -> INCOMPLETE; all NOT_APPLICABLE -> NOT_APPLICABLE; "
    "otherwise PASS. MANUAL, UNMAPPED and BLOCKED requirements never become PASS automatically."
)
DIGEST_NOTE = (
    "plan_digest = 'sha256:' + hex(SHA-256(UTF-8(JSON(digest_input)))) where JSON is serialized with keys sorted, "
    "separators ',' and ':' (no whitespace) and non-ASCII characters left unescaped."
)
MAPPING_COLUMNS = (
    ("assessment", "TEXT CHECK (assessment IN ('AUTOMATED','MANUAL'))"),
    ("rule_id", "TEXT"),
    ("rule_version_min", "TEXT"),
    ("rule_version_max", "TEXT"),
    ("evidence_type", "TEXT"),
    ("rule_parameters", "TEXT NOT NULL DEFAULT '{}'"),
    ("override_constraints", "TEXT NOT NULL DEFAULT '{}'"),
    ("coverage", "TEXT CHECK (coverage IN ('FULL','PARTIAL'))"),
    ("control_reference", "TEXT"),
    ("mapping_key", "TEXT"),
    ("version", "INTEGER NOT NULL DEFAULT 1"),
)
MAPPING_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS trg_mapping_execution_immutable
BEFORE UPDATE OF assessment, rule_id, rule_version_min, rule_version_max, evidence_type, rule_parameters,
    override_constraints, coverage, control_reference, mapping_key, version
ON framework_control_mapping WHEN OLD.status <> 'DRAFT'
BEGIN SELECT RAISE(ABORT, 'reviewed mappings are immutable'); END;
"""


def schema_ready(db: CatalogDb) -> bool:
    return any(c["name"] == "assessment" for c in db.q("PRAGMA table_info(framework_control_mapping)"))


def version_key(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in version.split("."))
    except (ValueError, AttributeError) as exc:
        raise CatalogError("INVALID_RULE_VERSION", f"'{version}' is not a dotted numeric rule version") from exc


def in_range(version: str, low: str, high: str | None) -> bool:
    return version_key(low) <= version_key(version) and (high is None or version_key(version) <= version_key(high))


# ------------------------------------------------------------------ parameter checks


def parameter_problems(spec: Any, parameters: dict[str, Any], overrides: dict[str, Any]) -> list[tuple[str, str]]:
    """Compare a mapping's approved parameters / override constraints with one rule version.

    Every parameter of the rule must be stated: a mapping never relies on a default.
    A parameter without an override constraint is fixed at its approved value."""
    problems: list[tuple[str, str]] = []
    known = spec.parameters
    for name in sorted(set(known) - set(parameters)):
        problems.append(("MISSING_PARAMETER", f"parameter '{name}' of {spec.rule_id} {spec.version} has no approved value"))
    for name, value in sorted(parameters.items()):
        p = known.get(name)
        if p is None:
            problems.append(("INVALID_PARAMETER", f"'{name}' is not a parameter of {spec.rule_id} {spec.version}"))
        elif p.type == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                problems.append(("INVALID_PARAMETER", f"parameter '{name}' must be an integer"))
            elif (p.minimum is not None and value < p.minimum) or (p.maximum is not None and value > p.maximum):
                problems.append(("INVALID_PARAMETER", f"parameter '{name}' must be between {p.minimum} and {p.maximum}"))
        elif p.type == "boolean":
            if not isinstance(value, bool):
                problems.append(("INVALID_PARAMETER", f"parameter '{name}' must be a boolean"))
        elif p.type == "enum_list":
            if (not isinstance(value, list) or not value or len(set(map(str, value))) != len(value)
                    or any(v not in p.items for v in value)):
                problems.append(("INVALID_PARAMETER",
                                 f"parameter '{name}' must be a non-empty list of distinct values from {list(p.items)}"))
        else:
            problems.append(("INVALID_PARAMETER", f"parameter '{name}' has an unsupported type"))
    for name, rule in sorted(overrides.items()):
        p, value = known.get(name), parameters.get(name)
        bad = ("INVALID_OVERRIDE_CONSTRAINT", f"override constraint for '{name}' is not valid for {spec.rule_id} {spec.version}")
        if p is None or not isinstance(rule, dict):
            problems.append(bad)
        elif p.type == "integer":
            low, high = rule.get("min"), rule.get("max")
            ok = (set(rule) == {"min", "max"} and all(isinstance(x, int) and not isinstance(x, bool) for x in (low, high))
                  and low <= high and (p.minimum is None or low >= p.minimum) and (p.maximum is None or high <= p.maximum)
                  and isinstance(value, int) and not isinstance(value, bool) and low <= value <= high)
            if not ok:
                problems.append(bad)
        elif p.type == "boolean":
            values = rule.get("values")
            if set(rule) != {"values"} or not isinstance(values, list) or not values \
                    or any(not isinstance(x, bool) for x in values) or value not in values:
                problems.append(bad)
        else:
            problems.append(bad)
    return problems


def check_rule_binding(engine_rules: dict[str, dict[str, Any]], rule_id: str, low: str, high: str | None,
                       parameters: dict[str, Any], overrides: dict[str, Any], evidence_type: str | None) -> str:
    """Validate a draft mapping against the rule catalog of the loaded bundle. Returns the evidence type."""
    versions = engine_rules.get(rule_id)
    if versions is None:
        raise CatalogError("UNKNOWN_RULE", f"rule '{rule_id}' is not in the loaded policy bundle")
    if high is not None and version_key(high) < version_key(low):
        raise CatalogError("INVALID_RULE_VERSION", "rule_version_max is lower than rule_version_min")
    specs = [s for v, s in versions.items() if in_range(v, low, high)]
    if not specs:
        raise CatalogError("RULE_VERSION_UNAVAILABLE",
                           f"no version of {rule_id} in the loaded bundle is within {low}..{high or 'any later'}")
    types = {s.evidence_type for s in specs}
    if len(types) != 1 or (evidence_type is not None and evidence_type not in types):
        raise CatalogError("EVIDENCE_TYPE_MISMATCH",
                           f"{rule_id} versions in range use evidence type(s) {sorted(types)}")
    for spec in specs:
        problems = parameter_problems(spec, parameters, overrides)
        if problems:
            raise CatalogError(problems[0][0], "; ".join(m for _, m in problems),
                               details={"problems": [{"code": c, "message": m} for c, m in problems]})
    return types.pop()


# ------------------------------------------------------------------ plan


def review_status(db: CatalogDb, fw: dict[str, Any]) -> str:
    if fw["verification_status"] == "VERIFIED":
        return "APPROVED"
    last = db.one("SELECT decision FROM review_approval WHERE entity_type='framework' AND entity_id=? ORDER BY id DESC LIMIT 1",
                  (fw["id"],))
    return "REJECTED" if last and last["decision"] == "REJECTED" else "PENDING"


def _effective(spec: Any, when: str) -> bool:
    start = spec.effective_from.date().isoformat()
    end = spec.effective_to.date().isoformat() if spec.effective_to else None
    return start <= when and (end is None or when < end)


def _blocker(blockers: dict[str, dict[str, Any]], code: str, message: str, **affected: Any) -> None:
    entry = blockers.setdefault(code, {"code": code, "message": message,
                                       "affected": {"requirement_ids": [], "mapping_ids": [], "rule_ids": []}})
    for key, value in affected.items():
        if value is not None and value not in entry["affected"][key]:
            entry["affected"][key].append(value)


def build_plan(db: CatalogDb, fw: dict[str, Any], when: str, engine: Any, *, tenant_id: str | None = None,
               rule_active: Callable[[str], bool] | None = None,
               public_requirement: Callable[[CatalogDb, dict[str, Any]], dict[str, Any]] | None = None,
               org_scope: str | None = None) -> dict[str, Any]:
    """Resolve the plan. ``engine`` is the rule catalog of the running bundle
    (``.rules`` and ``.bundle_version``). Deterministic for a given catalog,
    bundle, date, tenant and organization scope. ``org_scope=None`` sees only
    the global catalog; a scope sees the global catalog plus its own rows."""
    blockers: dict[str, dict[str, Any]] = {}
    status = review_status(db, fw)
    if status != "APPROVED":
        _blocker(blockers, "FRAMEWORK_NOT_APPROVED", f"Framework review status is {status}; approve the framework first.")
    if org_scope is None:
        scope_pred, scope_args = "r.organization_scope IS NULL", []
    else:
        scope_pred, scope_args = "(r.organization_scope IS NULL OR r.organization_scope=?)", [org_scope]
    requirements = db.q(
        "SELECT r.* FROM regulatory_requirement r WHERE r.framework_id=? AND r.status='APPROVED' AND r.published_seq IS NOT NULL "
        f"AND {scope_pred} "
        "AND (r.effective_from IS NULL OR r.effective_from<=?) AND (r.effective_to IS NULL OR r.effective_to>?) ORDER BY r.id",
        (fw["id"], *scope_args, when, when))
    if not requirements:
        _blocker(blockers, "NO_PUBLISHED_REQUIREMENTS",
                 "No reviewed requirement of this framework is published and in effect on the as-of date.")
    executions: dict[str, dict[str, Any]] = {}
    out_requirements: list[dict[str, Any]] = []
    documents: dict[str, dict[str, Any]] = {}
    totals = {"published_requirements": len(requirements), "automated_requirements": 0, "manual_requirements": 0,
              "unmapped_requirements": 0, "blocked_requirements": 0, "mapping_count": 0, "execution_count": 0}
    for req in requirements:
        public = public_requirement(db, req) if public_requirement else {"source_reference": {"section": req["section_ref"]}}
        ref = public["source_reference"]
        if ref.get("content_sha256"):
            documents.setdefault(ref["content_sha256"], {
                "document": ref.get("document"), "document_title": ref.get("document_title"),
                "document_version": ref.get("document_version"), "content_sha256": ref["content_sha256"],
                "url": ref.get("url"), "published_on": ref.get("published_on"), "language": req["original_language"]})
        mappings_out: list[dict[str, Any]] = []
        execution_ids: list[str] = []
        blocked = manual = False
        full = False
        for m in db.q("SELECT * FROM framework_control_mapping WHERE requirement_id=? AND status='APPROVED' "
                      "AND published_seq IS NOT NULL AND "
                      + ("organization_scope IS NULL" if org_scope is None
                         else "(organization_scope IS NULL OR organization_scope=?)")
                      + " ORDER BY id", (req["id"], *([] if org_scope is None else [org_scope]))):
            approval = db.one("SELECT reviewer, decided_at FROM review_approval WHERE entity_type='mapping' AND entity_id=? "
                              "AND decision='APPROVED' ORDER BY id DESC LIMIT 1", (str(m["id"]),))
            entry = {
                "mapping_id": m["id"], "mapping_key": m["mapping_key"], "mapping_version": m["version"],
                "assessment": m["assessment"] or "CONTROL_REFERENCE", "pam_control_id": m["pam_control_id"],
                "control_reference": m["control_reference"] or req["section_ref"], "coverage": m["coverage"],
                "strength": m["strength"], "rationale": m["rationale"], "limitations": m["limitations"],
                "rule_id": m["rule_id"], "rule_version_min": m["rule_version_min"], "rule_version_max": m["rule_version_max"],
                "execution_id": None, "blocker_codes": [], "review_status": "APPROVED",
                "reviewer": approval["reviewer"] if approval else None,
                "approved_at": approval["decided_at"] if approval else None, "published_in": m["published_seq"],
                "created_by": m["created_by"],
            }
            if m["assessment"] in ("AUTOMATED", "MANUAL"):
                totals["mapping_count"] += 1
            if m["assessment"] == "MANUAL":
                manual = True
            elif m["assessment"] == "AUTOMATED":
                def block(code: str, message: str) -> None:
                    entry["blocker_codes"].append(code)
                    _blocker(blockers, code, message, requirement_ids=req["id"], mapping_ids=m["id"], rule_ids=m["rule_id"])

                versions = engine.rules.get(m["rule_id"])
                usable = [s for v, s in (versions or {}).items()
                          if s.status == "ACTIVE" and in_range(v, m["rule_version_min"], m["rule_version_max"])
                          and _effective(s, when)]
                if versions is None:
                    block("RULE_NOT_IN_BUNDLE", "A mapped rule is not part of the running policy bundle.")
                elif not usable:
                    block("RULE_VERSION_UNAVAILABLE",
                          "No active rule version within the mapping's approved range is effective on the as-of date.")
                else:
                    spec = max(usable, key=lambda s: version_key(s.version))
                    problems = parameter_problems(spec, m["rule_parameters"], m["override_constraints"])
                    if spec.evidence_type != m["evidence_type"]:
                        block("EVIDENCE_TYPE_MISMATCH", "A mapped rule now uses a different evidence type than was reviewed.")
                    elif problems:
                        block("PARAMETERS_INCOMPATIBLE",
                              "Reviewed parameters or override constraints do not fit the selected rule version.")
                    elif tenant_id and spec.source == "PREDEFINED" and rule_active and not rule_active(m["rule_id"]):
                        block("RULE_INACTIVE_FOR_TENANT", "A mapped rule is deactivated for this tenant.")
                    else:
                        identity = {"rule_id": spec.rule_id, "rule_version": spec.version,
                                    "parameters": m["rule_parameters"], "override_constraints": m["override_constraints"]}
                        eid = "exec-" + digest_of(identity)[:16]
                        executions.setdefault(eid, {
                            "execution_id": eid, **identity, "rule_title": spec.title, "rule_source": spec.source,
                            "severity": spec.severity, "evidence_type": spec.evidence_type,
                            "evidence_requirements": list(spec.evidence_requirements),
                            "parameter_schema": spec.public()["parameters"],
                            "rule_effective_from": spec.public()["effective_from"],
                            "rule_effective_to": spec.public()["effective_to"],
                            "evaluate_request": {"rule_id": spec.rule_id, "rule_version": spec.version,
                                                 "policy_settings": {"parameters": m["rule_parameters"]}},
                            "requirement_ids": [], "mapping_ids": [],
                        })
                        executions[eid]["requirement_ids"].append(req["id"])
                        executions[eid]["mapping_ids"].append(m["id"])
                        entry["execution_id"] = eid
                        if eid not in execution_ids:
                            execution_ids.append(eid)
                        full = full or m["coverage"] == "FULL"
                if entry["blocker_codes"]:
                    blocked = True
            mappings_out.append(entry)
        if blocked:
            assessment = "BLOCKED"
        elif execution_ids:
            assessment = "AUTOMATED"
        elif manual:
            assessment = "MANUAL"
        else:
            assessment = "UNMAPPED"
        totals[f"{assessment.lower()}_requirements"] += 1
        out_requirements.append({
            "requirement_id": req["id"],
            "requirement_digest": "sha256:" + digest_of({k: req[k] for k in (
                "id", "framework_id", "document_version_id", "section_ref", "original_language", "original_text", "thresholds")}),
            "control_reference": req["section_ref"], "obligation_type": req["obligation_type"],
            "pam_domains": req["pam_domains"], "original_language": req["original_language"],
            "original_text": public.get("original_text"), "text_withheld_reason": public.get("text_withheld_reason"),
            "source_reference": ref, "effective_from": req["effective_from"], "effective_to": req["effective_to"],
            "published_in": req["published_seq"], "assessment": assessment,
            "technical_coverage": ("FULL" if full and not manual else "PARTIAL") if assessment == "AUTOMATED" else "NONE",
            "requires_manual_assessment": manual or assessment in ("MANUAL", "UNMAPPED", "BLOCKED"),
            "aggregation": AGGREGATION, "execution_ids": execution_ids if assessment == "AUTOMATED" else [],
            "mappings": mappings_out,
        })
    # An execution is only offered when every requirement that references it can use it.
    usable_ids = {e for r in out_requirements for e in r["execution_ids"]}
    plan_executions = [executions[e] for e in sorted(usable_ids)]
    for e in plan_executions:
        users = [r for r in out_requirements if e["execution_id"] in r["execution_ids"]]
        e["requirement_ids"] = [r["requirement_id"] for r in users]
        e["mapping_ids"] = [m["mapping_id"] for r in users for m in r["mappings"] if m["execution_id"] == e["execution_id"]]
    totals["execution_count"] = len(plan_executions)
    if requirements and not plan_executions:
        _blocker(blockers, "NO_EXECUTABLE_MAPPINGS",
                 "No published automated mapping of this framework can be executed; review and publish a mapping first.")
    if status != "APPROVED" or not plan_executions:
        readiness = "NOT_READY"
    elif totals["automated_requirements"] == totals["published_requirements"]:
        readiness = "READY"
    else:
        readiness = "PARTIAL"
    digest_input = {
        "framework": {k: fw[k] for k in ("id", "jurisdiction_code", "verification_status", "lifecycle", "effective_from", "effective_to")},
        "tenant_id": tenant_id, "policy_bundle_version": engine.bundle_version, "aggregation": AGGREGATION,
        # Only present for scoped plans, so digests of existing unscoped plans are unchanged.
        **({"organization_scope": org_scope} if org_scope is not None else {}),
        "requirements": [{
            "requirement_id": r["requirement_id"], "requirement_digest": r["requirement_digest"], "assessment": r["assessment"],
            "technical_coverage": r["technical_coverage"], "execution_ids": r["execution_ids"],
            "mappings": [{k: m[k] for k in ("mapping_id", "mapping_key", "mapping_version", "assessment", "coverage",
                                            "control_reference", "rule_id", "rule_version_min", "rule_version_max",
                                            "execution_id")} for m in r["mappings"]],
        } for r in out_requirements],
        "executions": [{k: e[k] for k in ("execution_id", "rule_id", "rule_version", "evidence_type", "parameters",
                                          "override_constraints", "parameter_schema")} for e in plan_executions],
    }
    return {
        "framework": {
            "framework_id": fw["id"], "title": fw["title"], "kind": fw["kind"], "adoption": fw["adoption"],
            "jurisdiction_code": fw["jurisdiction_code"], "review_status": status,
            "verification_status": fw["verification_status"], "lifecycle": fw["lifecycle"],
            "published_on": fw["published_on"], "effective_from": fw["effective_from"], "effective_to": fw["effective_to"],
            "documents": sorted(documents.values(), key=lambda d: d["content_sha256"]),
        },
        "tenant_id": tenant_id, "as_of": when, "policy_bundle_version": engine.bundle_version,
        "readiness": readiness, "totals": totals, "blockers": sorted(blockers.values(), key=lambda b: b["code"]),
        "aggregation": {"mode": AGGREGATION, "description": AGGREGATION_NOTE},
        "requirements": out_requirements, "executions": plan_executions,
        "digest_input": digest_input,
        "plan_digest": "sha256:" + hashlib.sha256(canonical(digest_input).encode("utf-8")).hexdigest(),
        "digest_algorithm": DIGEST_NOTE, "generated_at": now_iso(),
    }


def template_summary(plan: dict[str, Any]) -> dict[str, Any]:
    fw, totals = plan["framework"], plan["totals"]
    return {
        "framework_id": fw["framework_id"], "title": fw["title"], "review_status": fw["review_status"],
        "lifecycle": fw["lifecycle"], "jurisdiction_code": fw["jurisdiction_code"],
        "published_requirements": totals["published_requirements"],
        "automated_requirements": totals["automated_requirements"], "manual_requirements": totals["manual_requirements"],
        "unmapped_requirements": totals["unmapped_requirements"], "blocked_requirements": totals["blocked_requirements"],
        "mapping_count": totals["mapping_count"], "execution_count": totals["execution_count"],
        "readiness": plan["readiness"], "blockers": plan["blockers"],
    }


def parse_date(value: date | datetime | None) -> str:
    return (value or date.today()).isoformat()


# ------------------------------------------------------------------ response schemas


class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Affected(_Out):
    requirement_ids: list[int]
    mapping_ids: list[int]
    rule_ids: list[str]


class Blocker(_Out):
    code: str
    message: str
    affected: Affected


class TemplateItem(_Out):
    framework_id: str
    title: str
    review_status: Literal["PENDING", "APPROVED", "REJECTED"]
    lifecycle: str
    jurisdiction_code: str
    jurisdiction_match: Literal["EXACT", "INHERITED"] | None = Field(
        description="EXACT: registered for the requested jurisdiction. INHERITED: registered for a parent or a group it "
                    "belongs to. null when no jurisdiction filter was given. Neither value is an applicability decision.")
    jurisdiction_path: str | None
    published_requirements: int
    automated_requirements: int
    manual_requirements: int
    unmapped_requirements: int
    blocked_requirements: int
    mapping_count: int
    execution_count: int
    readiness: Literal["NOT_READY", "PARTIAL", "READY"]
    blockers: list[Blocker]
    # Django rewrite contract 1.0 (additive)
    assessable_requirements: int | None = None
    source_origin: Literal["UPLOADED_DOCUMENT", "OFFICIAL_DISCOVERY", "MIXED"] | None = None
    updated_at: str | None = None


class TemplatePage(_Out):
    schema_version: str
    catalog_version: int
    policy_bundle_version: str
    as_of: str
    jurisdiction: str | None
    include_inherited: bool
    items: list[TemplateItem]
    has_more: bool
    next_cursor: str | None
    note: str
    organization_scope: str | None = None  # echoed for scoped requests (rewrite contract 1.0)


class PlanDocument(_Out):
    document: str | None
    document_title: str | None
    document_version: str | None
    content_sha256: str
    url: str | None
    published_on: str | None
    language: str


class PlanFramework(_Out):
    framework_id: str
    title: str
    kind: str
    adoption: str
    jurisdiction_code: str
    review_status: Literal["PENDING", "APPROVED", "REJECTED"]
    verification_status: str
    lifecycle: str
    published_on: str | None
    effective_from: str | None
    effective_to: str | None
    documents: list[PlanDocument]


class PlanTotals(_Out):
    published_requirements: int
    automated_requirements: int
    manual_requirements: int
    unmapped_requirements: int
    blocked_requirements: int
    mapping_count: int
    execution_count: int


class PlanMapping(_Out):
    mapping_id: int
    mapping_key: str | None
    mapping_version: int
    assessment: Literal["AUTOMATED", "MANUAL", "CONTROL_REFERENCE"]
    pam_control_id: str
    control_reference: str
    coverage: Literal["FULL", "PARTIAL"] | None
    strength: str
    rationale: str
    limitations: str
    rule_id: str | None
    rule_version_min: str | None
    rule_version_max: str | None
    execution_id: str | None
    blocker_codes: list[str]
    review_status: Literal["APPROVED"]
    reviewer: str | None
    approved_at: str | None
    published_in: int
    created_by: str


class PlanRequirement(_Out):
    requirement_id: int
    requirement_digest: str
    control_reference: str
    obligation_type: str
    pam_domains: list[str]
    original_language: str
    original_text: str | None
    text_withheld_reason: str | None
    source_reference: dict[str, Any]
    effective_from: str | None
    effective_to: str | None
    published_in: int
    assessment: Literal["AUTOMATED", "MANUAL", "UNMAPPED", "BLOCKED"]
    technical_coverage: Literal["FULL", "PARTIAL", "NONE"]
    requires_manual_assessment: bool
    aggregation: Literal["ALL"]
    execution_ids: list[str]
    mappings: list[PlanMapping]
    # Only present when policy versions were selected (organization policy contexts).
    policy_resolution: dict[str, Any] | None = None


class PlanExecution(_Out):
    execution_id: str
    rule_id: str
    rule_version: str
    parameters: dict[str, Any] = Field(description="Reviewed values to send as policy_settings.parameters.")
    override_constraints: dict[str, Any] = Field(
        description="Per parameter: {min,max} for integers or {values:[...]} for booleans. A parameter that is absent "
                    "here must be sent exactly as approved.")
    rule_title: str
    rule_source: str
    severity: str
    evidence_type: str
    evidence_requirements: list[str]
    parameter_schema: dict[str, Any]
    rule_effective_from: str
    rule_effective_to: str | None
    evaluate_request: dict[str, Any] = Field(
        description="Fields to copy into POST /api/v1/evaluate (add tenant_id, item_reference, reporting_period, evidence).")
    requirement_ids: list[int]
    mapping_ids: list[int]


class PlanAggregation(_Out):
    mode: Literal["ALL"]
    description: str


class PlanResponse(_Out):
    schema_version: str
    catalog_version: int
    framework: PlanFramework
    tenant_id: str
    as_of: str
    policy_bundle_version: str
    readiness: Literal["NOT_READY", "PARTIAL", "READY"]
    totals: PlanTotals
    blockers: list[Blocker]
    aggregation: PlanAggregation
    requirements: list[PlanRequirement]
    executions: list[PlanExecution]
    digest_input: dict[str, Any]
    plan_digest: str
    digest_algorithm: str
    generated_at: str
    mapping_disclaimer: str
    organization_scope: str | None = None  # echoed for scoped requests (rewrite contract 1.0)
    # Only present when policy versions were selected (POLICY_CONTEXT_DJANGO_CONTRACT.md).
    policy_context: dict[str, Any] | None = None
