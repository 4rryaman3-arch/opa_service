"""Organization policy contexts: user-declared, versioned, scoped policy (CUSTOMER_POLICY).

A policy context belongs to exactly one organization scope and tenant. Each save
creates an immutable version that is active immediately (the organization
declares its own policy; there is no separate approval workflow). Versions are
never edited or deleted.

Supersession (deterministic): at any instant ``t`` the version of a context in
force is the highest version number whose ``[effective_from, effective_to)``
contains ``t``. A newer version therefore supersedes older ones only for the time
it covers; older versions stay in force (and assessable) outside it.

Values are validated against the pinned control-definition schema. Nothing is
defaulted, inferred or converted; target references are opaque PAM identifiers
that OPM never treats as proof of membership or authorization.
"""
from __future__ import annotations

import uuid
from datetime import date
from typing import Annotated, Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, StringConstraints, model_validator

from app.models.common import Identifier, TenantId, UtcDatetime, format_utc

from . import policy_controls as pc
from .db import CatalogDb, CatalogError, digest_of, now_iso

ORIGIN = "CUSTOMER_POLICY"
FOREVER = "9999-12-31T23:59:59.999999Z"
RequestKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")]
TargetType = Literal["ORGANIZATION", "ACCOUNT", "ACCOUNT_GROUP", "USER", "USER_GROUP", "RESOURCE", "RESOURCE_GROUP",
                     "SESSION_POLICY", "AUDIT_SOURCE"]


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TargetRef(_In):
    type: TargetType
    id: Identifier | None = None

    @model_validator(mode="after")
    def _check(self):
        if (self.type == "ORGANIZATION") != (self.id is None):
            raise ValueError("ORGANIZATION takes no id; every other target type needs an opaque PAM id")
        return self


class PolicyReference(_In):
    title: Annotated[str, StringConstraints(min_length=1, max_length=300)]
    identifier: Annotated[str, StringConstraints(min_length=1, max_length=128)] | None = None
    section: Annotated[str, StringConstraints(min_length=1, max_length=200)] | None = None
    url: Annotated[str, StringConstraints(pattern=r"^https://[^\s]{1,2000}$")] | None = None
    owner: Annotated[str, StringConstraints(min_length=1, max_length=200)] | None = None
    approved_on: date | None = None


class ControlIn(_In):
    control_id: Annotated[str, StringConstraints(pattern=r"^PC-[A-Z0-9-]{2,60}$")]
    control_version: Annotated[str, StringConstraints(pattern=r"^\d{1,3}\.\d{1,3}$")]
    parameters: dict[str, Any] = Field(max_length=50)
    targets: list[TargetRef] = Field(min_length=1, max_length=200)
    label: Annotated[str, StringConstraints(min_length=1, max_length=120)] | None = None


class PolicyVersionIn(_In):
    tenant_id: TenantId
    request_key: RequestKey
    title: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    description: Annotated[str, StringConstraints(max_length=4000)] | None = None
    policy_reference: PolicyReference
    effective_from: UtcDatetime
    effective_to: UtcDatetime | None = None
    controls: list[ControlIn] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def _check(self):
        if self.effective_to is not None and self.effective_to <= self.effective_from:
            raise ValueError("effective_to must be after effective_from")
        return self


class PolicyVersionNext(PolicyVersionIn):
    supersedes_version: int = Field(ge=1, description="The current latest version; a stale value returns 409.")


class EvidenceSupport(_In):
    evidence_type: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{1,63}$")]
    schema_version: Annotated[str, StringConstraints(pattern=r"^\d{1,3}\.\d{1,3}$")]
    # Optional detail (needed before OPM activates a GENERATED rule on this evidence type): the assessment
    # modes the collector can deliver and the record fields it actually populates.
    assessment_modes: list[Literal["EVENT_HISTORY", "CONFIGURATION_SNAPSHOT"]] | None = Field(
        default=None, min_length=1, max_length=2)
    supported_fields: list[Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]] | None = Field(
        default=None, min_length=1, max_length=64)
    # Fields that exist in the PAM database/model for this evidence type but are not yet sent by the collector.
    # When Django ships a field, move it from lookup_fields to supported_fields.
    lookup_fields: list[Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]] | None = Field(
        default=None, max_length=64)
    # COLLECTED: sent with evaluations today. LOOKUP_AVAILABLE: the PAM holds this data (a lookup over its
    # database) but the collector does not send it yet. Rule generation may design and test rules on it; they stay
    # validated (not activated) until the type is declared COLLECTED. Nothing else treats it as collected.
    collection_status: Literal["COLLECTED", "LOOKUP_AVAILABLE"] = "COLLECTED"
    source_models: list[Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.]{1,100}$")]] | None = Field(
        default=None, max_length=20)  # informational (PAM tables the lookup reads)
    caveats: list[Annotated[str, StringConstraints(min_length=1, max_length=500)]] | None = Field(
        default=None, max_length=10)
    # optional: what each field shows in this PAM, overriding OPM's defaults (regintel/data/field_meanings.json)
    # for the rule-generation model; {"field": {"meaning": "...", "shows": "..."}}
    field_meanings: dict[Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")],
                         dict[Literal["meaning", "shows"], Annotated[str, StringConstraints(min_length=1, max_length=300)]]
                         ] | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def _lookup_needs_detail(self):
        if self.collection_status == "LOOKUP_AVAILABLE" and (not self.supported_fields or not self.assessment_modes):
            raise ValueError("LOOKUP_AVAILABLE evidence needs assessment_modes and supported_fields")
        return self


class CollectorInfo(_In):
    name: Identifier
    version: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")]


class CollectorCapabilitiesIn(_In):
    # also accepts the PAM capability inventory file as-is (schema_version, evidence_capabilities, settings_sources)
    schema_version: Literal["1.0"] | None = None
    tenant_id: TenantId
    collector: CollectorInfo
    evidence: list[EvidenceSupport] = Field(max_length=100,
                                            validation_alias=AliasChoices("evidence", "evidence_capabilities"))
    # informational: where each threshold lives in the PAM; values arrive in PUT /pam-configuration
    settings_sources: dict[Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")],
                           Annotated[str, StringConstraints(max_length=200)]] | None = Field(default=None, max_length=50)


PolicyVersionId = Annotated[str, StringConstraints(pattern=r"^pcv-[0-9a-f]{32}$")]


class MemberRef(_In):
    type: Literal["ACCOUNT", "USER", "RESOURCE", "SESSION_POLICY", "AUDIT_SOURCE"]
    id: Identifier


class TargetResolution(_In):
    """Django-resolved membership of one group target, frozen for an interval. OPM only uses it to
    decide whether two policy bindings overlap; it is never proof of authorization."""
    target: TargetRef
    members: list[MemberRef] = Field(max_length=10_000)
    complete: bool
    valid_from: UtcDatetime
    valid_to: UtcDatetime | None = None

    @model_validator(mode="after")
    def _check(self):
        if pc.TARGET_TYPES[self.target.type]["kind"] != "GROUP":
            raise ValueError("target_resolutions describe group targets only")
        if self.valid_to is not None and self.valid_to <= self.valid_from:
            raise ValueError("valid_to must be after valid_from")
        member_type = pc.TARGET_TYPES[self.target.type]["member_type"]
        if any(m.type != member_type for m in self.members):
            raise ValueError(f"members of {self.target.type} must be of type {member_type}")
        return self

    def as_dict(self) -> dict[str, Any]:
        return {"target": self.target.model_dump(), "members": [m.model_dump() for m in self.members],
                "complete": self.complete, "valid_from": format_utc(self.valid_from),
                "valid_to": format_utc(self.valid_to) if self.valid_to else None}


class Period(_In):
    start: UtcDatetime
    end: UtcDatetime

    @model_validator(mode="after")
    def _check(self):
        if self.end <= self.start:
            raise ValueError("reporting_period.end must be after reporting_period.start")
        return self


class PlanRequest(_In):
    tenant_id: TenantId
    as_of: date | None = None
    catalog_version: int | None = Field(default=None, ge=0)
    expected_digest: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")] | None = None
    policy_version_ids: list[PolicyVersionId] = Field(default_factory=list, max_length=50)
    reporting_period: Period | None = None
    target_resolutions: list[TargetResolution] = Field(default_factory=list, max_length=500)


# ---------------------------------------------------------------- validation


def _target_key(t: dict[str, Any]) -> tuple[str, str]:
    return (t["type"], t.get("id") or "")


def validate_controls(controls: list[ControlIn]) -> list[dict[str, Any]]:
    """Pinned, validated control entries; raises INVALID_POLICY_CONTEXT with every problem."""
    problems: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    seen: dict[tuple[str, tuple[str, str]], int] = {}
    for i, c in enumerate(controls):
        path = f"controls[{i}]"
        defn = pc.get(c.control_id, c.control_version)
        if defn is None:
            known = sorted(v for (cid, v) in pc.CONTROLS if cid == c.control_id)
            problems.append({"code": "UNKNOWN_CONTROL", "path": path,
                             "message": f"{c.control_id} {c.control_version} is not in control catalog "
                                        f"{pc.CONTROL_CATALOG_VERSION}" + (f"; known versions {known}" if known else "")})
            continue
        for p in pc.value_problems(defn["parameter_schema"], c.parameters, f"{path}.parameters"):
            problems.append(p)
        targets = sorted((t.model_dump() for t in c.targets), key=_target_key)
        for t in targets:
            if t["type"] not in defn["target_types"]:
                problems.append({"code": "UNSUPPORTED_TARGET_TYPE", "path": f"{path}.targets",
                                 "message": f"{c.control_id} supports {defn['target_types']}, not {t['type']}"})
            key = (c.control_id, _target_key(t))
            if key in seen:
                problems.append({"code": "DUPLICATE_CONTROL_TARGET", "path": f"{path}.targets",
                                 "message": f"{t['type']} {t.get('id') or ''} is already targeted by "
                                            f"controls[{seen[key]}] for {c.control_id} in this version"})
            seen.setdefault(key, i)
        entries.append({"entry_id": f"ctl-{i + 1}", "control_id": c.control_id, "control_version": c.control_version,
                        "control_definition_digest": defn["definition_digest"], "parameters": c.parameters,
                        "targets": targets, "label": c.label})
    if problems:
        raise CatalogError("INVALID_POLICY_CONTEXT", f"{len(problems)} problem(s) in the policy context",
                           details={"problems": problems})
    return entries


# ---------------------------------------------------------------- storage


def _request_digest(kind: str, context_id: str | None, body: BaseModel) -> str:
    return "sha256:" + digest_of({"kind": kind, "context_id": context_id, "body": body.model_dump(mode="json")})


def _replay(db: CatalogDb, scope: str, tenant: str, key: str, request_digest: str) -> dict[str, Any] | None:
    row = db.one("SELECT * FROM policy_context_version WHERE organization_scope=? AND tenant_id=? AND request_key=?",
                 (scope, tenant, key))
    if row is None:
        return None
    if row["request_digest"] != request_digest:
        raise CatalogError("IDEMPOTENCY_CONFLICT", "This request_key was used for a different policy version.",
                           details={"policy_version_id": row["id"]})
    return row


def _insert_version(db: CatalogDb, *, context_id: str, version: int, scope: str, tenant: str, actor: str,
                    body: PolicyVersionIn, entries: list[dict[str, Any]], request_digest: str) -> str:
    vid = "pcv-" + uuid.uuid4().hex
    fields = {
        "context_id": context_id, "version": version, "organization_scope": scope, "tenant_id": tenant,
        "title": body.title, "description": body.description,
        "policy_reference": body.policy_reference.model_dump(mode="json"),
        "effective_from": format_utc(body.effective_from),
        "effective_to": format_utc(body.effective_to) if body.effective_to else None,
        "policy_controls": entries, "control_catalog_version": pc.CONTROL_CATALOG_VERSION,
    }
    db.insert("policy_context_version", id=vid, **fields, digest="sha256:" + digest_of(fields),
              request_key=body.request_key, request_digest=request_digest, created_by=actor, created_at=now_iso())
    db.audit(actor, "POLICY_VERSION_SAVED", "policy_context_version", vid, context_id=context_id, version=version,
             organization_scope=scope, tenant_id=tenant)
    return vid


def create_context(db: CatalogDb, *, scope: str, actor: str, body: PolicyVersionIn) -> tuple[dict[str, Any], bool]:
    """Create a context with version 1. Returns (version row, created)."""
    rdigest = _request_digest("create", None, body)
    with db.tx():
        existing = _replay(db, scope, body.tenant_id, body.request_key, rdigest)
        if existing:
            return existing, False
        entries = validate_controls(body.controls)
        cid = "pctx-" + uuid.uuid4().hex
        db.insert("policy_context", id=cid, organization_scope=scope, tenant_id=body.tenant_id, created_by=actor,
                  created_at=now_iso())
        vid = _insert_version(db, context_id=cid, version=1, scope=scope, tenant=body.tenant_id, actor=actor, body=body,
                              entries=entries, request_digest=rdigest)
    return db.one("SELECT * FROM policy_context_version WHERE id=?", (vid,)), True  # type: ignore[return-value]


def owned_context(db: CatalogDb, context_id: str, scope: str, tenant: str) -> dict[str, Any]:
    row = db.one("SELECT * FROM policy_context WHERE id=?", (context_id,))
    if row is None or row["organization_scope"] != scope or row["tenant_id"] != tenant:
        # another scope's or tenant's context looks exactly like an unknown one
        raise CatalogError("UNKNOWN_POLICY_CONTEXT", "Policy context not found in this organization scope.")
    return row


def add_version(db: CatalogDb, context_id: str, *, scope: str, actor: str, body: PolicyVersionNext
                ) -> tuple[dict[str, Any], bool]:
    rdigest = _request_digest("version", context_id, body)
    with db.tx():
        owned_context(db, context_id, scope, body.tenant_id)
        existing = _replay(db, scope, body.tenant_id, body.request_key, rdigest)
        if existing:
            return existing, False
        latest = int(db.scalar("SELECT MAX(version) FROM policy_context_version WHERE context_id=?", (context_id,)))
        if body.supersedes_version != latest:
            raise CatalogError("VERSION_CONFLICT", f"supersedes_version {body.supersedes_version} is not the latest "
                                                   f"version ({latest}); reload and retry.",
                               details={"latest_version": latest})
        entries = validate_controls(body.controls)
        vid = _insert_version(db, context_id=context_id, version=latest + 1, scope=scope, tenant=body.tenant_id,
                              actor=actor, body=body, entries=entries, request_digest=rdigest)
    return db.one("SELECT * FROM policy_context_version WHERE id=?", (vid,)), True  # type: ignore[return-value]


def versions_of(db: CatalogDb, context_id: str) -> list[dict[str, Any]]:
    return db.q("SELECT * FROM policy_context_version WHERE context_id=? ORDER BY version", (context_id,))


# ---------------------------------------------------------------- supersession


def winning_intervals(versions: list[dict[str, Any]]) -> dict[int, list[tuple[str, str]]]:
    """Per version number, the [start, end) intervals in which it is the version in force."""
    points = sorted({v["effective_from"] for v in versions} | {v["effective_to"] or FOREVER for v in versions})
    out: dict[int, list[tuple[str, str]]] = {v["version"]: [] for v in versions}
    for start, end in zip(points, points[1:]):
        covering = [v["version"] for v in versions
                    if v["effective_from"] <= start and start < (v["effective_to"] or FOREVER)]
        if not covering:
            continue
        winner = max(covering)
        spans = out[winner]
        if spans and spans[-1][1] == start:
            spans[-1] = (spans[-1][0], end)
        else:
            spans.append((start, end))
    return out


def clip(intervals: list[tuple[str, str]], start: str, end: str) -> list[tuple[str, str]]:
    return [(max(a, start), min(b, end)) for a, b in intervals if max(a, start) < min(b, end)]


def subtract(whole: tuple[str, str], parts: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """``whole`` minus the union of ``parts`` (all [start, end) intervals)."""
    gaps, cursor = [], whole[0]
    for a, b in sorted(parts):
        if a > cursor:
            gaps.append((cursor, min(a, whole[1])))
        cursor = max(cursor, b)
        if cursor >= whole[1]:
            break
    if cursor < whole[1]:
        gaps.append((cursor, whole[1]))
    return [(a, b) for a, b in gaps if a < b]


def _span(intervals: list[tuple[str, str]]) -> list[dict[str, str | None]]:
    return [{"start": a, "end": None if b == FOREVER else b} for a, b in intervals]


# ---------------------------------------------------------------- collector capabilities


def capabilities(db: CatalogDb, scope: str | None, tenant: str | None) -> dict[str, Any]:
    """Latest collector handshake of this organization, or the legacy bridge default."""
    if scope is None or tenant is None:
        return pc.legacy_capabilities()
    row = db.one("SELECT * FROM collector_capability WHERE organization_scope=? AND tenant_id=? ORDER BY id DESC "
                 "LIMIT 1", (scope, tenant))
    if row is None:
        return pc.legacy_capabilities()
    return {"source": "HANDSHAKE", "digest": row["digest"], "declared_at": row["declared_at"],
            "declared_by": row["declared_by"], "collector": row["collector_info"], "evidence": row["evidence_support"],
            "evidence_detail": row.get("evidence_detail") or {}}


def declare_capabilities(db: CatalogDb, *, scope: str, actor: str, body: CollectorCapabilitiesIn
                         ) -> tuple[dict[str, Any], bool]:
    from app.models.evidence import EVIDENCE_SCHEMA_VERSIONS

    unknown = sorted({e.evidence_type for e in body.evidence} - set(EVIDENCE_SCHEMA_VERSIONS))
    if unknown:
        raise CatalogError("UNKNOWN_EVIDENCE_TYPE", f"evidence types not defined by OPM: {unknown}",
                           details={"evidence_types": unknown})
    types = [e.evidence_type for e in body.evidence]
    if len(types) != len(set(types)):
        raise CatalogError("INVALID_CAPABILITIES", "each evidence_type may be declared once")
    from app.models.evidence import CUSTOM_RULE_FIELDS

    # only COLLECTED types count as collected (readiness, plans, existing-rule matching)
    evidence = {e.evidence_type: e.schema_version for e in sorted(body.evidence, key=lambda e: e.evidence_type)
                if e.collection_status == "COLLECTED"}
    detail: dict[str, Any] = {}
    for e in body.evidence:
        if e.supported_fields is not None:
            unknown_fields = sorted(set(e.supported_fields) - set(CUSTOM_RULE_FIELDS.get(e.evidence_type, {})))
            if unknown_fields:
                raise CatalogError("UNKNOWN_EVIDENCE_FIELD", f"{e.evidence_type}: fields not in OPM's evidence schema "
                                   f"{unknown_fields}", details={"evidence_type": e.evidence_type,
                                                                 "fields": unknown_fields})
        if e.assessment_modes is not None or e.supported_fields is not None:
            detail[e.evidence_type] = {"assessment_modes": sorted(set(e.assessment_modes or [])),
                                       "supported_fields": sorted(set(e.supported_fields or [])),
                                       # extra keys only for lookup types, so existing digests stay unchanged
                                       **({"collection_status": e.collection_status,
                                           "schema_version": e.schema_version}
                                          if e.collection_status != "COLLECTED" else {}),
                                       **({"caveats": e.caveats} if e.caveats else {}),
                                       **({"field_meanings": e.field_meanings} if e.field_meanings else {})}
            unknown_meant = sorted(set(e.field_meanings or {}) - set(e.supported_fields or []))
            if unknown_meant:
                raise CatalogError("UNKNOWN_EVIDENCE_FIELD", f"{e.evidence_type}: field_meanings for fields it does "
                                   f"not declare {unknown_meant}", details={"evidence_type": e.evidence_type,
                                                                           "fields": unknown_meant})
    collector = body.collector.model_dump()
    # declarations without the optional detail keep their earlier digest
    digest = "sha256:" + digest_of({"collector": collector, "evidence": evidence, **({"detail": detail} if detail else {})})
    with db.tx():
        latest = capabilities(db, scope, body.tenant_id)
        changed = latest.get("digest") != digest
        if changed:
            db.insert("collector_capability", organization_scope=scope, tenant_id=body.tenant_id,
                      collector_info=collector, evidence_support=evidence, evidence_detail=detail, digest=digest,
                      declared_by=actor, declared_at=now_iso())
            db.audit(actor, "COLLECTOR_CAPABILITIES_DECLARED", "collector_capability", digest,
                     organization_scope=scope, tenant_id=body.tenant_id)
    return capabilities_view(capabilities(db, scope, body.tenant_id)), changed


def capabilities_view(cap: dict[str, Any]) -> dict[str, Any]:
    from app.models.evidence import EVIDENCE_SCHEMA_VERSIONS

    declared = cap.get("evidence") or {}
    return {**cap, "evidence_types": [
        {"evidence_type": t, "opm_schema_version": v, "declared_schema_version": declared.get(t),
         "compatible": declared.get(t) == v} for t, v in sorted(EVIDENCE_SCHEMA_VERSIONS.items())]}


# ---------------------------------------------------------------- views


def control_view(entry: dict[str, Any], cap: dict[str, Any], engine: Any) -> dict[str, Any]:
    defn = pc.get(entry["control_id"], entry["control_version"])
    out = {**entry, "provenance": ORIGIN}
    if defn is None:
        return {**out, "implementation_status": None, "assessment_mode": None,
                "assessment_blockers": [{"code": "CONTROL_DEFINITION_UNAVAILABLE",
                                         "message": "The pinned control version is not in this OPM release."}]}
    blockers: list[dict[str, Any]] = []
    if defn["definition_digest"] != entry["control_definition_digest"]:
        blockers.append({"code": "CONTROL_DEFINITION_CHANGED",
                         "message": "The pinned control definition digest no longer matches; save a new version."})
    if defn["implementation"]["status"] != pc.EXECUTABLE:
        blockers.append({"code": "NO_EXECUTABLE_RULE", "message": "Documented policy only: no rule implements this "
                                                                  "control, so it is never assessed automatically."})
    for b in defn["bindings"]:
        s = pc.binding_support(b, cap, engine)
        blockers += [{"code": code, "rule_id": b["rule_id"], "rule_version": b["rule_version"],
                      "evidence_type": b["evidence_type"]} for code in s["blocker_codes"]]
    return {**out, "implementation_status": defn["implementation"]["status"],
            "assessment_mode": defn["assessment_mode"],
            "rule_bindings": [{k: b[k] for k in ("rule_id", "rule_version", "evidence_type", "evidence_schema_version",
                                                 "parameter_map")} for b in defn["bindings"]],
            "assessment_blockers": blockers}


def version_view(db: CatalogDb, row: dict[str, Any], *, cap: dict[str, Any] | None = None, engine: Any = None,
                 all_versions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    all_versions = all_versions if all_versions is not None else versions_of(db, row["context_id"])
    wins = winning_intervals(all_versions).get(row["version"], [])
    own = (row["effective_from"], row["effective_to"] or FOREVER)
    superseded = []
    for other in all_versions:
        if other["version"] > row["version"]:
            for a, b in clip(winning_intervals(all_versions).get(other["version"], []), *own):
                superseded.append({"by_version": other["version"], "by_policy_version_id": other["id"],
                                   "start": a, "end": None if b == FOREVER else b})
    cap = cap if cap is not None else capabilities(db, row["organization_scope"], row["tenant_id"])
    return {
        "policy_context_id": row["context_id"], "policy_version_id": row["id"], "version": row["version"],
        "organization_scope": row["organization_scope"], "tenant_id": row["tenant_id"],
        "title": row["title"], "description": row["description"], "policy_reference": row["policy_reference"],
        "effective_from": row["effective_from"], "effective_to": row["effective_to"],
        "status": "ACTIVE", "digest": row["digest"],
        "provenance": {"origin": ORIGIN, "declared_by": row["created_by"], "declared_at": row["created_at"],
                       "request_key": row["request_key"], "control_catalog_version": row["control_catalog_version"],
                       "approval": "NOT_REQUIRED: user-declared organization policy is active on save"},
        "supersession": {"rule": "highest version whose effective interval contains the instant",
                         "in_force_intervals": _span(wins), "superseded_intervals": superseded},
        "controls": [control_view(e, cap, engine) for e in row["policy_controls"]],
    }


def list_contexts(db: CatalogDb, scope: str, tenant: str, *, after: str, limit: int) -> list[dict[str, Any]]:
    rows = db.q("SELECT * FROM policy_context WHERE organization_scope=? AND tenant_id=? AND id>? ORDER BY id LIMIT ?",
                (scope, tenant, after, limit + 1))
    out = []
    for r in rows:
        versions = versions_of(db, r["id"])
        latest = versions[-1]
        out.append({"policy_context_id": r["id"], "created_by": r["created_by"], "created_at": r["created_at"],
                    "latest_version": latest["version"], "title": latest["title"],
                    "versions": [{"version": v["version"], "policy_version_id": v["id"], "digest": v["digest"],
                                  "effective_from": v["effective_from"], "effective_to": v["effective_to"],
                                  "created_at": v["created_at"],
                                  "control_ids": sorted({e["control_id"] for e in v["policy_controls"]})}
                                 for v in versions]})
    return out
