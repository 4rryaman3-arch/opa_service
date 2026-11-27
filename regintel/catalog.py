"""Reviewed catalog: drafting, human review, publication, withdrawal.

Four layers are kept as separate entities and are never merged:

  1. EXPLICIT_OBLIGATION      regulatory_requirement  (verbatim official text)
  2. INTERPRETIVE_MAPPING     framework_control_mapping (Securden's reading: rationale + limitations)
  3. CUSTOMER_POLICY          thresholds/parameters a customer chooses (never stored here as regulation)
  4. EXECUTABLE_RULE          rule_version (structured definition compiled for OPA; see rules.py)

Lifecycle of every catalog entity: DRAFT -> APPROVED (by a reviewer other than
the author) -> published (gets ``published_seq``). The API serves published
rows only.
"""

from __future__ import annotations

import json
import re
from typing import Any

from . import PAM_DOMAINS
from .db import CatalogDb, CatalogError, digest_of, now_iso
from .registry import check_date
from .sources.registry import is_verified
from .textproc import normalize

LAYERS = {
    "requirement": "EXPLICIT_OBLIGATION",
    "mapping": "INTERPRETIVE_MAPPING",
    "rule_version": "EXECUTABLE_RULE",
}
TABLES = {
    "requirement": "regulatory_requirement",
    "mapping": "framework_control_mapping",
    "evidence_requirement": "evidence_requirement",
    "applicability_criteria": "applicability_criteria",
    "remediation": "remediation_template",
}
_TERM = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
CRITERIA_LISTS = ("industries", "organization_types", "regulated_activities", "system_scopes")


def _get(db: CatalogDb, entity_type: str, entity_id: Any) -> dict[str, Any]:
    table = TABLES.get(entity_type)
    if table is None:
        raise CatalogError("UNKNOWN_ENTITY_TYPE", entity_type)
    row = db.one(f"SELECT * FROM {table} WHERE id=?", (entity_id,))
    if row is None:
        raise CatalogError("NOT_FOUND", f"{entity_type} {entity_id}")
    return row


def _control(db: CatalogDb, control_id: str) -> None:
    if not db.one("SELECT 1 FROM pam_control WHERE id=?", (control_id,)):
        raise CatalogError("UNKNOWN_PAM_CONTROL", control_id)


# ------------------------------------------------------------- documents


def review_document_version(db: CatalogDb, version_id: int, *, reviewer: str, decision: str, comment: str = "",
                            published_on: str | None = None, effective_from: str | None = None,
                            effective_to: str | None = None, supersede_previous: bool = False,
                            origin: str = "HUMAN", policy_version: str | None = None) -> None:
    """A reviewer confirms the retrieved file is the complete official text and
    records its dates as stated in that text."""
    v = db.one("SELECT v.*, d.source_id FROM regulatory_document_version v JOIN regulatory_document d "
               "ON d.id=v.document_id WHERE v.id=?", (version_id,))
    if v is None:
        raise CatalogError("NOT_FOUND", f"document version {version_id}")
    if v["status"] != "AWAITING_REVIEW":
        raise CatalogError("ALREADY_REVIEWED", f"version {version_id} is {v['status']}")
    if decision == "APPROVED":
        if not v["complete"]:
            raise CatalogError("DOCUMENT_INCOMPLETE", f"an incomplete document cannot be approved: {v['incomplete_reason']}")
        source = db.one("SELECT * FROM source WHERE id=?", (v["source_id"],))
        if not is_verified(db, source):  # type: ignore[arg-type]
            raise CatalogError("SOURCE_NOT_VERIFIED", "the document's source is no longer verified")
    elif decision != "REJECTED":
        raise CatalogError("INVALID_DECISION", decision)
    for name, val in (("published_on", published_on), ("effective_from", effective_from), ("effective_to", effective_to)):
        check_date(val, name)
    with db.tx():
        db.x("UPDATE regulatory_document_version SET status=?, published_on=?, effective_from=?, effective_to=? WHERE id=?",
             ("REVIEWED" if decision == "APPROVED" else "REJECTED", published_on, effective_from, effective_to, version_id))
        db.insert("review_approval", entity_type="document_version", entity_id=str(version_id), decision=decision,
                  reviewer=reviewer, comment=comment, entity_digest=v["content_sha256"], decided_at=now_iso(),
                  decision_origin=origin, policy_version=policy_version)
        db.x("UPDATE regulatory_change SET status='TRIAGED' WHERE new_version_id=?", (version_id,))
        if decision == "APPROVED" and supersede_previous and v["supersedes_version_id"]:
            _supersede_version(db, v["supersedes_version_id"], reviewer, ends_on=effective_from)
        db.audit(reviewer, f"DOCUMENT_{decision}", "document_version", version_id)


def _supersede_version(db: CatalogDb, old_version_id: int, actor: str, ends_on: str | None) -> None:
    """The old text stops applying on ``ends_on``. Requirements cited from it
    are kept (historical evaluations need them) but marked SUPERSEDED."""
    if not ends_on:
        raise CatalogError("MISSING_START_DATE", "superseding a version needs the new version's effective_from")
    db.x("UPDATE regulatory_document_version SET status='SUPERSEDED', effective_to=COALESCE(effective_to, ?) WHERE id=?",
         (ends_on, old_version_id))
    reqs = db.q("SELECT id, published_seq FROM regulatory_requirement WHERE document_version_id=? AND status='APPROVED'",
                (old_version_id,))
    db.x("UPDATE regulatory_requirement SET status='REJECTED' WHERE document_version_id=? AND status='DRAFT'",
         (old_version_id,))
    if reqs:
        db.x("UPDATE regulatory_requirement SET status='SUPERSEDED', effective_to=COALESCE(effective_to, ?) "
             "WHERE document_version_id=? AND status='APPROVED'", (ends_on, old_version_id))
        published = [("requirement", r["id"], "UPSERT") for r in reqs if r["published_seq"]]
        if published:
            db.publish(actor, "CATALOG", published, {"superseded_document_version": old_version_id})


# ------------------------------------------------------------- drafting


def create_mapping(db: CatalogDb, *, requirement_id: int, rationale: str, limitations: str, actor: str,
                   pam_control_id: str | None = None, strength: str | None = None, assessment: str | None = None,
                   rule_id: str | None = None, rule_version_min: str | None = None, rule_version_max: str | None = None,
                   evidence_type: str | None = None, parameters: dict[str, Any] | None = None,
                   override_constraints: dict[str, Any] | None = None, coverage: str | None = None,
                   control_reference: str | None = None, engine_rules: dict[str, Any] | None = None,
                   organization_scope: str | None = None) -> int:
    """Draft a mapping from an approved requirement.

    assessment=None       control reference only (interpretive; never executed)
    assessment=AUTOMATED  binds the requirement to an executable rule: version range, every
                          rule parameter stated explicitly, optional override constraints
    assessment=MANUAL     records that the requirement needs a person or a collector that
                          does not exist yet; it is reported, never executed
    A mapping is immutable once reviewed; a change is a new row with the next ``version``
    under the same ``mapping_key`` after the previous one is withdrawn."""
    from .plan import check_rule_binding

    req = _get(db, "requirement", requirement_id)
    if req["status"] != "APPROVED":
        raise CatalogError("REQUIREMENT_NOT_APPROVED", "mappings can only reference approved requirements")
    parameters, override_constraints = parameters or {}, override_constraints or {}
    if assessment not in (None, "AUTOMATED", "MANUAL"):
        raise CatalogError("INVALID_MAPPING", "assessment must be AUTOMATED or MANUAL")
    if assessment == "AUTOMATED":
        if not rule_id or not rule_version_min or coverage not in ("FULL", "PARTIAL"):
            raise CatalogError("INVALID_MAPPING", "an automated mapping needs rule_id, rule_version_min and coverage FULL or PARTIAL")
        definition = db.one("SELECT pam_control_id FROM opa_rule_definition WHERE rule_id=?", (rule_id,))
        if definition is None or engine_rules is None:
            raise CatalogError("UNKNOWN_RULE", f"rule '{rule_id}' is not registered in the rule catalog")
        if pam_control_id not in (None, definition["pam_control_id"]):
            raise CatalogError("INVALID_MAPPING", f"{rule_id} belongs to control {definition['pam_control_id']}")
        pam_control_id = definition["pam_control_id"]
        evidence_type = check_rule_binding(engine_rules, rule_id, rule_version_min, rule_version_max, parameters,
                                           override_constraints, evidence_type)
        strength = strength or ("DIRECT" if coverage == "FULL" else "PARTIAL")
    else:
        if rule_id or rule_version_min or rule_version_max or evidence_type or parameters or override_constraints or coverage:
            raise CatalogError("INVALID_MAPPING", "rule, parameter and coverage fields are only valid for an automated mapping")
        if not pam_control_id:
            raise CatalogError("INVALID_MAPPING", "pam_control_id is required")
        strength = strength or ("SUPPORTING" if assessment == "MANUAL" else None)
    _control(db, pam_control_id)  # type: ignore[arg-type]
    # A mapping lives in its requirement's namespace, or - for a global requirement - in one organization's
    # scope when its parameters come from that organization (policy, PAM configuration, uploaded material).
    scope = req["organization_scope"]
    if organization_scope is not None:
        if scope not in (None, organization_scope):
            raise CatalogError("SCOPE_MISMATCH", "a mapping cannot leave its requirement's organization scope")
        scope = organization_scope
    key = f"{req['framework_id']}:{requirement_id}:{pam_control_id}" + (
        f":{digest_of(scope)[:16]}" if scope is not None and req["organization_scope"] is None else "")
    with db.tx():
        version = 1 + int(db.scalar("SELECT COUNT(*) FROM framework_control_mapping WHERE mapping_key=?", (key,)) or 0)
        mid = db.insert("framework_control_mapping", requirement_id=requirement_id, pam_control_id=pam_control_id,
                        strength=strength, rationale=rationale.strip(), limitations=limitations.strip(),
                        assessment=assessment, rule_id=rule_id, rule_version_min=rule_version_min,
                        rule_version_max=rule_version_max, evidence_type=evidence_type, rule_parameters=parameters,
                        override_constraints=override_constraints, coverage=coverage,
                        control_reference=(control_reference or req["section_ref"]).strip(), mapping_key=key,
                        version=version, created_by=actor, created_at=now_iso(), organization_scope=scope)
        db.audit(actor, "DRAFT", "mapping", mid)
    return mid


def create_evidence_requirement(db: CatalogDb, *, pam_control_id: str, evidence_type: str, description: str,
                                fields: list[str], actor: str) -> int:
    from app.models.evidence import CUSTOM_RULE_FIELDS

    _control(db, pam_control_id)
    allowed = CUSTOM_RULE_FIELDS.get(evidence_type)
    if allowed is None:
        raise CatalogError("UNKNOWN_EVIDENCE_TYPE", evidence_type)
    unknown = sorted(set(fields) - set(allowed))
    if unknown:
        raise CatalogError("UNKNOWN_EVIDENCE_FIELD", f"{unknown} are not fields of '{evidence_type}'")
    with db.tx():
        eid = db.insert("evidence_requirement", pam_control_id=pam_control_id, evidence_type=evidence_type,
                        description=description.strip(), fields=sorted(fields), created_by=actor, created_at=now_iso())
        db.audit(actor, "DRAFT", "evidence_requirement", eid)
    return eid


def validate_criteria(criteria: dict[str, Any]) -> dict[str, Any]:
    allowed = {"nexus", "all_entities_in_jurisdiction", "legal_review_required", "legal_review_note", *CRITERIA_LISTS}
    unknown = set(criteria) - allowed
    if unknown:
        raise CatalogError("INVALID_CRITERIA", f"unknown keys {sorted(unknown)}")
    nexus = criteria.get("nexus", ["OPERATION"])
    if not nexus or set(nexus) - {"OPERATION", "DATA_PROCESSING"}:
        raise CatalogError("INVALID_CRITERIA", "nexus must be a non-empty subset of OPERATION, DATA_PROCESSING")
    out: dict[str, Any] = {
        "nexus": sorted(set(nexus)),
        "all_entities_in_jurisdiction": bool(criteria.get("all_entities_in_jurisdiction", False)),
        "legal_review_required": bool(criteria.get("legal_review_required", False)),
        "legal_review_note": str(criteria.get("legal_review_note", ""))[:500],
    }
    for key in CRITERIA_LISTS:
        values = criteria.get(key)
        if values is not None:
            if not isinstance(values, list) or not values or any(not isinstance(t, str) or not _TERM.match(t) for t in values):
                raise CatalogError("INVALID_CRITERIA", f"{key} must be a non-empty list of lowercase terms")
            values = sorted(set(values))
        out[key] = values
    if out["all_entities_in_jurisdiction"] and any(out[k] for k in CRITERIA_LISTS):
        raise CatalogError("INVALID_CRITERIA", "all_entities_in_jurisdiction cannot be combined with narrowing criteria")
    return out


def create_applicability_criteria(db: CatalogDb, *, framework_id: str, criteria: dict[str, Any], rationale: str,
                                  requirement_ids: list[int], actor: str) -> int:
    if not db.one("SELECT 1 FROM regulatory_framework WHERE id=?", (framework_id,)):
        raise CatalogError("UNKNOWN_FRAMEWORK", framework_id)
    for rid in requirement_ids:
        req = _get(db, "requirement", rid)
        if req["status"] != "APPROVED" or req["framework_id"] != framework_id:
            raise CatalogError("REQUIREMENT_NOT_APPROVED",
                               "criteria must cite approved scope provisions of the same framework")
    with db.tx():
        cid = db.insert("applicability_criteria", framework_id=framework_id, criteria=validate_criteria(criteria),
                        rationale=rationale.strip(), requirement_ids=sorted(requirement_ids), created_by=actor,
                        created_at=now_iso())
        db.audit(actor, "DRAFT", "applicability_criteria", cid)
    return cid


def create_remediation(db: CatalogDb, *, finding_category: str, pam_control_id: str, corrective_actions: list[str],
                       securden_capabilities: list[str], customer_responsibilities: list[str],
                       source_citations: list[dict[str, Any]], actor: str) -> int:
    _control(db, pam_control_id)
    if not re.match(r"^[A-Z][A-Z0-9_]{2,63}$", finding_category):
        raise CatalogError("INVALID_FINDING_CATEGORY", "finding_category must be an UPPER_SNAKE reason code")
    for name, items in (("corrective_actions", corrective_actions), ("securden_capabilities", securden_capabilities),
                        ("customer_responsibilities", customer_responsibilities)):
        if not items or any(not isinstance(i, str) or len(i.strip()) < 5 for i in items):
            raise CatalogError("INCOMPLETE_REMEDIATION", f"{name} needs at least one meaningful entry")
    if not source_citations:
        raise CatalogError("CITATION_REQUIRED", "a remediation template needs at least one source citation")
    for c in source_citations:
        if set(c) == {"requirement_id"}:
            if _get(db, "requirement", c["requirement_id"])["status"] != "APPROVED":
                raise CatalogError("REQUIREMENT_NOT_APPROVED", "citations must reference approved requirements")
        elif set(c) == {"securden_documentation"} and len(str(c["securden_documentation"])) >= 5:
            continue
        else:
            raise CatalogError("INVALID_CITATION", "a citation is {requirement_id} or {securden_documentation}")
    with db.tx():
        tid = db.insert("remediation_template", finding_category=finding_category, pam_control_id=pam_control_id,
                        corrective_actions=corrective_actions, securden_capabilities=securden_capabilities,
                        customer_responsibilities=customer_responsibilities, source_citations=source_citations,
                        created_by=actor, created_at=now_iso())
        db.audit(actor, "DRAFT", "remediation", tid)
    return tid


# ------------------------------------------------------------- review


def review_translation(db: CatalogDb, requirement_id: int, *, reviewer: str, decision: str,
                       corrected_translation: str | None = None, origin: str = "HUMAN",
                       policy_version: str | None = None, attempt_id: int | None = None) -> None:
    req = _get(db, "requirement", requirement_id)
    if req["translation_status"] == "NOT_REQUIRED":
        raise CatalogError("NO_TRANSLATION", "the requirement is in English")
    if decision not in ("REVIEWED", "REJECTED"):
        raise CatalogError("INVALID_DECISION", decision)
    text = corrected_translation.strip() if corrected_translation else req["translation_en"]
    if decision == "REVIEWED" and not text:
        raise CatalogError("NO_TRANSLATION", "there is no translation to approve; supply corrected_translation")
    with db.tx():
        db.x("UPDATE regulatory_requirement SET translation_status=?, translation_en=?, translation_reviewer=? WHERE id=?",
             (decision, text if decision == "REVIEWED" else req["translation_en"], reviewer, requirement_id))
        db.insert("review_approval", entity_type="translation", entity_id=str(requirement_id), decision="APPROVED"
                  if decision == "REVIEWED" else "REJECTED", reviewer=reviewer, entity_digest=digest_of(text or ""),
                  attestations={"corrected": bool(corrected_translation)}, decided_at=now_iso(),
                  decision_origin=origin, policy_version=policy_version, attempt_id=attempt_id)


def _check_requirement(db: CatalogDb, req: dict[str, Any], attestations: dict[str, Any]) -> None:
    v = db.one("SELECT v.status, v.complete, d.source_id, d.framework_id FROM regulatory_document_version v "
               "JOIN regulatory_document d ON d.id=v.document_id WHERE v.id=?", (req["document_version_id"],))
    if v is None or v["status"] != "REVIEWED" or not v["complete"]:
        raise CatalogError("DOCUMENT_NOT_REVIEWED", "the cited document version has not been reviewed as complete official text")
    if v["framework_id"] != req["framework_id"]:
        raise CatalogError("SOURCE_ATTRIBUTION_MISMATCH", "requirement framework differs from its document's framework")
    if not is_verified(db, db.one("SELECT * FROM source WHERE id=?", (v["source_id"],))):  # type: ignore[arg-type]
        raise CatalogError("SOURCE_NOT_VERIFIED", "the document's source is not verified")
    section = db.one("SELECT * FROM document_section WHERE id=?", (req["section_id"],))
    if section is None or section["version_id"] != req["document_version_id"] \
            or normalize(req["original_text"]) not in normalize(section["text"]):
        raise CatalogError("SOURCE_ATTRIBUTION_MISMATCH", "the passage is not present in the cited section")
    if set(req["pam_domains"]) - set(PAM_DOMAINS):
        raise CatalogError("INVALID_PAM_DOMAIN", str(req["pam_domains"]))
    if any(normalize(t["value_text"]) not in req["original_text"] for t in req["thresholds"]):
        raise CatalogError("INVENTED_THRESHOLD", "a recorded threshold is not present in the passage")
    if req["translation_status"] not in ("NOT_REQUIRED", "REVIEWED") \
            and attestations.get("reviewed_in_original_language") is not True:
        raise CatalogError(
            "TRANSLATION_UNREVIEWED",
            f"the passage is in '{req['original_language']}' and its English translation is {req['translation_status']}; "
            "review the translation, or attest reviewed_in_original_language")


def review(db: CatalogDb, entity_type: str, entity_id: int, *, reviewer: str, decision: str, comment: str = "",
           attestations: dict[str, Any] | None = None, origin: str = "HUMAN", policy_version: str | None = None,
           attempt_id: int | None = None) -> None:
    """Approve or reject a DRAFT. Approval never publishes.

    ``origin`` is ``HUMAN`` for the review endpoints and ``AUTOMATED`` only for
    the engine's automation policy (``regintel.automation``), which must pass
    the policy version and, where one exists, the model review attempt."""
    with db.tx():
        _review(db, entity_type, entity_id, reviewer, decision, comment, attestations or {},
                origin=origin, policy_version=policy_version, attempt_id=attempt_id)


def _review(db: CatalogDb, entity_type: str, entity_id: int, reviewer: str, decision: str, comment: str,
            attestations: dict[str, Any], *, origin: str = "HUMAN", policy_version: str | None = None,
            attempt_id: int | None = None) -> None:
    row = _get(db, entity_type, entity_id)
    if row["status"] != "DRAFT":
        raise CatalogError("NOT_DRAFT", f"{entity_type} {entity_id} is {row['status']}")
    if decision not in ("APPROVED", "REJECTED"):
        raise CatalogError("INVALID_DECISION", decision)
    if origin not in ("HUMAN", "AUTOMATED", "AUTOMATED_LLM"):
        raise CatalogError("INVALID_ORIGIN", origin)
    if origin == "AUTOMATED_LLM" and entity_type != "mapping":
        raise CatalogError("INVALID_ORIGIN", "AUTOMATED_LLM decisions exist for mappings only")
    if origin in ("AUTOMATED", "AUTOMATED_LLM") and not policy_version:
        raise CatalogError("POLICY_REQUIRED", "an automated decision must record its policy version")
    if reviewer.startswith("llm:"):  # a model never approves anything; a person may review their own draft
        raise CatalogError("SELF_APPROVAL", "a model identity cannot review catalog content")
    if decision == "APPROVED":
        if entity_type == "requirement":
            _check_requirement(db, row, attestations)
        elif entity_type == "mapping":
            if _get(db, "requirement", row["requirement_id"])["status"] != "APPROVED":
                raise CatalogError("REQUIREMENT_NOT_APPROVED", "the mapped requirement is no longer approved")
        elif entity_type == "applicability_criteria":
            validate_criteria(row["criteria"])
            db.x("UPDATE applicability_criteria SET status='WITHDRAWN' WHERE framework_id=? AND status='APPROVED' "
                 "AND published_seq IS NULL", (row["framework_id"],))
            if db.one("SELECT 1 FROM applicability_criteria WHERE framework_id=? AND status='APPROVED'",
                      (row["framework_id"],)):
                raise CatalogError("CRITERIA_EXIST", "withdraw the published criteria for this framework first")
    content = {k: v for k, v in row.items() if k not in ("status", "published_seq")}
    with db.tx():
        db.x(f"UPDATE {TABLES[entity_type]} SET status=? WHERE id=?", (decision, entity_id))
        db.insert("review_approval", entity_type=entity_type, entity_id=str(entity_id), decision=decision,
                  reviewer=reviewer, comment=comment, attestations=attestations, entity_digest=digest_of(content),
                  decided_at=now_iso(), decision_origin=origin, policy_version=policy_version, attempt_id=attempt_id)
        db.audit(reviewer, decision, entity_type, entity_id, origin=origin)


# ------------------------------------------------------------- publication

_ORDER = ("requirement", "mapping", "evidence_requirement", "applicability_criteria", "remediation")


def pending_publication(db: CatalogDb) -> dict[str, list[int]]:
    return {t: [r["id"] for r in db.q(f"SELECT id FROM {TABLES[t]} WHERE status='APPROVED' AND published_seq IS NULL ORDER BY id")]
            for t in _ORDER}


def publish_catalog(db: CatalogDb, actor: str) -> dict[str, Any]:
    """Publish every approved, unpublished entity as one immutable publication.
    The whole batch is re-validated first; one broken reference blocks it."""
    with db.tx():
        pending = pending_publication(db)
        problems: list[str] = []
        for rid in pending["requirement"]:
            try:
                last = db.one("SELECT attestations FROM review_approval WHERE entity_type='requirement' AND entity_id=? "
                              "AND decision='APPROVED' ORDER BY id DESC LIMIT 1", (str(rid),))
                _check_requirement(db, _get(db, "requirement", rid), (last or {}).get("attestations") or {})
            except CatalogError as exc:
                problems.append(f"requirement {rid}: {exc}")
        for mid in pending["mapping"]:
            m = _get(db, "mapping", mid)
            if _get(db, "requirement", m["requirement_id"])["status"] != "APPROVED":
                problems.append(f"mapping {mid}: requirement {m['requirement_id']} is not approved")
        for tid in pending["remediation"]:
            for c in _get(db, "remediation", tid)["source_citations"]:
                if "requirement_id" in c and _get(db, "requirement", c["requirement_id"])["status"] != "APPROVED":
                    problems.append(f"remediation {tid}: cited requirement {c['requirement_id']} is not approved")
        for etype, ids in pending.items():
            for eid in ids:
                if not db.one("SELECT 1 FROM review_approval WHERE entity_type=? AND entity_id=? AND decision='APPROVED'",
                              (etype, str(eid))):
                    problems.append(f"{etype} {eid}: no approval record")
        if problems:
            raise CatalogError("PUBLICATION_BLOCKED", "; ".join(problems), details={"problems": problems})
        changes = [(t, i, "UPSERT") for t in _ORDER for i in pending[t]]
        if not changes:
            return {"published": False, "catalog_version": db.catalog_version(), "counts": {}}
        counts = {t: len(pending[t]) for t in _ORDER if pending[t]}
        seq = db.publish(actor, "CATALOG", changes, counts)
        for t in _ORDER:
            for i in pending[t]:
                db.x(f"UPDATE {TABLES[t]} SET published_seq=? WHERE id=?", (seq, i))
    return {"published": True, "catalog_version": seq, "counts": counts}


def publish_scoped(db: CatalogDb, actor: str, requirement_ids: list[int], mapping_ids: list[int] | None = None,
                   organization_scope: str | None = None) -> dict[str, Any]:
    """Publish exactly the given approved requirements/mappings and nothing else.

    Used by the automated pipelines so one job can never publish unrelated
    pending content (other entity types, other frameworks, other jobs' drafts,
    other organization scopes). Each entity is re-validated like in
    ``publish_catalog``; already published ids are skipped (idempotent retries)."""
    with db.tx():
        reqs: list[int] = []
        maps: list[int] = []
        problems: list[str] = []
        for rid in sorted(set(requirement_ids)):
            req = _get(db, "requirement", rid)
            if req["published_seq"] is not None:
                continue  # already published: a retry must not duplicate the publication
            if req["status"] != "APPROVED":
                problems.append(f"requirement {rid}: status is {req['status']}, not APPROVED")
                continue
            last = db.one("SELECT attestations FROM review_approval WHERE entity_type='requirement' AND entity_id=? "
                          "AND decision='APPROVED' ORDER BY id DESC LIMIT 1", (str(rid),))
            if last is None:
                problems.append(f"requirement {rid}: no approval record")
                continue
            try:
                _check_requirement(db, req, last.get("attestations") or {})
            except CatalogError as exc:
                problems.append(f"requirement {rid}: {exc}")
                continue
            reqs.append(rid)
        for mid in sorted(set(mapping_ids or [])):
            m = _get(db, "mapping", mid)
            if m["published_seq"] is not None:
                continue
            if m["status"] != "APPROVED":
                problems.append(f"mapping {mid}: status is {m['status']}, not APPROVED")
                continue
            req = _get(db, "requirement", m["requirement_id"])
            if req["status"] != "APPROVED" or (req["published_seq"] is None and m["requirement_id"] not in reqs):
                problems.append(f"mapping {mid}: requirement {m['requirement_id']} is not approved and published")
                continue
            if not db.one("SELECT 1 FROM review_approval WHERE entity_type='mapping' AND entity_id=? AND decision='APPROVED'",
                          (str(mid),)):
                problems.append(f"mapping {mid}: no approval record")
                continue
            if m["organization_scope"] != organization_scope:
                problems.append(f"mapping {mid}: belongs to a different organization scope than this publication")
                continue
            maps.append(mid)
        if problems:
            raise CatalogError("PUBLICATION_BLOCKED", "; ".join(problems), details={"problems": problems})
        if not reqs and not maps:
            return {"published": False, "catalog_version": db.catalog_version(), "requirement_ids": [], "mapping_ids": []}
        changes = [("requirement", i, "UPSERT") for i in reqs] + [("mapping", i, "UPSERT") for i in maps]
        summary: dict[str, Any] = {"requirement": len(reqs), "mapping": len(maps), "scope": "AUTOMATED_PIPELINE"}
        if organization_scope:
            summary["organization_scope"] = organization_scope
        seq = db.publish(actor, "CATALOG", changes, summary)
        for rid in reqs:
            db.x("UPDATE regulatory_requirement SET published_seq=? WHERE id=?", (seq, rid))
        for mid in maps:
            db.x("UPDATE framework_control_mapping SET published_seq=? WHERE id=?", (seq, mid))
    return {"published": True, "catalog_version": seq, "requirement_ids": reqs, "mapping_ids": maps}


def publish_requirements(db: CatalogDb, actor: str, requirement_ids: list[int]) -> dict[str, Any]:
    """Backward-compatible wrapper used by the build_framework pipeline."""
    out = publish_scoped(db, actor, requirement_ids)
    return {k: out[k] for k in ("published", "catalog_version", "requirement_ids")}


_BULK_RESET = re.compile(r"\bgenerated rules removed\b", re.I)


def rejected_rules(db: CatalogDb, requirement_id: int, scope: str | None) -> dict[str, str]:
    """rule_id -> reason, for links of this requirement a person withdrew: automation must not create them again.
    Withdrawals by automation (replacements, gates) and bulk resets ("... generated rules removed ...") are not
    judgements about the rule. Approving the same link by hand afterwards lifts the block."""
    out: dict[str, str] = {}
    for m in db.q("SELECT id, rule_id FROM framework_control_mapping WHERE requirement_id=? AND status='WITHDRAWN' AND "
                  "rule_id IS NOT NULL AND (organization_scope IS NULL OR organization_scope=?) ORDER BY id",
                  (requirement_id, scope)):
        for e in db.q("SELECT actor, detail FROM audit_event WHERE action='WITHDRAW' AND entity_type='mapping' AND "
                      "entity_id=? ORDER BY id", (str(m["id"]),)):
            detail = e["detail"] if isinstance(e["detail"], dict) else json.loads(e["detail"] or "{}")
            reason = str(detail.get("reason") or "")
            if e["actor"].startswith("engine:") or reason.startswith("AUTOMATED") or _BULK_RESET.search(reason):
                continue
            out[m["rule_id"]] = reason
            manual = db.one("SELECT 1 AS x FROM framework_control_mapping m JOIN review_approval r ON r.entity_type="
                            "'mapping' AND r.entity_id=m.id WHERE m.requirement_id=? AND m.rule_id=? AND m.id>? AND "
                            "m.status='APPROVED' AND r.decision='APPROVED' AND r.reviewer NOT LIKE 'engine:%'",
                            (requirement_id, m["rule_id"], m["id"]))
            if manual:
                out.pop(m["rule_id"], None)
    return out


def withdraw(db: CatalogDb, entity_type: str, entity_id: int, *, actor: str, reason: str,
             status: str = "WITHDRAWN") -> dict[str, Any]:
    """Remove something from the published catalog immediately (its own
    publication, so subscribers receive a tombstone). Dependants are withdrawn too."""
    row = _get(db, entity_type, entity_id)
    if len(reason.strip()) < 10:
        raise CatalogError("REASON_REQUIRED", "state why this is being withdrawn")
    if entity_type == "requirement" and status not in ("WITHDRAWN", "REPEALED"):
        raise CatalogError("INVALID_STATUS", status)
    if entity_type != "requirement":
        status = "WITHDRAWN"
    if row["status"] not in ("APPROVED", "SUPERSEDED"):
        raise CatalogError("NOT_PUBLISHABLE", f"{entity_type} {entity_id} is {row['status']}")
    with db.tx():
        changes: list[tuple[str, Any, str]] = []

        def take(etype: str, r: dict[str, Any], new_status: str) -> None:
            db.x(f"UPDATE {TABLES[etype]} SET status=? WHERE id=?", (new_status, r["id"]))
            if r["published_seq"]:
                changes.append((etype, r["id"], "WITHDRAW"))

        take(entity_type, row, status)
        affected_rules: list[str] = []
        if entity_type == "requirement":
            for m in db.q("SELECT * FROM framework_control_mapping WHERE requirement_id=? AND status IN ('DRAFT','APPROVED')",
                          (entity_id,)):
                take("mapping", m, "WITHDRAWN")
            for rv in db.q("SELECT rule_id, version, threshold_provenance FROM rule_version WHERE status IN ('DRAFT','APPROVED')"):
                if any(p.get("requirement_id") == entity_id for p in rv["threshold_provenance"]):
                    affected_rules.append(f"{rv['rule_id']} {rv['version']}")
        seq = db.publish(actor, "WITHDRAWAL", changes, {"reason": reason.strip(), "affected_rule_versions": affected_rules}) \
            if changes else db.catalog_version()
        db.audit(actor, "WITHDRAW", entity_type, entity_id, reason=reason.strip())
    return {"catalog_version": seq, "withdrawn": [f"{t}:{i}" for t, i, _ in changes],
            "rule_versions_to_review": affected_rules}
