"""LLM-assisted PAM rule assignment (mapping policy ``llm-auto-v1``, prompt ``llm-map-v1``).

The local LLM is the mapping ANALYST: per published requirement it proposes one decision in
strict JSON. Deterministic code is the GATE: nothing the model says is trusted until verified.

Pipeline per requirement (no human step):
  pre-gates (approved+published, operative, in PAM scope, MANDATORY, fully parsed, canonical control
  resolved, at least one semantic candidate rule)  ->  LLM proposal  ->  deterministic validation
  ->  draft (create_mapping)  ->  automated review (decision_origin AUTOMATED_LLM)  ->  scoped
  publication by the caller (publish_scoped)  ->  readiness recomputation by the caller.

Validation (all must hold; otherwise a structured gap is stored):
  * the rule is one of the semantic candidates for the canonical control (or the passage's
    tested-behaviour topics for frameworks without control headings) - never an arbitrary rule;
  * the pinned version is the single ACTIVE version of that rule in the running bundle;
  * the evidence type matches the rule and is declared by this organization's collector handshake;
  * every rule parameter is resolved deterministically, in this order: regulatory text ->
    approved organization policy (organization-wide, in force) -> verified PAM configuration
    snapshot; regulatory text may ground only a boolean that selects the STRICT reading
    (e.g. "full video playbacks" -> accept_partial_recordings=false);
    the model's binding must equal the resolved value and cite the same source, and every
    quotation must occur in the cited source;
  * coverage is PARTIAL (a FULL proposal is recorded and published as PARTIAL), rationale,
    limitations and the applicable population are present, confidence >= the threshold;
  * no different live mapping exists for the requirement (global or this organization's).
The model never supplies Rego, expressions, rule IDs outside the catalog, or values: a number,
duration, threshold or boolean policy choice without a verifiable source is PARAMETER_SOURCE_MISSING.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import catalog, control_ids, mapping_policy as mp, mapping_recipes as mr
from . import pam_configuration, policy_contexts as pctx, policy_controls as pc
from .db import CatalogDb, CatalogError, canonical, digest_of, now_iso
from .llm import LlmError

PROMPT_VERSION = "llm-map-v1"
POLICY_VERSION = "llm-auto-v1"
DEFAULT_MIN_CONFIDENCE = 0.8

GAP_CODES = ("LLM_MAPPING_AMBIGUOUS", "PARAMETER_SOURCE_MISSING", "COLLECTOR_MISSING", "NO_EXECUTABLE_RULE",
             "POLICY_CONFLICT", "SOURCE_GROUNDING_FAILED", "CANONICAL_CONTROL_UNRESOLVED", "RULE_VERSION_INVALID",
             "EVIDENCE_SCHEMA_INCOMPATIBLE", "LLM_OUTPUT_INVALID", "LLM_ERROR", "LLM_NO_MAP",
             "MANUAL_ASSESSMENT_RECOMMENDED", "NON_OPERATIVE_TEXT", "OUTSIDE_PAM_SCOPE", "NOT_MANDATORY",
             "PARTIALLY_PARSED", "VALIDATION_FAILED")

# Semantic candidate relationships (canonical control, clause or None for any clause, rules).
# Candidates only: parameters, collectors and grounding must still validate.
SEMANTIC_CANDIDATES: tuple[tuple[str, str | None, tuple[str, ...]], ...] = (
    ("AC-2", "j", ("PAM-REVIEW-001",)),
    ("AC-2", "i", ("PAM-UNAUTH-001",)),
    ("AC-2", None, ("PAM-DORMANT-001",)),
    ("AC-2(3)", None, ("PAM-DORMANT-001",)),
    ("AC-3", None, ("PAM-APPROVAL-001", "PAM-UNAUTH-001")),
    ("AC-3(2)", None, ("PAM-APPROVAL-001",)),
    ("AC-7", None, ("PAM-AUTHFAIL-001",)),
    ("AC-11", None, ("PAM-SESSIDLE-001",)),
    ("IA-2(*)", None, ("PAM-MFAACC-001",)),
    ("IA-5", "f", ("PAM-ROTATION-001",)),
    ("AU-14", "a", ("PAM-SESSREC-001",)),
)
PINNED_VERSIONS = {("IA-5", "f", "PAM-ROTATION-001"): "1.1"}

# The unit in which a regulation states each integer parameter. Parameters missing here (character lengths,
# percentages, seconds) are never read from prose: their value comes only from organization settings or a
# verified PAM configuration.
TEXT_UNITS: dict[str, str] = {
    "max_rotation_age_days": "days", "dormant_after_days": "days", "review_interval_days": "days",
    "max_exception_duration_days": "days", "max_approval_age_hours": "hours", "post_review_within_hours": "hours",
    "max_idle_minutes": "minutes", "max_session_minutes": "minutes", "window_minutes": "minutes",
    "max_failed_attempts": "attempts",
}
override_constraint = mr.override_constraint

# Strict readings of a boolean that regulatory text may ground.
_STRICT_BOOLEANS: dict[str, tuple[bool, re.Pattern[str]]] = {
    "accept_partial_recordings": (False, re.compile(
        r"\b(?:full|complete|entire)\b[^.;]{0,40}\b(?:video\s+)?(?:playbacks?|recordings?)\b"
        r"|\brecord\w*\b[^.;]{0,80}\b(?:all|every|each)\b[^.;]{0,60}\bsessions?\b", re.I)),
}

SYSTEM_MAP = (
    "You are a PAM compliance mapping analyst. For ONE regulatory requirement decide whether one of the "
    "CANDIDATE RULES technically tests it. Answer with JSON only, matching the schema. Rules: choose rule_id and "
    "rule_version ONLY from the candidate list; never write code, expressions or new rule ids. decision MAP only "
    "when the rule tests the behaviour the requirement mandates; NO_MAP when no candidate does; "
    "MANUAL_ASSESSMENT when a person must assess it. Never invent numbers, durations, thresholds or boolean "
    "choices: every parameter binding must quote its source (REGULATORY_TEXT = the requirement text, "
    "POLICY_DOCUMENT or PAM_CONFIGURATION = a listed value). If a "
    "parameter has no source, still answer but leave that binding out. coverage is PARTIAL unless the rule "
    "tests every element of the requirement. State limitations and the applicable population.")

_BINDING = {"type": "object", "additionalProperties": False,
            "required": ["name", "value", "source_type"],
            "properties": {"name": {"type": "string"}, "value": {},
                           "source_type": {"enum": ["REGULATORY_TEXT", "POLICY_DOCUMENT", "PAM_CONFIGURATION"]},
                           "source_document_id": {"type": ["integer", "null"]},
                           "quotation": {"type": ["string", "null"]}}}
SCHEMA = {"type": "object", "additionalProperties": False,
          "required": ["requirement_id", "decision", "confidence", "rationale", "limitations"],
          "properties": {"requirement_id": {"type": "integer"},
                         "decision": {"enum": ["MAP", "NO_MAP", "MANUAL_ASSESSMENT"]},
                         "rule_id": {"type": ["string", "null"]}, "rule_version": {"type": ["string", "null"]},
                         "coverage": {"enum": ["FULL", "PARTIAL", None]},
                         "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                         "parameter_bindings": {"type": "array", "items": _BINDING},
                         "rationale": {"type": "string"}, "limitations": {"type": "array", "items": {"type": "string"}},
                         "applicable_population": {"type": ["string", "null"]},
                         "evidence_type": {"type": ["string", "null"]}}}


class Binding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(max_length=80)
    value: bool | int | list[str] | None
    source_type: Literal["REGULATORY_TEXT", "POLICY_DOCUMENT", "PAM_CONFIGURATION"]
    source_document_id: int | None = None
    quotation: str | None = Field(default=None, max_length=600)


class Proposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requirement_id: int
    decision: Literal["MAP", "NO_MAP", "MANUAL_ASSESSMENT"]
    rule_id: str | None = Field(default=None, max_length=40)
    rule_version: str | None = Field(default=None, max_length=12)
    coverage: Literal["FULL", "PARTIAL"] | None = None
    confidence: float = Field(ge=0, le=1)
    parameter_bindings: list[Binding] = Field(default_factory=list, max_length=20)
    rationale: str = Field(max_length=4000)
    limitations: list[str] = Field(default_factory=list, max_length=20)
    applicable_population: str | None = Field(default=None, max_length=600)
    evidence_type: str | None = Field(default=None, max_length=60)


def min_confidence() -> float:
    try:
        return min(1.0, max(0.0, float(os.environ.get("OPM_REGINTEL_LLM_MAPPING_MIN_CONFIDENCE",
                                                      DEFAULT_MIN_CONFIDENCE))))
    except ValueError:
        return DEFAULT_MIN_CONFIDENCE


def _norm(t: str | None) -> str:
    return re.sub(r"\s+", " ", (t or "").replace("’", "'")).strip().lower()


# Vetted rule per evidence type, used for controls the Securden NIST matrix (control hub) covers but
# SEMANTIC_CANDIDATES does not list (NIST run 2026-11-20: 251 of 295 requirements had no candidate, so AC-2(3),
# AC-12, AC-2(2) ... went to generation although a vetted rule tests exactly the matrix's recommended evidence).
# privileged_session has two rules; the matrix entry's recommended test field picks one.
VETTED_BY_EVIDENCE: dict[str, tuple[str, ...]] = {
    "credential_rotation": ("PAM-ROTATION-001",), "privileged_access_request": ("PAM-APPROVAL-001",),
    "privileged_account": ("PAM-DORMANT-001",), "authentication_summary": ("PAM-AUTHFAIL-001",),
    "access_authorization": ("PAM-UNAUTH-001",), "break_glass_event": ("PAM-BREAKGLASS-001",),
    "policy_exception": ("PAM-EXCEPTION-001",), "access_review": ("PAM-REVIEW-001",),
    "audit_log_coverage": ("PAM-AUDITCOMP-001",), "mfa_configuration": ("PAM-MFACFG-001",),
    "privileged_access_authentication": ("PAM-MFAACC-001",), "session_policy_configuration": ("PAM-SESSIDLE-001",),
}
_SESSION_BY_FIELD = {"recording_status": "PAM-SESSREC-001", "recording_required": "PAM-SESSREC-001",
                     "recording_reference": "PAM-SESSREC-001", "ended_at": "PAM-SESSDUR-001",
                     "started_at": "PAM-SESSDUR-001"}
MATRIX_CANDIDATES_VERSION = "matrix-candidates-v1"


def matrix_candidates(ref: dict[str, Any]) -> list[str]:
    """Vetted rules for the evidence the Securden matrix lists for this exact control (or clause/enhancement)."""
    from . import control_hub

    out: list[str] = []
    for e in control_hub.entries_for(ref):
        et = e.get("evidence_type")
        if et == "privileged_session":
            rule = _SESSION_BY_FIELD.get((e.get("recommended_test") or {}).get("field"))
            rules = (rule,) if rule else ()
        else:
            rules = VETTED_BY_EVIDENCE.get(et, ())
        out.extend(r for r in rules if r not in out)
    return out


def candidates_for(ref: dict[str, Any], text: str) -> list[str]:
    if ref.get("status") == "DERIVED" and ref.get("canonical_id"):
        cid, clause, base = ref["canonical_id"], ref.get("clause"), ref.get("control_id")
        for key, cl, rules in SEMANTIC_CANDIDATES:
            if key == cid and cl is not None and cl == clause:
                return list(rules)
        for key, cl, rules in SEMANTIC_CANDIDATES:
            if cl is None and (key == cid or (key.endswith("(*)") and cid.startswith(key[:-3] + "(")
                                              and base == key[:-3])):
                return list(rules)
        # statement text of a hub control only (never discussion or front matter); the model still judges the fit
        if ref.get("location") in (None, "CONTROL_STATEMENT"):
            return matrix_candidates(ref)
        return []
    return sorted({rule for _n, rule, _p in mp.topics(text) if rule})


def _active(engine: Any, rule_id: str) -> dict[str, Any]:
    return {v: s for v, s in ((getattr(engine, "rules", {}) or {}).get(rule_id) or {}).items() if s.status == "ACTIVE"}


def _policy_values(db: CatalogDb, scope: str, tenant: str | None, rule_id: str) -> dict[str, dict[str, Any]]:
    """Organization-wide parameter values of policy versions in force now that pin ``rule_id``."""
    if tenant is None:
        return {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    out: dict[str, dict[str, Any]] = {}
    rows = db.q("SELECT * FROM policy_context_version WHERE organization_scope=? AND tenant_id=? ORDER BY context_id, "
                "version", (scope, tenant))
    by_ctx: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_ctx.setdefault(r["context_id"], []).append(r)
    for versions in by_ctx.values():
        wins = pctx.winning_intervals(versions)
        for v in versions:
            if not any(a <= now < e for a, e in wins.get(v["version"], [])):
                continue
            for entry in v["policy_controls"]:
                if not any(t["type"] == "ORGANIZATION" for t in entry["targets"]):
                    continue  # a value for selected targets cannot bind an organization-wide mapping
                defn = pc.get(entry["control_id"], entry["control_version"]) or {}
                for b in defn.get("bindings", []):
                    if b["rule_id"] != rule_id:
                        continue
                    for rule_param, ctl_param in b["parameter_map"].items():
                        if ctl_param in entry["parameters"]:
                            out[rule_param] = {"value": entry["parameters"][ctl_param], "provenance": "CUSTOMER_POLICY",
                                               "source_type": "POLICY_DOCUMENT", "policy_version_id": v["id"],
                                               "policy_digest": v["digest"], "control_id": entry["control_id"],
                                               "title": v["title"]}
    return out


def resolve_parameters(db: CatalogDb, *, req: dict[str, Any], rule_id: str, spec: Any,
                       scope: str, tenant: str | None, snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Deterministic parameter resolution, one entry per rule parameter (value None = PARAMETER_SOURCE_MISSING)."""
    text = req.get("translation_en") or req.get("original_text") or ""
    policy = _policy_values(db, scope, tenant, rule_id)
    out = []
    for name, p in sorted(spec.parameters.items()):
        entry: dict[str, Any] = {"name": name, "value": None, "source_type": None, "reason": None}
        if p.type in ("integer",) and name in TEXT_UNITS:
            value, why = mr.extract(TEXT_UNITS[name], text, p)
            if value is not None:
                entry.update(value=value, source_type="REGULATORY_TEXT", provenance="REGULATORY_TEXT", quotation=why)
        elif p.type == "boolean" and name in _STRICT_BOOLEANS:
            strict, pattern = _STRICT_BOOLEANS[name]
            m = pattern.search(mr._outside_brackets(text))
            if m and not re.search(r"\bpartial\w*", text, re.I):
                entry.update(value=strict, source_type="REGULATORY_TEXT", provenance="REGULATORY_TEXT",
                             quotation=m.group(0))
        if entry["value"] is None and name in policy:
            entry.update(**policy[name])
        if entry["value"] is None:
            cfg = pam_configuration.value_for(snapshot, rule_id, name)
            if cfg is not None:
                entry.update(**cfg)
        if entry["value"] is None:
            entry["reason"] = ("no value in the regulatory text, no organization-wide policy in force and no verified "
                               "PAM configuration value for this parameter")
        out.append(entry)
    return out


def _context(db: CatalogDb, req: dict[str, Any], ref: dict[str, Any],
             cands: list[str], engine: Any, cap: dict[str, Any], resolved: dict[str, list[dict[str, Any]]],
             existing: list[dict[str, Any]]) -> str:
    section = db.one("SELECT text FROM document_section WHERE id=?", (req["section_id"],)) if req.get("section_id") else None
    text = req.get("translation_en") or req["original_text"]
    around = ""
    if section:
        s = re.sub(r"\s+", " ", section["text"])
        at = s.find(re.sub(r"\s+", " ", req["original_text"])[:80])
        around = s[max(0, at - 500): at + len(text) + 500] if at >= 0 else s[:1200]
    fw = db.one("SELECT id, title FROM regulatory_framework WHERE id=?", (req["framework_id"],)) or {}
    rules = []
    for rid in cands:
        for v, spec in _active(engine, rid).items():
            rules.append({"rule_id": rid, "rule_version": v, "evidence_type": spec.evidence_type,
                          "title": getattr(spec, "title", None) or "", "description": getattr(spec, "description", ""),
                          "parameters": {n: {"type": p.type, "min": p.minimum, "max": p.maximum,
                                             "items": list(p.items or []) or None}
                                         for n, p in spec.parameters.items()},
                          "available_parameter_values": [
                              {k: e.get(k) for k in ("name", "value", "source_type", "quotation", "source_document_id")}
                              for e in resolved.get(rid, []) if e["value"] is not None]})
    payload = {
        "requirement_id": req["id"],
        "framework": {"id": fw.get("id"), "title": fw.get("title")},
        "canonical_control": {k: ref.get(k) for k in ("canonical_id", "control_title", "enhancement_title", "clause")},
        "requirement_text": text, "surrounding_source_text": around,
        "candidate_rules": rules,
        "collector_declaration": {"source": cap.get("source"), "evidence": cap.get("evidence") or {}},
        "existing_mappings": [{"rule_id": m["rule_id"], "parameters": m["rule_parameters"]} for m in existing],
        "allowed": {"decision": ["MAP", "NO_MAP", "MANUAL_ASSESSMENT"], "coverage": ["FULL", "PARTIAL"]},
    }
    return json.dumps(payload, ensure_ascii=False, indent=1)


def _gap(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"outcome": "GAP", "gap_code": code, "message": message, **extra}


def validate(db: CatalogDb, *, req: dict[str, Any], ref: dict[str, Any], proposal: Proposal, cands: list[str],
             engine: Any, cap: dict[str, Any], collected: tuple[str, ...], resolved: dict[str, list[dict[str, Any]]],
             existing: list[dict[str, Any]], scope: str) -> dict[str, Any]:
    checks: list[str] = []
    if proposal.requirement_id != req["id"]:
        return _gap("LLM_OUTPUT_INVALID", f"the proposal is for requirement {proposal.requirement_id}, not {req['id']}")
    if proposal.decision == "NO_MAP":
        return {"outcome": "NO_MAP", "gap_code": "LLM_NO_MAP", "message": proposal.rationale[:500]}
    if proposal.decision == "MANUAL_ASSESSMENT":
        return {"outcome": "MANUAL_ASSESSMENT", "gap_code": "MANUAL_ASSESSMENT_RECOMMENDED",
                "message": proposal.rationale[:500]}
    rule = proposal.rule_id or ""
    if rule not in cands:
        return _gap("NO_EXECUTABLE_RULE", f"'{rule}' is not a candidate rule for this control {cands}; the model may "
                                          "choose only supplied candidates")
    checks.append("candidate_rule")
    active = _active(engine, rule)
    pinned = PINNED_VERSIONS.get((ref.get("canonical_id"), ref.get("clause"), rule))
    if len(active) != 1 or proposal.rule_version not in active or (pinned and proposal.rule_version != pinned):
        return _gap("RULE_VERSION_INVALID", f"{rule} {proposal.rule_version} is not the single ACTIVE version "
                                            f"{sorted(active)}" + (f" (pinned {pinned})" if pinned else ""))
    version, spec = proposal.rule_version, active[proposal.rule_version]  # type: ignore[index]
    checks.append("active_pinned_version")
    if proposal.evidence_type not in (None, spec.evidence_type):
        return _gap("EVIDENCE_SCHEMA_INCOMPATIBLE", f"{rule} uses {spec.evidence_type}, not {proposal.evidence_type}")
    if cap.get("source") != "HANDSHAKE" or rule not in collected:
        return _gap("COLLECTOR_MISSING", f"this organization's collector declaration does not supply "
                                         f"{spec.evidence_type} for {rule}", rule_id=rule, rule_version=version)
    checks.append("collector_declared")
    if proposal.confidence < min_confidence():
        return _gap("LLM_MAPPING_AMBIGUOUS", f"confidence {proposal.confidence} is below the automation threshold "
                                             f"{min_confidence()}", rule_id=rule)
    checks.append("confidence")
    resolution = resolved[rule]
    missing = [e["name"] for e in resolution if e["value"] is None]
    if missing:
        return _gap("PARAMETER_SOURCE_MISSING", f"no verifiable source for {missing}", rule_id=rule,
                    rule_version=version, parameters_missing=missing)
    by_name = {b.name: b for b in proposal.parameter_bindings}
    unknown = sorted(set(by_name) - set(spec.parameters))
    if unknown:
        return _gap("SOURCE_GROUNDING_FAILED", f"bindings for parameters the rule does not have: {unknown}", rule_id=rule)
    for e in resolution:
        b = by_name.get(e["name"])
        if b is None or b.value != e["value"] or b.source_type != e["source_type"]:
            return _gap("SOURCE_GROUNDING_FAILED",
                        f"parameter '{e['name']}': the model bound {getattr(b, 'value', None)!r} from "
                        f"{getattr(b, 'source_type', None)}, the verifiable source gives {e['value']!r} from "
                        f"{e['source_type']}", rule_id=rule)
        if b.quotation and b.source_type == "REGULATORY_TEXT":
            if _norm(b.quotation) not in _norm(req.get("translation_en") or req["original_text"]):
                return _gap("SOURCE_GROUNDING_FAILED", f"quotation for '{e['name']}' does not occur in the cited "
                                                       "source", rule_id=rule)
    checks.append("parameters_grounded")
    if len(proposal.rationale.strip()) < 40 or not [x for x in proposal.limitations if x.strip()] \
            or not (proposal.applicable_population or "").strip():
        return _gap("VALIDATION_FAILED", "rationale, limitations and applicable population are required", rule_id=rule)
    checks.append("rationale_limitations_population")
    params = {e["name"]: e["value"] for e in resolution}
    same = [m for m in existing if m["rule_id"] == rule and canonical(m["rule_parameters"] or {}) == canonical(params)]
    # our own earlier automatic mapping for this rule, bound to organization values that have since changed,
    # is replaced (§5.3); anything else (human, global, another rule) still blocks as a conflict
    replaces = [] if same else [m["id"] for m in _customer_sourced(db, scope, req["id"], existing) if m["rule_id"] == rule]
    others = [m["id"] for m in existing if m not in same and m["id"] not in replaces]
    if others:
        return _gap("POLICY_CONFLICT", "a different live mapping exists for this requirement; it is kept",
                    rule_id=rule, conflicting_mapping_ids=others)
    if same:
        return {"outcome": "EXISTING", "gap_code": None, "mapping_id": same[0]["id"], "rule_id": rule,
                "rule_version": version, "checks": checks}
    if req["organization_scope"] not in (None, scope):
        return _gap("VALIDATION_FAILED", "tenant/organization ownership does not match", rule_id=rule)
    checks.append("ownership")
    limitations = [x.strip() for x in proposal.limitations if x.strip()]
    odp = mp.organization_defined(req.get("translation_en") or req["original_text"])
    if odp:
        limitations.append("Organization-defined parameters of the passage not established by this mapping: "
                           + "; ".join(odp) + f". Applicable population: {proposal.applicable_population.strip()}")
    for e in resolution:
        if e["source_type"] == "PAM_CONFIGURATION":
            limitations.append(f"'{e['name']}' = {e['value']!r} is the organization's PAM configuration observed at "
                               f"{e['captured_at']} (CUSTOMER_POLICY), not a regulatory threshold; the rule verifies "
                               "behaviour during the reporting period from its evidence.")
        elif e["source_type"] == "POLICY_DOCUMENT":
            limitations.append(f"'{e['name']}' = {e['value']!r} comes from organization policy version "
                               f"{e['policy_version_id']} (CUSTOMER_POLICY), not from the regulation.")
    return {"outcome": "VALIDATED", "gap_code": None, "rule_id": rule, "rule_version": version,
            "evidence_type": spec.evidence_type, "parameters": params, "parameter_provenance": resolution,
            "coverage": "PARTIAL", "coverage_adjusted": proposal.coverage == "FULL",
            "limitations": limitations, "checks": checks, "replaces_mapping_ids": replaces}


def _customer_sourced(db: CatalogDb, scope: str, rid: int, existing: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Live mappings of this organization that an earlier llm-auto decision created with at least one
    organization-defined value (organization settings or PAM configuration)."""
    ours = {}
    for d in db.q("SELECT mapping_id, parameter_resolution FROM llm_mapping_decision WHERE organization_scope=? AND "
                  "requirement_id=? AND mapping_id IS NOT NULL", (scope, rid)):
        if any((e or {}).get("provenance") == "CUSTOMER_POLICY" for e in d["parameter_resolution"] or []):
            ours[d["mapping_id"]] = True
    return [m for m in existing if m["organization_scope"] == scope and m["id"] in ours]


def _withdraw(db: CatalogDb, ids: list[int], *, actor: str, reason: str) -> list[int]:
    done = []
    for mid in ids:
        try:
            catalog.withdraw(db, "mapping", mid, actor=actor, reason=reason)
            done.append(mid)
        except CatalogError:
            continue  # already withdrawn or no longer approved: nothing to replace
    return done


def _live_mappings(db: CatalogDb, rid: int, scope: str) -> list[dict[str, Any]]:
    return db.q("SELECT id, rule_id, rule_parameters, status, organization_scope FROM framework_control_mapping "
                "WHERE requirement_id=? AND status IN ('DRAFT','APPROVED') AND (organization_scope IS NULL OR "
                "organization_scope=?)", (rid, scope))


def assign(db: CatalogDb, engine: Any, llm: Any, requirement_ids: list[int], *, scope: str, tenant: str | None,
           actor: str, job_id: str | None = None, progress: Any = None) -> dict[str, Any]:
    """Run the LLM-assisted assignment for published requirements visible in ``scope``. Drafts and reviews
    validated mappings (decision_origin AUTOMATED_LLM); returns mapping ids for scoped publication.
    ``progress(stage, **info)`` gets a counted 'llm_mapping' marker per requirement (detail marker)."""
    from .automation import engine_actor

    me = engine_actor(actor)
    cap = pctx.capabilities(db, scope, tenant)
    collected = pc.collected_rules(cap, engine) if cap.get("source") == "HANDSHAKE" else ()
    snapshot = pam_configuration.latest(db, scope, tenant)
    info = getattr(llm, "info", None)
    model, model_digest = (getattr(info, "model", None), getattr(info, "version", None)) if info else (None, None)
    out: dict[str, Any] = {"decisions": [], "mapping_ids": [], "policy_version": POLICY_VERSION,
                           "prompt_version": PROMPT_VERSION, "model": model, "model_digest": model_digest,
                           "collector_source": cap.get("source"), "tenant_id": tenant,
                           "pam_configuration_snapshot": (snapshot or {}).get("snapshot_id"),
                           "min_confidence": min_confidence(), "llm_errors": 0}
    indexes: dict[int, Any] = {}
    cache: dict[int, Any] = {}
    ordered = sorted(set(requirement_ids))
    for i, rid in enumerate(ordered):
        if progress is not None:
            progress("llm_mapping", done=i, total=len(ordered), unit="requirements", current={"requirement_id": rid},
                     detail=True)
        req = db.one("SELECT * FROM regulatory_requirement WHERE id=?", (rid,))
        if req is None or req["status"] != "APPROVED" or req["published_seq"] is None \
                or req["organization_scope"] not in (None, scope):
            continue
        ref = control_ids.annotate(db, [req], _cache=indexes)[rid] if req.get("section_id") else {"status": "NO_SOURCE_SECTION"}
        text = req.get("translation_en") or req["original_text"]
        record: dict[str, Any] = {"requirement_id": rid, "canonical_id": ref.get("canonical_id"),
                                  "clause": ref.get("clause")}
        pre = None
        problems = mp.assess(db, req, _cache=cache)
        if problems:
            pre = _gap(problems[0]["code"], problems[0]["message"])
        elif req["obligation_type"] != "MANDATORY":
            pre = _gap("NOT_MANDATORY", f"obligation type is {req['obligation_type']}")
        elif mr.partially_parsed(req, ref):
            pre = _gap("PARTIALLY_PARSED", mr.partially_parsed(req, ref) or "")
        elif ref.get("status") in ("QUOTE_NOT_LOCATED", "NO_SOURCE_SECTION") or (
                ref.get("status") == "DERIVED" and not ref.get("canonical_id")):
            pre = _gap("CANONICAL_CONTROL_UNRESOLVED", f"canonical control reference: {ref.get('status')}")
        cands = [] if pre else candidates_for(ref, text)
        if pre is None and not cands:
            pre = _gap("NO_EXECUTABLE_RULE", "no semantic candidate rule exists for this control or passage")
        resolved: dict[str, list[dict[str, Any]]] = {}
        for rule in cands:
            active = _active(engine, rule)
            if len(active) == 1:
                resolved[rule] = resolve_parameters(db, req=req, rule_id=rule, spec=next(iter(active.values())),
                                                    scope=scope, tenant=tenant, snapshot=snapshot)
        existing = _live_mappings(db, rid, scope)
        digest_input = {"requirement": digest_of({k: req[k] for k in ("id", "original_text", "translation_en",
                                                                       "document_version_id", "section_ref")}),
                        "ref": ref, "candidates": cands,
                        "resolved": resolved, "collector": cap.get("digest"), "collected": list(collected),
                        "prompt": PROMPT_VERSION, "policy": POLICY_VERSION, "model": [model, model_digest],
                        "min_confidence": min_confidence()}
        input_digest = digest_of(digest_input)
        prior = db.one("SELECT * FROM llm_mapping_decision WHERE organization_scope=? AND requirement_id=? AND "
                       "input_digest=?", (scope, rid, input_digest))
        if prior is not None:  # idempotent re-run: same inputs, same decision, no new model call
            live = [m for m in existing if m["id"] == prior["mapping_id"]]
            rule_id = (prior["llm_validation"] or {}).get("rule_id") or (prior["llm_proposal"] or {}).get("rule_id")
            record.update(decision_id=prior["id"], outcome="EXISTING" if live else prior["outcome"],
                          gap_code=prior["gap_code"], mapping_id=prior["mapping_id"], reused=True, rule_id=rule_id)
            if prior["gap_code"] == "PARAMETER_SOURCE_MISSING" and rule_id:
                # inputs returned to an earlier "missing" state (a settings section was removed again)
                stale = [m["id"] for m in _customer_sourced(db, scope, rid, existing) if m["rule_id"] == rule_id]
                if stale:
                    record["withdrawn_mapping_ids"] = _withdraw(
                        db, stale, actor=me, reason=f"AUTOMATED_LLM ({POLICY_VERSION}): the organization-defined "
                                                    "value it was bound to is no longer in force")
            out["decisions"].append(record)
            continue
        raw, proposal_json, result = None, None, pre
        if result is None:
            prompt = _context(db, req, ref, cands, engine, cap, resolved, existing)
            try:
                raw_out = llm.generate_raw(SYSTEM_MAP, prompt, SCHEMA)
                raw = raw_out.content
                if getattr(raw_out, "truncated", False):
                    raise ValueError("the model output was truncated at the output limit")
                proposal = Proposal.model_validate(json.loads(raw))
                proposal_json = proposal.model_dump()
                result = validate(db, req=req, ref=ref, proposal=proposal, cands=cands, engine=engine, cap=cap,
                                  collected=tuple(collected), resolved=resolved, existing=existing,
                                  scope=scope)
                if result["outcome"] == "VALIDATED":
                    result = _publishable(db, engine, req, ref, proposal, result, scope=scope, actor=me, model=model,
                                          model_digest=model_digest, input_digest=input_digest, job_id=job_id)
            except LlmError as exc:
                out["llm_errors"] += 1
                result = _gap("LLM_ERROR", str(exc)[:300])
            except (ValueError, ValidationError) as exc:
                result = _gap("LLM_OUTPUT_INVALID", f"the model output is not valid JSON for the schema: "
                                                    f"{str(exc)[:300]}")
            except CatalogError as exc:
                result = _gap("VALIDATION_FAILED", f"{exc.code}: {exc.message}")
        if result.get("gap_code") == "PARAMETER_SOURCE_MISSING" and result.get("rule_id"):
            # the organization value an earlier automatic mapping relied on is no longer in force (a section
            # left the settings): that mapping must not keep testing a threshold nobody defines any more
            stale = [m["id"] for m in _customer_sourced(db, scope, rid, existing) if m["rule_id"] == result["rule_id"]]
            if stale:
                result["withdrawn_mapping_ids"] = _withdraw(
                    db, stale, actor=me, reason=f"AUTOMATED_LLM ({POLICY_VERSION}): the organization-defined value "
                                                f"it was bound to is no longer in force; {result['message'][:200]}")
        with db.tx():
            did = db.insert("llm_mapping_decision", organization_scope=scope, tenant_id=tenant, requirement_id=rid,
                            job_id=job_id, input_digest=input_digest, model=model if pre is None else None,
                            model_digest=model_digest if pre is None else None, prompt_version=PROMPT_VERSION,
                            policy_version=POLICY_VERSION, raw_output=raw, llm_proposal=proposal_json,
                            llm_validation={k: v for k, v in result.items()
                                            if k not in ("parameter_provenance", "limitations")},
                            parameter_resolution=result.get("parameter_provenance") or [r for v in resolved.values()
                                                                                         for r in v],
                            outcome=result["outcome"], gap_code=result.get("gap_code"),
                            mapping_id=result.get("mapping_id"), created_at=now_iso())
        record.update(decision_id=did, outcome=result["outcome"], gap_code=result.get("gap_code"),
                      message=result.get("message"), mapping_id=result.get("mapping_id"),
                      rule_id=result.get("rule_id") or (proposal_json or {}).get("rule_id"),
                      rule_version=result.get("rule_version"), llm_called=pre is None,
                      **{k: result[k] for k in ("replaced_mapping_ids", "withdrawn_mapping_ids") if result.get(k)})
        if result["outcome"] == "PUBLISHABLE":
            out["mapping_ids"].append(result["mapping_id"])
        out["decisions"].append(record)
    out["counts"] = counts(out["decisions"])
    return out


def _publishable(db: CatalogDb, engine: Any, req: dict[str, Any], ref: dict[str, Any],
                 proposal: Proposal, v: dict[str, Any], *, scope: str, actor: str, model: str | None,
                 model_digest: str | None, input_digest: str, job_id: str | None) -> dict[str, Any]:
    """Draft and automatically review a validated proposal (separate audit records); publication follows."""
    specs = _active(engine, v["rule_id"]).get(v["rule_version"])
    numeric = {e["name"]: override_constraint(e["name"], e["value"], specs.parameters[e["name"]] if specs else None)
               for e in v["parameter_provenance"]
               if e["source_type"] == "REGULATORY_TEXT" and isinstance(e["value"], int)
               and not isinstance(e["value"], bool)}
    rationale = (f"AUTOMATED_LLM ({POLICY_VERSION}, prompt {PROMPT_VERSION}, model {model}): "
                 f"{proposal.rationale.strip()} Applicable population: {proposal.applicable_population.strip()}.")
    with db.tx():  # replace atomically: the superseded mapping is withdrawn only if its replacement is created
        replaced = _withdraw(db, v.get("replaces_mapping_ids") or [], actor=actor,
                             reason=f"AUTOMATED_LLM ({POLICY_VERSION}): replaced because the organization-defined "
                                    f"values it was bound to changed (input {input_digest[:23]})")
        mid = catalog.create_mapping(
            db, requirement_id=req["id"], assessment="AUTOMATED", rule_id=v["rule_id"],
            rule_version_min=v["rule_version"], rule_version_max=v["rule_version"], coverage="PARTIAL",
            parameters=v["parameters"], override_constraints=numeric, evidence_type=v["evidence_type"],
            rationale=rationale, limitations="PARTIAL technical coverage. " + " ".join(v["limitations"]), actor=actor,
            engine_rules=engine.rules, organization_scope=scope)
    record = {"automated": True, "decision_origin": "AUTOMATED_LLM", "mapping_policy_version": POLICY_VERSION,
              "prompt_version": PROMPT_VERSION, "model": model, "model_digest": model_digest,
              "input_digest": input_digest, "job_id": job_id, "confidence": proposal.confidence,
              "source_requirement": {"requirement_id": req["id"], "framework_id": req["framework_id"],
                                     "section_ref": req["section_ref"], "document_version_id": req["document_version_id"],
                                     "canonical_id": ref.get("canonical_id"), "clause": ref.get("clause")},
              "rule_id": v["rule_id"], "rule_version": v["rule_version"], "evidence_type": v["evidence_type"],
              "parameters": v["parameters"], "parameter_provenance": v["parameter_provenance"],
              "coverage": "PARTIAL",
              "coverage_adjusted_from_full": v["coverage_adjusted"], "limitations": v["limitations"],
              "applicable_population": proposal.applicable_population, "checks": v["checks"],
              "organization_scope_bound": True, "replaces_mapping_ids": replaced}
    catalog.review(db, "mapping", mid, reviewer=actor, decision="APPROVED",
                   comment=f"AUTOMATED_LLM approval ({POLICY_VERSION}): model proposal by {model}; deterministic "
                           f"checks passed: {', '.join(v['checks'])}.",
                   attestations=record, origin="AUTOMATED_LLM", policy_version=POLICY_VERSION)
    return {**v, "outcome": "PUBLISHABLE", "mapping_id": mid, "replaced_mapping_ids": replaced}


def counts(decisions: list[dict[str, Any]]) -> dict[str, int]:
    def n(*codes: str) -> int:
        return sum(1 for d in decisions if d.get("gap_code") in codes)
    return {"llm_candidates": sum(1 for d in decisions if d.get("llm_called")),
            "mappings_validated": sum(1 for d in decisions if d["outcome"] in ("PUBLISHABLE", "EXISTING")),
            "mappings_published": sum(1 for d in decisions if d["outcome"] == "PUBLISHABLE"),
            "ambiguous_candidates": n("LLM_MAPPING_AMBIGUOUS"),
            "missing_parameters": n("PARAMETER_SOURCE_MISSING"),
            "missing_collectors": n("COLLECTOR_MISSING"),
            "unsupported_requirements": n("NO_EXECUTABLE_RULE", "LLM_NO_MAP", "MANUAL_ASSESSMENT_RECOMMENDED",
                                          "NON_OPERATIVE_TEXT", "OUTSIDE_PAM_SCOPE", "NOT_MANDATORY")}


def latest_decision(db: CatalogDb, requirement_id: int, scope: str | None) -> dict[str, Any] | None:
    if scope is None:
        return None
    row = db.one("SELECT * FROM llm_mapping_decision WHERE organization_scope=? AND requirement_id=? "
                 "ORDER BY id DESC LIMIT 1", (scope, requirement_id))
    if row is None:
        return None
    p = row["llm_proposal"] or {}
    return {"decision_id": row["id"], "outcome": row["outcome"], "gap_code": row["gap_code"],
            "message": (row["llm_validation"] or {}).get("message"), "mapping_id": row["mapping_id"],
            "rule_id": p.get("rule_id") or (row["llm_validation"] or {}).get("rule_id"),
            "rule_version": (row["llm_validation"] or {}).get("rule_version"), "confidence": p.get("confidence"),
            "model": row["model"], "model_digest": row["model_digest"], "prompt_version": row["prompt_version"],
            "policy_version": row["policy_version"], "parameter_resolution": row["parameter_resolution"],
            "decided_at": row["created_at"]}
