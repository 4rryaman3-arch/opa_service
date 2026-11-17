"""Deterministic mapping recipes (automation policy auto-v3).

A recipe states which executable rule technically checks a passage and how every rule
parameter is read from the passage text. Two kinds:

  * TEXT recipes - any framework: a privileged-access passage whose wording names the tested
    behaviour (mapping_policy.topics), e.g. "rotate privileged credentials every 90 days";
  * CANONICAL recipes - NIST SP 800-53 Rev. 5 controls, matched by the canonical control
    reference derived from the official headings (control ID, clause and the control title).

``resolve`` returns exactly one decision per requirement. A mapping is proposed only when ALL hold:
  the requirement is MANDATORY, operative, in PAM scope and not a licensing/provenance statement;
  it is fully parsed (balanced brackets, quote located in its source);
  exactly one rule is resolved across all matching recipes;
  the passage has no organization-defined parameters;
  exactly one ACTIVE version of that rule is in the running bundle, with the recipe's evidence type;
  the evidence is collected (PAM bridge / collector handshake);
  every rule parameter has a value stated in the passage (provenance SOURCE_TEXT);
  no conflicting live mapping exists.
Anything else is a structured NOT_MAPPED decision. A recipe never uses a rule default, a
company policy or a vendor document as a threshold.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from . import mapping_policy as mp
from .db import CatalogDb, canonical

RECIPE_SET_VERSION = "pam-recipes-v1"

# decision codes (NOT_MAPPED); mapping_policy gap codes are reused where they apply
NOT_MANDATORY = "NOT_MANDATORY"
PARTIALLY_PARSED = "PARTIALLY_PARSED"
AMBIGUOUS_REQUIREMENT = "AMBIGUOUS_REQUIREMENT"
RULE_UNAVAILABLE = "RULE_UNAVAILABLE"
RULE_VERSION_AMBIGUOUS = "RULE_VERSION_AMBIGUOUS"
EVIDENCE_SCHEMA_INCOMPATIBLE = "EVIDENCE_SCHEMA_INCOMPATIBLE"
PARAMETER_NOT_SOURCE_GROUNDED = "PARAMETER_NOT_SOURCE_GROUNDED"
MAPPING_CONFLICT = "MAPPING_CONFLICT"
VALIDATION_FAILED = "VALIDATION_FAILED"
DECISION_CODES = (NOT_MANDATORY, mp.NON_OPERATIVE_TEXT, mp.OUTSIDE_PAM_SCOPE, PARTIALLY_PARSED, mp.NO_EXECUTABLE_RULE,
                  mp.MAPPING_MISSING, AMBIGUOUS_REQUIREMENT, mp.POLICY_CONTEXT_REQUIRED, RULE_UNAVAILABLE,
                  RULE_VERSION_AMBIGUOUS, EVIDENCE_SCHEMA_INCOMPATIBLE, mp.COLLECTOR_MISSING,
                  PARAMETER_NOT_SOURCE_GROUNDED, MAPPING_CONFLICT, VALIDATION_FAILED)


@dataclass(frozen=True)
class Recipe:
    recipe_id: str
    rule_id: str
    evidence_type: str
    params: tuple[tuple[str, str], ...]          # (rule parameter, extractor)
    tests: str
    limitations: str
    canonical: tuple[tuple[str, str | None, str], ...] = ()   # (canonical_id, clause, control_title)
    text: bool = False                                        # TEXT recipe (topic + privileged wording)


_PRIV = "Only privileged accounts and sessions managed by Securden are covered."
RECIPES: tuple[Recipe, ...] = (
    Recipe("TXT-ROTATION", "PAM-ROTATION-001", "credential_rotation", (("max_rotation_age_days", "days"),),
           "every in-scope privileged credential was rotated within the stated number of days",
           f"Age-based rotation only; event-triggered changes are not tested. {_PRIV}", text=True),
    Recipe("TXT-DORMANT", "PAM-DORMANT-001", "privileged_account", (("dormant_after_days", "days"),),
           "no enabled privileged account was unused for longer than the stated number of days",
           f"Inactivity only; account expiry, removal and other disabling conditions are not tested. {_PRIV}", text=True),
    Recipe("TXT-SESSREC", "PAM-SESSREC-001", "privileged_session", (("accept_partial_recordings", "strict_recording"),),
           "every privileged session requiring recording has an available, complete recording",
           f"Recording availability only; viewing rights, retention and review of recordings are not tested. {_PRIV}",
           text=True),
    # ---- NIST SP 800-53 Rev. 5 (canonical control references)
    Recipe("NIST-IA-5-f", "PAM-ROTATION-001", "credential_rotation", (("max_rotation_age_days", "days"),),
           "privileged credentials were changed within the stated refresh period",
           f"Tests the refresh period of privileged credentials only, not other authenticators or event triggers. {_PRIV}",
           canonical=(("IA-5", "f", "AUTHENTICATOR MANAGEMENT"),)),
    Recipe("NIST-AC-2(3)", "PAM-DORMANT-001", "privileged_account", (("dormant_after_days", "days"),),
           "privileged accounts inactive for longer than the stated period were not left enabled",
           f"Tests condition (d), inactivity, only; expired, disassociated and policy-violating accounts are not "
           f"tested. {_PRIV}", canonical=(("AC-2(3)", None, "ACCOUNT MANAGEMENT"), ("AC-2(3)", "d", "ACCOUNT MANAGEMENT"))),
    Recipe("NIST-AU-14-a", "PAM-SESSREC-001", "privileged_session", (("accept_partial_recordings", "strict_recording"),),
           "every privileged session requiring recording has an available, complete recording",
           f"Tests the 'record' capability only, not view, hear or log, and not who may use it. {_PRIV}",
           canonical=(("AU-14", "a", "SESSION AUDIT"),)),
    Recipe("NIST-AC-2-j", "PAM-REVIEW-001", "access_review", (("review_interval_days", "days"),),
           "every privileged account had a completed access review within the stated interval",
           f"Tests that reviews were completed, not their quality or the account-management requirements. {_PRIV}",
           canonical=(("AC-2", "j", "ACCOUNT MANAGEMENT"),)),
    Recipe("NIST-AC-2-i", "PAM-UNAUTH-001", "access_authorization", (),
           "every privileged access was backed by an entitlement valid at access time",
           f"Tests item 1 (valid access authorization) only. {_PRIV}",
           canonical=(("AC-2", "i", "ACCOUNT MANAGEMENT"),)),
    Recipe("NIST-IA-2-MFA", "PAM-MFAACC-001", "privileged_access_authentication", (("accepted_methods", "never"),),
           "each granted privileged access had a verified MFA with an accepted method",
           f"Separate-device and strength-of-mechanism conditions are not in the evidence schema. {_PRIV}",
           canonical=(("IA-2(1)", None, "IDENTIFICATION AND AUTHENTICATION (ORGANIZATIONAL USERS)"),
                      ("IA-2(2)", None, "IDENTIFICATION AND AUTHENTICATION (ORGANIZATIONAL USERS)"),
                      ("IA-2(6)", None, "IDENTIFICATION AND AUTHENTICATION (ORGANIZATIONAL USERS)"))),
    Recipe("NIST-AC-3(2)", "PAM-APPROVAL-001", "privileged_access_request", (("max_approval_age_hours", "hours"),),
           "privileged access requiring approval was approved by someone other than the requester in time",
           f"Tests requester/approver separation on access requests, not dual authorization of every command. {_PRIV}",
           canonical=(("AC-3(2)", None, "ACCESS ENFORCEMENT"),)),
    Recipe("NIST-AC-11-a", "PAM-SESSIDLE-001", "session_policy_configuration", (("max_idle_minutes", "minutes"),),
           "the privileged session policy enforces an idle timeout no longer than the stated period",
           f"Tests the configured idle timeout, not device locks outside Securden. {_PRIV}",
           canonical=(("AC-11", "a", "DEVICE LOCK"),)),
    Recipe("NIST-AC-7-a", "PAM-AUTHFAIL-001", "authentication_summary",
           (("max_failed_attempts", "attempts"), ("window_minutes", "minutes"), ("lockout_is_mitigation", "never")),
           "no principal exceeded the stated failed-attempt limit within one window",
           f"Observed attempt counts per window only, not the enforcement mechanism. {_PRIV}",
           canonical=(("AC-7", "a", "UNSUCCESSFUL LOGON ATTEMPTS"),)),
)

_UNITS = {
    "days": re.compile(r"\b(\d{1,4})\s*(?:calendar\s+)?days?\b", re.I),
    "minutes": re.compile(r"\b(\d{1,5})\s*(?:minutes?|mins?)\b", re.I),
    "hours": re.compile(r"\b(\d{1,4})\s*hours?\b", re.I),
    "attempts": re.compile(r"\b(\d{1,4})\s+(?:consecutive\s+)?(?:invalid|unsuccessful|failed)\b", re.I),
}
_STRICT_RECORDING = re.compile(r"\brecord\w*\b[^.;]{0,80}\b(?:all|every|each)\b[^.;]{0,60}\bsessions?\b"
                               r"|\b(?:all|every|each)\b[^.;]{0,60}\bsessions?\b[^.;]{0,40}\brecord\w*", re.I)
_PARTIAL_WORDING = re.compile(r"\bpartial\w*\b", re.I)


def _outside_brackets(text: str) -> str:
    return re.sub(r"\[[^\]]*\]", " ", text)


def extract(kind: str, text: str, spec: Any) -> tuple[Any, str] | tuple[None, str]:
    """(value, grounding) from the passage itself, or (None, reason)."""
    plain = _outside_brackets(text)
    if kind in _UNITS:
        values = {int(m.group(1)) for m in _UNITS[kind].finditer(plain)}
        if not values:
            return None, f"no {kind} value is stated in the passage"
        if len(values) > 1:
            return None, f"more than one {kind} value is stated ({sorted(values)}); the binding value is ambiguous"
        value = values.pop()
        low, high = getattr(spec, "minimum", None), getattr(spec, "maximum", None)
        if (low is not None and value < low) or (high is not None and value > high):
            return None, f"the stated value {value} is outside the rule's range {low}..{high}"
        m = next(_UNITS[kind].finditer(plain))
        return value, m.group(0)
    if kind == "strict_recording":
        if _PARTIAL_WORDING.search(plain):
            return None, "the passage mentions partial recordings; their acceptance is not stated unambiguously"
        m = _STRICT_RECORDING.search(plain)
        if not m:
            return None, "the passage does not require recording of all/every/each session"
        return False, m.group(0)
    return None, "the source does not state this parameter (e.g. accepted MFA methods, lockout handling)"


def partially_parsed(req: dict[str, Any], ref: dict[str, Any]) -> str | None:
    text = req.get("translation_en") or req.get("original_text") or ""
    if text.count("[") != text.count("]") or text.count("(") < text.count(")") - 1:
        return "unbalanced brackets: the passage was cut while parsing"
    if ref.get("status") in ("QUOTE_NOT_LOCATED", "NO_SOURCE_SECTION"):
        return f"the quote cannot be located in its source ({ref.get('status')})"
    return None


def matching(req: dict[str, Any], ref: dict[str, Any]) -> list[Recipe]:
    text = req.get("translation_en") or req.get("original_text") or ""
    out = []
    topic_rules = {rule for _n, rule, _p in mp.topics(text) if rule}
    privileged = bool(re.search(r"\b(?:privileg\w*|administrat\w*|admin-?level|root|superuser|privilegiert\w*)\b",
                                text, re.I))
    for r in RECIPES:
        if r.text:
            if privileged and r.rule_id in topic_rules:
                out.append(r)
        elif ref.get("status") == "DERIVED" and any(
                ref.get("canonical_id") == cid and (ref.get("clause") or None) == clause
                and (ref.get("control_title") or "").upper() == title for cid, clause, title in r.canonical):
            out.append(r)
    return out


def recipe_catalog(engine: Any, collected: tuple[str, ...] | list[str]) -> list[dict[str, Any]]:
    """Support status of every recipe against the running bundle and collectors (never claimed otherwise)."""
    out = []
    for r in RECIPES:
        versions = {v: s for v, s in ((getattr(engine, "rules", {}) or {}).get(r.rule_id) or {}).items()
                    if s.status == "ACTIVE"}
        status = ("RULE_UNAVAILABLE" if not versions else "RULE_VERSION_AMBIGUOUS" if len(versions) > 1
                  else EVIDENCE_SCHEMA_INCOMPATIBLE if next(iter(versions.values())).evidence_type != r.evidence_type
                  else "COLLECTOR_UNAVAILABLE" if r.rule_id not in collected
                  else "PARAMETERS_NEVER_IN_SOURCE" if any(k == "never" for _p, k in r.params) else "SUPPORTED")
        out.append({"recipe_id": r.recipe_id, "kind": "TEXT" if r.text else "CANONICAL", "rule_id": r.rule_id,
                    "rule_version": next(iter(versions)) if len(versions) == 1 else None,
                    "evidence_type": r.evidence_type, "parameters": [{"name": p, "extractor": k} for p, k in r.params],
                    "canonical": [{"canonical_id": c, "clause": cl, "control_title": t} for c, cl, t in r.canonical],
                    "support_status": status, "tests": r.tests, "limitations": r.limitations})
    return out


VISIBLE = "(m.organization_scope IS NULL OR m.organization_scope IS ? OR m.organization_scope IS ?)"


def resolve(db: CatalogDb, req: dict[str, Any], ref: dict[str, Any], engine: Any,
            collected: tuple[str, ...] | list[str], *, _cache: dict[int, Any] | None = None,
            scope: str | None = None) -> dict[str, Any]:
    """One structured decision: {decision: PROPOSED|EXISTING|NOT_MAPPED, code, ...}."""
    rid = req["id"]
    base = {"requirement_id": rid, "canonical_reference": ref, "recipe_set_version": RECIPE_SET_VERSION}

    def no(code: str, message: str, **extra: Any) -> dict[str, Any]:
        return {**base, "decision": "NOT_MAPPED", "code": code, "message": message, **extra}

    text = req.get("translation_en") or req.get("original_text") or ""
    if req.get("obligation_type") != "MANDATORY":
        return no(NOT_MANDATORY, f"obligation type is {req.get('obligation_type')}; only MANDATORY duties are mapped")
    problems = mp.assess(db, req, _cache=_cache)
    if problems:
        return no(problems[0]["code"], problems[0]["message"])
    why = partially_parsed(req, ref)
    if why:
        return no(PARTIALLY_PARSED, why)
    recipes = matching(req, ref)
    rules = sorted({r.rule_id for r in recipes})
    if not rules:
        return no(mp.NO_EXECUTABLE_RULE if any(rule is None for _n, rule, _p in mp.topics(text)) else mp.MAPPING_MISSING,
                  "no deterministic recipe resolves an executable rule for this passage")
    if len(rules) > 1:
        return no(AMBIGUOUS_REQUIREMENT, f"more than one rule is resolved ({rules}); a person must decide",
                  candidate_rules=rules)
    recipe = sorted(recipes, key=lambda r: (r.text, r.recipe_id))[0]  # canonical recipe first when both match
    versions ={v: s for v, s in ((getattr(engine, "rules", {}) or {}).get(recipe.rule_id) or {}).items()
                if s.status == "ACTIVE"}
    if not versions:
        return no(RULE_UNAVAILABLE, f"{recipe.rule_id} has no ACTIVE version in the running bundle",
                  rule_id=recipe.rule_id, recipe_id=recipe.recipe_id)
    if len(versions) > 1:
        return no(RULE_VERSION_AMBIGUOUS, f"{recipe.rule_id} has several ACTIVE versions {sorted(versions)}",
                  rule_id=recipe.rule_id, recipe_id=recipe.recipe_id)
    version, spec = next(iter(versions.items()))
    if spec.evidence_type != recipe.evidence_type:
        return no(EVIDENCE_SCHEMA_INCOMPATIBLE, f"{recipe.rule_id} {version} uses {spec.evidence_type}, the recipe "
                  f"expects {recipe.evidence_type}", rule_id=recipe.rule_id, recipe_id=recipe.recipe_id)
    if recipe.rule_id not in collected:
        return no(mp.COLLECTOR_MISSING, f"no evidence collector supplies {spec.evidence_type} for {recipe.rule_id}",
                  rule_id=recipe.rule_id, rule_version=version, recipe_id=recipe.recipe_id)
    odp = mp.organization_defined(text)  # same order as mapping_policy.mapping_gaps: collector first
    if odp:
        return no(mp.POLICY_CONTEXT_REQUIRED, "the passage leaves values or selectors to the organization",
                  rule_id=recipe.rule_id, rule_version=version, recipe_id=recipe.recipe_id, organization_defined=odp)
    stated = {p for p, _k in recipe.params}
    if stated != set(spec.parameters):
        return no(PARAMETER_NOT_SOURCE_GROUNDED, f"the recipe grounds {sorted(stated)}, the rule needs "
                  f"{sorted(spec.parameters)}", rule_id=recipe.rule_id, recipe_id=recipe.recipe_id)
    params, provenance, constraints = {}, [], {}
    for name, kind in recipe.params:
        value, grounding = extract(kind, text, spec.parameters[name])
        if value is None:
            return no(PARAMETER_NOT_SOURCE_GROUNDED, f"parameter '{name}': {grounding}", rule_id=recipe.rule_id,
                      rule_version=version, recipe_id=recipe.recipe_id)
        params[name] = value
        provenance.append({"name": name, "value": value, "provenance": "SOURCE_TEXT", "source_text": grounding})
        if kind in _UNITS:  # local policy may be stricter, never weaker than the stated value
            constraints[name] = {"min": spec.parameters[name].minimum or 1, "max": value}
    # visible mappings only: global ones, the requirement's own namespace and the caller's organization
    live = db.q("SELECT m.id, m.status, m.rule_id, m.rule_parameters FROM framework_control_mapping m "
                "WHERE m.requirement_id=? AND m.status IN ('DRAFT','APPROVED') AND " + VISIBLE,
                (rid, req.get("organization_scope"), scope))
    same = [m for m in live if m["rule_id"] == recipe.rule_id and canonical(m["rule_parameters"] or {}) == canonical(params)]
    others = [m["id"] for m in live if m not in same]
    if others:
        return no(MAPPING_CONFLICT, "a different live mapping exists for this requirement; it is kept",
                  rule_id=recipe.rule_id, conflicting_mapping_ids=others)
    rationale = (f"AUTOMATED ({RECIPE_SET_VERSION}, recipe {recipe.recipe_id}): {recipe.rule_id} {version} tests that "
                 f"{recipe.tests}. Parameters stated in the passage: "
                 + ("; ".join(f"{p['name']}={p['value']} ('{p['source_text']}')" for p in provenance) or "none")
                 + ". The rule checks the technical control only; it does not interpret the full obligation.")
    limitations = f"PARTIAL technical coverage. {recipe.limitations}"
    out = {**base, "decision": "EXISTING" if same else "PROPOSED", "code": None, "recipe_id": recipe.recipe_id,
           "rule_id": recipe.rule_id, "rule_version": version, "evidence_type": spec.evidence_type,
           "parameters": params, "parameter_provenance": provenance, "override_constraints": constraints,
           "coverage": "PARTIAL", "rationale": rationale, "limitations": limitations}
    if same:
        out["mapping_id"] = same[0]["id"]
    problems = validate(out)
    if problems:
        return no(VALIDATION_FAILED, "; ".join(problems), rule_id=recipe.rule_id)
    return out


def validate(d: dict[str, Any]) -> list[str]:
    """Coverage, rationale and limitations of a proposed automated mapping."""
    out = []
    if d.get("coverage") != "PARTIAL":
        out.append("automated mappings are PARTIAL coverage only")
    if len(d.get("rationale") or "") < 60 or d["rule_id"] not in d["rationale"]:
        out.append("rationale must name the rule and what it tests")
    if not (d.get("limitations") or "").startswith("PARTIAL") or len(d["limitations"]) < 40:
        out.append("limitations must state the partial coverage")
    for p in d.get("parameter_provenance", []):
        if p["provenance"] != "SOURCE_TEXT" or not p.get("source_text"):
            out.append(f"parameter {p['name']} is not source-grounded")
    return out
