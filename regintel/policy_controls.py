"""Schema-driven policy-control catalog (organization policy contexts).

A *policy control* is a versioned, Securden-defined description of something an
organization can declare in its own policy: parameters (as a JSON Schema
subset), the target types it can apply to, how it is assessed, and - only when
an implementation exists - the pinned rule version and evidence contract that
test it. Controls are code-reviewed data: nothing here accepts uploaded Rego or
expressions, and no value is ever filled in by default.

Assessment modes
  CONFIGURATION_SNAPSHOT  the evidence is a configuration captured at one instant
                          inside the reporting period; a PASS describes that
                          configuration, not enforcement over the period
  EVENT_HISTORY           the evidence is the events / state history of the
                          reporting period (what actually happened)

A control is end-to-end assessable only when it is EXECUTABLE, its pinned rule
version is in the running bundle, and the organization's collector declared a
compatible evidence schema version (collector capability handshake).
"""
from __future__ import annotations

import math
import re
from typing import Any

from .db import digest_of
from . import mapping_policy

CONTROL_CATALOG_VERSION = "2026.11.16-1"
SCHEMA_DIALECT = "securden-policy-schema-subset/1"

CONFIGURATION_SNAPSHOT = "CONFIGURATION_SNAPSHOT"
EVENT_HISTORY = "EVENT_HISTORY"
ASSESSMENT_MODES = {
    CONFIGURATION_SNAPSHOT: "Configuration captured at one instant inside the reporting period. A PASS describes that "
                            "configuration only; it is not evidence that the setting was enforced for every event.",
    EVENT_HISTORY: "Events or state history of the reporting period: what actually happened.",
}
EXECUTABLE, NOT_IMPLEMENTED = "EXECUTABLE", "NOT_IMPLEMENTED"

# Target references are a type plus an opaque PAM identifier. OPM never treats them as
# proof of membership or authorization; Django resolves them inside the organization.
TARGET_TYPES: dict[str, dict[str, Any]] = {
    "ORGANIZATION": {"kind": "ALL", "description": "Every in-scope object of the control's subject type in the "
                                                   "organization scope (resolved by Django). Takes no id."},
    "ACCOUNT": {"kind": "LEAF", "description": "One privileged account."},
    "ACCOUNT_GROUP": {"kind": "GROUP", "member_type": "ACCOUNT", "description": "A PAM account group or folder."},
    "USER": {"kind": "LEAF", "description": "One PAM user."},
    "USER_GROUP": {"kind": "GROUP", "member_type": "USER", "description": "A PAM user group or role."},
    "RESOURCE": {"kind": "LEAF", "description": "One managed system (server, database, application)."},
    "RESOURCE_GROUP": {"kind": "GROUP", "member_type": "RESOURCE", "description": "A group of managed systems."},
    "SESSION_POLICY": {"kind": "LEAF", "description": "One session policy."},
    "AUDIT_SOURCE": {"kind": "LEAF", "description": "One audit log source."},
}

# ---------------------------------------------------------------- JSON Schema subset

TYPE_KEYWORDS: dict[str, frozenset[str]] = {
    "boolean": frozenset(),
    "integer": frozenset({"minimum", "maximum", "enum"}),
    "number": frozenset({"minimum", "maximum"}),
    "string": frozenset({"minLength", "maxLength", "pattern", "enum"}),
    "array": frozenset({"items", "minItems", "maxItems", "uniqueItems"}),
    "object": frozenset({"properties", "required", "additionalProperties"}),
}
ANNOTATIONS = frozenset({"title", "description"})
SCHEMA_SUBSET = {
    "dialect": SCHEMA_DIALECT,
    "types": sorted(TYPE_KEYWORDS),
    "keywords": {t: sorted(k | {"type"} | ANNOTATIONS) for t, k in TYPE_KEYWORDS.items()},
    "rules": [
        "Every schema node has exactly one 'type' from 'types'.",
        "Objects must list every property in 'required' and set additionalProperties to false: no optional "
        "parameter and no default is ever filled in by OPM.",
        "Arrays have exactly one 'items' schema.",
        "'enum' lists strings (type string) or integers (type integer).",
        "'pattern' is an ECMA-262 / Python-compatible regular expression anchored with ^...$.",
        "integer accepts JSON integers only (true/false and 5.0 are rejected); number accepts integers and finite "
        "decimals; boolean accepts true/false only.",
        "Any other keyword (default, $ref, oneOf, anyOf, allOf, not, const, format, multipleOf, exclusiveMinimum, "
        "patternProperties, if/then/else, ...) is unsupported and rejected.",
    ],
}


def schema_problems(schema: Any, path: str = "$") -> list[str]:
    """Reasons a schema is outside the supported subset (empty when valid)."""
    if not isinstance(schema, dict):
        return [f"{path}: a schema must be an object"]
    kind = schema.get("type")
    if kind not in TYPE_KEYWORDS:
        return [f"{path}: unsupported or missing type {kind!r}"]
    problems = [f"{path}: unsupported keyword '{k}' for type {kind}"
                for k in sorted(set(schema) - TYPE_KEYWORDS[kind] - ANNOTATIONS - {"type"})]
    if kind == "object":
        props = schema.get("properties")
        if not isinstance(props, dict) or not props:
            problems.append(f"{path}: object needs non-empty properties")
            props = {}
        if schema.get("additionalProperties") is not False:
            problems.append(f"{path}: additionalProperties must be false")
        if sorted(schema.get("required") or []) != sorted(props):
            problems.append(f"{path}: every property must be required")
        for name, sub in props.items():
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name):
                problems.append(f"{path}.{name}: property names are lower_snake_case")
            problems += schema_problems(sub, f"{path}.{name}")
    elif kind == "array":
        if "items" not in schema:
            problems.append(f"{path}: array needs items")
        else:
            problems += schema_problems(schema["items"], f"{path}[]")
    elif "enum" in schema:
        enum = schema["enum"]
        want = str if kind == "string" else int
        if not isinstance(enum, list) or not enum or any(not isinstance(v, want) or isinstance(v, bool) for v in enum):
            problems.append(f"{path}: enum must be a non-empty list of {kind} values")
    if kind == "string" and "pattern" in schema:
        pat = schema["pattern"]
        if not isinstance(pat, str) or not (pat.startswith("^") and pat.endswith("$")):
            problems.append(f"{path}: pattern must be anchored ^...$")
        else:
            try:
                re.compile(pat)
            except re.error:
                problems.append(f"{path}: pattern is not a valid regular expression")
    return problems


def value_problems(schema: dict[str, Any], value: Any, path: str = "$") -> list[dict[str, str]]:
    """Strict validation of ``value`` against a subset schema. No coercion, no defaults."""
    def bad(code: str, message: str) -> list[dict[str, str]]:
        return [{"code": code, "path": path, "message": message}]

    kind = schema["type"]
    if kind == "boolean":
        return [] if isinstance(value, bool) else bad("INVALID_TYPE", "expected a boolean")
    if kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            return bad("INVALID_TYPE", "expected an integer")
    elif kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            return bad("INVALID_TYPE", "expected a finite number")
    elif kind == "string":
        if not isinstance(value, str):
            return bad("INVALID_TYPE", "expected a string")
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 10_000):
            return bad("OUT_OF_RANGE", f"length must be {schema.get('minLength', 0)}..{schema.get('maxLength', 10_000)}")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            return bad("PATTERN_MISMATCH", f"must match {schema['pattern']}")
    elif kind == "array":
        if not isinstance(value, list):
            return bad("INVALID_TYPE", "expected an array")
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 1000):
            return bad("OUT_OF_RANGE", f"must have {schema.get('minItems', 0)}..{schema.get('maxItems', 1000)} items")
        if schema.get("uniqueItems") and len({digest_of(v) for v in value}) != len(value):
            return bad("DUPLICATE_ITEMS", "items must be unique")
        out: list[dict[str, str]] = []
        for i, item in enumerate(value):
            out += value_problems(schema["items"], item, f"{path}[{i}]")
        return out
    elif kind == "object":
        if not isinstance(value, dict):
            return bad("INVALID_TYPE", "expected an object")
        props = schema["properties"]
        out = [{"code": "UNKNOWN_PARAMETER", "path": f"{path}.{k}", "message": "not defined by the control schema"}
               for k in sorted(set(value) - set(props))]
        out += [{"code": "MISSING_PARAMETER", "path": f"{path}.{k}",
                 "message": "required: every value must be stated explicitly (no defaults)"}
                for k in sorted(set(props) - set(value))]
        for k in sorted(set(props) & set(value)):
            out += value_problems(props[k], value[k], f"{path}.{k}")
        return out
    if "enum" in schema and value not in schema["enum"]:
        return bad("NOT_IN_ENUM", f"must be one of {schema['enum']}")
    if kind in ("integer", "number"):
        low, high = schema.get("minimum"), schema.get("maximum")
        if (low is not None and value < low) or (high is not None and value > high):
            return bad("OUT_OF_RANGE", f"must be between {low} and {high}")
    return []


# ---------------------------------------------------------------- definitions

MFA_METHODS = ["email_otp", "fido2", "hardware_token", "push", "smart_card", "sms", "totp"]


def _int(low: int, high: int, title: str) -> dict[str, Any]:
    return {"type": "integer", "minimum": low, "maximum": high, "title": title}


def _bool(title: str) -> dict[str, Any]:
    return {"type": "boolean", "title": title}


def _obj(**props: dict[str, Any]) -> dict[str, Any]:
    return {"type": "object", "properties": props, "required": sorted(props), "additionalProperties": False}


def _ui(**params: tuple[str, str, str]) -> dict[str, Any]:
    return {"order": list(params), "parameters": {k: {"label": label, "unit": unit, "help": help_}
                                                   for k, (label, unit, help_) in params.items()}}


ACCOUNT_TARGETS = ["ORGANIZATION", "ACCOUNT", "ACCOUNT_GROUP", "RESOURCE", "RESOURCE_GROUP"]
ACCESS_TARGETS = ["ORGANIZATION", "USER", "USER_GROUP", "ACCOUNT", "ACCOUNT_GROUP", "RESOURCE", "RESOURCE_GROUP"]


def _exec(rule_id: str, rule_version: str, evidence_type: str, params: list[str],
          limitations: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return ([{"rule_id": rule_id, "rule_version": rule_version, "evidence_type": evidence_type,
              "parameter_map": {p: p for p in params}}],
            {"status": EXECUTABLE, "limitations": limitations})


def _definitions() -> list[dict[str, Any]]:
    d: list[dict[str, Any]] = []

    def add(control_id: str, category: str, pam_control_id: str | None, title: str, description: str,
            schema: dict[str, Any], ui: dict[str, Any], targets: list[str], mode: str,
            bindings: list[dict[str, Any]], implementation: dict[str, Any], addresses: list[str] | None = None) -> None:
        d.append({"control_id": control_id, "control_version": "1.0", "category": category,
                  "pam_control_id": pam_control_id, "title": title, "description": description,
                  "parameter_schema": schema, "ui": ui, "target_types": targets, "assessment_mode": mode,
                  "bindings": bindings, "implementation": implementation,
                  # mapping-gap topics (regintel.mapping_policy) whose POLICY_CONTEXT_REQUIRED this control can resolve
                  "addresses_gap_rules": addresses if addresses is not None else [b["rule_id"] for b in bindings]})

    add("PC-CRED-ROTATION", "credential_lifecycle", "PAMC-CRED-ROTATION", "Privileged credential rotation interval",
        "Maximum age of a privileged credential before it must have been rotated successfully.",
        _obj(max_rotation_age_days=_int(1, 730, "Maximum credential age")),
        _ui(max_rotation_age_days=("Maximum credential age", "days", "Accounts not rotated within this many days "
                                                                     "before the period end fail.")),
        ACCOUNT_TARGETS, EVENT_HISTORY,
        *_exec("PAM-ROTATION-001", "1.1", "credential_rotation", ["max_rotation_age_days"],
               ["Rule 1.1 is effective from 2026-07-01; earlier reporting periods cannot use this control version."]))
    add("PC-SESSION-RECORDING", "session_monitoring", "PAMC-SESSION-RECORDING", "Privileged session recording",
        "Privileged sessions that the PAM recording policy marks as requiring recording must have a recording.",
        _obj(accept_partial_recordings=_bool("Accept partial recordings")),
        _ui(accept_partial_recordings=("Accept partial recordings", "none", "When false, a PARTIAL recording is a "
                                                                            "violation.")),
        ACCESS_TARGETS, EVENT_HISTORY,  # users/roles: e.g. NIST AU-14 "organization-defined users or roles"
        *_exec("PAM-SESSREC-001", "1.0", "privileged_session", ["accept_partial_recordings"],
               ["Which sessions require recording comes from the PAM recording policy (recording_required); "
                "the control does not decide that.",
                "Tests that required recordings exist. It does not test who may view or hear them, under which "
                "circumstances recording applies, or legal review of session auditing."]))
    add("PC-ACCESS-APPROVAL", "privileged_access_management", "PAMC-ACCESS-APPROVAL",
        "Approval before privileged access", "Privileged access requiring approval is approved, recently enough, "
                                             "before use.",
        _obj(max_approval_age_hours=_int(1, 720, "Maximum approval age")),
        _ui(max_approval_age_hours=("Maximum approval age", "hours", "An approval older than this at access time "
                                                                    "fails.")),
        ACCESS_TARGETS, EVENT_HISTORY,
        *_exec("PAM-APPROVAL-001", "1.0", "privileged_access_request", ["max_approval_age_hours"], []))
    add("PC-DORMANT-ACCOUNTS", "identity_governance", "PAMC-DORMANT-ACCOUNTS", "Dormant privileged accounts",
        "Enabled privileged accounts unused for longer than the limit are violations.",
        _obj(dormant_after_days=_int(1, 730, "Dormant after")),
        _ui(dormant_after_days=("Dormant after", "days", "Inactivity measured to the reporting period end.")),
        ACCOUNT_TARGETS, EVENT_HISTORY,
        *_exec("PAM-DORMANT-001", "1.0", "privileged_account", ["dormant_after_days"], []))
    add("PC-AUTH-FAILURE-MONITORING", "security_event_monitoring", "PAMC-AUTH-FAILURE-MONITORING",
        "Failed authentication threshold", "Excessive failed authentication attempts per principal and window. This "
                                           "is monitoring of failed logons; it is not multi-factor authentication.",
        _obj(max_failed_attempts=_int(1, 1000, "Maximum failed attempts"), window_minutes=_int(1, 1440, "Window"),
             lockout_is_mitigation=_bool("Lockout counts as mitigation")),
        _ui(max_failed_attempts=("Maximum failed attempts", "count", "Per principal within the window."),
            window_minutes=("Window", "minutes", "Length of the counting window."),
            lockout_is_mitigation=("Lockout counts as mitigation", "none", "When true, a triggered lockout is not a "
                                                                          "violation.")),
        ["ORGANIZATION", "USER", "USER_GROUP"], EVENT_HISTORY,
        *_exec("PAM-AUTHFAIL-001", "1.0", "authentication_summary",
               ["max_failed_attempts", "window_minutes", "lockout_is_mitigation"],
               ["Monitors failed logons only; this is not MFA evidence (use PC-MFA-AT-ACCESS)."]))
    add("PC-ACCESS-AUTHORIZATION", "access_control", "PAMC-ACCESS-AUTHORIZATION", "Entitlement-based access",
        "Privileged access is exercised only under a valid entitlement.", _obj_empty(), _ui(),
        ACCESS_TARGETS, EVENT_HISTORY, *_exec("PAM-UNAUTH-001", "1.0", "access_authorization", [], []))
    add("PC-EMERGENCY-ACCESS", "emergency_access", "PAMC-EMERGENCY-ACCESS", "Break-glass governance",
        "Emergency access is justified, ticketed when required, and reviewed after use.",
        _obj(min_justification_length=_int(1, 2000, "Minimum justification length"),
             require_ticket_reference=_bool("Require ticket reference"),
             post_review_within_hours=_int(0, 2160, "Post-review deadline")),
        _ui(min_justification_length=("Minimum justification length", "characters", ""),
            require_ticket_reference=("Require ticket reference", "none", ""),
            post_review_within_hours=("Post-review deadline", "hours", "Review must complete within this many hours.")),
        ACCESS_TARGETS, EVENT_HISTORY,
        *_exec("PAM-BREAKGLASS-001", "1.0", "break_glass_event",
               ["min_justification_length", "require_ticket_reference", "post_review_within_hours"], []))
    add("PC-POLICY-EXCEPTIONS", "identity_governance", "PAMC-POLICY-EXCEPTIONS", "Policy exception lifetime",
        "Policy exceptions are time-bound and not used after expiry or revocation.",
        _obj(max_exception_duration_days=_int(1, 1095, "Maximum exception duration")),
        _ui(max_exception_duration_days=("Maximum exception duration", "days", "")),
        ["ORGANIZATION"], EVENT_HISTORY,
        *_exec("PAM-EXCEPTION-001", "1.0", "policy_exception", ["max_exception_duration_days"], []))
    add("PC-ACCESS-REVIEW", "access_reviews", "PAMC-ACCESS-REVIEW", "Periodic privileged access review",
        "Privileged accounts are reviewed at least every interval.",
        _obj(review_interval_days=_int(1, 730, "Review interval")),
        _ui(review_interval_days=("Review interval", "days", "")),
        ACCOUNT_TARGETS, EVENT_HISTORY,
        *_exec("PAM-REVIEW-001", "1.0", "access_review", ["review_interval_days"], []))
    add("PC-AUDIT-LOG-COMPLETENESS", "audit_logging", "PAMC-AUDIT-LOG-COMPLETENESS", "Audit log completeness",
        "Audit sources are complete, gap-free within tolerance and integrity-verified.",
        _obj(min_completeness_percent=_int(1, 100, "Minimum completeness"),
             max_allowed_gap_seconds=_int(0, 604800, "Maximum gap"),
             require_integrity_verification=_bool("Require integrity verification")),
        _ui(min_completeness_percent=("Minimum completeness", "percent", ""),
            max_allowed_gap_seconds=("Maximum gap", "seconds", ""),
            require_integrity_verification=("Require integrity verification", "none", "")),
        ["ORGANIZATION", "AUDIT_SOURCE"], EVENT_HISTORY,
        *_exec("PAM-AUDITCOMP-001", "1.0", "audit_log_coverage",
               ["min_completeness_percent", "max_allowed_gap_seconds", "require_integrity_verification"], []))
    methods = {"type": "array", "items": {"type": "string", "enum": MFA_METHODS}, "minItems": 1,
               "maxItems": len(MFA_METHODS), "uniqueItems": True, "title": "Accepted MFA methods"}
    add("PC-MFA-CONFIGURATION", "authentication", "PAMC-MFA-PRIVILEGED", "MFA enforcement configured",
        "MFA is configured as enforced, with an accepted method, for privileged users and accounts.",
        _obj(accepted_methods=methods),
        _ui(accepted_methods=("Accepted MFA methods", "none", "At least one enforced method must be in this list.")),
        ["ORGANIZATION", "USER", "USER_GROUP", "ACCOUNT", "ACCOUNT_GROUP"], CONFIGURATION_SNAPSHOT,
        *_exec("PAM-MFACFG-001", "1.0", "mfa_configuration", ["accepted_methods"],
               ["Configuration snapshot only: shows the configuration at captured_at, not that MFA was performed at "
                "each access. It therefore never resolves a requirement to use MFA when accessing (see "
                "PC-MFA-AT-ACCESS)."]),
        addresses=[])
    add("PC-MFA-AT-ACCESS", "authentication", "PAMC-MFA-PRIVILEGED", "MFA performed at privileged access",
        "Every granted privileged access was preceded by a verified MFA challenge with an accepted method.",
        _obj(accepted_methods=methods),
        _ui(accepted_methods=("Accepted MFA methods", "none", "A verified challenge with another method fails.")),
        ACCESS_TARGETS, EVENT_HISTORY,
        *_exec("PAM-MFAACC-001", "1.0", "privileged_access_authentication", ["accepted_methods"],
               ["Failed-logon monitoring (PC-AUTH-FAILURE-MONITORING) is not MFA evidence."]))
    add("PC-SESSION-IDLE-LIMIT", "session_monitoring", "PAMC-SESSION-LIMITS", "Privileged session idle limit",
        "Session policies applying to privileged sessions lock or terminate idle sessions within the limit.",
        _obj(max_idle_minutes=_int(1, 1440, "Maximum idle time")),
        _ui(max_idle_minutes=("Maximum idle time", "minutes", "Configured idle timeout must not exceed this.")),
        ["ORGANIZATION", "SESSION_POLICY"], CONFIGURATION_SNAPSHOT,
        *_exec("PAM-SESSIDLE-001", "1.0", "session_policy_configuration", ["max_idle_minutes"],
               ["Configuration snapshot of session policies; individual sessions' idle behaviour is not measured."]))
    add("PC-SESSION-DURATION-LIMIT", "session_monitoring", "PAMC-SESSION-LIMITS", "Privileged session duration limit",
        "No privileged session lasts longer than the maximum.",
        _obj(max_session_minutes=_int(1, 10080, "Maximum session duration")),
        _ui(max_session_minutes=("Maximum session duration", "minutes", "Open sessions are measured to the period "
                                                                         "end.")),
        ACCOUNT_TARGETS, EVENT_HISTORY,
        *_exec("PAM-SESSDUR-001", "1.0", "privileged_session", ["max_session_minutes"], []))
    add("PC-PASSWORD-POLICY", "credential_lifecycle", "PAMC-CRED-ROTATION", "Password composition policy",
        "Minimum length, character classes, entropy and history of privileged passwords.",
        _obj(min_length=_int(8, 256, "Minimum length"), required_character_classes=_int(0, 4, "Character classes"),
             min_entropy_bits={"type": "number", "minimum": 0, "maximum": 512, "title": "Minimum entropy"},
             history_depth=_int(0, 100, "Password history")),
        _ui(min_length=("Minimum length", "characters", ""), required_character_classes=("Character classes", "count", ""),
            min_entropy_bits=("Minimum entropy", "bits", ""), history_depth=("Password history", "count", "")),
        ACCOUNT_TARGETS, CONFIGURATION_SNAPSHOT, [],
        {"status": NOT_IMPLEMENTED, "limitations": ["No rule or evidence contract exists; saved values are "
                                                    "documented policy only and always report NO_EXECUTABLE_RULE."]})
    add("PC-SEGREGATION-OF-DUTIES", "segregation_of_duties", "PAMC-SEGREGATION-OF-DUTIES",
        "Segregation of duties for privileged operations",
        "Role pairs that one identity must never hold together, and whether the PAM prevents or only detects it.",
        _obj(conflicting_role_pairs={"type": "array", "minItems": 1, "maxItems": 50, "uniqueItems": True,
                                     "items": _obj(first_role={"type": "string", "minLength": 1, "maxLength": 128,
                                                               "pattern": r"^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,127}$"},
                                                   second_role={"type": "string", "minLength": 1, "maxLength": 128,
                                                                "pattern": r"^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,127}$"})},
             enforcement={"type": "string", "enum": ["PREVENT", "DETECT"]}),
        _ui(conflicting_role_pairs=("Conflicting role pairs", "none", "Opaque PAM role names."),
            enforcement=("Enforcement", "none", "")),
        ["ORGANIZATION", "USER_GROUP"], CONFIGURATION_SNAPSHOT, [],
        {"status": NOT_IMPLEMENTED, "limitations": ["No rule or evidence contract exists; documented policy only."]})
    return d


def _obj_empty() -> dict[str, Any]:
    return {"type": "object", "properties": {}, "required": [], "additionalProperties": False}


def _finalise(defn: dict[str, Any]) -> dict[str, Any]:
    from app.models.evidence import EVIDENCE_MODELS, EVIDENCE_SCHEMA_VERSIONS

    for b in defn["bindings"]:
        b["evidence_schema_version"] = EVIDENCE_SCHEMA_VERSIONS[b["evidence_type"]]
        b["evidence_schema"] = EVIDENCE_MODELS[b["evidence_type"]].model_json_schema()
    defn["definition_digest"] = "sha256:" + digest_of({k: v for k, v in defn.items() if k != "definition_digest"})
    return defn


def _check(defs: list[dict[str, Any]]) -> None:
    seen: set[tuple[str, str]] = set()
    for c in defs:
        key = (c["control_id"], c["control_version"])
        if key in seen:
            raise RuntimeError(f"duplicate control {key}")
        seen.add(key)
        schema = c["parameter_schema"]
        problems = [] if schema == _obj_empty() else schema_problems(schema)
        if problems:
            raise RuntimeError(f"{key}: {problems}")
        if set(c["ui"]["parameters"]) != set(schema["properties"]):
            raise RuntimeError(f"{key}: UI metadata must describe every parameter")
        if not set(c["target_types"]) <= set(TARGET_TYPES) or c["assessment_mode"] not in ASSESSMENT_MODES:
            raise RuntimeError(f"{key}: invalid targets or assessment mode")
        if (c["implementation"]["status"] == EXECUTABLE) != bool(c["bindings"]):
            raise RuntimeError(f"{key}: executable controls need bindings and vice versa")
        for b in c["bindings"]:
            if set(b["parameter_map"]) != set(schema["properties"]):
                raise RuntimeError(f"{key}: every control parameter must map to a rule parameter")


_DEFS = _definitions()
_check(_DEFS)
CONTROLS: dict[tuple[str, str], dict[str, Any]] = {(c["control_id"], c["control_version"]): _finalise(c)
                                                    for c in _DEFS}


def get(control_id: str, control_version: str) -> dict[str, Any] | None:
    return CONTROLS.get((control_id, control_version))


# ---------------------------------------------------------------- collector support

LEGACY_BRIDGE_RULES = mapping_policy.DEFAULT_BRIDGE_COLLECTED_RULES  # collected before the handshake existed


def legacy_capabilities() -> dict[str, Any]:
    """Collector support assumed for scopes that never sent a handshake: only the three
    evidence contracts the original Django bridge collects (and only when still configured)."""
    from app.models.evidence import EVIDENCE_SCHEMA_VERSIONS

    rules = [r for r in mapping_policy.bridge_collected_rules() if r in LEGACY_BRIDGE_RULES]
    types = {b["evidence_type"] for c in CONTROLS.values() for b in c["bindings"] if b["rule_id"] in rules}
    return {"source": "LEGACY_BRIDGE_DEFAULT", "digest": None, "declared_at": None,
            "legacy_rules": sorted(rules),
            "evidence": {t: EVIDENCE_SCHEMA_VERSIONS[t] for t in sorted(types)}}


def binding_support(binding: dict[str, Any], capabilities: dict[str, Any], engine: Any) -> dict[str, Any]:
    """Whether one binding can run end to end for an organization: rule in bundle + collector support."""
    problems: list[str] = []
    spec = (getattr(engine, "rules", {}) or {}).get(binding["rule_id"], {}).get(binding["rule_version"])
    if spec is None:
        problems.append("RULE_NOT_IN_BUNDLE")
    elif spec.evidence_type != binding["evidence_type"] or set(spec.parameters) != set(binding["parameter_map"].values()):
        problems.append("RULE_CONTRACT_MISMATCH")
    declared = (capabilities.get("evidence") or {}).get(binding["evidence_type"])
    if capabilities.get("source") == "LEGACY_BRIDGE_DEFAULT" and binding["rule_id"] not in capabilities.get(
            "legacy_rules", []):
        declared = None  # the legacy default covers the original bridge rules only, never newer controls
    if declared is None:
        problems.append(mapping_policy.COLLECTOR_MISSING)
    elif declared != binding["evidence_schema_version"]:
        problems.append("EVIDENCE_SCHEMA_INCOMPATIBLE")
    return {"rule_id": binding["rule_id"], "rule_version": binding["rule_version"],
            "evidence_type": binding["evidence_type"], "evidence_schema_version": binding["evidence_schema_version"],
            "collector_declared_version": declared, "capability_source": capabilities.get("source"),
            "end_to_end_assessable": not problems, "blocker_codes": problems}


def collected_rules(capabilities: dict[str, Any], engine: Any) -> tuple[str, ...]:
    """Rules whose evidence this organization's collector declares in a compatible schema version."""
    return tuple(sorted({b["rule_id"] for c in CONTROLS.values() for b in c["bindings"]
                         if not {mapping_policy.COLLECTOR_MISSING, "EVIDENCE_SCHEMA_INCOMPATIBLE"}
                         & set(binding_support(b, capabilities, engine)["blocker_codes"])}))


def public(defn: dict[str, Any], *, capabilities: dict[str, Any] | None = None, engine: Any = None,
           include_evidence_schema: bool = True) -> dict[str, Any]:
    out = {k: v for k, v in defn.items()}
    out["bindings"] = [{k: v for k, v in b.items() if include_evidence_schema or k != "evidence_schema"}
                       for b in defn["bindings"]]
    if capabilities is None:
        out["assessability"] = {"end_to_end_assessable": None, "reason": "Send the organization scope header and "
                                "tenant_id to see collector support for this organization.", "bindings": []}
    elif defn["implementation"]["status"] != EXECUTABLE:
        out["assessability"] = {"end_to_end_assessable": False, "reason": mapping_policy.NO_EXECUTABLE_RULE,
                                "bindings": []}
    else:
        support = [binding_support(b, capabilities, engine) for b in defn["bindings"]]
        ok = all(s["end_to_end_assessable"] for s in support)
        out["assessability"] = {"end_to_end_assessable": ok,
                                "reason": None if ok else sorted({c for s in support for c in s["blocker_codes"]})[0],
                                "bindings": support}
    return out
