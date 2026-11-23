"""Bounded automatic rule generation (RuleSpec 1.0, compiler ``pam-rulespec-compiler-1.0``).

Used by ``prepare_catalog`` when no existing rule can be assigned to a PAM-applicable requirement
(``llm_mapping`` ended with NO_EXECUTABLE_RULE or LLM_NO_MAP). The local LLM may only return a JSON
*proposal* conforming to the allowlisted ``RuleSpec`` schema (``schemas/generated_rule_spec_v1.schema.json``).
It never writes Rego, expressions, rule ids or values. OPM-owned deterministic code then:

  1. scans the raw output for forbidden content (code, URLs, paths, templates, credential material,
     claims of full coverage) and parses it strictly (unknown fields are rejected);
  2. validates every evidence field against the pinned evidence schema AND the organization's collector
     handshake (evidence type, schema version, assessment mode, supported fields), every operator against
     the allowlist and its field type, and every unit;
  3. resolves every threshold from grounded sources only - regulatory text (exact quotation), then the
     organization's in-force settings (policy contexts); never the model, never a default;
  4. compiles the spec into the fixed structure evaluated by the pinned Rego interpreter
     ``securden.custom.v1`` (no Rego is generated: the interpreter is the single fixed template);
  5. builds deterministic validation cases (pass, fail, empty, incomplete, missing field, outside the
     reporting period, out of scope, numeric boundaries) from the evidence schema and the condition tree,
     and runs every case through the real OPA binary against the service's policy bundle;
  6. only then (and only with ``auto_publish_validated_rules``) activates the rule for the tenant in the
     evaluator's rule store and publishes an organization-scoped mapping (decision_origin AUTOMATED_LLM,
     coverage PARTIAL). Superseded generated mappings are withdrawn only after the replacement exists.

Generated rules use the ``PAM-GEN-<12 hex>`` namespace: the digest of organization scope, tenant, the
canonical rule structure and the resolved values, so an equivalent specification reuses the existing rule.
Every input, raw output, parsed proposal, check, test vector and result is preserved.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, model_validator

from app.engine.compiler import ENGINE_PACKAGE, compile_rule
from app.engine.evaluator import GENERATED_RULE_PREFIX, Evaluator, custom_spec_from_row
from app.models.api import Evidence, ReportingPeriod
from app.models.custom_rules import CustomFrameworkMapping, CustomRuleDefinition
from app.models.evidence import CUSTOM_RULE_FIELDS, EVIDENCE_SCHEMA_VERSIONS

from . import catalog, control_hub, mapping_recipes as mr, pam_vector_db, policy_contexts as pctx, policy_controls as pc
from .db import CatalogDb, CatalogError, canonical, digest_of, now_iso
from .llm import LlmError

SPEC_VERSION = "1.0"
COMPILER_VERSION = "pam-rulespec-compiler-1.0"
# v2: compact context and schema (v1 overflowed a 4096-token window, so the model never saw the requirement)
# v3: per-requirement decoding grammar (enums, no $ref/patterns), evidence screen, one synthetic example
# v4: the grammar pairs each field only with the operators its type allows (v3 let the model write "equals" on a
# string_list such as scope_tags, which validation then rejected), and offers exists/not_exists only on
# nullable fields
# v5: 'contains' only in population filters, exists/not_exists without a value, integer/datetime thresholds only
# as declared parameters, subject_field only a never-null identifier (each mirrors a validate() rule)
# v6: parameter names from a closed list; a condition repeating a population filter is rejected by name
# v7: no record_id/scope_tags in the grammar; each parameter name has one unit and only fits fields of that unit
# v8: enum/boolean literals typed per field, no empty anyOf (Ollama rejects it), unreferenced parameters and
# population filters that repeat the condition are removed before validation (recorded as a limitation)
# v9: v8 without the population-filter repair (it produced an unintended stricter rule for AC-2 f)
# v10: the model only names a parameter in the condition; OPM declares it (unit, setting binding) before validation
# v11: population filters take only boolean scope flags (statuses, timestamps, counts are condition-only)
# v12: scope flags filter only, every other field is condition-only (filter and condition are disjoint)
# v13: a condition requiring accounts to be enabled is rejected
# v14: limitations copied from the worked example are rejected; the example no longer says to declare parameters
# v15: reason first, then write, then review: a plain-text analysis (obligation, compliant vs violating record, the
# field that tells them apart, or NOT_TESTABLE / PERSON_JUDGES) precedes the grammar-constrained RuleSpec, fields
# carry their meaning (regintel/data/field_meanings.json or the collector's field_meanings), and an independent
# plain-text review must accept the finished rule; word grounding becomes a hint to the review instead of a gate
# v16: a NOT_TESTABLE analysis that names a declared test field with a value goes on to write and judge
# v17: that check also reads "`field` as VALUE", "field shows ...", "field: VALUE"
# v18: the review is a concrete choice between a passing and a failing example record (catches inverted rules)
PROMPT_VERSION = "rule-spec-v18"
POLICY_VERSION = "rule-gen-v1"
FLAG_GENERATE = "REGINTEL_AUTO_RULE_GENERATION"
FLAG_PUBLISH = "REGINTEL_AUTO_PUBLISH_GENERATED_RULES"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MIN_CONFIDENCE = 0.8
# existing-rule matching found nothing, or its candidate could not be assigned. The second group falls back to
# generation since matrix-candidates-v1 offers vetted rules for every hub control: before, those requirements had no
# candidate and were generated; a low-confidence or invalid answer on the vetted candidate left them with nothing
# (NIST run 2026-11-20: 24 requirements, e.g. AC-17(1), MA-4 a, IA-2, which had good generated rules before).
TRIGGER_CODES = frozenset({"NO_EXECUTABLE_RULE", "LLM_NO_MAP",
                           "LLM_MAPPING_AMBIGUOUS", "LLM_OUTPUT_INVALID", "VALIDATION_FAILED"})

# outcome codes (DJANGO_CONTRACT §5.4)
GENERATED_RULE_ACTIVATED = "GENERATED_RULE_ACTIVATED"
GENERATED_RULE_VALIDATED = "GENERATED_RULE_VALIDATED"  # passed every gate; activation not requested
OUTCOME_CODES = ("EXISTING_RULE_ASSIGNED", GENERATED_RULE_ACTIVATED, GENERATED_RULE_VALIDATED,
                 "PARAMETER_SOURCE_MISSING", "COLLECTOR_MISSING", "EVIDENCE_SCHEMA_INCOMPATIBLE",
                 "RULE_PROPOSAL_AMBIGUOUS", "RULE_SPEC_INVALID", "RULE_COMPILATION_FAILED", "RULE_TEST_FAILED",
                 "SOURCE_GROUNDING_FAILED", "POLICY_CONFLICT", "OUTSIDE_PAM_SCOPE", "MANUAL_ASSESSMENT_REQUIRED",
                 "NO_RULE_PROPOSED", "LLM_OUTPUT_INVALID", "LLM_ERROR")


def _flag(name: str) -> bool:
    raw = os.environ.get(name, os.environ.get("OPM_" + name, "false"))
    return raw.strip().lower() in ("1", "true", "yes", "on")


def generation_enabled() -> bool:
    return _flag(FLAG_GENERATE)


def publish_enabled() -> bool:
    return _flag(FLAG_PUBLISH)


def min_confidence() -> float:
    try:
        return min(1.0, max(0.0, float(os.environ.get("OPM_REGINTEL_RULE_GENERATION_MIN_CONFIDENCE",
                                                      DEFAULT_MIN_CONFIDENCE))))
    except ValueError:
        return DEFAULT_MIN_CONFIDENCE


# ---------------------------------------------------------------- RuleSpec 1.0 (the only thing the model may emit)

FieldName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
SafeText = Annotated[str, StringConstraints(pattern=r"^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]*$")]
Operator = Literal["equals", "not_equals", "less_than", "less_than_or_equal", "greater_than", "greater_than_or_equal",
                   "in", "not_in", "contains", "exists", "not_exists", "older_than_days", "within_last_days"]
Literal_ = bool | int | Annotated[str, StringConstraints(max_length=64)]


class _S(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Predicate(_S):
    field: FieldName
    operator: Operator
    value: Literal_ | list[Literal_] | None = Field(default=None, description="Only for boolean/enum/tag literals.")
    parameter: FieldName | None = Field(default=None, description="Name of a declared parameter (every threshold).")

    @model_validator(mode="after")
    def _one_source(self) -> "Predicate":
        if self.value is not None and self.parameter is not None:
            raise ValueError("a predicate takes either a literal value or a parameter, not both")
        if isinstance(self.value, list) and len(self.value) > 20:
            raise ValueError("at most 20 list values")
        return self


class LeafGroup(_S):
    operator: Literal["all", "any", "none"]
    where: list[Predicate] = Field(min_length=1, max_length=10)


class RootGroup(_S):
    operator: Literal["all", "any", "none"]
    where: list[Predicate | LeafGroup] = Field(min_length=1, max_length=10)


class PolicyBinding(_S):
    control_id: Annotated[str, StringConstraints(pattern=r"^PC-[A-Z0-9-]{2,40}$")]
    parameter: FieldName


class ParameterDecl(_S):
    type: Literal["integer", "boolean"]
    unit: Literal["days", "hours", "minutes", "seconds", "attempts", "count", "none"] = "none"
    description: Annotated[SafeText, Field(max_length=300)] = ""
    policy_control: PolicyBinding | None = Field(
        default=None, description="Organization setting that may supply the value when the text states none.")
    minimum: int | None = Field(default=None, ge=0, le=10**9)
    maximum: int | None = Field(default=None, ge=0, le=10**9)


class Population(_S):
    type: Literal["ORGANIZATION_SUPPORTED_ENTITIES"]
    period_field: FieldName = Field(description="Non-null datetime field; only records inside the period count.")
    where: list[Predicate] = Field(default_factory=list, max_length=10)


class RuleSpec(_S):
    spec_version: Literal["1.0"]
    title: Annotated[SafeText, Field(min_length=3, max_length=120)]
    description: Annotated[SafeText, Field(max_length=2000)] = ""
    pam_control_id: Annotated[str, StringConstraints(pattern=r"^PAMC-[A-Z0-9-]{2,40}$")]
    evidence_type: FieldName
    evidence_schema_version: Annotated[str, StringConstraints(pattern=r"^\d{1,3}\.\d{1,3}$")]
    assessment_mode: Literal["EVENT_HISTORY", "CONFIGURATION_SNAPSHOT"]
    subject_field: FieldName
    population: Population
    parameters: dict[FieldName, ParameterDecl] = Field(default_factory=dict, max_length=6)
    condition: Predicate | RootGroup = Field(description="What every in-population record must satisfy.")
    missing_evidence_result: Literal["INSUFFICIENT_EVIDENCE"]
    coverage: Literal["PARTIAL"] = "PARTIAL"
    source_requirement_ids: list[int] = Field(min_length=1, max_length=20)
    limitations: list[Annotated[SafeText, Field(min_length=10, max_length=500)]] = Field(min_length=1, max_length=10)


class Proposal(_S):
    requirement_id: int
    decision: Literal["PROPOSE", "NO_RULE", "MANUAL_ASSESSMENT"]
    confidence: float = Field(ge=0, le=1)
    rationale: Annotated[SafeText, Field(min_length=1, max_length=2000)]
    rule_spec: RuleSpec | None = None


class GeneratedRuleDefinition(CustomRuleDefinition):
    """The fixed interpreter's definition schema in the PAM-GEN namespace (no hand-written framework mappings)."""
    rule_id: Annotated[str, StringConstraints(pattern=r"^PAM-GEN-[0-9A-F]{12}$")]  # fits the evaluate API's RuleId
    framework_mappings: list[CustomFrameworkMapping] = Field(default_factory=list, max_length=0)


def json_schema() -> dict[str, Any]:
    schema = RuleSpec.model_json_schema()
    schema["$comment"] = (f"RuleSpec {SPEC_VERSION}: the only rule content an LLM may propose. Validated, resolved, "
                          f"compiled ({COMPILER_VERSION}) and tested by OPM; never executed as code.")
    return schema


# ---------------------------------------------------------------- forbidden content (raw output scan)

_FORBIDDEN: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("EXECUTABLE_CODE", re.compile(r"\bpackage\s+[a-z_][\w.]*|\bimport\s+(?:data|input|future|rego)\b|:=|"
                                   r"\bdefault\s+\w+\s*=|\bdef\s+\w+\s*\(|\blambda\b|\beval\s*\(|\bexec\s*\(|"
                                   r"__import__|\bos\.system|\bsubprocess\b|<script|\brequire\s*\(", re.I)),
    ("URL", re.compile(r"\b(?:https?|ftp|file|data):(?://)?|\bwww\.", re.I)),
    ("FILESYSTEM_PATH", re.compile(r"[A-Za-z]:\\\\|\\\\\\\\|(?:^|[\s\"'])/(?:etc|usr|var|tmp|home|root|bin|opt)/|\.\./")),
    ("TEMPLATE", re.compile(r"\{\{|\}\}|\$\{|<%|%>")),
    ("CREDENTIAL_MATERIAL", re.compile(r"-----BEGIN|\b(?:password|passwd|secret|api[_-]?key|bearer|otp|private[_ ]key)"
                                       r"\s*[:=]\s*\S", re.I)),
    ("COVERAGE_CLAIM", re.compile(r"\bfull(?:y)?\s+(?:regulatory\s+)?(?:coverage|compliant|compliance)\b|"
                                  r"\bfully\s+(?:covers|satisfies|meets)\b|\"coverage\"\s*:\s*\"FULL\"", re.I)),
)


def _strings(node: Any) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for k, v in node.items() for s in (str(k), *_strings(v))]
    if isinstance(node, list):
        return [s for v in node for s in _strings(v)]
    return []


def forbidden_content(raw: str) -> list[str]:
    """Forbidden content in every key and string value of the output (JSON structure itself, e.g. the '}}'
    closing nested objects, is not content); unparseable output is scanned as a whole."""
    try:
        text = "\n".join(_strings(json.loads(raw or "")))
    except ValueError:
        text = raw or ""
    return [code for code, pattern in _FORBIDDEN if pattern.search(text)]


# ---------------------------------------------------------------- deterministic validation

_SPEC_OPS: dict[str, frozenset[str]] = {
    "boolean": frozenset({"equals", "not_equals"}),
    "enum": frozenset({"equals", "not_equals", "in", "not_in", "exists", "not_exists"}),
    "string": frozenset({"exists", "not_exists"}),  # identifiers are never compared to literals
    "integer": frozenset({"equals", "not_equals", "less_than", "less_than_or_equal", "greater_than",
                          "greater_than_or_equal", "exists", "not_exists"}),
    "datetime": frozenset({"older_than_days", "within_last_days", "exists", "not_exists"}),
    "string_list": frozenset({"contains"}),
}
_NULL_OPS = frozenset({"exists", "not_exists"})
_PARAM_OPS = frozenset({"less_than", "less_than_or_equal", "greater_than", "greater_than_or_equal",
                        "older_than_days", "within_last_days"})
_TAG = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,63}$")
_TIME_UNITS = {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400}
_TEXT_UNITS = frozenset({"days", "hours", "minutes", "attempts"})  # units read from regulatory prose


class Gap(Exception):
    def __init__(self, code: str, message: str, **extra: Any) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.extra = code, message, extra


def field_unit(name: str) -> str | None:
    for suffix, unit in (("_seconds", "seconds"), ("_minutes", "minutes"), ("_hours", "hours"), ("_days", "days")):
        if name.endswith(suffix):
            return unit
    if name.endswith("_attempts"):
        return "attempts"
    if name.endswith(("_count", "_length")):
        return "count"
    return None


def drop_unused_parameters(spec: RuleSpec) -> tuple[RuleSpec, list[str]]:
    """Remove declared parameters that no condition predicate references. An unreferenced parameter cannot change
    what the rule tests, so removing it is semantics-preserving; small models often declare one anyway."""
    used = {p.parameter for p in _predicates(spec.condition) if p.parameter is not None}
    dropped = sorted(set(spec.parameters) - used)
    if not dropped:
        return spec, []
    return spec.model_copy(update={"parameters": {k: v for k, v in spec.parameters.items() if k in used}}), dropped


def _predicates(node: Any):
    if isinstance(node, Predicate):
        yield node
    else:
        for child in node.where:
            yield from _predicates(child)


def _fields(spec: RuleSpec) -> set[str]:
    out = {spec.subject_field, spec.population.period_field}
    out |= {p.field for p in spec.population.where}
    out |= {p.field for p in _predicates(spec.condition)}
    return out


def disables_every_account(spec: RuleSpec) -> bool:
    """The whole condition is "enabled is false". Disabling is owed for dormant, departed or unauthorized accounts,
    never for every account in scope, so alone it fails every account in use (AC-2 a and AC-2(7), 2026-11-20; the
    model review accepted it about half the time)."""
    leaves = list(_predicates(spec.condition))
    if len(leaves) != 1 or not (isinstance(spec.condition, Predicate) or spec.condition.operator == "all"):
        return False
    p = leaves[0]
    return p.field == "enabled" and ((p.operator == "equals" and p.value is False)
                                     or (p.operator == "not_equals" and p.value is True))


def validate(spec: RuleSpec, *, req: dict[str, Any], cap: dict[str, Any], db: CatalogDb) -> list[str]:
    """Every deterministic gate before resolution. Raises Gap; returns the checks that passed."""
    checks: list[str] = []
    if spec.source_requirement_ids != [req["id"]]:
        raise Gap("SOURCE_GROUNDING_FAILED", f"source_requirement_ids must be exactly [{req['id']}]")
    if db.one("SELECT 1 FROM pam_control WHERE id=?", (spec.pam_control_id,)) is None:
        raise Gap("RULE_SPEC_INVALID", f"unknown PAM control '{spec.pam_control_id}'")
    catalogue = CUSTOM_RULE_FIELDS.get(spec.evidence_type)
    if catalogue is None:
        raise Gap("RULE_SPEC_INVALID", f"unknown evidence type '{spec.evidence_type}'")
    checks.append("schema_and_allowlist")
    if spec.evidence_schema_version != EVIDENCE_SCHEMA_VERSIONS[spec.evidence_type]:
        raise Gap("EVIDENCE_SCHEMA_INCOMPATIBLE", f"{spec.evidence_type} schema {spec.evidence_schema_version} is not "
                  f"OPM's pinned version {EVIDENCE_SCHEMA_VERSIONS[spec.evidence_type]}")
    declared = declared_version(cap, spec.evidence_type)
    if cap.get("source") != "HANDSHAKE" or declared is None:
        raise Gap("COLLECTOR_MISSING", f"this organization's collector declaration does not supply {spec.evidence_type}",
                  evidence_type=spec.evidence_type)
    if declared != spec.evidence_schema_version:
        raise Gap("EVIDENCE_SCHEMA_INCOMPATIBLE", f"the collector declares {spec.evidence_type} schema "
                  f"{declared}, the rule needs {spec.evidence_schema_version}")
    detail = (cap.get("evidence_detail") or {}).get(spec.evidence_type)
    if not detail or not detail.get("supported_fields") or not detail.get("assessment_modes"):
        raise Gap("EVIDENCE_SCHEMA_INCOMPATIBLE", f"the collector declaration lists no assessment_modes / "
                  f"supported_fields for {spec.evidence_type}; generated rules need both")
    if spec.assessment_mode not in detail["assessment_modes"]:
        raise Gap("EVIDENCE_SCHEMA_INCOMPATIBLE", f"the collector does not deliver {spec.evidence_type} as "
                  f"{spec.assessment_mode} (declared: {detail['assessment_modes']})")
    used = _fields(spec)
    undeclared = sorted(used - set(catalogue))
    if undeclared:
        raise Gap("RULE_SPEC_INVALID", f"fields not in the {spec.evidence_type} evidence schema: {undeclared}")
    unsupported = sorted(used - set(detail["supported_fields"]))
    if unsupported:
        raise Gap("EVIDENCE_SCHEMA_INCOMPATIBLE", f"the collector does not populate {unsupported} of "
                  f"{spec.evidence_type}", fields=unsupported)
    checks.append("collector_compatible")
    subject = catalogue[spec.subject_field]
    if subject["type"] != "string" or subject["nullable"]:
        raise Gap("RULE_SPEC_INVALID", "subject_field must be a non-null identifier field")
    period = catalogue[spec.population.period_field]
    if period["type"] != "datetime" or period["nullable"]:
        raise Gap("RULE_SPEC_INVALID", "population.period_field must be a non-null datetime field")
    referenced: set[str] = set()
    for pred in spec.population.where:
        if pred.parameter is not None:
            raise Gap("RULE_SPEC_INVALID", "population filters take literal boolean/enum/tag values only")
        _check_predicate(pred, catalogue, spec, referenced)
    filters = {(p.field, p.operator, json.dumps(p.value, sort_keys=True)) for p in spec.population.where}
    leaves = list(_predicates(spec.condition))
    if disables_every_account(spec):
        raise Gap("RULE_SPEC_INVALID", "the condition requires every in-scope account to be disabled; that fails "
                  "every account in use, so the rule would flag compliant behaviour (say which accounts must be "
                  "disabled, e.g. dormant ones)")
    for pred in leaves:
        if pred.operator == "contains":
            raise Gap("RULE_SPEC_INVALID", "'contains' is allowed only in population filters")
        if pred.field == "enabled" and ((pred.operator == "equals" and pred.value is True)
                                        or (pred.operator == "not_equals" and pred.value is False)):
            # no control obliges accounts to be enabled; account obligations are about disabling (dormant,
            # departed, unauthorized). AC-2 f produced "every privileged account must be enabled" twice.
            raise Gap("RULE_SPEC_INVALID", "the condition requires accounts to be enabled; no PAM control obliges "
                      "that (account obligations require disabling), so the rule would flag compliant behaviour")
        if (pred.field, pred.operator, json.dumps(pred.value, sort_keys=True)) in filters:
            raise Gap("RULE_SPEC_INVALID", f"the condition repeats the population filter on '{pred.field}', so no "
                      "in-population record can fail it")
        _check_predicate(pred, catalogue, spec, referenced)
    # a condition only on the record's own identity/period (e.g. "account_id exists") is always true: it would
    # report PASS for everything and claim coverage it does not test
    identity = {spec.subject_field, spec.population.period_field, "record_id"}
    if not any(p.field not in identity for p in _predicates(spec.condition)):
        raise Gap("RULE_SPEC_INVALID", "the condition tests only the record's identity or period fields; it "
                  "would pass every record")
    quality = rule_quality_gap(spec)
    if quality:
        raise Gap("RULE_SPEC_INVALID", quality)
    unused = sorted(set(spec.parameters) - referenced)
    if unused:
        raise Gap("RULE_SPEC_INVALID", f"declared parameters not used by the condition: {unused}")
    for name, p in spec.parameters.items():
        if p.minimum is not None and p.maximum is not None and p.minimum > p.maximum:
            raise Gap("RULE_SPEC_INVALID", f"parameter '{name}': minimum > maximum")
        if p.policy_control is not None:
            defn = pc.get(p.policy_control.control_id, "1.0")
            props = ((defn or {}).get("parameter_schema") or {}).get("properties") or {}
            target = props.get(p.policy_control.parameter)
            if target is None or target.get("type") != p.type:
                raise Gap("RULE_SPEC_INVALID", f"parameter '{name}': {p.policy_control.control_id}."
                          f"{p.policy_control.parameter} is not a {p.type} organization setting")
            ui_unit = (((defn or {}).get("ui") or {}).get("parameters") or {}).get(
                p.policy_control.parameter, {}).get("unit")
            if p.type == "integer" and ui_unit in _TIME_UNITS and ui_unit != p.unit:
                raise Gap("RULE_SPEC_INVALID", f"parameter '{name}': the setting is in {ui_unit}, not {p.unit}")
    checks.append("operators_types_units")
    copied = [x for x in spec.limitations if x.strip().lower() in _EXAMPLE_LIMITATIONS]
    if copied and spec.evidence_type != "privileged_session":
        # the worked example's limitation on an unrelated rule means the model copied the example instead of
        # reasoning about this requirement (AC-5 a: an authorization test whose only limitation was about recordings)
        raise Gap("RULE_SPEC_INVALID", f"the limitations are copied from the prompt's worked example {copied}; the "
                  "proposal does not reason about this requirement")
    return checks


# Quality gates (rule-quality-v1, 2026-11-20). Each pattern went live in the NIST gpt-4.1 run and would misreport:
# - AU-3 / AU-12 c: "every audit event has event type, location, source, outcome, actor AND target" fails compliant
#   logs, because events legitimately leave context fields empty (a logon has no target, a system event no actor);
# - MA-4 e: "every recorded session has ended_at" fails every session still running when the period closes;
# - AC-2(4), AC-6(9), AU-2 a: "event_type exists" over all audit events passes any feed; it never checks that the
#   events the requirement names (account changes, privileged functions) are logged.
RULE_QUALITY_VERSION = "rule-quality-v1"
_OPTIONAL_CONTEXT: dict[str, frozenset[str]] = {"audit_event": frozenset({"target_id", "location_id"})}
_IN_PROGRESS_FIELDS: dict[str, frozenset[str]] = {"privileged_session": frozenset({"ended_at"})}
_GENERAL_STREAMS = frozenset({"audit_event"})


def rule_quality_gap(spec: RuleSpec) -> str | None:
    """Why the rule would misreport compliant evidence (or pass anything), or None."""
    leaves = list(_predicates(spec.condition))
    required = [p for p in leaves if p.operator == "exists"]
    context = sorted({p.field for p in required} & _OPTIONAL_CONTEXT.get(spec.evidence_type, frozenset()))
    if context:
        return (f"the condition requires {context} on every {spec.evidence_type} record; those fields are "
                "legitimately empty for many events, so compliant evidence would fail (test only fields every "
                "in-scope record must carry, or filter the population to the events that have them)")
    running = sorted({p.field for p in required} & _IN_PROGRESS_FIELDS.get(spec.evidence_type, frozenset()))
    if running:
        return (f"the condition requires {running} to be set; sessions still running when the period closes have "
                "none, so the rule would fail them (test a recorded property of the session instead)")
    # only for the general audit stream: on a specific type (a break-glass event "has a ticket") the population
    # already is the events the requirement names
    if (spec.evidence_type in _GENERAL_STREAMS and len(leaves) == 1 and leaves[0].operator in _NULL_OPS
            and not spec.population.where):
        return (f"the condition only checks that {leaves[0].field} is present on every record, without narrowing "
                "the population to the records the requirement names; any evidence feed passes it")
    return None


def _check_predicate(pred: Predicate, catalogue: dict[str, Any], spec: RuleSpec, referenced: set[str]) -> None:
    f = catalogue[pred.field]
    ftype = f["type"]
    if pred.operator not in _SPEC_OPS[ftype]:
        raise Gap("RULE_SPEC_INVALID", f"operator '{pred.operator}' is not allowed for {ftype} field '{pred.field}'")
    if pred.operator in _NULL_OPS:
        if not f["nullable"]:
            raise Gap("RULE_SPEC_INVALID", f"field '{pred.field}' is never null; '{pred.operator}' tests nothing")
        if pred.value is not None or pred.parameter is not None:
            raise Gap("RULE_SPEC_INVALID", f"'{pred.operator}' takes no value")
        return
    if ftype in ("integer", "datetime"):
        if pred.parameter is None:
            raise Gap("RULE_SPEC_INVALID", f"'{pred.field}': numeric and duration thresholds must be declared "
                      "parameters (OPM resolves their values from grounded sources), never literals")
        decl = spec.parameters.get(pred.parameter)
        if decl is None or decl.type != "integer":
            raise Gap("RULE_SPEC_INVALID", f"'{pred.field}' references undeclared integer parameter '{pred.parameter}'")
        if ftype == "datetime":
            if decl.unit != "days":
                raise Gap("RULE_SPEC_INVALID", f"'{pred.operator}' needs a parameter in days, not {decl.unit}")
        else:
            unit = field_unit(pred.field)
            ok = (decl.unit == unit) or (decl.unit in _TIME_UNITS and unit in _TIME_UNITS) or (
                unit is None and decl.unit == "count")
            if not ok:
                raise Gap("RULE_SPEC_INVALID", f"parameter '{pred.parameter}' is in {decl.unit}; field "
                          f"'{pred.field}' is in {unit or 'plain counts'}")
        referenced.add(pred.parameter)
        return
    if pred.parameter is not None:  # boolean field bound to an organization choice
        decl = spec.parameters.get(pred.parameter)
        if ftype != "boolean" or decl is None or decl.type != "boolean" or pred.operator not in ("equals", "not_equals"):
            raise Gap("RULE_SPEC_INVALID", f"'{pred.field}': only boolean fields may reference a boolean parameter")
        referenced.add(pred.parameter)
        return
    values = pred.value if isinstance(pred.value, list) else [pred.value]
    if pred.operator in ("in", "not_in") and not isinstance(pred.value, list):
        raise Gap("RULE_SPEC_INVALID", f"'{pred.operator}' needs a list")
    if pred.operator not in ("in", "not_in") and isinstance(pred.value, list):
        raise Gap("RULE_SPEC_INVALID", f"'{pred.operator}' takes a single value")
    for v in values:
        if ftype == "boolean" and not isinstance(v, bool):
            raise Gap("RULE_SPEC_INVALID", f"'{pred.field}' takes true/false")
        if ftype == "enum" and v not in f["values"]:
            raise Gap("RULE_SPEC_INVALID", f"'{pred.field}' takes one of {list(f['values'])}")
        if ftype == "string_list" and not (isinstance(v, str) and _TAG.match(v)):
            raise Gap("RULE_SPEC_INVALID", f"'{pred.field}' takes a tag")


# ---------------------------------------------------------------- parameter resolution (never the model)

def in_force_settings(db: CatalogDb, scope: str, tenant: str | None) -> dict[tuple[str, str], dict[str, Any]]:
    """(control_id, parameter) -> organization-wide value of the policy versions in force now."""
    if tenant is None:
        return {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    by_ctx: dict[str, list[dict[str, Any]]] = {}
    for r in db.q("SELECT * FROM policy_context_version WHERE organization_scope=? AND tenant_id=? ORDER BY context_id, "
                  "version", (scope, tenant)):
        by_ctx.setdefault(r["context_id"], []).append(r)
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for versions in by_ctx.values():
        wins = pctx.winning_intervals(versions)
        for v in versions:
            if not any(a <= now < e for a, e in wins.get(v["version"], [])):
                continue
            for entry in v["policy_controls"]:
                if not any(t["type"] == "ORGANIZATION" for t in entry["targets"]):
                    continue
                for name, value in entry["parameters"].items():
                    out[(entry["control_id"], name)] = {
                        "value": value, "provenance": "CUSTOMER_POLICY", "source_type": "POLICY_DOCUMENT",
                        "policy_version_id": v["id"], "policy_digest": v["digest"], "control_id": entry["control_id"],
                        "title": v["title"]}
    return out


def resolve(spec: RuleSpec, *, req: dict[str, Any], settings: dict[tuple[str, str], dict[str, Any]]
            ) -> list[dict[str, Any]]:
    text = req.get("translation_en") or req.get("original_text") or ""
    out = []
    for name, p in sorted(spec.parameters.items()):
        entry: dict[str, Any] = {"name": name, "value": None, "source_type": None, "unit": p.unit}
        why = None
        if p.type == "integer" and p.unit in _TEXT_UNITS:
            value, why = mr.extract(p.unit, text, p)
            if value is not None:
                entry.update(value=value, source_type="REGULATORY_TEXT", provenance="REGULATORY_TEXT", quotation=why)
        if entry["value"] is None and p.policy_control is not None:
            hit = settings.get((p.policy_control.control_id, p.policy_control.parameter))
            if hit is not None:
                v = hit["value"]
                if p.type == "integer" and ((p.minimum is not None and v < p.minimum)
                                            or (p.maximum is not None and v > p.maximum)):
                    entry["reason"] = f"the organization setting {v} is outside {p.minimum}..{p.maximum}"
                else:
                    entry.update(**hit)
        if entry["value"] is None:
            entry.setdefault("reason", "no value in the regulatory text" + (f" ({why})" if why else "") +
                             (" and no confirmed organization setting " + p.policy_control.control_id
                              if p.policy_control else " and no organization setting is bound to this parameter"))
        out.append(entry)
    return out


# ---------------------------------------------------------------- compiler (fixed template: securden.custom.v1)

_POS = {"equals": "eq", "not_equals": "ne", "less_than": "lt", "less_than_or_equal": "lte", "greater_than": "gt",
        "greater_than_or_equal": "gte", "in": "in", "not_in": "not_in", "contains": "contains", "exists": "not_null",
        "not_exists": "is_null", "older_than_days": "older_than_days", "within_last_days": "within_last_days"}
_NEG = {"equals": "ne", "not_equals": "eq", "less_than": "gte", "less_than_or_equal": "gt", "greater_than": "lte",
        "greater_than_or_equal": "lt", "in": "not_in", "not_in": "in", "exists": "is_null", "not_exists": "not_null",
        "older_than_days": "within_last_days", "within_last_days": "older_than_days"}
EPOCH_EFFECTIVE = "2000-01-01T00:00:00Z"  # rule semantics are time-independent; the mapping pins applicability


def _interpreter_files(bundle_dir: Path) -> list[Path]:
    return [bundle_dir / "securden" / "custom" / "v1" / "policy.rego", bundle_dir / "securden" / "lib" / "lib.rego"]


def _value(pred: Predicate, spec: RuleSpec, values: dict[str, Any]) -> Any:
    if pred.parameter is None:
        return pred.value
    v = values[pred.parameter]
    decl = spec.parameters[pred.parameter]
    unit = field_unit(pred.field)
    if decl.type == "integer" and decl.unit in _TIME_UNITS and unit in _TIME_UNITS and decl.unit != unit:
        seconds = v * _TIME_UNITS[decl.unit]
        if seconds % _TIME_UNITS[unit]:
            raise Gap("RULE_COMPILATION_FAILED", f"{v} {decl.unit} is not a whole number of {unit}")
        v = seconds // _TIME_UNITS[unit]
    return v


def _cond(pred: Predicate, spec: RuleSpec, values: dict[str, Any], negate: bool) -> dict[str, Any]:
    if negate and pred.operator not in _NEG:
        raise Gap("RULE_SPEC_INVALID", f"'{pred.operator}' cannot be negated")
    op = (_NEG if negate else _POS)[pred.operator]
    out: dict[str, Any] = {"field": pred.field, "op": op}
    if pred.operator not in _NULL_OPS:
        out["value"] = _value(pred, spec, values)
    return out


def _leaf(node: Any, spec: RuleSpec, values: dict[str, Any], negate: bool) -> dict[str, Any]:
    """A child of the root, in the interpreter's form, holding when the child holds (negate=False) or fails."""
    if isinstance(node, Predicate):
        return _cond(node, spec, values, negate)
    conds_pos = [_cond(p, spec, values, False) for p in node.where]
    conds_neg = [_cond(p, spec, values, True) for p in node.where]
    if node.operator == "all":
        return {"any": conds_neg} if negate else {"all": conds_pos}
    if node.operator == "any":
        return {"all": conds_neg} if negate else {"any": conds_pos}
    return {"any": conds_pos} if negate else {"all": conds_neg}  # none


def violation_group(spec: RuleSpec, values: dict[str, Any]) -> dict[str, Any]:
    """The condition says what every record must satisfy; the interpreter tests the violation (its negation)."""
    c = spec.condition
    if isinstance(c, Predicate):
        return {"all": [_cond(c, spec, values, True)]}
    if c.operator == "all":
        return {"any": [_leaf(x, spec, values, True) for x in c.where]}
    if c.operator == "any":
        return {"all": [_leaf(x, spec, values, True) for x in c.where]}
    return {"any": [_leaf(x, spec, values, False) for x in c.where]}  # none: violated when any child holds


def structure_of(spec: RuleSpec) -> dict[str, Any]:
    return spec.model_dump(mode="json", exclude={"title", "description", "limitations", "source_requirement_ids",
                                                  "coverage"})


def compile_spec(spec: RuleSpec, resolution: list[dict[str, Any]], *, scope: str, tenant: str,
                 bundle_dir: Path) -> dict[str, Any]:
    values = {e["name"]: e["value"] for e in resolution}
    structure = structure_of(spec)
    structure_digest = "sha256:" + digest_of(structure)
    values_digest = "sha256:" + digest_of(values)
    rule_id = GENERATED_RULE_PREFIX + digest_of({"scope": scope, "tenant": tenant, "structure": structure_digest,
                                                 "values": values_digest})[:12].upper()
    definition = {
        "rule_id": rule_id, "version": "1.0", "title": spec.title, "description": spec.description,
        "severity": "MEDIUM", "evidence_type": spec.evidence_type, "subject_field": spec.subject_field,
        "scope": {"all": [_cond(p, spec, values, False) for p in spec.population.where]} if spec.population.where
        else None,
        "violation_when": violation_group(spec, values), "tolerance": 0, "effective_from": EPOCH_EFFECTIVE,
        "framework_mappings": [], "remediation": "",
    }
    try:
        model = GeneratedRuleDefinition.model_validate(definition)
    except ValidationError as exc:
        raise Gap("RULE_COMPILATION_FAILED", "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}"
                                                      for e in exc.errors(include_input=False))[:500]) from exc
    result = compile_rule(model)
    if not result.valid:
        raise Gap("RULE_COMPILATION_FAILED", json.dumps(result.errors)[:500])
    compiled = dict(result.compiled or {})
    compiled["period_field"] = spec.population.period_field
    compiled["required_fields"] = sorted({p.field for p in _predicates(spec.condition) if p.operator not in _NULL_OPS})
    files = _interpreter_files(bundle_dir)
    if not all(f.is_file() for f in files):
        raise Gap("RULE_COMPILATION_FAILED", "the pinned interpreter package is not in the policy bundle")
    h = hashlib.sha256()
    for f in files:
        h.update(f.read_bytes())
    h.update(canonical(compiled).encode("utf-8"))
    return {"rule_id": rule_id, "version": "1.0", "definition": model.model_dump(mode="json"), "compiled": compiled,
            "rule_digest": "sha256:" + str(result.digest), "rego_digest": "sha256:" + h.hexdigest(),
            "structure_digest": structure_digest, "values_digest": values_digest,
            "spec_digest": "sha256:" + digest_of(spec.model_dump(mode="json")), "values": values}


# ---------------------------------------------------------------- deterministic validation cases

AS_OF = datetime(2026, 6, 30, tzinfo=timezone.utc)
PERIOD_DAYS = 30


def _ts(days_before: float) -> str:
    return (AS_OF - timedelta(days=days_before)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class CaseError(Exception):
    pass


def _other(f: dict[str, Any], excluded: list[Any]) -> Any:
    if f["type"] == "boolean":
        if len(excluded) != 1:
            raise CaseError("no boolean value outside the list")
        return not excluded[0]
    rest = [v for v in f["values"] if v not in excluded]
    if not rest:
        raise CaseError("no enum value outside the list")
    return rest[0]


def _assign_pred(pred: Predicate, want: bool, spec: RuleSpec, values: dict[str, Any], cat: dict[str, Any]
                 ) -> dict[str, Any]:
    f = cat[pred.field]
    op = pred.operator
    v = None if op in _NULL_OPS else _value(pred, spec, values)
    if op in ("not_equals", "not_in", "not_exists"):
        op, want = {"not_equals": "equals", "not_in": "in", "not_exists": "exists"}[op], not want
    if op == "equals":
        return {pred.field: v if want else _other(f, [v])}
    if op == "in":
        return {pred.field: v[0] if want else _other(f, list(v))}
    if op == "exists":
        return {pred.field: _sample(pred.field, f) if want else None}
    if op == "contains":
        return {pred.field: [v] if want else []}
    if op in ("less_than", "less_than_or_equal", "greater_than", "greater_than_or_equal"):
        t = int(v)
        choice = {("less_than", True): t - 1, ("less_than", False): t, ("less_than_or_equal", True): t,
                  ("less_than_or_equal", False): t + 1, ("greater_than", True): t + 1, ("greater_than", False): t,
                  ("greater_than_or_equal", True): t, ("greater_than_or_equal", False): t - 1}[(op, want)]
        if choice < 0:
            raise CaseError(f"no non-negative value makes '{pred.field} {op} {t}' {want}")
        return {pred.field: choice}
    n = int(v)
    older = (op == "older_than_days") == want
    return {pred.field: _ts(n + 1 if older else max(n - 1, 0))}


def _merge(*parts: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for part in parts:
        for k, v in part.items():
            if k in out and out[k] != v:
                raise CaseError(f"contradictory requirements for field '{k}'")
            out[k] = v
    return out


_MAX_ALTERNATIVES = 32


def _combine(choices: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Cartesian merge of per-child alternatives; contradictory combinations are dropped."""
    out: list[dict[str, Any]] = [{}]
    for alts in choices:
        nxt = []
        for base in out:
            for alt in alts:
                try:
                    nxt.append(_merge(base, alt))
                except CaseError:
                    continue
                if len(nxt) >= _MAX_ALTERNATIVES:
                    break
        out = nxt
        if not out:
            raise CaseError("contradictory requirements in the condition")
    return out


def _alternatives(node: Any, want: bool, spec: RuleSpec, values: dict[str, Any], cat: dict[str, Any]
                  ) -> list[dict[str, Any]]:
    """Every field assignment (bounded) that makes ``node`` evaluate to ``want``."""
    if isinstance(node, Predicate):
        return [_assign_pred(node, want, spec, values, cat)]
    kids = node.where
    # a conjunction is needed when all children take the same value, a disjunction picks one decisive child
    every = (node.operator == "all" and want) or (node.operator == "any" and not want) or (
        node.operator == "none" and want)
    kid_want = want if node.operator != "none" else False
    if every:
        return _combine([_alternatives(k, kid_want, spec, values, cat) for k in kids])
    # all→False: one child false, rest true; any→True / none→False: one child true, rest false
    decisive, other = (False, True) if node.operator == "all" else (True, False)
    out: list[dict[str, Any]] = []
    for i in range(len(kids)):
        parts = [_alternatives(k, decisive if j == i else other, spec, values, cat) for j, k in enumerate(kids)]
        try:
            out.extend(_combine(parts))
        except CaseError:
            continue
    if not out:
        raise CaseError("no assignment satisfies the condition")
    return out[:_MAX_ALTERNATIVES]


def _accepts(etype: str, rec: dict[str, Any]) -> bool:
    try:
        Evidence.model_validate({"evidence_type": etype, "records": [rec], "completeness": {
            "expected_record_count": 1, "received_record_count": 1, "source_complete": True, "collection_errors": 0}})
    except ValidationError:
        return False
    return True


def _sample(name: str, f: dict[str, Any]) -> Any:
    return {"string": f"{name.replace('_', '-')}-1", "boolean": True, "enum": (f["values"] or ("x",))[0],
            "integer": 0, "datetime": _ts(2), "string_list": []}[f["type"]]


def _record(spec: RuleSpec, values: dict[str, Any], n: int, *, passing: bool) -> dict[str, Any]:
    cat = CUSTOM_RULE_FIELDS[spec.evidence_type]
    population = _merge(*(_assign_pred(p, True, spec, values, cat) for p in spec.population.where))
    fixed = set(population)
    for alt in _alternatives(spec.condition, passing, spec, values, cat):
        try:
            assigned = _merge(population, alt)
        except CaseError:
            continue
        base = {name: _sample(name, f) for name, f in cat.items()}
        base.update(assigned)
        base["record_id"] = f"rec-{n}"
        base[spec.subject_field] = f"subject-{n}"
        if not (_ts(PERIOD_DAYS) <= base[spec.population.period_field] <= _ts(0)):
            continue
        if _accepts(spec.evidence_type, base):
            return base
        locked = fixed | set(alt) | {"record_id", spec.subject_field, spec.population.period_field}
        for name in [k for k in cat if k not in locked]:
            f = cat[name]
            options = ([None] if f["nullable"] else []) + ([not base[name]] if f["type"] == "boolean" else []) + [
                v for v in f["values"] if v != base[name]]
            for opt in options:
                cand = {**base, name: opt}
                if _accepts(spec.evidence_type, cand):
                    return cand
    raise CaseError(f"no {'passing' if passing else 'failing'} record satisfies both the condition and the "
                    f"{spec.evidence_type} evidence schema")


def build_cases(spec: RuleSpec, values: dict[str, Any], stored_null: dict[str, str] | None = None
                ) -> list[dict[str, Any]]:
    """Deterministic validation vectors from the evidence schema and the condition tree (never from the model)."""
    cat = CUSTOM_RULE_FIELDS[spec.evidence_type]
    good, bad = _record(spec, values, 1, passing=True), _record(spec, values, 2, passing=False)
    cases: list[dict[str, Any]] = [
        {"name": "passing_evidence", "records": [good], "expected_status": "PASS", "expected_violation_subjects": []},
        {"name": "failing_evidence", "records": [bad], "expected_status": "FAIL",
         "expected_violation_subjects": ["subject-2"]},
        {"name": "empty_evidence", "records": [], "expected_status": "NOT_APPLICABLE"},
        {"name": "empty_incomplete_evidence", "records": [], "expected_status": "INSUFFICIENT_EVIDENCE",
         "completeness": {"expected_record_count": 1, "received_record_count": 0, "source_complete": False,
                          "collection_errors": 0}},
    ]
    etype = spec.evidence_type

    def derived(name: str, rec: dict[str, Any], expected: str, **extra: Any) -> None:
        # a variant the evidence schema itself forbids can never reach the rule; it is not a rule test
        if _accepts(etype, rec):
            cases.append({"name": name, "records": [rec], "expected_status": expected, **extra})

    required = sorted({p.field for p in _predicates(spec.condition) if p.operator not in _NULL_OPS})
    for f in [f for f in required if cat[f]["nullable"]][:3]:
        missing = {**good, f: None}
        if _accepts(etype, missing):
            cases.append({"name": f"missing_required_field_{f}", "records": [missing],
                          "expected_status": "INSUFFICIENT_EVIDENCE"})
        else:  # the schema guarantees the field whenever the record is judgeable
            cases.append({"name": f"schema_rejects_missing_{f}", "kind": "SCHEMA", "records": [missing],
                          "expected_status": "REJECTED"})
    for f in [f for f in required if not cat[f]["nullable"]][:2]:
        cases.append({"name": f"schema_rejects_missing_{f}", "kind": "SCHEMA",
                      "records": [{k: v for k, v in good.items() if k != f}], "expected_status": "REJECTED"})
    derived("outside_reporting_period", {**bad, spec.population.period_field: _ts(PERIOD_DAYS + 1)}, "NOT_APPLICABLE")
    for i, pred in enumerate(spec.population.where[:3]):
        try:
            derived(f"out_of_scope_entity_{i + 1}", {**bad, **_assign_pred(pred, False, spec, values, cat)},
                    "NOT_APPLICABLE")
        except CaseError:
            continue
    derived("out_of_scope_tag", {**bad, "scope_tags": ["pam-out-of-scope"]}, "NOT_APPLICABLE",
            scope_tags=["pam-in-scope"])
    roots = [spec.condition] if isinstance(spec.condition, Predicate) else (
        [x for x in spec.condition.where if isinstance(x, Predicate)] if spec.condition.operator == "all" else [])
    for pred in roots:
        if pred.parameter is None or pred.operator not in _PARAM_OPS:
            continue
        v = _value(pred, spec, values)
        if pred.operator in ("older_than_days", "within_last_days"):
            if pred.field == spec.population.period_field and v > PERIOD_DAYS:
                continue
            boundary, holds = _ts(v), pred.operator == "within_last_days"
        else:
            boundary, holds = v, pred.operator in ("less_than_or_equal", "greater_than_or_equal")
        derived(f"boundary_{pred.field}_{pred.operator}", {**good, pred.field: boundary}, "PASS" if holds else "FAIL",
                expected_violation_subjects=[] if holds else ["subject-1"])
    # the PAM may store these fields empty (vector.db); a field the rule does not use must not change the outcome
    used = _fields(spec) | {"record_id", "scope_tags", spec.subject_field, spec.population.period_field}
    for f, source in sorted((stored_null or {}).items()):
        if f in cat and f not in used and cat[f]["nullable"]:
            derived(f"pam_stored_null_{f}", {**good, f: None}, "PASS", pam_source=source)
    return cases


def opa_binary() -> str | None:
    explicit = os.environ.get("OPM_REGINTEL_OPA_BINARY")
    if explicit:
        return explicit
    local = ROOT / ".tools" / ("opa.exe" if os.name == "nt" else "opa")
    return str(local) if local.is_file() else shutil.which("opa")


def run_cases(definition: dict[str, Any], compiled: dict[str, Any], cases: list[dict[str, Any]], *,
              bundle_dir: Path) -> list[dict[str, Any]]:
    """Every case through the service's own input builder and the real OPA binary."""
    binary = opa_binary()
    version = json.loads((bundle_dir / "securden" / "bundle" / "data.json").read_text(encoding="utf-8"))["version"]
    spec = custom_spec_from_row({"definition": definition, "status": "ACTIVE", "compiled": compiled})
    end = AS_OF
    period = ReportingPeriod(start=end - timedelta(days=PERIOD_DAYS), end=end)
    results = []
    for case in cases:
        n = len(case["records"])
        payload = {"evidence_type": definition["evidence_type"], "records": case["records"],
                   "completeness": case.get("completeness") or {"expected_record_count": n, "received_record_count": n,
                                                                "source_complete": True, "collection_errors": 0}}
        try:
            evidence = Evidence.model_validate(payload)
        except ValidationError as exc:
            got = "REJECTED"
            results.append({"name": case["name"], "expected": case["expected_status"], "got": got,
                            "passed": case["expected_status"] == got,
                            **({} if case["expected_status"] == got else {"detail": str(exc)[:300]})})
            continue
        if case.get("kind") == "SCHEMA":
            results.append({"name": case["name"], "expected": "REJECTED", "got": "ACCEPTED", "passed": False})
            continue
        if binary is None:
            results.append({"name": case["name"], "expected": case["expected_status"], "got": None, "passed": False,
                            "detail": "OPA binary unavailable"})
            continue
        opa_input = Evaluator.build_input(spec, period, evidence, [], {"scope_tags": case.get("scope_tags", [])})
        try:
            proc = subprocess.run([binary, "eval", "--data", bundle_dir.name, "--stdin-input", "--format", "json",
                                   f"data.{ENGINE_PACKAGE}.decision"], cwd=bundle_dir.parent, input=json.dumps(opa_input),
                                  capture_output=True, text=True, timeout=120, encoding="utf-8")
        except (OSError, subprocess.TimeoutExpired) as exc:
            results.append({"name": case["name"], "expected": case["expected_status"], "got": None, "passed": False,
                            "detail": f"could not run OPA: {type(exc).__name__}"})
            continue
        try:
            decision = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
        except (KeyError, IndexError, json.JSONDecodeError):
            results.append({"name": case["name"], "expected": case["expected_status"], "got": None, "passed": False,
                            "detail": "decision undefined: " + (proc.stdout + proc.stderr)[:200]})
            continue
        got = decision.get("status")
        subjects = sorted(v["subject_id"] for v in decision.get("violations", []))
        ok = got == case["expected_status"] and decision.get("bundle_version") == version and (
            "expected_violation_subjects" not in case or subjects == sorted(case["expected_violation_subjects"]))
        results.append({"name": case["name"], "expected": case["expected_status"], "got": got, "passed": ok,
                        **({} if ok else {"violation_subjects": subjects})})
    return results


# ---------------------------------------------------------------- engine view: generated rules beside the bundle

class EngineView:
    """The running bundle's rule catalog plus this organization's generated rules (``rules``), with their
    provenance under ``generated``. Everything else is delegated to the bundle catalog."""

    def __init__(self, engine: Any, extra: dict[str, dict[str, Any]], generated: dict[tuple[str, str], Any]) -> None:
        self._engine = engine
        self.rules = {**engine.rules, **extra}
        self.generated = generated

    def __getattr__(self, name: str) -> Any:
        return getattr(self._engine, name)


def provenance(row: dict[str, Any]) -> dict[str, Any]:
    try:
        spec = RuleSpec.model_validate(row["rule_spec"])
        required_fields = sorted(_fields(spec))
    except (KeyError, TypeError, ValidationError):
        # Historical rows can predate RuleSpec provenance. They remain readable,
        # but callers must treat the missing field contract as unsupported.
        required_fields = []
    return {"rule_origin": "GENERATED", "generated_rule_version_id": row["id"], "spec_digest": row["spec_digest"],
            "rule_digest": row["rule_digest"], "rego_digest": row["rego_digest"],
            "compiler_version": row["compiler_version"], "evidence_type": row["evidence_type"],
            "evidence_schema_version": row["evidence_schema_version"], "assessment_mode": row["assessment_mode"],
            "required_fields": required_fields,
            "collector_capability_digest": row["collector_digest"], "status": row["status"],
            "source_references": row["source_references"], "limitations": row["rule_limitations"]}


def engine_for(db: CatalogDb, engine: Any, scope: str | None, tenant: str | None = None) -> Any:
    if engine is None or scope is None:
        return engine
    try:
        rows = db.q("SELECT * FROM generated_rule_version WHERE organization_scope=? AND status IN ('ACTIVE',"
                    "'SUPERSEDED')" + (" AND tenant_id=?" if tenant else "") + " ORDER BY id",
                    (scope, *([tenant] if tenant else [])))
    except sqlite3.OperationalError:  # a read-only connection to a database created before this table existed
        return engine
    if not rows:
        return engine
    extra: dict[str, dict[str, Any]] = {}
    generated: dict[tuple[str, str], Any] = {}
    for row in rows:
        spec = custom_spec_from_row({"definition": row["definition"], "compiled": row["compiled_rule"],
                                     "status": "ACTIVE" if row["status"] == "ACTIVE" else "INACTIVE"})
        extra.setdefault(row["rule_id"], {})[row["version"]] = spec
        generated[(row["rule_id"], row["version"])] = provenance(row)
    return EngineView(engine, extra, generated)


def collected_with_generated(collected: tuple[str, ...] | None, view: Any, cap: dict[str, Any]) -> tuple[str, ...] | None:
    """Generated rules count as collected when the organization's handshake declares their evidence type."""
    if collected is None or not isinstance(view, EngineView):
        return collected
    declared = cap.get("evidence") or {} if cap.get("source") == "HANDSHAKE" else {}
    extra = {rid for (rid, _v), p in view.generated.items() if p["evidence_type"] in declared}
    return tuple(sorted(set(collected) | extra))


def latest_decision(db: CatalogDb, requirement_id: int, scope: str | None) -> dict[str, Any] | None:
    if scope is None:
        return None
    try:
        row = db.one("SELECT * FROM rule_generation_decision WHERE organization_scope=? AND requirement_id=? "
                     "ORDER BY id DESC LIMIT 1", (scope, requirement_id))
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    v = row["llm_validation"] or {}
    return {"decision_id": row["id"], "outcome": row["outcome"], "gap_code": row["gap_code"],
            "message": v.get("message"), "rule_id": v.get("rule_id"), "rule_version": v.get("rule_version"),
            "generated_rule_version_id": row["generated_rule_version_id"], "mapping_id": row["mapping_id"],
            "rule_spec_digest": v.get("spec_digest"), "rego_digest": v.get("rego_digest"),
            "compiler_version": row["compiler_version"], "prompt_version": row["prompt_version"],
            "decided_at": row["created_at"]}


# ---------------------------------------------------------------- the model's task

SYSTEM_RULESPEC = (
    "You are a PAM compliance rule designer. For ONE regulatory requirement for which no existing rule fits, either "
    "propose ONE technical control test as a RuleSpec or decline. Answer with JSON only, matching the schema. "
    "Use ONLY the evidence types, fields, operators, PAM controls and organization settings listed in the context. "
    "Never write code, Rego, expressions, templates, URLs or paths. Never invent numbers: every numeric or duration "
    "threshold is a parameter name from the schema in the condition (OPM declares it and finds its value in the "
    "regulatory text or the organization's confirmed settings); leave 'parameters' empty. population.where only "
    "selects which records are in scope; 'condition' states what every in-scope record must satisfy and must test a "
    "different field than population.where (never repeat a filter as the condition). coverage is always PARTIAL; "
    "list what the test does not establish under limitations. decision NO_RULE when the listed evidence cannot "
    "test the obligation; MANUAL_ASSESSMENT when a person must judge it. The condition must test a field that shows "
    "compliance (a status, a flag or a timestamp age), not merely that the record exists.")


def _context(db: CatalogDb, req: dict[str, Any], ref: dict[str, Any], cap: dict[str, Any],
             analysis: dict[str, Any] | None = None) -> str:
    detail = cap.get("evidence_detail") or {}
    evidence = []
    for etype in sorted(detail):
        d, version = detail[etype], declared_version(cap, etype)
        if version is None or etype not in CUSTOM_RULE_FIELDS:
            continue
        cat = CUSTOM_RULE_FIELDS[etype]
        evidence.append({"evidence_type": etype, "schema_version": version, "assessment_modes": d["assessment_modes"],
                         "collection": "available by PAM lookup (collector pending)" if is_lookup(cap, etype)
                         else "collected", **({"caveats": d["caveats"]} if d.get("caveats") else {}),
                         "fields": {n: {"type": cat[n]["type"], "nullable": cat[n]["nullable"],
                                        **({"values": list(cat[n]["values"])} if cat[n]["values"] else {}),
                                        **({"unit": field_unit(n)} if field_unit(n) else {}),
                                        **field_meaning(cap, etype, n)}
                                    for n in d["supported_fields"] if n in cat}})
    settings = []
    for (cid, _v), defn in sorted(pc.CONTROLS.items()):
        for name, schema in ((defn.get("parameter_schema") or {}).get("properties") or {}).items():
            if schema.get("type") in ("integer", "boolean"):
                ui = ((defn.get("ui") or {}).get("parameters") or {}).get(name, {})
                settings.append({"control_id": cid, "parameter": name, "type": schema["type"],
                                 "unit": ui.get("unit"), "title": ui.get("label") or schema.get("title")})
    controls = [{"id": r["id"], "title": r["title"]} for r in db.q("SELECT id, title FROM pam_control ORDER BY id")]
    guidance = matrix_guidance(req, ref)
    payload = {
        "requirement_id": req["id"], "requirement_text": req.get("translation_en") or req["original_text"],
        "canonical_control": {k: ref.get(k) for k in ("canonical_id", "control_title", "clause")},
        **({"securden_nist_training_reference": guidance} if guidance else {}),
        **({"your_analysis": analysis["text"]} if analysis else {}),
        "evidence_types": evidence, "pam_controls": controls, "organization_settings": settings,
        "operators": {t: sorted(ops) for t, ops in _SPEC_OPS.items()},
        "rules": ["population.period_field: the record's event or capture timestamp (non-null datetime)",
                  "contains: population filters only", "spec_version 1.0; missing_evidence_result INSUFFICIENT_EVIDENCE",
                  f"source_requirement_ids: [{req['id']}]"],
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _prompt_schema() -> dict[str, Any]:
    """Proposal schema without 'title' keys: identical constraints, ~25% fewer prompt tokens."""
    def strip(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: strip(v) for k, v in o.items() if k != "title"}
        return [strip(v) for v in o] if isinstance(o, list) else o
    return strip(Proposal.model_json_schema())


# Which requirement wording an evidence type can speak to (screen rule-screen-v2). A requirement is sent to the
# model only with the declared evidence types its wording relates to; with none it is COLLECTOR_MISSING without a
# call. v2: every evidence type has an entry and a type without one is never offered (v1 offered it for every
# requirement, so lookup-only types such as session_policy_configuration reached account-management requirements).
SCREEN_VERSION = "rule-screen-v2"
GROUNDING_VERSION = "rule-grounding-v3"
# v3 also: a requirement about these subjects is not about PAM access events, whatever words it shares with them
# ("Enforce authorized access to the corresponding private key" in IA-5(2) grounded an entitlement-status rule)
OFF_SUBJECT: dict[str, tuple[str, ...]] = {}
EVIDENCE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "privileged_session": ("session", "record", "playback", "shadow", "keystroke", "remote access", "nonlocal maintenance"),
    "privileged_account": ("account", "inactiv", "dormant", "disable", "temporary", "identifier", "discover", "lifecycle"),
    "credential_rotation": ("authenticator", "password", "credential", "rotat", "refresh", "key", "secret", "salted",
                            "hash", "composition", "complexity", "aes-256", "service account", "a2a"),
    "audit_event": ("audit record", "audit log", "event", "audit account", "audit action", "time stamp", "timestamp",
                    "privileged function", "query event", "logging"),
    "privileged_access_request": ("approv", "request", "dual authorization", "ticket", "itsm", "change control",
                                  "elevat", "just-in-time", "jit", "nonsecurity function", "allowlist", "blocklist",
                                  "application execution"),
    "access_authorization": ("authoriz", "entitle", "permission", "least privilege", "access enforcement", "account",
                             "role", "privilege", "prohibit", "prevent", "restrict", "security function", "private key",
                             "time-bound", "access policy", "access broker", "identifier"),
    "authentication_summary": ("unsuccessful", "failed logon", "failed login", "logon attempt", "login attempt",
                               "invalid logon", "lock"),
    "privileged_access_authentication": ("multi-factor", "multifactor", "mfa", "two-factor", "authenticat", "identify",
                                         "shared account", "non-organizational", "vendor", "contractor", "endpoint"),
    "mfa_configuration": ("multi-factor", "multifactor", "mfa", "two-factor"),
    "break_glass_event": ("emergency", "break-glass", "break glass", "backup", "recovery", "crisis"),
    "access_review": ("review", "recertif", "certif", "separation of duties", "segregation of duties",
                      "duties of individuals", "conflicting role", "sod"),
    "session_policy_configuration": ("inactiv", "idle", "session lock", "session termination", "timeout", "time-out",
                                     "time out", "concurrent session", "device lock"),
    "audit_log_coverage": ("audit", "logging", "monitoring", "siem", "syslog", "retain", "retention", "incident",
                           "anomal", "uba", "encrypt", "tls", "fips"),
    "policy_exception": ("exception", "waiver", "separation of duties", "sod"),
    # further Securden capabilities (LOOKUP_AVAILABLE until the collector sends them)
    "endpoint_elevation": ("elevat", "privilege", "endpoint", "workstation", "least privilege", "user-installed",
                           "execution", "temporary privilege", "privileged function", "install",
                           "application execution", "run as admin", "temporary admin"),
    "local_admin_membership": ("local admin", "administrator", "administrative group", "membership", "local account",
                               "group membership", "administrative", "privileged account", "least privilege",
                               "privileged group", "endpoint"),
    "application_control_policy": ("application", "software", "execution", "allowlist", "blocklist", "whitelisting",
                                   "blacklisting", "authorized software", "unauthorized software", "allow-list",
                                   "whitelist", "deny-list", "blacklist", "application execution",
                                   "program execution", "least functionality"),
    "password_policy_configuration": ("password", "authenticator", "complexity", "length", "composition", "history",
                                      "rotation period", "password-based", "reuse"),
    "audit_forwarding_configuration": ("audit", "forward", "destination", "syslog", "siem", "export", "offload",
                                       "centraliz", "telemetry", "central", "transfer", "alternate storage",
                                       "integrat", "correlat", "aggregat", "repository"),
    "backup_configuration": ("backup", "schedul", "encrypt", "recovery", "retention", "contingency", "restore",
                             "back up", "back-up", "cryptographic protection"),
}


# What a tested field means, as words the requirement must use for a rule on that field to test it (grounding
# gate rule-grounding-v3). A field without an entry cannot ground a generated rule. Each term is a regular
# expression matched at a word start in the lower-case requirement text.
# v2: session recording needs "record"/"recording"/"recorded", not the noun "records" ("audit records" in AU-3 is
# about log content and grounded a session-recording rule under v1).
# v3: the bare noun "record" no longer counts either ("audit record reduction" in AU-7 grounded the session-recording
# rule under v2); "recording"/"recorded", or "record" as a verb or a list item ("[...: record; view; ...]"), still do.
RECORDING = r"record(?:ings?|ed)\b|record(?=[;,\]]| (?:the|all|and|privileged|user|session))|session|remote|maintenance|shadow|playback"
FIELD_TERMS: dict[str, dict[str, tuple[str, ...]]] = {
    "privileged_session": {"recording_status": (RECORDING,), "recording_reference": (RECORDING,),
                           "recording_required": (RECORDING,),
                           "ended_at": ("terminat", "logout", "log out", "duration", "session", "remote"),
                           "credential_reset_after_use": ("reset", "revok", "one-time", "after use", "post-session",
                                                          "checkout"),
                           "shadowed": ("shadow", "control mode", "monitor", "view", "observ", "listen",
                                        "real time", "real-time"),
                           "terminated_by_admin": ("terminat", "disconnect", "disable", "stop", "end the session"),
                           "credential_disclosed": ("disclos", "expos", "reveal", "protect", "authenticator",
                                                    "password", "credential")},
    "privileged_account": {"enabled": ("enable", "disable", "account"),
                           "owner_id": ("owner", "custodian", "accountable", "individual", "assign", "account manager",
                                        "responsib"),
                           "last_used_at": ("inactiv", "dormant", "unused", "not used", "last used", "last use",
                                            "disable", "remove", "temporary", "account")},
    "credential_rotation": {"last_rotated_at": ("rotat", "refresh", "chang", "expir", "authenticator", "password", "key"),
                            "last_rotation_status": ("rotat", "refresh", "chang", "authenticator", "password", "key",
                                                     "credential", "salted", "hash", "complexity", "composition", "encrypt"),
                            "captured_at": ("snapshot", "time", "date", "rotat", "capture"),
                            "breached": ("compromis", "breach", "exposed", "commonly-used", "expected", "list"),
                            "policy_compliant": ("complexity", "composition", "length", "policy", "compliant",
                                                 "compli", "password", "authenticator", "strength")},
    "privileged_access_request": {"approval_status": ("approv", "request", "authoriz", "ticket", "elevat", "privilege",
                                                      "account", "application", "change"),
                                  "approval_id": ("approv", "ticket", "request"),
                                  "approved_at": ("approv", "request"),
                                  "approver_id": ("approv", "request", "authoriz"),
                                  "approvals_required": ("approv", "dual authorization", "two-person", "quorum",
                                                         "threshold", "dual", "two person", "multiple"),
                                  "approvals_received": ("approv", "authoriz", "quorum", "received", "dual",
                                                         "two-person", "two person", "multiple"),
                                  "credential_reset_after_use": ("reset", "revok", "one-time", "after use",
                                                                 "post-use", "checkout", "single use", "chang",
                                                                 "authenticator", "password"),
                                  "ticket_reference": ("ticket", "change request", "itsm", "change control"),
                                  "justification_provided": ("justif", "business need", "reason", "purpose"),
                                  "auto_approved": ("automat", "approv"),
                                  "access_expires_at": ("temporary", "time-bound", "time bound", "just-in-time",
                                                        "expir", "duration", "period", "time"),
                                  "revoked_at": ("revok", "remov", "disable", "temporary", "expir", "terminat")},
    "authentication_summary": {"failed_attempts": ("unsuccessful", "failed", "invalid logon", "attempt", "lock"),
                               "lockout_triggered": ("lock", "unsuccessful", "failed", "invalid logon", "attempt")},
    "access_authorization": {"entitlement_status": ("authoriz", "entitle", "privilege", "account", "role", "access",
                                                    "prohibit", "prevent", "restrict", "identifier", "key", "function"),
                             "entitlement_id": ("authoriz", "entitle", "privilege", "account", "role", "access"),
                             "entitlement_valid_from": ("authoriz", "entitle", "time", "access"),
                             "entitlement_valid_to": ("authoriz", "entitle", "expir", "temporary", "time", "vendor")},
    "break_glass_event": {"justification_provided": ("justif", "emergency", "break-glass", "break glass", "backup", "recover"),
                          "justification_length": ("justif", "emergency", "break-glass"),
                          "ticket_reference": ("ticket", "change request", "emergency", "incident"),
                          "post_review_completed": ("review", "emergency", "break-glass"),
                          "post_review_at": ("review", "emergency", "break-glass")},
    "policy_exception": {"status": ("exception", "separation", "duties", "sod", "waiver"),
                         "expires_at": ("exception", "expir", "separation", "sod")},
    "access_review": {"last_review_completed_at": ("review", "recertif", "certif", "compliance", "frequency"),
                      "last_review_outcome": ("review", "recertif", "certif", "separation", "segregation", "duties",
                                              "privilege", "compliance", "sod"),
                      "reviewer_id": ("review", "recertif", "certif", "separation", "duties"),
                      "owner_id": ("owner", "review", "account")},
    "audit_event": {"event_type": (r"type of event", r"event type", "event", "audit", "log", "action", "time stamp", "timestamp"),
                    "location_id": (r"where", r"location", "audit", "event"),
                    "source_id": (r"source", "audit", "event"),
                    "outcome": (r"outcome", "audit", "event", "action"),
                    "actor_id": (r"identit", r"individual", r"subject", "user", "actor", "audit", "event", "query"),
                    "target_id": (r"object", r"entit", "account", "target", "audit", "event", "query")},
    "audit_log_coverage": {"max_gap_seconds": ("gap", "continu", "complete", "audit", "log", "monitor", "storage", "fail"),
                           "received_event_count": ("complete", "event", "audit", "log", "retain", "monitor", "siem", "syslog"),
                           "integrity_verified": ("integrit", "tamper", "protect", "unauthoriz", "modif", "delet",
                                                  "audit", "retain", "review", "analy", "report", "incident", "encrypt",
                                                  "monitor")},
    "mfa_configuration": {"mfa_enforced": ("multi-factor", "multifactor", "mfa", "two-factor", "authenticat"),
                          "mfa_methods": ("multi-factor", "multifactor", "mfa", "two-factor", "authenticat")},
    "privileged_access_authentication": {"mfa_status": ("multi-factor", "multifactor", "mfa", "two-factor",
                                                        "authenticat", "identify", "shared", "authenticator", "vendor",
                                                        "non-organizational", "device", "endpoint"),
                                         "mfa_method": ("multi-factor", "multifactor", "mfa", "two-factor", "authenticat"),
                                         "access_granted": ("authenticat", "identify", "grant", "access", "map")},
    "session_policy_configuration": {"idle_timeout_enabled": ("idle", "inactiv", "lock", "terminat", "session", "concurrent"),
                                     "idle_timeout_minutes": ("idle", "inactiv", "lock", "terminat", "session", "time")},
    "endpoint_elevation": {"approval_status": ("approv", "authoriz", "auto-approv", "deni", "elevat", "privilege",
                                               "install", "execut"),
                           "elevation_id": ("elevat", "request"),
                           "user_id": ("user", "actor", "individual"),
                           "device_id": ("device", "workstation", "endpoint"),
                           "requested_at": ("request", "time"),
                           "application_id": ("application", "software", "program", "executable"),
                           "approver_id": ("approv", "authoriz"),
                           "approved_at": ("approv", "time"),
                           "elevation_expires_at": ("expir", "time-bound", "duration", "temporary", "time", "revok"),
                           "revoked_at": ("revok", "terminat", "remov", "temporary", "expir")},
    "local_admin_membership": {"approved_member": ("approv", "authoriz", "member", "allow", "permit", "administrat",
                                                   "admin", "privilege", "restrict", "account"),
                               "device_id": ("device", "workstation", "endpoint", "host"),
                               "account_id": ("account", "admin", "user"),
                               "captured_at": ("snapshot", "time", "date")},
    "application_control_policy": {"mode": ("mode", "allowlist", "blocklist", "monitor", "allow", "block", "deny",
                                            "whitelist", "blacklist", "exception"),
                                   "enforced": ("enforc", "prevent", "restrict", "control", "allow", "block", "deny",
                                                "whitelist", "blacklist", "authorized software",
                                                "unauthorized software", "execution", "functionality"),
                                   "policy_id": ("policy", "rule"),
                                   "captured_at": ("snapshot", "time", "date")},
    "password_policy_configuration": {"applies_to_privileged": ("privileged", "administrative"),
                                      "min_length": ("length", "characters", "minimum length", "complexity",
                                                     "composition", "password"),
                                      "complexity_required": ("complexity", "character classes", "composition",
                                                              "character", "password"),
                                      "enforced_on_reset": ("reset", "change", "enforc", "enforce", "complexity",
                                                            "composition", "password"),
                                      "rotation_period_days": ("rotat", "period", "days", "age", "frequency",
                                                               "chang", "lifetime", "expir", "password"),
                                      "history_count": ("history", "previous", "reuse", "prohibit", "password"),
                                      "policy_id": ("policy", "rule"),
                                      "captured_at": ("snapshot", "time", "date")},
    "audit_forwarding_configuration": {"protocol": ("protocol", "syslog", "api", "transport"),
                                       "enabled": ("enabl", "forward", "active", "deliver", "siem", "syslog",
                                                   "central", "transfer", "offload", "alternate", "integrat",
                                                   "correlat", "aggregat", "repository"),
                                       "destination_id": ("destination", "target", "server", "siem"),
                                       "last_delivery_at": ("deliver", "time", "last", "timestamp", "transfer",
                                                            "offload", "siem", "syslog", "central"),
                                       "captured_at": ("snapshot", "time", "date")},
    "backup_configuration": {"scheduled": ("schedul", "automated", "periodic", "frequency", "backup", "back up"),
                             "encrypted": ("encrypt", "cryptograph", "protect", "backup"),
                             "last_backup_status": ("status", "success", "failed", "outcome", "backup", "back up",
                                                    "recover", "restore"),
                             "backup_id": ("backup", "job"),
                             "last_backup_at": ("last backup", "backup time", "timestamp", "backup", "back up",
                                                "frequency"),
                             "captured_at": ("snapshot", "time", "date")},
}


def is_lookup(cap: dict[str, Any], etype: str) -> bool:
    """True when the PAM holds this evidence but the collector does not send it yet (LOOKUP_AVAILABLE)."""
    return ((cap.get("evidence_detail") or {}).get(etype) or {}).get("collection_status") == "LOOKUP_AVAILABLE"


def lookup_fields_used(cap: dict[str, Any], spec: "RuleSpec") -> list[str]:
    """Fields the rule uses that the PAM holds but the collector does not send yet (declared lookup_fields)."""
    held = set(((cap.get("evidence_detail") or {}).get(spec.evidence_type) or {}).get("lookup_fields") or [])
    return sorted(_fields(spec) & held)


def declared_version(cap: dict[str, Any], etype: str) -> str | None:
    """Declared schema version: collected types from the handshake evidence map, lookup types from their detail."""
    if etype in (cap.get("evidence") or {}):
        return cap["evidence"][etype]
    return ((cap.get("evidence_detail") or {}).get(etype) or {}).get("schema_version") if is_lookup(cap, etype) else None


def catalog_digest(cap: dict[str, Any]) -> str:
    """What the PAM can supply (types, versions, modes, fields), independent of collection status, so a type moving
    from LOOKUP_AVAILABLE to COLLECTED re-checks the stored proposal instead of asking the model again."""
    detail = cap.get("evidence_detail") or {}
    return digest_of({e: {"v": declared_version(cap, e), "modes": d.get("assessment_modes"),
                          "fields": d.get("supported_fields"),
                          **({"meanings": d["field_meanings"]} if d.get("field_meanings") else {})}
                      for e, d in sorted(detail.items())})


# ---------------------------------------------------------------- meaning-based reasoning (analyse, then judge)

_MEANINGS_FILE = Path(__file__).resolve().parent / "field_meanings.json"
FIELD_MEANINGS: dict[str, dict[str, dict[str, str]]] = {
    e: f for e, f in json.loads(_MEANINGS_FILE.read_text(encoding="utf-8")).items() if not e.startswith("$")}
_MATRIX_FILE = Path(__file__).resolve().parent / "securden_nist_800_53_matrix.json"
SECURDEN_NIST_MATRIX: list[dict[str, Any]] = (
    json.loads(_MATRIX_FILE.read_text(encoding="utf-8")).get("controls", []) if _MATRIX_FILE.is_file() else [])


def matrix_guidance(req: dict[str, Any], ref: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Matching Securden NIST SP 800-53 Control Mapping Matrix reference entries for this requirement."""
    ref = ref or {}
    cid = (ref.get("canonical_id") or "").upper()
    clause = (ref.get("clause") or "").lower()
    full = f"{cid} {clause}".strip() if cid and clause else cid
    full_paren = f"{cid}({clause})" if cid and clause else cid
    text = (req.get("translation_en") or req.get("original_text") or "").lower()
    exact, base_hits, text_hits = [], [], []
    for entry in SECURDEN_NIST_MATRIX:
        ecid = entry["control_id"].upper()
        aliases = {a.upper() for a in entry.get("aliases", [])} | {ecid}
        if full and (full.upper() in aliases or full_paren.upper() in aliases):
            exact.append(entry)
        elif cid and (cid in aliases or ecid == cid.split("(")[0]):
            base_hits.append(entry)
        elif ecid.lower() in text or any(w in text for w in (entry.get("title") or "").lower().split() if len(w) > 5):
            text_hits.append(entry)
    return (exact or base_hits or text_hits)[:3]


def field_meaning(cap: dict[str, Any], etype: str, field: str) -> dict[str, str]:
    """What a field shows: the collector's own declaration (field_meanings) over OPM's framework-neutral defaults."""
    declared = (((cap.get("evidence_detail") or {}).get(etype) or {}).get("field_meanings") or {}).get(field)
    return dict(declared or FIELD_MEANINGS.get(etype, {}).get(field) or {})


def _evidence_brief(cap: dict[str, Any], etypes: list[str], *, req: dict[str, Any] | None = None,
                    ref: dict[str, Any] | None = None) -> str:
    """Compact plain-text description of the offered evidence for the reasoning and judging calls."""
    lines = []
    if req is not None:
        for g in matrix_guidance(req, ref):
            t = g.get("recommended_test") or {}
            rhs = t.get("parameter") or json.dumps(t.get("value")) if ("parameter" in t or "value" in t) else ""
            lines.append(f"Securden NIST SP 800-53 Reference ({g['control_id']} - {g['title']}): "
                         f"{g['securden_capability']} Recommended technical test: "
                         f"{g['evidence_type']}.{t.get('field')} {t.get('operator')} {rhs} ({t.get('rationale')}).")
    for etype in etypes:
        d = (cap.get("evidence_detail") or {}).get(etype) or {}
        cat = CUSTOM_RULE_FIELDS.get(etype, {})
        caveats = f" [{' '.join(d['caveats'])}]" if d.get("caveats") else ""
        lines.append(f"{etype} ({'available by lookup' if is_lookup(cap, etype) else 'collected'}){caveats}:")
        for f in d.get("supported_fields") or []:
            if f in ("record_id", "scope_tags") or f not in cat:
                continue
            m = field_meaning(cap, etype, f)
            vals = f" values {'/'.join(cat[f]['values'])}" if cat[f].get("values") else ""
            shows = f"; shows: {m['shows']}" if m.get("shows") else ""
            lines.append(f"  - {f} [{cat[f]['type']}{vals}]: {m.get('meaning', 'no description')}{shows}")
    return "\n".join(lines)


SYSTEM_ANALYSE = (
    "You are a PAM compliance analyst. Decide whether ONE regulatory requirement can be checked automatically from "
    "the listed PAM evidence. Reason from what each field MEANS, not from shared words. Answer in at most 150 words:\n"
    "1. Obligation: what the requirement obliges, in one sentence.\n"
    "2. Compliant vs violating: what a compliant record and a violating record would look like.\n"
    "3. Evidence: which listed field tells them apart, and which records are in scope; or why none does.\n"
    "Many requirements are about documents, procedures, design or people's judgement: those are NOT testable from "
    "records. A field that merely shares a word with the requirement does not test it.\n"
    "End with exactly one line, one of:\n"
    "VERDICT: TESTABLE <evidence_type>.<field>\nVERDICT: NOT_TESTABLE\nVERDICT: PERSON_JUDGES")

# Asked as one concrete choice between two records OPM writes from the rule (one passing, one failing, in an order
# fixed by the spec digest). Abstract questions failed on gemma3:4b (NIST run 2026-11-20): "does the rule test the
# requirement" became "does it cover all of it" (9 of 9 partial rules rejected, AC-7 a's failed-logon limit among
# them) and "would a compliant organisation fail it" was answered FAIL for nearly every rule. The concrete choice
# also catches inverted rules ("each record must have failed_attempts >= the maximum"), which no other gate sees.
SYSTEM_JUDGE = (
    "You check one automated PAM rule against a regulatory requirement. You get the requirement and two example "
    "records, A and B. Decide which record shows the organisation BREAKING the requirement (doing what it forbids or "
    "not doing what it demands). Answer NEITHER when neither record says anything about this requirement. The rule "
    "only checks one specific thing; that is expected. Explain in at most 50 words, then end with exactly one "
    "line: ANSWER: A, ANSWER: B or ANSWER: NEITHER")

_OP_WORDS = {"equals": "is", "not_equals": "is not", "less_than": "is below", "less_than_or_equal": "is at most",
             "greater_than": "is above", "greater_than_or_equal": "is at least", "in": "is one of",
             "not_in": "is none of", "contains": "contains", "exists": "is filled in", "not_exists": "is empty",
             "older_than_days": "is more than {} days ago", "within_last_days": "is within the last {} days"}
_OP_NEGATED = {"equals": "not_equals", "not_equals": "equals", "less_than": "greater_than_or_equal",
               "less_than_or_equal": "greater_than", "greater_than": "less_than_or_equal",
               "greater_than_or_equal": "less_than", "in": "not_in", "not_in": "in", "exists": "not_exists",
               "not_exists": "exists", "older_than_days": "within_last_days", "within_last_days": "older_than_days",
               "contains": "contains"}


def _says(p: Predicate, cap: dict[str, Any], etype: str, *, negate: bool = False) -> str:
    op = _OP_NEGATED[p.operator] if negate else p.operator
    rhs = (p.parameter.replace("_", " ") if p.parameter else
           ("" if p.value is None else ", ".join(map(str, p.value)) if isinstance(p.value, list) else str(p.value)))
    words = _OP_WORDS[op]
    words = words.format(rhs) if "{}" in words else f"{words} {rhs}".strip()
    if negate and p.operator == "contains":
        words = f"does not contain {rhs}"
    meaning = field_meaning(cap, etype, p.field).get("meaning", "")
    return f"{p.field} {words}" + (f" ({meaning.split('.')[0][:90]})" if meaning else "")


def example_records(spec: RuleSpec, cap: dict[str, Any]) -> tuple[str, str]:
    """(passing, failing) records in words, derived from the condition: the passing one satisfies every test, the
    failing one breaks it in the least way (first test negated for all/leaf, every test negated for any)."""
    node = spec.condition
    leaves = list(_predicates(node))
    op = "all" if isinstance(node, Predicate) else node.operator
    ok = [_says(p, cap, spec.evidence_type) for p in leaves]
    if op == "none":
        passing = [_says(p, cap, spec.evidence_type, negate=True) for p in leaves]
        failing = [ok[0]] + passing[1:]
    elif op == "any":
        passing, failing = ok, [_says(p, cap, spec.evidence_type, negate=True) for p in leaves]
    else:
        passing, failing = ok, [_says(leaves[0], cap, spec.evidence_type, negate=True)] + ok[1:]
    scope = "; ".join(_says(p, cap, spec.evidence_type) for p in spec.population.where)
    head = f"A {spec.evidence_type.replace('_', ' ')} record" + (f" where {scope}" if scope else "") + ": "
    return head + "; ".join(passing) + ".", head + "; ".join(failing) + "."

_VERDICT = re.compile(r"VERDICT:\s*(TESTABLE\s+([a-z_]+)\.([a-z_]+)|NOT_TESTABLE|PERSON_JUDGES)")
_ANSWER = re.compile(r"ANSWER:\s*\**\s*(A|B|NEITHER)\b")


def can_reason(llm: Any) -> bool:
    return callable(getattr(llm, "generate_text", None))


def named_fields(text: str, cap: dict[str, Any], etypes: list[str]) -> list[str]:
    """Declared fields (other than identifiers, timestamps of the period and scope flags) the reasoning names
    together with a value or comparison, e.g. "entitlement_status = AUTHORIZED" or "`mfa_status` is VERIFIED"."""
    out = []
    for etype in etypes:
        cat = CUSTOM_RULE_FIELDS.get(etype, {})
        for f in (((cap.get("evidence_detail") or {}).get(etype) or {}).get("supported_fields") or []):
            if f not in cat or f in ("record_id", "scope_tags") or (cat[f]["type"] == "string" and not cat[f]["nullable"]):
                continue
            if re.search(rf"`?\b{re.escape(f)}\b`?\s*(?:=|==|!=|<|>|:|is\b|as\b|equals?\b|of\b|set to\b|shows?\b"
                         rf"|reads?\b|being\b|would be\b|must be\b)", text):
                out.append(f)
    return sorted(set(out))


def analyse(llm: Any, req: dict[str, Any], cap: dict[str, Any], etypes: list[str], *,
            ref: dict[str, Any] | None = None) -> dict[str, Any]:
    """Step 1 (no grammar): the model reasons about the obligation and names the field that would test it.
    Returns {"text", "verdict": TESTABLE|NOT_TESTABLE|PERSON_JUDGES|UNCLEAR, "evidence_type", "field"}."""
    prompt = (f"Requirement: {req.get('translation_en') or req['original_text']}\n\nPAM evidence:\n"
              f"{_evidence_brief(cap, etypes, req=req, ref=ref)}")
    text = llm.generate_text(SYSTEM_ANALYSE, prompt, max_tokens=400).content.strip()
    found = _VERDICT.findall(text)
    if not found:
        return {"text": text[:2000], "verdict": "UNCLEAR", "evidence_type": None, "field": None}
    whole, etype, field = found[-1]
    verdict = "TESTABLE" if whole.startswith("TESTABLE") else whole
    if verdict == "TESTABLE" and (etype not in etypes or field not in
                                  (((cap.get("evidence_detail") or {}).get(etype) or {}).get("supported_fields") or [])):
        verdict = "UNCLEAR"  # named something that is not offered: let the writing step choose among the offered
    if verdict == "NOT_TESTABLE" and (named_fields(text, cap, etypes) or matrix_guidance(req, ref)):
        # small models contradict themselves ("a compliant record shows entitlement_status = AUTHORIZED ... VERDICT:
        # NOT_TESTABLE" for AC-2 i): reasoning that names a declared test field is not a decline; write and judge it
        verdict = "UNCLEAR"
    return {"text": text[:2000], "verdict": verdict, "evidence_type": etype or None, "field": field or None}


def describe_rule(spec: RuleSpec, cap: dict[str, Any], *, limitations: bool = True) -> str:
    def pred(p: Any) -> str:
        m = field_meaning(cap, spec.evidence_type, p.field).get("meaning", "")
        rhs = f"parameter {p.parameter}" if p.parameter else ("" if p.value is None else json.dumps(p.value))
        return f"{p.field} {p.operator} {rhs}".strip() + (f" ({m})" if m else "")
    scope = "; ".join(pred(p) for p in spec.population.where) or "all records"
    tests = "; ".join(pred(p) for p in _predicates(spec.condition))
    out = (f"Evidence: {spec.evidence_type} records in the assessment period (by {spec.population.period_field}).\n"
           f"In scope: {scope}.\nEach in-scope record must satisfy: {tests}.")
    return out + (f"\nStated limitations: {'; '.join(spec.limitations) or 'none'}." if limitations else "")


def judge(llm: Any, req: dict[str, Any], spec: RuleSpec, cap: dict[str, Any], *, grounded: bool,
          ref: dict[str, Any] | None = None) -> dict[str, Any]:
    """Step 3 (no grammar): an independent review of the finished rule against the requirement."""
    note = "" if grounded else ("\nNote: the requirement text does not use the usual words for the tested field; "
                                "accept only if the meaning clearly matches.")
    guidance = matrix_guidance(req, ref)
    matrix_note = ("\nSecurden PAM Capability Alignment: " + " ".join(
        f"{g['control_id']}: {g['securden_capability']}" for g in guidance)) if guidance else ""
    passing, failing = example_records(spec, cap)
    swap = int(digest_of(spec.model_dump(mode="json")).split(":")[-1][:2], 16) % 2 == 1
    a, b = (failing, passing) if swap else (passing, failing)
    prompt = (f"Requirement: {req.get('translation_en') or req['original_text']}{matrix_note}\n\n"
              f"Record A: {a}\nRecord B: {b}{note}")
    text = llm.generate_text(SYSTEM_JUDGE, prompt, max_tokens=200).content.strip()
    found = _ANSWER.findall(text)
    answer = found[-1] if found else None
    failing_label = "A" if swap else "B"
    verdict = ("UNCLEAR" if answer is None else "YES" if answer == failing_label else
               "NO" if answer == "NEITHER" else "FLAGS_COMPLIANT")
    return {"text": text[:1500], "verdict": verdict, "answer": answer, "failing_record": failing_label,
            "records": {"A": a, "B": b}}


def grounded_fields(spec: RuleSpec, req: dict[str, Any]) -> list[str]:
    """Condition fields whose meaning the requirement text states (see FIELD_TERMS)."""
    text = (req.get("translation_en") or req.get("original_text") or "").lower()
    if any(re.search(r"\b" + t, text) for t in OFF_SUBJECT.get(spec.evidence_type, ())):
        return []
    terms = FIELD_TERMS.get(spec.evidence_type, {})
    return sorted({p.field for p in _predicates(spec.condition)
                   if any(re.search(r"\b" + t, text) for t in terms.get(p.field, ()))})


def relevant_evidence(req: dict[str, Any], cap: dict[str, Any], *, ref: dict[str, Any] | None = None) -> list[str]:
    text = (req.get("translation_en") or req.get("original_text") or "").lower()
    guided = {g["evidence_type"] for g in matrix_guidance(req, ref) if g.get("evidence_type")}
    out = []
    for etype in sorted((cap.get("evidence_detail") or {})):
        if etype not in CUSTOM_RULE_FIELDS:
            continue
        cat, supported = CUSTOM_RULE_FIELDS[etype], (cap["evidence_detail"][etype].get("supported_fields") or [])
        if not any(f in cat and cat[f]["type"] == "datetime" and not cat[f]["nullable"] for f in supported):
            continue  # no period field is collected for this type, so no generated rule can use it
        if etype in guided or any(w in text for w in EVIDENCE_KEYWORDS.get(etype, ())):
            out.append(etype)
    return out


def grammar_schema(db: CatalogDb, req: dict[str, Any], cap: dict[str, Any]) -> dict[str, Any]:
    """The decoding grammar for one requirement: no $ref, no regex patterns (Ollama's converter drops both and then
    accepts anything), enums for every identifier that must exist. Everything the validator requires is required
    here, so the model cannot omit it. The Proposal model still validates the result; this only removes the ways a
    small model fails (invented control ids, unknown fields, wrong shapes)."""
    detail = cap.get("evidence_detail") or {}
    variants = [v for etype in sorted(detail) if etype in CUSTOM_RULE_FIELDS
                for v in [_spec_grammar(db, req, cap, etype)] if v is not None]
    spec: dict[str, Any] = {"anyOf": variants} if len(variants) > 1 else (variants[0] if variants else {"type": "null"})
    return {"type": "object", "additionalProperties": False,
            "required": ["requirement_id", "decision", "confidence", "rationale", "rule_spec"],
            "properties": {"requirement_id": {"const": req["id"]},
                           "decision": {"enum": ["PROPOSE", "NO_RULE", "MANUAL_ASSESSMENT"]},
                           "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                           "rationale": {"type": "string", "minLength": 1, "maxLength": 800},
                           "rule_spec": {"anyOf": [spec, {"type": "null"}]}}}


def _spec_grammar(db: CatalogDb, req: dict[str, Any], cap: dict[str, Any], etype: str) -> dict[str, Any] | None:
    """One RuleSpec branch per declared evidence type: its own version, modes and supported fields. None when the
    type has no collected non-null datetime field, since every generated rule needs one as its period field."""
    d = (cap.get("evidence_detail") or {})[etype]
    versions = [str(declared_version(cap, etype) or EVIDENCE_SCHEMA_VERSIONS.get(etype, "1.0"))]
    # record_id and scope_tags are bookkeeping: tag values are defined per organization and the model cannot know
    # them (it invented tags such as "account_details"), so neither is offered as a testable field
    fields = sorted(f for f in d.get("supported_fields") or [] if f in CUSTOM_RULE_FIELDS[etype]
                    and f not in ("record_id", "scope_tags"))
    times = [f for f in fields if CUSTOM_RULE_FIELDS[etype][f]["type"] == "datetime"
             and not CUSTOM_RULE_FIELDS[etype][f]["nullable"]]
    if not times:
        return None
    modes = sorted(d.get("assessment_modes") or []) or ["EVENT_HISTORY"]
    etypes = [etype]
    controls = [r["id"] for r in db.q("SELECT id FROM pam_control ORDER BY id")]
    settings = [(cid, name) for (cid, _v), defn in sorted(pc.CONTROLS.items())
                for name, s in ((defn.get("parameter_schema") or {}).get("properties") or {}).items()
                if s.get("type") in ("integer", "boolean")]
    # parameter names: a closed list (Ollama ignores string patterns, so a free string let the model write "7.000..."
    # as a parameter name); the organization-setting names plus generic thresholds by unit
    # only integer thresholds take parameters in conditions; each name carries one unit and its own setting binding
    param_unit = {n: p["unit"] for n, p in parameter_catalog().items()}
    param_names = sorted(param_unit)
    text = {"type": "string", "minLength": 1, "maxLength": 400}
    lit = {"anyOf": [{"type": "boolean"}, {"type": "integer"}, {"type": "string", "maxLength": 64},
                     {"type": "array", "items": {"type": "string", "maxLength": 64}, "maxItems": 20}, {"type": "null"}]}
    # a predicate takes a literal value (or none, for exists/not_exists) OR a declared parameter, never both; one
    # branch per field type so the model can only pair a field with an operator its type allows (validate's table)
    # (and exists/not_exists only for nullable fields: on a never-null field they test nothing)
    by_type: dict[tuple[str, bool], list[str]] = {}
    for f in fields:
        by_type.setdefault((CUSTOM_RULE_FIELDS[etype][f]["type"], bool(CUSTOM_RULE_FIELDS[etype][f]["nullable"])),
                           []).append(f)
    order = list(get_args(Operator))

    def predicate_grammar(population: bool) -> dict[str, Any]:
        # validate(): 'contains' only in population filters; population filters take literals, never parameters
        # exists/not_exists take no value; integer and datetime thresholds are declared parameters, never literals
        # population filters only select scope by yes/no flags (privileged, recording_required, approval_required,
        # ...); statuses, timestamps and counts are what a condition tests. Small models otherwise put the tested
        # status into the filter too ("among AUTHORIZED records, each is AUTHORIZED"), which tests nothing.
        # v12: scope flags (privileged, *_required, applies_to_*) only filter; everything else only in conditions,
        # so a filter and the condition can never test the same field
        def scope_flag(f: str) -> bool:
            return f in ("privileged", "enabled") or f.endswith("_required") or f.startswith("applies_to_")
        period_only = set(times) - ({"expires_at"} if etype == "policy_exception" else set())
        variants: list[dict[str, Any]] = []
        for (ftype, nullable), all_names in sorted(by_type.items()):
            if population and ftype != "boolean":
                continue
            names = [f for f in all_names if scope_flag(f) == population and (population or f not in period_only)]
            if not names:
                continue
            allowed = [o for o in order if o in _SPEC_OPS.get(ftype, ()) and (nullable or o not in _NULL_OPS)
                       and (population or o != "contains")]
            null_ops = [o for o in allowed if o in _NULL_OPS]
            if null_ops:
                variants.append({"type": "object", "additionalProperties": False, "required": ["field", "operator"],
                                 "properties": {"field": {"enum": names}, "operator": {"enum": null_ops}}})
            rest = [o for o in allowed if o not in _NULL_OPS]
            if ftype in ("integer", "datetime"):
                with_param = [o for o in rest if o in _PARAM_OPS]
                for name in names if with_param and not population else []:
                    # only parameter names whose unit fits the field (validate's unit rule)
                    unit = "days" if ftype == "datetime" else field_unit(name)
                    fit = [p for p in param_names if param_unit[p] == unit or (
                        ftype == "integer" and (param_unit[p] in _TIME_UNITS and unit in _TIME_UNITS
                                                or unit is None and param_unit[p] == "count"))]
                    if fit:
                        variants.append({"type": "object", "additionalProperties": False,
                                         "required": ["field", "operator", "parameter"],
                                         "properties": {"field": {"const": name}, "operator": {"enum": with_param},
                                                        "parameter": {"enum": fit}}})
            elif rest:
                # literal values typed per field: booleans, or the field's enum values (scalar, or a list for in/not_in)
                for name in names:
                    allowed_values = list(CUSTOM_RULE_FIELDS[etype][name]["values"] or [])
                    if ftype == "boolean":
                        shapes = [(rest, {"type": "boolean"})]
                    elif allowed_values:
                        scalar = [o for o in rest if o not in ("in", "not_in")]
                        listed = [o for o in rest if o in ("in", "not_in")]
                        shapes = [s for s in ((scalar, {"enum": allowed_values}),
                                              (listed, {"type": "array", "items": {"enum": allowed_values},
                                                        "minItems": 1, "maxItems": len(allowed_values)})) if s[0]]
                    else:
                        shapes = [(rest, lit)]
                    for ops_, value in shapes:
                        variants.append({"type": "object", "additionalProperties": False,
                                         "required": ["field", "operator", "value"],
                                         "properties": {"field": {"const": name}, "operator": {"enum": ops_},
                                                        "value": value}})
        return {"anyOf": variants}
    pred, pop_pred = predicate_grammar(False), predicate_grammar(True)
    if not pred["anyOf"]:
        return None  # nothing testable in a condition for this type (and Ollama rejects an empty anyOf)
    leaf = {"type": "object", "additionalProperties": False, "required": ["operator", "where"],
            "properties": {"operator": {"enum": ["all", "any", "none"]},
                           "where": {"type": "array", "items": pred, "minItems": 1, "maxItems": 10}}}
    root = {"type": "object", "additionalProperties": False, "required": ["operator", "where"],
            "properties": {"operator": {"enum": ["all", "any", "none"]},
                           "where": {"type": "array", "items": {"anyOf": [pred, leaf]}, "minItems": 1, "maxItems": 10}}}
    spec = {"type": "object", "additionalProperties": False,
            "required": ["spec_version", "title", "description", "pam_control_id", "evidence_type",
                         "evidence_schema_version", "assessment_mode", "subject_field", "population", "parameters",
                         "condition", "missing_evidence_result", "coverage", "source_requirement_ids", "limitations"],
            "properties": {
                "spec_version": {"const": SPEC_VERSION}, "title": {"type": "string", "minLength": 3, "maxLength": 120},
                "description": text, "pam_control_id": {"enum": controls}, "evidence_type": {"enum": etypes},
                "evidence_schema_version": {"enum": versions}, "assessment_mode": {"enum": modes},
                "subject_field": {"enum": [f for f in fields if CUSTOM_RULE_FIELDS[etype][f]["type"] == "string"
                                           and not CUSTOM_RULE_FIELDS[etype][f]["nullable"]] or fields},
                "population": {"type": "object", "additionalProperties": False, "required": ["type", "period_field", "where"],
                               "properties": {"type": {"const": "ORGANIZATION_SUPPORTED_ENTITIES"},
                                              "period_field": {"enum": times},
                                              # Ollama rejects an empty anyOf: no filterable field, no filters
                                              "where": ({"type": "array", "items": pop_pred, "maxItems": 10}
                                                        if pop_pred["anyOf"] else
                                                        {"type": "array", "maxItems": 0})}},
                # OPM declares the parameters the condition names (parameter_catalog); listing every allowed name
                # here made the model fill all of them and run out of output tokens
                "parameters": {"type": "object", "additionalProperties": False, "properties": {}},
                "condition": {"anyOf": [pred, root]},
                "missing_evidence_result": {"const": "INSUFFICIENT_EVIDENCE"}, "coverage": {"const": "PARTIAL"},
                "source_requirement_ids": {"type": "array", "items": {"const": req["id"]}, "minItems": 1, "maxItems": 1},
                "limitations": {"type": "array", "items": {"type": "string", "minLength": 10, "maxLength": 300},
                                "minItems": 1, "maxItems": 5}}}
    return spec


def _model_input(proposal: dict[str, Any]) -> dict[str, Any]:
    """The grammar makes every key explicit (null predicate value/parameter, empty description); drop the nulls
    so the result is the RuleSpec the validator expects."""
    def clean(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: clean(v) for k, v in o.items()
                    if not (v is None and k in ("value", "parameter", "policy_control"))}
        return [clean(v) for v in o] if isinstance(o, list) else o
    return clean(proposal)


# One synthetic example of a well-formed answer (never a real regulation; the model must not copy its content).
EXAMPLE_PROPOSAL = (
    'Synthetic example of the answer format only (requirement 0 "Every privileged session must have a complete '
    'recording"; do not copy its content): {"requirement_id":0,"decision":"PROPOSE","confidence":0.9,"rationale":'
    '"Recording status is collected per privileged session.","rule_spec":{"spec_version":"1.0","title":"Privileged '
    'sessions are fully recorded","description":"Each in-period privileged session has an available recording.",'
    '"pam_control_id":"<one listed PAM control id>","evidence_type":"privileged_session","evidence_schema_version":'
    '"1.0","assessment_mode":"EVENT_HISTORY","subject_field":"session_id","population":{"type":'
    '"ORGANIZATION_SUPPORTED_ENTITIES","period_field":"started_at","where":[{"field":"recording_required","operator":'
    '"equals","value":true,"parameter":null}]},"parameters":{},"condition":{"field":"recording_status","operator":'
    '"equals","value":"AVAILABLE","parameter":null},"missing_evidence_result":"INSUFFICIENT_EVIDENCE","coverage":'
    '"PARTIAL","source_requirement_ids":[0],"limitations":["Does not establish who may view recordings."]}}. '
    'A threshold is never a literal: put a parameter name from the schema in the condition (OPM declares it); '
    'leave "parameters" empty. When the listed evidence cannot test the obligation answer '
    '{"decision":"NO_RULE","rule_spec":null,...}.')
_EXAMPLE_LIMITATIONS = frozenset(x.strip().lower() for x in re.findall(
    r'"limitations":\["([^"]+)"', EXAMPLE_PROPOSAL))


# ---------------------------------------------------------------- orchestration per requirement

def _gap(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"outcome": "GAP", "gap_code": code, "message": message[:600], **extra}


def _live_mappings(db: CatalogDb, rid: int, scope: str) -> list[dict[str, Any]]:
    return db.q("SELECT id, rule_id, rule_version_min, organization_scope FROM framework_control_mapping WHERE "
                "requirement_id=? AND status IN ('DRAFT','APPROVED') AND (organization_scope IS NULL OR "
                "organization_scope=?)", (rid, scope))


def _store_activate(store_path: Path, tenant: str, compiled: dict[str, Any], actor: str) -> None:
    from app.engine.store import RuleStore

    store = RuleStore(store_path)
    try:
        d = compiled["definition"]
        row = store.get_custom(tenant, d["rule_id"], d["version"])
        if row is None:
            store.create_custom(tenant, d, compiled["compiled"], compiled["rule_digest"].split(":", 1)[1], actor)
        elif row["digest"] != compiled["rule_digest"].split(":", 1)[1] and row["compiled"] != compiled["compiled"]:
            # same id but different logic would be a digest collision; identical logic with a different title or
            # source requirement (a second requirement proposing the same test) reuses the stored rule
            raise Gap("RULE_COMPILATION_FAILED", f"{d['rule_id']} exists in the rule store with different logic")
        if row is None or row["status"] != "ACTIVE":
            store.set_custom_status(tenant, d["rule_id"], d["version"], "ACTIVE", actor)
    finally:
        store.close()


def _store_deactivate(store_path: Path, tenant: str, rule_id: str, actor: str) -> None:
    from app.engine.store import RuleStore

    store = RuleStore(store_path)
    try:
        row = store.get_custom(tenant, rule_id, "1.0")
        if row is not None and row["status"] == "ACTIVE":
            store.set_custom_status(tenant, rule_id, "1.0", "INACTIVE", actor)
    finally:
        store.close()


def _persist_rule(db: CatalogDb, *, spec: RuleSpec, compiled: dict[str, Any], resolution: list[dict[str, Any]],
                  scope: str, tenant: str, cap: dict[str, Any], req: dict[str, Any], checks: list[str],
                  cases: list[dict[str, Any]], results: list[dict[str, Any]], llm_prov: dict[str, Any],
                  bundle_version: str) -> dict[str, Any]:
    existing = db.one("SELECT * FROM generated_rule_version WHERE organization_scope=? AND tenant_id=? AND rule_id=? "
                      "AND version=?", (scope, tenant, compiled["rule_id"], compiled["version"]))
    if existing is not None:
        return existing
    with db.tx():
        if db.one("SELECT 1 FROM opa_rule_definition WHERE rule_id=?", (compiled["rule_id"],)) is None:
            db.insert("opa_rule_definition", rule_id=compiled["rule_id"], pam_control_id=spec.pam_control_id,
                      kind="STRUCTURED", title=spec.title, created_at=now_iso())
        gid = db.insert(
            "generated_rule_version", organization_scope=scope, tenant_id=tenant, rule_id=compiled["rule_id"],
            version=compiled["version"], pam_control_id=spec.pam_control_id, rule_spec=spec.model_dump(mode="json"),
            spec_digest=compiled["spec_digest"], structure_digest=compiled["structure_digest"],
            parameter_resolution=resolution, values_digest=compiled["values_digest"],
            definition=compiled["definition"], compiled_rule=compiled["compiled"], rule_digest=compiled["rule_digest"],
            rego_digest=compiled["rego_digest"], compiler_version=COMPILER_VERSION, evidence_type=spec.evidence_type,
            evidence_schema_version=spec.evidence_schema_version, assessment_mode=spec.assessment_mode,
            collector_digest=cap["digest"], source_references=[{
                "requirement_id": req["id"], "framework_id": req["framework_id"],
                "document_version_id": req["document_version_id"], "section_ref": req["section_ref"],
                "quotation": (req.get("original_text") or "")[:600]}],
            llm_provenance=llm_prov, validation_result={"checks": checks}, tests=cases, test_results=results,
            bundle_version=bundle_version, rule_limitations=list(spec.limitations), status="VALIDATED",
            created_at=now_iso())
        db.audit(llm_prov.get("actor") or "opm", "GENERATED_RULE_VALIDATED", "generated_rule_version", gid,
                 rule_id=compiled["rule_id"], organization_scope=scope)
    return db.one("SELECT * FROM generated_rule_version WHERE id=?", (gid,))  # type: ignore[return-value]


def _activate_and_map(db: CatalogDb, engine: Any, *, row: dict[str, Any], compiled: dict[str, Any], spec: RuleSpec,
                      req: dict[str, Any], scope: str, tenant: str, actor: str, store_path: Path,
                      proposal: Proposal, decision_digest: str, job_id: str | None) -> dict[str, Any]:
    live = _live_mappings(db, req["id"], scope)
    ours = [m for m in live if (m["rule_id"] or "").startswith(GENERATED_RULE_PREFIX) and m["organization_scope"] == scope]
    same = [m for m in ours if m["rule_id"] == compiled["rule_id"]]
    others = [m["id"] for m in live if m not in ours]
    if others:
        return _gap("POLICY_CONFLICT", "a different live mapping exists for this requirement; it is kept",
                    conflicting_mapping_ids=others, rule_id=compiled["rule_id"])
    _store_activate(store_path, tenant, compiled, actor)
    if row["status"] != "ACTIVE":
        with db.tx():
            db.x("UPDATE generated_rule_version SET status='ACTIVE', status_reason=?, activated_at=? WHERE id=?",
                 ("all deterministic gates and generated tests passed", now_iso(), row["id"]))
            db.audit(actor, "GENERATED_RULE_ACTIVATED", "generated_rule_version", row["id"], rule_id=row["rule_id"])
    if same:
        return {"outcome": "EXISTING", "gap_code": None, "mapping_id": same[0]["id"], "rule_id": compiled["rule_id"],
                "rule_version": compiled["version"], "generated_rule_version_id": row["id"]}
    view = engine_for(db, engine, scope, tenant)
    rationale = (f"AUTOMATED_LLM ({POLICY_VERSION}, prompt {PROMPT_VERSION}, compiler {COMPILER_VERSION}): generated "
                 f"rule {compiled['rule_id']} ({spec.title}). {proposal.rationale.strip()}"[:3800])
    replaced: list[int] = []
    with db.tx():  # replace atomically: superseded generated mappings go only if the replacement is created
        for m in ours:
            catalog.withdraw(db, "mapping", m["id"], actor=actor, reason=f"AUTOMATED_LLM ({POLICY_VERSION}): "
                             f"replaced by a mapping to {compiled['rule_id']} (new immutable decision)")
            replaced.append(m["id"])
        mid = catalog.create_mapping(
            db, requirement_id=req["id"], assessment="AUTOMATED", rule_id=compiled["rule_id"], rule_version_min="1.0",
            rule_version_max="1.0", coverage="PARTIAL", parameters={}, override_constraints={},
            evidence_type=spec.evidence_type, rationale=rationale,
            limitations="PARTIAL technical coverage by an OPM-generated rule. " + " ".join(spec.limitations),
            actor=actor, engine_rules=view.rules, organization_scope=scope)
    record = {"automated": True, "decision_origin": "AUTOMATED_LLM", "mapping_policy_version": POLICY_VERSION,
              "prompt_version": PROMPT_VERSION, "compiler_version": COMPILER_VERSION, "job_id": job_id,
              "decision_digest": decision_digest, "confidence": proposal.confidence,
              "generated_rule": provenance(db.one("SELECT * FROM generated_rule_version WHERE id=?", (row["id"],))),
              "parameter_provenance": row["parameter_resolution"], "coverage": "PARTIAL",
              "organization_scope_bound": True}
    catalog.review(db, "mapping", mid, reviewer=actor, decision="APPROVED",
                   comment=f"AUTOMATED_LLM approval ({POLICY_VERSION}): generated rule passed schema, collector, "
                           "grounding, compilation and every generated test against the real OPA binary.",
                   attestations=record, origin="AUTOMATED_LLM", policy_version=POLICY_VERSION)
    for rule_id in sorted({m["rule_id"] for m in ours}):
        if not _live_mappings_for_rule(db, rule_id, scope):  # no other requirement of this organization uses it
            with db.tx():
                db.x("UPDATE generated_rule_version SET status='SUPERSEDED', superseded_by=?, status_reason=? WHERE "
                     "organization_scope=? AND tenant_id=? AND rule_id=? AND status='ACTIVE'",
                     (row["id"], f"replaced by {compiled['rule_id']}", scope, tenant, rule_id))
            _store_deactivate(store_path, tenant, rule_id, actor)
    return {"outcome": "PUBLISHABLE", "gap_code": None, "mapping_id": mid, "rule_id": compiled["rule_id"],
            "rule_version": compiled["version"], "generated_rule_version_id": row["id"],
            **({"replaced_mapping_ids": replaced} if replaced else {})}


def _retire_generated(db: CatalogDb, rid: int, *, scope: str, tenant: str | None, actor: str, store_path: Path,
                      reason: str) -> list[int]:
    """Withdraw this organization's live generated mappings of a requirement that the hub no longer allows, and
    deactivate each generated rule no other live mapping of the organization uses. Returns the withdrawn ids."""
    withdrawn: list[int] = []
    for m in _live_mappings(db, rid, scope):
        if not (m["rule_id"] or "").startswith(GENERATED_RULE_PREFIX) or m["organization_scope"] != scope:
            continue
        if db.scalar("SELECT status FROM framework_control_mapping WHERE id=?", (m["id"],)) != "APPROVED":
            continue
        catalog.withdraw(db, "mapping", m["id"], actor=actor, reason=f"AUTOMATED_LLM ({POLICY_VERSION}): {reason}")
        withdrawn.append(m["id"])
        if tenant is not None and not _live_mappings_for_rule(db, m["rule_id"], scope):
            with db.tx():
                db.x("UPDATE generated_rule_version SET status='FAILED', status_reason=? WHERE organization_scope=? "
                     "AND tenant_id=? AND rule_id=? AND status='ACTIVE'", (reason[:500], scope, tenant, m["rule_id"]))
                db.audit(actor, "GENERATED_RULE_DEACTIVATED", "generated_rule_version", m["rule_id"],
                         reason=reason[:500])
            _store_deactivate(store_path, tenant, m["rule_id"], actor)
    return withdrawn


def _live_mappings_for_rule(db: CatalogDb, rule_id: str, scope: str) -> list[dict[str, Any]]:
    return db.q("SELECT id FROM framework_control_mapping WHERE rule_id=? AND organization_scope=? AND status IN "
                "('DRAFT','APPROVED')", (rule_id, scope))


def _analysis_gap(analysis: dict[str, Any]) -> dict[str, Any] | None:
    if analysis["verdict"] == "NOT_TESTABLE":
        return _gap("NO_RULE_PROPOSED", "analysis: not testable from the declared evidence - "
                    + analysis["text"][-600:], analysis=analysis)
    if analysis["verdict"] == "PERSON_JUDGES":
        return _gap("MANUAL_ASSESSMENT_REQUIRED", "analysis: a person must judge this - " + analysis["text"][-600:],
                    analysis=analysis)
    return None


def _cached_review(db: CatalogDb, scope: str, rid: int, proposal_key: str, spec: RuleSpec) -> dict[str, Any] | None:
    """The stored model review of this exact rule for these inputs, so a re-run does not ask again."""
    want = digest_of(spec.model_dump(mode="json"))
    for row in db.q("SELECT llm_validation FROM rule_generation_decision WHERE organization_scope=? AND "
                    "requirement_id=? ORDER BY id DESC", (scope, rid)):
        v = row["llm_validation"] or {}
        r = v.get("review")
        if v.get("proposal_key") == proposal_key and r and r.get("spec_digest") == want:
            return r
    return None


def _proposal_for(db: CatalogDb, llm: Any, req: dict[str, Any], ref: dict[str, Any], cap: dict[str, Any], *,
                  scope: str, proposal_key: str, step: Any = None
                  ) -> tuple[str | None, dict[str, Any] | None, dict[str, Any] | None, bool, dict[str, Any] | None]:
    """(raw, parsed proposal json, gap, model_called, analysis). Two model steps when the client can reason in plain
    text: analyse (no grammar) then write (RuleSpec grammar, given the analysis). For identical inputs the stored
    analysis and raw output are re-checked deterministically instead of asking the model again."""
    step = step or (lambda _s: None)
    hub_gap = control_hub.scope_gap(ref)  # deterministic, before any stored proposal is reused
    if hub_gap:
        return None, None, _gap("OUTSIDE_PAM_SCOPE", hub_gap, hub=control_hub.HUB_VERSION), False, None
    for row in db.q("SELECT raw_output, llm_validation FROM rule_generation_decision WHERE organization_scope=? AND "
                    "requirement_id=? ORDER BY id DESC", (scope, req["id"])):
        v = row["llm_validation"] or {}
        if v.get("proposal_key") != proposal_key:
            continue
        analysis = v.get("analysis")
        if row["raw_output"] is not None:
            return (row["raw_output"], *_parse(row["raw_output"], truncated=False), False, analysis)
        if analysis and _analysis_gap(analysis):
            return None, None, _analysis_gap(analysis), False, analysis
    relevant = relevant_evidence(req, cap, ref=ref)
    if control_hub.governed(ref):  # a hub control is offered only the evidence the matrix lists for it
        relevant = [e for e in relevant if e in control_hub.evidence_types(ref)]
    if not relevant:
        declared = sorted((cap.get("evidence_detail") or {}))
        return None, None, _gap("COLLECTOR_MISSING", f"no declared evidence type relates to this requirement "
                                f"({SCREEN_VERSION}; declared: {', '.join(declared) or 'none'}); not sent to the "
                                "model"), False, None
    analysis = None
    if can_reason(llm):
        step("analyse")
        try:
            analysis = analyse(llm, req, cap, relevant, ref=ref)
        except LlmError as exc:
            return None, None, _gap("LLM_ERROR", f"analysis: {str(exc)[:280]}"), True, None
        gap = _analysis_gap(analysis)
        if gap:
            return None, None, gap, True, analysis
        if analysis["verdict"] == "TESTABLE":
            relevant = [analysis["evidence_type"]]  # write against the one type the analysis chose (smaller grammar)
    narrowed = {**cap, "evidence_detail": {e: (cap.get("evidence_detail") or {})[e] for e in relevant}}
    step("write")
    try:
        out = llm.generate_raw(SYSTEM_RULESPEC + " " + EXAMPLE_PROPOSAL, _context(db, req, ref, narrowed, analysis),
                               grammar_schema(db, req, narrowed))
    except LlmError as exc:
        return None, None, _gap("LLM_ERROR", str(exc)[:300]), True, analysis
    return (out.content, *_parse(out.content, truncated=bool(getattr(out, "truncated", False))), True, analysis)


def _first_object(raw: str) -> Any:
    """The first complete JSON value at the start of the output. Small models often emit one valid object and
    then keep generating (repeats, prose); that tail is never used, so it is neither parsed nor scanned."""
    text = raw.lstrip()
    if not text.startswith("{"):
        raise ValueError("output does not start with a JSON object")
    value, _end = json.JSONDecoder().raw_decode(text)
    return value


def parameter_catalog() -> dict[str, dict[str, Any]]:
    """The parameter names a generated condition may use: each organization integer setting (bound to its policy
    control when the name is unique) plus generic thresholds; every name has exactly one unit."""
    owners: dict[str, list[str]] = {}
    for (cid, _v), defn in sorted(pc.CONTROLS.items()):
        for name, s in ((defn.get("parameter_schema") or {}).get("properties") or {}).items():
            if s.get("type") == "integer":
                owners.setdefault(name, []).append(cid)
    out = {n: {"unit": u, "policy_control": None} for n, u in (
        ("max_age_days", "days"), ("max_age_hours", "hours"), ("max_age_minutes", "minutes"),
        ("max_seconds", "seconds"), ("max_count", "count"), ("min_count", "count"))}
    for name, cids in owners.items():
        out[name] = {"unit": field_unit(name) or "count",
                     "policy_control": {"control_id": cids[0], "parameter": name} if len(set(cids)) == 1 else None}
    return out


def _declare_referenced_parameters(obj: dict[str, Any]) -> dict[str, Any]:
    """Before schema validation, declare exactly the parameters the condition names: a catalogued name gets OPM's
    declaration (type, unit, setting binding); another name keeps the model's own declaration if it gave one.
    Unreferenced declarations are dropped (semantics-preserving: they cannot change what the rule tests)."""
    spec = obj.get("rule_spec")
    if not isinstance(spec, dict):
        return obj
    used: list[str] = []

    def walk(n: Any) -> None:
        if isinstance(n, dict):
            if isinstance(n.get("parameter"), str) and n["parameter"] not in used:
                used.append(n["parameter"])
            for v in n.get("where") or []:
                walk(v)
    walk(spec.get("condition"))
    given = spec.get("parameters") if isinstance(spec.get("parameters"), dict) else {}
    known = parameter_catalog()
    params = {}
    for name in used:
        if name in known:
            params[name] = {"type": "integer", "unit": known[name]["unit"], "policy_control": known[name]["policy_control"],
                            "description": f"Threshold {name.replace('_', ' ')} (declared by OPM from the condition)."}
        elif name in given:
            params[name] = given[name]
    return {**obj, "rule_spec": {**spec, "parameters": params}}


def _parse(raw: str, *, truncated: bool) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    try:
        obj = _first_object(raw)
    except ValueError:
        obj = None
    # a decline never uses a rule_spec; small models attach a filler one ("No rule available ...") that would
    # otherwise turn a clear NO_RULE / MANUAL_ASSESSMENT answer into RULE_SPEC_INVALID
    if isinstance(obj, dict) and obj.get("decision") in ("NO_RULE", "MANUAL_ASSESSMENT"):
        obj = {k: v for k, v in obj.items() if k != "rule_spec"}
    if isinstance(obj, dict):
        obj = _model_input(obj)
        obj = _declare_referenced_parameters(obj)
    # A population filter that repeats the condition is NOT repaired: removing it turns an empty rule into a
    # stricter one the model never stated (AC-2 f: "among enabled accounts, each is enabled" became "every account
    # must be enabled", which flags legitimate disabling). validate() rejects it instead.
    # scan exactly what would be used: the decoded object (string values), else the whole raw text
    bad = forbidden_content(json.dumps(obj, ensure_ascii=False) if obj is not None else raw)
    if bad:
        return None, _gap("RULE_SPEC_INVALID", f"the proposal contains forbidden content: {bad}", forbidden=bad)
    if obj is None:
        if truncated:
            return None, _gap("LLM_OUTPUT_INVALID", "the model output was truncated at the output limit")
        return None, _gap("LLM_OUTPUT_INVALID", "the model output is not a JSON object")
    try:
        proposal = Proposal.model_validate(obj)
    except (ValueError, ValidationError) as exc:
        code = "RULE_SPEC_INVALID" if isinstance(exc, ValidationError) else "LLM_OUTPUT_INVALID"
        return None, _gap(code, f"the proposal does not conform to RuleSpec {SPEC_VERSION}: {str(exc)[:300]}")
    return proposal.model_dump(mode="json"), None


def generate(db: CatalogDb, engine: Any, llm: Any, decisions: list[dict[str, Any]], *, scope: str, tenant: str | None,
             actor: str, job_id: str | None, publish: bool, pinned_digest: str | None, bundle_dir: Path | None,
             store_path: Path | None, progress: Any = None) -> dict[str, Any]:
    """Propose, validate, compile, test and (optionally) activate rules for requirements that existing-rule
    matching left without a rule. Returns decisions, mapping ids for scoped publication and counts."""
    from .automation import engine_actor
    from . import control_ids

    me = engine_actor(actor)
    cap = pctx.capabilities(db, scope, tenant)
    try:
        vector = pam_vector_db.load_for_generation()
    except pam_vector_db.PamVectorDbError as exc:
        raise CatalogError("PAM_VECTOR_DB_INVALID", f"rule generation stopped: {exc}") from exc
    info = getattr(llm, "info", None)
    model, model_digest = (getattr(info, "model", None), getattr(info, "version", None)) if info else (None, None)
    out: dict[str, Any] = {"decisions": [], "mapping_ids": [], "compiler_version": COMPILER_VERSION,
                           "prompt_version": PROMPT_VERSION, "policy_version": POLICY_VERSION, "model": model,
                           "model_digest": model_digest, "collector_capability_digest": cap.get("digest"),
                           "publish": publish, "llm_errors": 0,
                           "pam_vector_db": {"digest": vector.digest, "schema_tests_passed": vector.schema_tests}
                           if vector else None}
    todo = [d for d in decisions if d.get("gap_code") in TRIGGER_CODES and d.get("outcome") not in
            ("PUBLISHABLE", "EXISTING")]
    settings = in_force_settings(db, scope, tenant)
    stage_counts = dict.fromkeys(("propose_missing_rules", "validate_rule_specs", "compile_generated_rules",
                                  "test_generated_rules", "publish_generated_rules"), 0)
    bundle_version = None
    if bundle_dir is not None and (bundle_dir / "securden" / "bundle" / "data.json").is_file():
        bundle_version = json.loads((bundle_dir / "securden" / "bundle" / "data.json").read_text(
            encoding="utf-8"))["version"]
    tally: dict[str, int] = {}  # running outcome counts, shown in progress
    recent: list[dict[str, Any]] = []  # the last decisions with their reason (why a rule was not generated)
    started = datetime.now(timezone.utc)

    def tick(done: int, substep: str, current: dict[str, Any] | None) -> None:
        """Live progress: counted (done/total/unit, so the job ETA applies), the requirement being worked on,
        its sub-step and the outcomes so far. Detail markers are not added to the job's stage list."""
        if progress is None:
            return
        spent = (datetime.now(timezone.utc) - started).total_seconds()
        progress("propose_missing_rules", done=done, total=len(todo), unit="requirements", completed=done,
                 substep=substep, current=current, outcomes=dict(sorted(tally.items())),
                 rules_activated=tally.get(GENERATED_RULE_ACTIVATED, 0),
                 rules_validated=tally.get(GENERATED_RULE_VALIDATED, 0), recent=list(recent),
                 seconds_per_requirement=round(spent / done, 1) if done else None, detail=True)

    for n, d in enumerate(todo, 1):
        rid = d["requirement_id"]
        req = db.one("SELECT * FROM regulatory_requirement WHERE id=?", (rid,))
        if req is None:
            continue
        ref = control_ids.annotate(db, [req]).get(rid, {}) if req.get("section_id") else {}
        current = {"requirement_id": rid, "section_ref": req.get("section_ref"),
                   "control_id": ref.get("canonical_id"), "clause": ref.get("clause")}
        tick(n - 1, "propose", current)
        proposal_key = digest_of({"requirement": digest_of({k: req[k] for k in ("id", "original_text", "translation_en",
                                                                                "document_version_id")}),
                                  "ref": {k: ref.get(k) for k in ("canonical_id", "clause")},
                                  "collector": catalog_digest(cap), "prompt": PROMPT_VERSION, "spec": SPEC_VERSION,
                                  "screen": SCREEN_VERSION,
                                  **({"vector_db": vector.digest} if vector else {}),
                                  "model": [model, model_digest]})
        record: dict[str, Any] = {"requirement_id": rid, "trigger_gap_code": d.get("gap_code")}
        raw, proposal_json, result, _called, analysis = _proposal_for(
            db, llm, req, ref, cap, scope=scope, proposal_key=proposal_key,
            step=lambda s: tick(n - 1, s, current))
        review: dict[str, Any] | None = None
        if result is not None and result["gap_code"] == "LLM_ERROR":
            out["llm_errors"] += 1
        checks: list[str] = []
        compiled: dict[str, Any] | None = None
        resolution: list[dict[str, Any]] = []
        cases: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        proposal = Proposal.model_validate(proposal_json) if proposal_json is not None else None
        try:
            if result is not None:
                raise Gap(result["gap_code"], result["message"], **{k: v for k, v in result.items()
                                                                    if k not in ("outcome", "gap_code", "message")})
            assert proposal is not None
            stage_counts["propose_missing_rules"] += 1
            if proposal.requirement_id != rid:
                raise Gap("LLM_OUTPUT_INVALID", f"the proposal is for requirement {proposal.requirement_id}")
            if proposal.decision == "NO_RULE":
                raise Gap("NO_RULE_PROPOSED", proposal.rationale)
            if proposal.decision == "MANUAL_ASSESSMENT":
                raise Gap("MANUAL_ASSESSMENT_REQUIRED", proposal.rationale)
            if proposal.rule_spec is None:
                raise Gap("RULE_SPEC_INVALID", "decision PROPOSE without a rule_spec")
            if proposal.confidence < min_confidence():
                raise Gap("RULE_PROPOSAL_AMBIGUOUS", f"confidence {proposal.confidence} is below the automation "
                          f"threshold {min_confidence()}")
            spec, dropped = drop_unused_parameters(proposal.rule_spec)
            off_hub = control_hub.mapping_gap(ref, spec.evidence_type) if control_hub.governed(ref) else None
            if off_hub:  # also catches a stored proposal written before the hub gate existed
                raise Gap("OUTSIDE_PAM_SCOPE", off_hub, hub=control_hub.HUB_VERSION)
            tick(n - 1, "validate", current)
            stage_counts["validate_rule_specs"] += 1
            checks = validate(spec, req=req, cap=cap, db=db)
            if dropped:
                checks.append(f"unused_parameters_dropped:{','.join(dropped)}")
            grounded = grounded_fields(spec, req)
            tested = sorted({p.field for p in _predicates(spec.condition)})
            reasoning = can_reason(llm)
            if not grounded and not reasoning:
                raise Gap("RULE_SPEC_INVALID", f"the condition tests {tested}, which the requirement text does not "
                          f"mention ({GROUNDING_VERSION}); a rule on these fields would not test this obligation")
            checks.append(f"condition_grounded:{','.join(grounded)}" if grounded else "condition_not_word_grounded")
            if reasoning:
                # an independent review of the finished rule by meaning: the deciding check, so wording the word
                # lists do not know (other documents) can still produce a rule, and shared words alone cannot
                tick(n - 1, "judge", current)
                review = _cached_review(db, scope, rid, proposal_key, spec)
                if review is None:
                    try:
                        review = judge(llm, req, spec, cap, grounded=bool(grounded), ref=ref)
                    except LlmError as exc:
                        raise Gap("LLM_ERROR", f"judge: {str(exc)[:280]}") from exc
                    review["spec_digest"] = digest_of(spec.model_dump(mode="json"))
                if review["verdict"] != "YES":
                    why = {"NO": "neither a passing nor a failing record says anything about this requirement",
                           "FLAGS_COMPLIANT": "the record this rule passes is the one breaking the requirement "
                                              "(the rule is inverted)",
                           }.get(review["verdict"], "the review gave no clear answer")
                    raise Gap("RULE_SPEC_INVALID", f"review ({review['verdict']}): {why} - {review['text'][-500:]}")
                checks.append("judged_by_model")
            resolution = resolve(spec, req=req, settings=settings)
            missing = [e["name"] for e in resolution if e["value"] is None]
            if missing:
                raise Gap("PARAMETER_SOURCE_MISSING", f"no verifiable source for {missing}", parameters_missing=missing,
                          parameter_resolution=resolution)
            checks.append("parameters_grounded")
            if bundle_dir is None or tenant is None:
                raise Gap("RULE_COMPILATION_FAILED", "no policy bundle or tenant is configured for this job")
            tick(n - 1, "compile", current)
            stage_counts["compile_generated_rules"] += 1
            compiled = compile_spec(spec, resolution, scope=scope, tenant=tenant, bundle_dir=bundle_dir)
            checks.append("compiled")
            tick(n - 1, "test", current)
            stage_counts["test_generated_rules"] += 1
            try:
                cases = build_cases(spec, compiled["values"],
                                    vector.stored_null.get(spec.evidence_type) if vector else None)
            except CaseError as exc:
                raise Gap("RULE_SPEC_INVALID", f"deterministic validation cases cannot be built: {exc}") from exc
            results = run_cases(compiled["definition"], compiled["compiled"], cases, bundle_dir=bundle_dir)
            failed = [r for r in results if not r["passed"]]
            if failed:
                raise Gap("RULE_TEST_FAILED", f"{len(failed)} of {len(results)} generated cases failed: "
                          + "; ".join(f"{r['name']} expected {r['expected']} got {r['got']}" for r in failed[:5]),
                          test_results=results)
            checks.append("generated_tests_passed")
            row = _persist_rule(db, spec=spec, compiled=compiled, resolution=resolution, scope=scope, tenant=tenant,
                                cap=cap, req=req, checks=checks, cases=cases, results=results,
                                llm_prov={"model": model, "model_digest": model_digest,
                                          "prompt_version": PROMPT_VERSION, "proposal_key": proposal_key,
                                          "actor": me}, bundle_version=bundle_version or "")
            pending = lookup_fields_used(cap, spec)
            if is_lookup(cap, spec.evidence_type) or pending:
                # the PAM holds this data but the collector does not send it yet: nothing to evaluate, so the rule
                # waits; the next job after the type (or field) is declared collected activates it from the stored
                # proposal
                why = (f"{spec.evidence_type} (declared LOOKUP_AVAILABLE)" if is_lookup(cap, spec.evidence_type)
                       else f"{spec.evidence_type} fields {pending} (declared lookup_fields)")
                result = {"outcome": GENERATED_RULE_VALIDATED, "gap_code": "COLLECTOR_MISSING",
                          "rule_id": compiled["rule_id"], "rule_version": compiled["version"],
                          "generated_rule_version_id": row["id"], "waiting_for_collector": {
                              "evidence_type": spec.evidence_type,
                              "fields": sorted(_fields(spec)), **({"pending_fields": pending} if pending else {})},
                          "message": f"validated, compiled and tested; waits until the collector sends {why}"}
            elif not publish:
                result = {"outcome": GENERATED_RULE_VALIDATED, "gap_code": None, "rule_id": compiled["rule_id"],
                          "rule_version": compiled["version"], "generated_rule_version_id": row["id"],
                          "message": "validated, compiled and tested; activation was not requested"}
            else:
                live_digest = pctx.capabilities(db, scope, tenant).get("digest")
                if pinned_digest is None or live_digest != pinned_digest or cap.get("digest") != pinned_digest:
                    raise Gap("EVIDENCE_SCHEMA_INCOMPATIBLE", "the collector declaration changed after the job was "
                              "submitted (stale collector_capability_digest); activation refused")
                absent = vector.not_collected(spec.evidence_type, _fields(spec)) if vector else []
                if absent:
                    raise Gap("COLLECTOR_MISSING", f"vector.db does not list {absent} as collected for "
                              f"{spec.evidence_type}; activation refused", fields=absent)
                if vector:
                    checks.append("pam_vector_db_collected")
                tick(n - 1, "activate", current)
                stage_counts["publish_generated_rules"] += 1
                result = _activate_and_map(db, engine, row=row, compiled=compiled, spec=spec, req=req, scope=scope,
                                           tenant=tenant, actor=me, store_path=store_path or Path("opm.db"),
                                           proposal=proposal, decision_digest=proposal_key, job_id=job_id)
        except Gap as g:
            result = _gap(g.code, g.message, **g.extra)
            if g.code == "LLM_ERROR" and g.message.startswith("judge:"):
                out["llm_errors"] += 1  # the review call failed (proposal errors are counted above)
        except CatalogError as exc:
            result = _gap("RULE_COMPILATION_FAILED" if exc.code.startswith("RULE") else "POLICY_CONFLICT"
                          if exc.code in ("MAPPING_CONFLICT", "DUPLICATE_MAPPING") else "VALIDATION_FAILED",
                          f"{exc.code}: {exc.message}")
        if result.get("gap_code") == "OUTSIDE_PAM_SCOPE" and result.get("hub"):
            retired = _retire_generated(db, rid, scope=scope, tenant=tenant, actor=me,
                                        store_path=store_path or Path("opm.db"), reason=result["message"])
            if retired:
                result["withdrawn_mapping_ids"] = retired
                out.setdefault("withdrawn_mapping_ids", []).extend(retired)
        decision_input = digest_of({"proposal_key": proposal_key, "proposal": proposal_json,
                                    "values": compiled["values"] if compiled else None, "publish": publish,
                                    "pinned": pinned_digest, "compiler": COMPILER_VERSION,
                                    "outcome": [result.get("outcome"), result.get("gap_code"), result.get("mapping_id")]})
        validation = {"proposal_key": proposal_key, "checks": checks, "message": result.get("message"),
                      "rule_id": result.get("rule_id") or (compiled or {}).get("rule_id"),
                      "rule_version": result.get("rule_version"), "spec_digest": (compiled or {}).get("spec_digest"),
                      "rego_digest": (compiled or {}).get("rego_digest"), "parameter_resolution": resolution,
                      "test_results": results or result.get("test_results") or [],
                      **({"analysis": analysis} if analysis else {}), **({"review": review} if review else {}),
                      **{k: result[k] for k in ("forbidden", "fields", "parameters_missing", "conflicting_mapping_ids",
                                                "replaced_mapping_ids") if k in result}}
        prior = db.one("SELECT id FROM rule_generation_decision WHERE organization_scope=? AND requirement_id=? AND "
                       "input_digest=?", (scope, rid, decision_input))
        if prior is None:
            with db.tx():
                did = db.insert("rule_generation_decision", organization_scope=scope, tenant_id=tenant,
                                requirement_id=rid, job_id=job_id, input_digest=decision_input, model=model,
                                model_digest=model_digest, prompt_version=PROMPT_VERSION,
                                compiler_version=COMPILER_VERSION, raw_output=raw, llm_proposal=proposal_json,
                                llm_validation=validation, outcome=result["outcome"], gap_code=result.get("gap_code"),
                                generated_rule_version_id=result.get("generated_rule_version_id"),
                                mapping_id=result.get("mapping_id"), created_at=now_iso())
        else:
            did = prior["id"]
        orchestration = (GENERATED_RULE_ACTIVATED if result["outcome"] in ("PUBLISHABLE", "EXISTING")
                         else result["outcome"] if result["outcome"] == GENERATED_RULE_VALIDATED else result["gap_code"])
        record.update(decision_id=did, outcome=orchestration, gap_code=result.get("gap_code"),
                      message=result.get("message"), rule_id=validation["rule_id"],
                      rule_version=result.get("rule_version") or ("1.0" if compiled else None),
                      mapping_id=result.get("mapping_id"), generated_rule_version_id=result.get("generated_rule_version_id"),
                      **({"waiting_for_collector": result["waiting_for_collector"]}
                         if result.get("waiting_for_collector") else {}),
                      evidence_type=proposal.rule_spec.evidence_type if proposal and proposal.rule_spec else None,
                      evidence_schema_version=proposal.rule_spec.evidence_schema_version
                      if proposal and proposal.rule_spec else None,
                      assessment_mode=proposal.rule_spec.assessment_mode if proposal and proposal.rule_spec else None,
                      coverage="PARTIAL", rule_spec_digest=validation["spec_digest"],
                      rego_digest=validation["rego_digest"],
                      source_references=[{"requirement_id": rid, "section_ref": req["section_ref"],
                                          "document_version_id": req["document_version_id"]}],
                      limitations=list(proposal.rule_spec.limitations) if proposal and proposal.rule_spec else [],
                      **{k: result[k] for k in ("replaced_mapping_ids", "parameters_missing", "withdrawn_mapping_ids")
                         if k in result})
        if result["outcome"] == "PUBLISHABLE":
            out["mapping_ids"].append(result["mapping_id"])
        out["decisions"].append(record)
        tally[orchestration] = tally.get(orchestration, 0) + 1
        recent[:] = (recent + [{**current, "outcome": orchestration, "rule_id": record.get("rule_id"),
                                "reason": (result.get("message") or "")[:300],
                                "model_called": _called}])[-5:]
        tick(n, "done", current)
    if progress is not None:
        for stage, done in stage_counts.items():
            # the proposal stage keeps its requirement counter (done == total) so the closed step stays counted
            extra = {"done": len(todo), "unit": "requirements"} if stage == "propose_missing_rules" else {}
            progress(stage, completed=done, total=len(todo), **extra)
    out["counts"] = {
        "rule_generation_candidates": len(todo),
        "rule_proposals_created": stage_counts["propose_missing_rules"],
        "rules_generated": sum(1 for d in out["decisions"] if d.get("generated_rule_version_id")),
        "rules_activated": sum(1 for d in out["decisions"] if d["outcome"] == GENERATED_RULE_ACTIVATED),
        "generated_mappings_published": len(out["mapping_ids"]),
        "generated_mappings_withdrawn": len(out.get("withdrawn_mapping_ids", [])),
    }
    return out
