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
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, model_validator

from app.engine.compiler import ENGINE_PACKAGE, compile_rule
from app.engine.evaluator import GENERATED_RULE_PREFIX, Evaluator, custom_spec_from_row
from app.models.api import Evidence, ReportingPeriod
from app.models.custom_rules import CustomFrameworkMapping, CustomRuleDefinition
from app.models.evidence import CUSTOM_RULE_FIELDS, EVIDENCE_SCHEMA_VERSIONS

from . import catalog, mapping_recipes as mr, policy_contexts as pctx, policy_controls as pc
from .db import CatalogDb, CatalogError, canonical, digest_of, now_iso
from .llm import LlmError

SPEC_VERSION = "1.0"
COMPILER_VERSION = "pam-rulespec-compiler-1.0"
# v2: compact context and schema (v1 overflowed a 4096-token window, so the model never saw the requirement)
PROMPT_VERSION = "rule-spec-v2"
POLICY_VERSION = "rule-gen-v1"
FLAG_GENERATE = "REGINTEL_AUTO_RULE_GENERATION"
FLAG_PUBLISH = "REGINTEL_AUTO_PUBLISH_GENERATED_RULES"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MIN_CONFIDENCE = 0.8
TRIGGER_CODES = frozenset({"NO_EXECUTABLE_RULE", "LLM_NO_MAP"})  # existing-rule matching found nothing

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
    if cap.get("source") != "HANDSHAKE" or spec.evidence_type not in (cap.get("evidence") or {}):
        raise Gap("COLLECTOR_MISSING", f"this organization's collector declaration does not supply {spec.evidence_type}",
                  evidence_type=spec.evidence_type)
    if cap["evidence"][spec.evidence_type] != spec.evidence_schema_version:
        raise Gap("EVIDENCE_SCHEMA_INCOMPATIBLE", f"the collector declares {spec.evidence_type} schema "
                  f"{cap['evidence'][spec.evidence_type]}, the rule needs {spec.evidence_schema_version}")
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
    for pred in _predicates(spec.condition):
        if pred.operator == "contains":
            raise Gap("RULE_SPEC_INVALID", "'contains' is allowed only in population filters")
        _check_predicate(pred, catalogue, spec, referenced)
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
    return checks


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


def build_cases(spec: RuleSpec, values: dict[str, Any]) -> list[dict[str, Any]]:
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
    return {"rule_origin": "GENERATED", "generated_rule_version_id": row["id"], "spec_digest": row["spec_digest"],
            "rule_digest": row["rule_digest"], "rego_digest": row["rego_digest"],
            "compiler_version": row["compiler_version"], "evidence_type": row["evidence_type"],
            "evidence_schema_version": row["evidence_schema_version"], "assessment_mode": row["assessment_mode"],
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
    "threshold must be a declared parameter (OPM finds its value in the regulatory text or the organization's "
    "confirmed settings; bind policy_control when a listed setting fits). 'condition' states what every in-scope "
    "record must satisfy. coverage is always PARTIAL; list what the test does not establish under limitations. "
    "decision NO_RULE when the listed evidence cannot test the obligation; MANUAL_ASSESSMENT when a person must "
    "judge it.")


def _context(db: CatalogDb, req: dict[str, Any], ref: dict[str, Any], cap: dict[str, Any]) -> str:
    detail = cap.get("evidence_detail") or {}
    evidence = []
    for etype, version in sorted((cap.get("evidence") or {}).items()):
        d = detail.get(etype)
        if not d or etype not in CUSTOM_RULE_FIELDS:
            continue
        cat = CUSTOM_RULE_FIELDS[etype]
        evidence.append({"evidence_type": etype, "schema_version": version, "assessment_modes": d["assessment_modes"],
                         "fields": {n: {"type": cat[n]["type"], "nullable": cat[n]["nullable"],
                                        **({"values": list(cat[n]["values"])} if cat[n]["values"] else {}),
                                        **({"unit": field_unit(n)} if field_unit(n) else {})}
                                    for n in d["supported_fields"] if n in cat}})
    settings = []
    for (cid, _v), defn in sorted(pc.CONTROLS.items()):
        for name, schema in ((defn.get("parameter_schema") or {}).get("properties") or {}).items():
            if schema.get("type") in ("integer", "boolean"):
                ui = ((defn.get("ui") or {}).get("parameters") or {}).get(name, {})
                settings.append({"control_id": cid, "parameter": name, "type": schema["type"],
                                 "unit": ui.get("unit"), "title": ui.get("label") or schema.get("title")})
    controls = [{"id": r["id"], "title": r["title"]} for r in db.q("SELECT id, title FROM pam_control ORDER BY id")]
    payload = {
        "requirement_id": req["id"], "requirement_text": req.get("translation_en") or req["original_text"],
        "canonical_control": {k: ref.get(k) for k in ("canonical_id", "control_title", "clause")},
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
        elif row["digest"] != compiled["rule_digest"].split(":", 1)[1]:
            raise Gap("RULE_COMPILATION_FAILED", f"{d['rule_id']} exists in the rule store with a different digest")
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


def _live_mappings_for_rule(db: CatalogDb, rule_id: str, scope: str) -> list[dict[str, Any]]:
    return db.q("SELECT id FROM framework_control_mapping WHERE rule_id=? AND organization_scope=? AND status IN "
                "('DRAFT','APPROVED')", (rule_id, scope))


def _proposal_for(db: CatalogDb, llm: Any, req: dict[str, Any], ref: dict[str, Any], cap: dict[str, Any], *,
                  scope: str, proposal_key: str) -> tuple[str | None, dict[str, Any] | None, dict[str, Any] | None, bool]:
    """(raw, parsed proposal json, gap, model_called). For identical inputs the earlier raw output is
    re-checked deterministically instead of asking the model again (also when it was rejected)."""
    for row in db.q("SELECT raw_output, llm_validation FROM rule_generation_decision WHERE organization_scope=? AND "
                    "requirement_id=? ORDER BY id DESC", (scope, req["id"])):
        if (row["llm_validation"] or {}).get("proposal_key") == proposal_key and row["raw_output"] is not None:
            return (row["raw_output"], *_parse(row["raw_output"], truncated=False), False)
    try:
        out = llm.generate_raw(SYSTEM_RULESPEC, _context(db, req, ref, cap), _prompt_schema())
    except LlmError as exc:
        return None, None, _gap("LLM_ERROR", str(exc)[:300]), True
    return (out.content, *_parse(out.content, truncated=bool(getattr(out, "truncated", False))), True)


def _parse(raw: str, *, truncated: bool) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    bad = forbidden_content(raw)
    if bad:
        return None, _gap("RULE_SPEC_INVALID", f"the proposal contains forbidden content: {bad}", forbidden=bad)
    if truncated:
        return None, _gap("LLM_OUTPUT_INVALID", "the model output was truncated at the output limit")
    try:
        proposal = Proposal.model_validate(json.loads(raw))
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
    info = getattr(llm, "info", None)
    model, model_digest = (getattr(info, "model", None), getattr(info, "version", None)) if info else (None, None)
    out: dict[str, Any] = {"decisions": [], "mapping_ids": [], "compiler_version": COMPILER_VERSION,
                           "prompt_version": PROMPT_VERSION, "policy_version": POLICY_VERSION, "model": model,
                           "model_digest": model_digest, "collector_capability_digest": cap.get("digest"),
                           "publish": publish, "llm_errors": 0}
    todo = [d for d in decisions if d.get("gap_code") in TRIGGER_CODES and d.get("outcome") not in
            ("PUBLISHABLE", "EXISTING")]
    settings = in_force_settings(db, scope, tenant)
    stage_counts = dict.fromkeys(("propose_missing_rules", "validate_rule_specs", "compile_generated_rules",
                                  "test_generated_rules", "publish_generated_rules"), 0)
    bundle_version = None
    if bundle_dir is not None and (bundle_dir / "securden" / "bundle" / "data.json").is_file():
        bundle_version = json.loads((bundle_dir / "securden" / "bundle" / "data.json").read_text(
            encoding="utf-8"))["version"]
    for n, d in enumerate(todo, 1):
        rid = d["requirement_id"]
        req = db.one("SELECT * FROM regulatory_requirement WHERE id=?", (rid,))
        if req is None:
            continue
        ref = control_ids.annotate(db, [req]).get(rid, {}) if req.get("section_id") else {}
        if progress is not None:
            progress("propose_missing_rules", completed=n - 1, total=len(todo), requirement_id=rid)
        proposal_key = digest_of({"requirement": digest_of({k: req[k] for k in ("id", "original_text", "translation_en",
                                                                                "document_version_id")}),
                                  "ref": {k: ref.get(k) for k in ("canonical_id", "clause")},
                                  "collector": cap.get("digest"), "prompt": PROMPT_VERSION, "spec": SPEC_VERSION,
                                  "model": [model, model_digest]})
        record: dict[str, Any] = {"requirement_id": rid, "trigger_gap_code": d.get("gap_code")}
        raw, proposal_json, result, _called = _proposal_for(db, llm, req, ref, cap, scope=scope,
                                                            proposal_key=proposal_key)
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
            spec = proposal.rule_spec
            stage_counts["validate_rule_specs"] += 1
            checks = validate(spec, req=req, cap=cap, db=db)
            resolution = resolve(spec, req=req, settings=settings)
            missing = [e["name"] for e in resolution if e["value"] is None]
            if missing:
                raise Gap("PARAMETER_SOURCE_MISSING", f"no verifiable source for {missing}", parameters_missing=missing,
                          parameter_resolution=resolution)
            checks.append("parameters_grounded")
            if bundle_dir is None or tenant is None:
                raise Gap("RULE_COMPILATION_FAILED", "no policy bundle or tenant is configured for this job")
            stage_counts["compile_generated_rules"] += 1
            compiled = compile_spec(spec, resolution, scope=scope, tenant=tenant, bundle_dir=bundle_dir)
            checks.append("compiled")
            stage_counts["test_generated_rules"] += 1
            try:
                cases = build_cases(spec, compiled["values"])
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
            if not publish:
                result = {"outcome": GENERATED_RULE_VALIDATED, "gap_code": None, "rule_id": compiled["rule_id"],
                          "rule_version": compiled["version"], "generated_rule_version_id": row["id"],
                          "message": "validated, compiled and tested; activation was not requested"}
            else:
                current = pctx.capabilities(db, scope, tenant).get("digest")
                if pinned_digest is None or current != pinned_digest or cap.get("digest") != pinned_digest:
                    raise Gap("EVIDENCE_SCHEMA_INCOMPATIBLE", "the collector declaration changed after the job was "
                              "submitted (stale collector_capability_digest); activation refused")
                stage_counts["publish_generated_rules"] += 1
                result = _activate_and_map(db, engine, row=row, compiled=compiled, spec=spec, req=req, scope=scope,
                                           tenant=tenant, actor=me, store_path=store_path or Path("opm.db"),
                                           proposal=proposal, decision_digest=proposal_key, job_id=job_id)
        except Gap as g:
            result = _gap(g.code, g.message, **g.extra)
        except CatalogError as exc:
            result = _gap("RULE_COMPILATION_FAILED" if exc.code.startswith("RULE") else "POLICY_CONFLICT"
                          if exc.code in ("MAPPING_CONFLICT", "DUPLICATE_MAPPING") else "VALIDATION_FAILED",
                          f"{exc.code}: {exc.message}")
        decision_input = digest_of({"proposal_key": proposal_key, "proposal": proposal_json,
                                    "values": compiled["values"] if compiled else None, "publish": publish,
                                    "pinned": pinned_digest, "compiler": COMPILER_VERSION,
                                    "outcome": [result.get("outcome"), result.get("gap_code"), result.get("mapping_id")]})
        validation = {"proposal_key": proposal_key, "checks": checks, "message": result.get("message"),
                      "rule_id": result.get("rule_id") or (compiled or {}).get("rule_id"),
                      "rule_version": result.get("rule_version"), "spec_digest": (compiled or {}).get("spec_digest"),
                      "rego_digest": (compiled or {}).get("rego_digest"), "parameter_resolution": resolution,
                      "test_results": results or result.get("test_results") or [],
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
                      evidence_type=proposal.rule_spec.evidence_type if proposal and proposal.rule_spec else None,
                      evidence_schema_version=proposal.rule_spec.evidence_schema_version
                      if proposal and proposal.rule_spec else None,
                      assessment_mode=proposal.rule_spec.assessment_mode if proposal and proposal.rule_spec else None,
                      coverage="PARTIAL", rule_spec_digest=validation["spec_digest"],
                      rego_digest=validation["rego_digest"],
                      source_references=[{"requirement_id": rid, "section_ref": req["section_ref"],
                                          "document_version_id": req["document_version_id"]}],
                      limitations=list(proposal.rule_spec.limitations) if proposal and proposal.rule_spec else [],
                      **{k: result[k] for k in ("replaced_mapping_ids", "parameters_missing") if k in result})
        if result["outcome"] == "PUBLISHABLE":
            out["mapping_ids"].append(result["mapping_id"])
        out["decisions"].append(record)
    if progress is not None:
        for stage, done in stage_counts.items():
            progress(stage, completed=done, total=len(todo))
    out["counts"] = {
        "rule_generation_candidates": len(todo),
        "rule_proposals_created": stage_counts["propose_missing_rules"],
        "rules_generated": sum(1 for d in out["decisions"] if d.get("generated_rule_version_id")),
        "rules_activated": sum(1 for d in out["decisions"] if d["outcome"] == GENERATED_RULE_ACTIVATED),
        "generated_mappings_published": len(out["mapping_ids"]),
    }
    return out
