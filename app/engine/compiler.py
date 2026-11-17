"""Compile customer rule definitions into the safe structure evaluated by the
fixed Rego interpreter ``securden.custom.v1``.

Nothing customer-supplied is ever executed: fields are looked up in an explicit
allowlist, operators come from a closed set, values are type-checked and
converted (datetimes -> integer nanoseconds), and the output is plain data.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pydantic import TypeAdapter, ValidationError

from ..errors import sanitize_validation_errors
from ..models.common import UtcDatetime
from ..models.custom_rules import Condition, CustomRuleDefinition, Group, LeafGroup
from ..models.evidence import CUSTOM_RULE_FIELDS

ENGINE = "securden.custom.v1"
ENGINE_PACKAGE = "securden.custom.v1"

MAX_TOTAL_CONDITIONS = 25
MAX_LIST_VALUES = 100
MAX_ABS_INT = 10**12
MAX_DAYS = 3650

OPS_BY_TYPE: dict[str, frozenset[str]] = {
    "string": frozenset({"eq", "ne", "in", "not_in", "is_null", "not_null"}),
    "enum": frozenset({"eq", "ne", "in", "not_in", "is_null", "not_null"}),
    "boolean": frozenset({"eq", "ne"}),
    "integer": frozenset({"eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in"}),
    "datetime": frozenset(
        {"gt", "gte", "lt", "lte", "older_than_days", "within_last_days", "is_null", "not_null"}
    ),
    "string_list": frozenset({"contains"}),
}
NULL_OPS = frozenset({"is_null", "not_null"})
_STR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,63}$")
_dt_adapter = TypeAdapter(UtcDatetime)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def datetime_to_ns(dt: datetime) -> int:
    delta = dt.astimezone(timezone.utc) - _EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


@dataclass
class CompileResult:
    definition: CustomRuleDefinition | None = None
    compiled: dict[str, Any] | None = None
    errors: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    digest: str | None = None

    @property
    def valid(self) -> bool:
        return not self.errors and self.compiled is not None


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("ascii")).hexdigest()


class _Compiler:
    def __init__(self, definition: CustomRuleDefinition) -> None:
        self.d = definition
        self.fields = CUSTOM_RULE_FIELDS[definition.evidence_type]
        self.errors: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self.total_conditions = 0

    def err(self, loc: list[str], msg: str) -> None:
        self.errors.append({"loc": loc, "msg": msg, "type": "rule_semantic_error"})

    # -- values ---------------------------------------------------------
    def _scalar(self, loc, spec, v):
        t = spec["type"]
        if t == "boolean":
            if not isinstance(v, bool):
                return self.err(loc, "value must be a boolean")
            return v
        if t == "integer":
            if isinstance(v, bool) or not isinstance(v, int) or abs(v) > MAX_ABS_INT:
                return self.err(loc, f"value must be an integer with magnitude <= {MAX_ABS_INT}")
            return v
        if t == "enum":
            if v not in spec["values"]:
                return self.err(loc, f"value must be one of {list(spec['values'])}")
            return v
        if t == "string":
            if not isinstance(v, str) or not _STR_RE.match(v):
                return self.err(loc, "value must be an identifier string (1-128 chars, [A-Za-z0-9._:@/-])")
            return v
        if t == "datetime":
            try:
                return datetime_to_ns(_dt_adapter.validate_python(v))
            except ValidationError:
                return self.err(loc, "value must be an RFC 3339 timestamp with a timezone")
        return self.err(loc, "unsupported field type")

    def condition(self, loc: list[str], c: Condition, cid: str) -> dict[str, Any] | None:
        self.total_conditions += 1
        spec = self.fields.get(c.field)
        if spec is None:
            self.err(loc + ["field"], f"field '{c.field}' is not allowed for evidence type '{self.d.evidence_type}'")
            return None
        ftype = spec["type"]
        if c.op not in OPS_BY_TYPE[ftype]:
            self.err(loc + ["op"], f"operator '{c.op}' is not allowed for {ftype} field '{c.field}'")
            return None
        if c.op in NULL_OPS:
            if not spec["nullable"]:
                self.err(loc + ["op"], f"field '{c.field}' is never null")
                return None
            if c.value is not None:
                self.err(loc + ["value"], f"operator '{c.op}' takes no value")
                return None
            value: Any = None
        elif c.op in ("in", "not_in"):
            if not isinstance(c.value, list) or not 1 <= len(c.value) <= MAX_LIST_VALUES:
                self.err(loc + ["value"], f"'{c.op}' requires a list of 1-{MAX_LIST_VALUES} values")
                return None
            before = len(self.errors)
            value = [self._scalar(loc + ["value", str(i)], spec, v) for i, v in enumerate(c.value)]
            if len(self.errors) > before:
                return None
            if len(set(map(str, value))) != len(value):
                self.err(loc + ["value"], "list values must be unique")
                return None
            value = sorted(value)
        elif c.op in ("older_than_days", "within_last_days"):
            v = c.value
            if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= MAX_DAYS:
                self.err(loc + ["value"], f"'{c.op}' requires an integer number of days 0-{MAX_DAYS}")
                return None
            value = v
        elif c.op == "contains":
            if not isinstance(c.value, str) or not _TAG_RE.match(c.value):
                self.err(loc + ["value"], "'contains' requires a tag string")
                return None
            value = c.value
        else:
            if c.value is None:
                self.err(loc + ["value"], f"operator '{c.op}' requires a value")
                return None
            before = len(self.errors)
            value = self._scalar(loc + ["value"], spec, c.value)
            if len(self.errors) > before:
                return None
        if spec["nullable"] and c.op in ("ne", "not_in", "gt", "gte", "lt", "lte", "older_than_days", "within_last_days"):
            self.warnings.append(
                f"{'.'.join(loc)}: field '{c.field}' is nullable; records with null never match "
                f"'{c.op}'. Combine with an 'is_null' condition in an 'any' group if needed."
            )
        return {"id": cid, "field": c.field, "type": ftype, "op": c.op, "value": value}

    def group(self, loc: list[str], g: Group | LeafGroup, prefix: str, leaf: bool) -> dict[str, Any]:
        mode = "all" if g.all is not None else "any"
        items = g.all if g.all is not None else g.any
        conditions: list[dict[str, Any]] = []
        groups: list[dict[str, Any]] = []
        ci = gi = 0
        for idx, item in enumerate(items or []):
            item_loc = loc + [mode, str(idx)]
            if isinstance(item, Condition):
                ci += 1
                compiled = self.condition(item_loc, item, f"{prefix}c{ci}")
                if compiled is not None:
                    conditions.append(compiled)
            else:
                if leaf:
                    self.err(item_loc, "groups may be nested at most one level deep")
                    continue
                gi += 1
                groups.append(self.group(item_loc, item, f"{prefix}g{gi}.", leaf=True))
        return {"mode": mode, "conditions": conditions, "groups": groups}

    def run(self) -> dict[str, Any]:
        d = self.d
        spec = self.fields.get(d.subject_field)
        if spec is None or spec["type"] != "string" or spec["nullable"]:
            self.err(["subject_field"], "subject_field must be a non-nullable identifier field of the evidence type")
        scope = self.group(["scope"], d.scope, "scope.", leaf=False) if d.scope else None
        violation = self.group(["violation_when"], d.violation_when, "", leaf=False)
        if self.total_conditions > MAX_TOTAL_CONDITIONS:
            self.err([], f"a rule may contain at most {MAX_TOTAL_CONDITIONS} conditions")
        return {
            "rule_id": d.rule_id,
            "rule_version": d.version,
            "subject_field": d.subject_field,
            "tolerance": d.tolerance,
            "scope": scope,
            "violation": violation,
        }


def compile_rule(raw: dict[str, Any] | CustomRuleDefinition) -> CompileResult:
    result = CompileResult()
    try:
        definition = (
            raw if isinstance(raw, CustomRuleDefinition) else CustomRuleDefinition.model_validate(raw)
        )
    except ValidationError as exc:
        result.errors = sanitize_validation_errors(exc.errors(include_input=False, include_url=False))
        return result
    compiler = _Compiler(definition)
    compiled = compiler.run()
    result.definition = definition
    result.errors = compiler.errors
    result.warnings = compiler.warnings
    if not compiler.errors:
        result.compiled = compiled
        result.digest = sha256_hex(definition.model_dump(mode="json"))
    return result
