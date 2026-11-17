"""Customer-defined rule schema (structural layer).

This model checks *shape* only. Semantic checks (field allowlist per evidence
type, operator/type compatibility, value types, limits) are performed by
``app.engine.compiler`` so that /rules/validate can return every problem at once.
Customer rules can never contain Rego, Python, expressions or paths.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from .common import Severity, UtcDatetime
from .evidence import EvidenceType

FieldName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
SafeText = Annotated[str, StringConstraints(pattern=r"^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]*$")]

Operator = Literal[
    "eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in",
    "is_null", "not_null", "older_than_days", "within_last_days", "contains",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Condition(_Strict):
    field: FieldName
    op: Operator
    value: Any = None


class LeafGroup(_Strict):
    all: list[Condition] | None = Field(default=None, min_length=1, max_length=20)
    any: list[Condition] | None = Field(default=None, min_length=1, max_length=20)

    @model_validator(mode="after")
    def _one(self):
        if (self.all is None) == (self.any is None):
            raise ValueError("a group must define exactly one of 'all' or 'any'")
        return self


class Group(_Strict):
    all: list[Condition | LeafGroup] | None = Field(default=None, min_length=1, max_length=20)
    any: list[Condition | LeafGroup] | None = Field(default=None, min_length=1, max_length=20)

    @model_validator(mode="after")
    def _one(self):
        if (self.all is None) == (self.any is None):
            raise ValueError("a group must define exactly one of 'all' or 'any'")
        return self


class CustomFrameworkMapping(_Strict):
    framework: Literal["ISO27001:2022", "SOC2-TSC-2017"]
    control: Annotated[str, StringConstraints(pattern=r"^(A\.)?\d{1,2}(\.\d{1,2}){0,2}$|^(CC|A|C|PI|P)\d{1,2}(\.\d{1,2})?$")]
    title: Annotated[SafeText, Field(max_length=200)] | None = None


class CustomRuleDefinition(_Strict):
    rule_id: Annotated[str, StringConstraints(pattern=r"^CUST(-[A-Z0-9]{1,20}){1,4}$")]
    version: Annotated[str, StringConstraints(pattern=r"^\d{1,3}\.\d{1,3}$")]
    title: Annotated[SafeText, Field(min_length=3, max_length=120)]
    description: Annotated[SafeText, Field(max_length=2000)] = ""
    severity: Severity
    evidence_type: EvidenceType
    subject_field: FieldName
    scope: Group | None = None
    violation_when: Group
    tolerance: Annotated[int, Field(ge=0, le=100_000, strict=True)] = 0
    effective_from: UtcDatetime
    effective_to: UtcDatetime | None = None
    framework_mappings: list[CustomFrameworkMapping] = Field(default_factory=list, max_length=20)
    remediation: Annotated[SafeText, Field(max_length=2000)] = ""

    @model_validator(mode="after")
    def _dates(self):
        if self.effective_to is not None and self.effective_to <= self.effective_from:
            raise ValueError("effective_to must be after effective_from")
        return self
