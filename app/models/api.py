"""API request and response models.

All request models use ``extra="forbid"``: a caller cannot inject server-owned
fields such as ``evaluated_at``, ``evaluation_id`` or an authorization context.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from .common import Identifier, RuleId, RuleVersion, Severity, Status, Tag, TenantId, UtcDatetime
from .custom_rules import CustomRuleDefinition
from .evidence import EVIDENCE_MODELS, BaseRecord, EvidenceType

MAX_PERIOD = timedelta(days=400)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReportingPeriod(StrictModel):
    start: UtcDatetime
    end: UtcDatetime

    @model_validator(mode="after")
    def _check(self):
        if self.end <= self.start:
            raise ValueError("reporting_period.end must be after reporting_period.start")
        if self.end - self.start > MAX_PERIOD:
            raise ValueError("reporting_period may not exceed 400 days")
        return self


class Completeness(StrictModel):
    expected_record_count: Annotated[StrictInt, Field(ge=0)] | None = None
    received_record_count: Annotated[StrictInt, Field(ge=0)]
    source_complete: StrictBool
    collection_errors: Annotated[StrictInt, Field(ge=0)] = 0


class Evidence(StrictModel):
    evidence_type: EvidenceType
    # Hard upper bound; the configurable (lower) limit is enforced at runtime.
    records: list[Any] = Field(max_length=100_000)
    completeness: Completeness

    @field_validator("records")
    @classmethod
    def _validate_records(cls, value: list[Any], info: ValidationInfo) -> list[BaseRecord]:
        evidence_type = info.data.get("evidence_type")
        if evidence_type is None:
            return value  # evidence_type error already reported
        model = EVIDENCE_MODELS[evidence_type]
        parsed: list[BaseRecord] = []
        problems: list[str] = []
        for idx, raw in enumerate(value):
            try:
                parsed.append(model.model_validate(raw))
            except ValidationError as exc:
                for e in exc.errors(include_input=False, include_url=False)[:3]:
                    loc = ".".join(str(p) for p in e["loc"]) or "<record>"
                    problems.append(f"records[{idx}].{loc}: {e['msg']}")
            if len(problems) >= 20:
                break
        if problems:
            raise ValueError("; ".join(problems))
        seen: set[str] = set()
        dupes: set[str] = set()
        for rec in parsed:
            (dupes if rec.record_id in seen else seen).add(rec.record_id)
        if dupes:
            sample = ", ".join(sorted(dupes)[:10])
            raise ValueError(f"duplicate record_id values are not allowed: {sample}")
        return parsed

    @model_validator(mode="after")
    def _check_counts(self):
        if self.completeness.received_record_count != len(self.records):
            raise ValueError(
                "completeness.received_record_count must equal the number of records supplied"
            )
        return self


class ApprovedException(StrictModel):
    exception_id: Identifier
    rule_id: RuleId
    subject_ids: list[Identifier] = Field(min_length=1, max_length=1000)
    approved_by: Identifier
    approved_at: UtcDatetime
    expires_at: UtcDatetime

    @model_validator(mode="after")
    def _check(self):
        if self.expires_at <= self.approved_at:
            raise ValueError("exception expires_at must be after approved_at")
        return self


ParamValue = StrictBool | StrictInt | list[Tag]


class PolicySettings(StrictModel):
    policy_version: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")] | None = None
    effective_from: UtcDatetime | None = None
    effective_to: UtcDatetime | None = None
    parameters: dict[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")], ParamValue] = Field(
        default_factory=dict, max_length=50
    )
    scope_tags: list[Tag] = Field(default_factory=list, max_length=50)


class EvaluationItem(StrictModel):
    """One evaluation, without the tenant (used inside batches)."""

    item_reference: Identifier | None = None
    rule_id: RuleId
    rule_version: RuleVersion | None = None
    evaluation_mode: Literal["CURRENT", "HISTORICAL"] = "CURRENT"
    reporting_period: ReportingPeriod
    evidence: Evidence
    policy_settings: PolicySettings = Field(default_factory=PolicySettings)
    exceptions: list[ApprovedException] = Field(default_factory=list, max_length=1000)


class EvaluateRequest(EvaluationItem):
    tenant_id: TenantId


class BatchEvaluateRequest(StrictModel):
    tenant_id: TenantId
    items: list[EvaluationItem] = Field(min_length=1, max_length=1000)


class RuleValidateRequest(StrictModel):
    tenant_id: TenantId
    rule: dict[str, Any]


class RuleTestRequest(StrictModel):
    tenant_id: TenantId
    rule: dict[str, Any]
    reporting_period: ReportingPeriod
    evidence: Evidence
    exceptions: list[ApprovedException] = Field(default_factory=list, max_length=1000)
    scope_tags: list[Tag] = Field(default_factory=list, max_length=50)


class CustomRuleCreateRequest(StrictModel):
    tenant_id: TenantId
    rule: CustomRuleDefinition


class TenantRequest(StrictModel):
    tenant_id: TenantId


# ------------------------------------------------------------------ responses


class FrameworkMapping(BaseModel):
    framework: str
    control: str
    title: str | None = None


class Finding(BaseModel):
    record_id: str | None
    subject_id: str | None
    reasons: list[str]
    exception_ids: list[str] | None = None


class EvidenceCompleteness(BaseModel):
    complete: bool
    gaps: list[str]
    expected_record_count: int | None
    received_record_count: int
    evaluated_record_count: int
    in_scope_record_count: int


class DecisionDetails(BaseModel):
    summary: str
    engine: str
    policy_package: str
    rule_source: Literal["PREDEFINED", "PUBLISHED", "CUSTOM", "DRAFT"]
    evaluation_mode: Literal["CURRENT", "HISTORICAL", "TEST"]
    as_of: str
    violation_count: int
    tolerance: int
    parameters: dict[str, Any]
    customer_policy_version: str | None
    input_digest: str


class EvaluationResult(BaseModel):
    evaluation_id: str
    correlation_id: str | None
    tenant_id: str
    item_reference: str | None = None
    rule_id: str
    rule_version: str
    policy_bundle_version: str
    status: Status
    severity: Severity
    metrics: dict[str, Any]
    evidence_references: list[str]
    evidence_references_truncated: bool
    violations: list[Finding]
    excepted: list[Finding]
    undetermined: list[Finding]
    findings_truncated: bool
    evidence_completeness: EvidenceCompleteness
    decision_details: DecisionDetails
    framework_mappings: list[FrameworkMapping]
    framework_mapping_disclaimer: str
    remediation: str
    reporting_period: dict[str, str]
    evaluated_at: str


class BatchItemError(BaseModel):
    code: str
    message: str
    details: Any = None


class BatchItemResult(BaseModel):
    index: int
    item_reference: str | None
    ok: bool
    result: EvaluationResult | None = None
    error: BatchItemError | None = None


class BatchSummary(BaseModel):
    total: int
    succeeded: int
    failed: int
    by_status: dict[str, int]


class BatchEvaluateResponse(BaseModel):
    batch_id: str
    correlation_id: str | None
    tenant_id: str
    summary: BatchSummary
    results: list[BatchItemResult]
    evaluated_at: str
