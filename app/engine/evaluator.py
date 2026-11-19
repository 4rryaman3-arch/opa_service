"""Evaluation orchestration.

Pipeline for every evaluation:
  1. resolve rule + version (tenant-scoped for customer rules, effective dates,
     activation status, CURRENT vs HISTORICAL semantics)
  2. resolve parameters (catalog defaults + validated customer overrides)
  3. evidence checks (type match, size, as-of consistency, exceptions)
  4. build a canonical OPA input (sorted, UTC-normalised) and its digest
  5. query the versioned Rego package
  6. strictly validate the decision document and cross-check it against the
     request (rule id/version, bundle version, counts, status consistency)

Any failure in 1-6 raises ServiceError. No step defaults to PASS.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, ValidationError

from ..config import Settings
from ..errors import ServiceError
from ..logging_config import correlation_id_var
from ..metrics import Metrics
from ..models.api import (
    ApprovedException,
    Completeness,
    EvaluationItem,
    EvaluationResult,
    Evidence,
    PolicySettings,
    ReportingPeriod,
)
from ..models.common import Status, format_utc
from ..models.evidence import CUSTOM_RULE_FIELDS, FUTURE_ALLOWED_FIELDS
from .catalog import Catalog, RuleVersionSpec
from .compiler import ENGINE, ENGINE_PACKAGE, CompileResult, sha256_hex
from .opa_client import OpaClient
from .store import RuleStore

log = logging.getLogger("opm.evaluator")

Mode = Literal["CURRENT", "HISTORICAL", "TEST"]


# ----------------------------------------------------------- decision schema


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _OpaFinding(_Strict):
    record_id: str | None
    subject_id: str | None
    reasons: list[str]
    exception_ids: list[str] | None = None


class _OpaCompleteness(_Strict):
    complete: StrictBool
    gaps: list[str]
    expected_record_count: StrictInt | None
    received_record_count: StrictInt


class _OpaDecision(_Strict):
    rule_id: str
    rule_version: str
    bundle_version: str
    status: Status
    summary: str
    metrics: dict[str, Any]
    violations: list[_OpaFinding]
    violation_count: StrictInt
    tolerance: StrictInt
    excepted: list[_OpaFinding]
    undetermined: list[_OpaFinding]
    in_scope_record_count: StrictInt
    evaluated_record_count: StrictInt
    completeness: _OpaCompleteness
    as_of: str


# Tenant-scoped rule namespaces resolved from the rule store: customer rules (CUST-) and rules OPM generated
# from a validated RuleSpec (PAM-GEN-, regintel.generated_rules). Both run in the fixed interpreter.
GENERATED_RULE_PREFIX = "PAM-GEN-"
TENANT_RULE_PREFIXES = ("CUST-", GENERATED_RULE_PREFIX)


def custom_spec_from_row(row: dict[str, Any]) -> RuleVersionSpec:
    d = row["definition"]
    from pydantic import TypeAdapter

    from ..models.common import UtcDatetime

    dt = TypeAdapter(UtcDatetime)
    return RuleVersionSpec(
        rule_id=d["rule_id"],
        version=d["version"],
        title=d["title"],
        status=row["status"],
        effective_from=dt.validate_python(d["effective_from"]),
        effective_to=dt.validate_python(d["effective_to"]) if d.get("effective_to") else None,
        package=ENGINE_PACKAGE,
        severity=d["severity"],
        description=d.get("description", ""),
        evidence_type=d["evidence_type"],
        evidence_requirements=(f"Records of evidence type '{d['evidence_type']}'",),
        parameters={},
        framework_mappings=tuple(d.get("framework_mappings", [])),
        remediation=d.get("remediation", ""),
        subject_field=d["subject_field"],
        source="GENERATED" if d["rule_id"].startswith(GENERATED_RULE_PREFIX) else "CUSTOM",
        compiled=row["compiled"],
    )


class Evaluator:
    def __init__(
        self, settings: Settings, catalog: Catalog, store: RuleStore, opa: OpaClient, metrics: Metrics
    ) -> None:
        self.settings = settings
        self.catalog = catalog
        self.store = store
        self.opa = opa
        self.metrics = metrics

    # ------------------------------------------------------------ resolution
    def resolve_rule(self, tenant_id: str, item: EvaluationItem) -> RuleVersionSpec:
        start, end = item.reporting_period.start, item.reporting_period.end
        mode = item.evaluation_mode
        allowed = {"CURRENT": {"ACTIVE"}, "HISTORICAL": {"ACTIVE", "RETIRED", "INACTIVE"}}[mode]

        if item.rule_id.startswith(TENANT_RULE_PREFIXES):  # customer rules and OPM-generated rules
            if item.rule_version is not None:
                row = self.store.get_custom(tenant_id, item.rule_id, item.rule_version)
                candidates = [row] if row else []
            else:
                candidates = [r for r in self.store.list_custom(tenant_id, item.rule_id) if r["status"] == "ACTIVE"]
            if not candidates:
                # Identical response whether the rule exists for another tenant or not at all.
                raise ServiceError(404, "RULE_NOT_FOUND", "Rule (version) not found for this tenant.")
            spec = custom_spec_from_row(candidates[0])
        else:
            versions = self.catalog.rules.get(item.rule_id)
            if versions is None:
                raise ServiceError(404, "RULE_NOT_FOUND", "Unknown rule_id.")
            if mode == "CURRENT" and not self.store.predefined_active(tenant_id, item.rule_id):
                raise ServiceError(409, "RULE_INACTIVE", "This rule is deactivated for the tenant.")
            if item.rule_version is not None:
                spec = versions.get(item.rule_version)
                if spec is None:
                    raise ServiceError(404, "RULE_VERSION_NOT_FOUND", "Unknown rule version.")
            else:
                effective = [v for v in versions.values() if v.status == "ACTIVE" and v.covers(start, end)]
                if not effective:
                    if any(v.covers(start, end) for v in versions.values()):
                        raise ServiceError(
                            422, "HISTORICAL_MODE_REQUIRED",
                            "The reporting period is covered only by a retired rule version; "
                            "use evaluation_mode=HISTORICAL with an explicit rule_version.",
                        )
                    raise ServiceError(
                        422, "NO_EFFECTIVE_RULE_VERSION",
                        "No single rule version is effective for the whole reporting period; "
                        "split the period at the version boundary.",
                    )
                spec = max(effective, key=lambda v: tuple(int(p) for p in v.version.split(".")))

        if spec.status == "DRAFT":
            raise ServiceError(409, "RULE_NOT_ACTIVE", "Draft rules can only be run via /api/v1/rules/test.")
        if spec.status not in allowed:
            raise ServiceError(
                409 if mode == "CURRENT" else 422,
                "RULE_NOT_ACTIVE" if mode == "CURRENT" else "RULE_VERSION_NOT_USABLE",
                f"Rule version status is {spec.status}; "
                + ("use evaluation_mode=HISTORICAL for retired/inactive versions." if mode == "CURRENT" else "not usable."),
            )
        if not spec.covers(start, end):
            raise ServiceError(
                422, "RULE_VERSION_NOT_EFFECTIVE",
                "The rule version's effective dates do not cover the whole reporting period.",
                details={
                    "effective_from": format_utc(spec.effective_from),
                    "effective_to": format_utc(spec.effective_to) if spec.effective_to else None,
                },
            )
        return spec

    def check_temporal(self, item: EvaluationItem, now: datetime) -> None:
        period = item.reporting_period
        if period.end > now + timedelta(seconds=self.settings.clock_skew_seconds):
            raise ServiceError(422, "PERIOD_IN_FUTURE", "reporting_period.end lies in the future.")
        ps = item.policy_settings
        if item.evaluation_mode == "CURRENT":
            if period.end < now - timedelta(days=self.settings.historical_threshold_days):
                raise ServiceError(
                    422, "HISTORICAL_MODE_REQUIRED",
                    f"Reporting periods ending more than {self.settings.historical_threshold_days} days ago "
                    "require evaluation_mode=HISTORICAL with explicit rule and policy versions.",
                )
        else:
            if item.rule_version is None:
                raise ServiceError(422, "RULE_VERSION_REQUIRED", "HISTORICAL evaluations require rule_version.")
            if ps.policy_version is None or ps.effective_from is None:
                raise ServiceError(
                    422, "HISTORICAL_POLICY_CONTEXT_REQUIRED",
                    "HISTORICAL evaluations require policy_settings.policy_version and "
                    "policy_settings.effective_from (the customer policy in force during the period).",
                )
        if ps.effective_from is not None and ps.effective_from > period.start:
            raise ServiceError(
                422, "POLICY_SETTINGS_NOT_EFFECTIVE",
                "policy_settings.effective_from is after reporting_period.start; "
                "split the period at the policy change.",
            )
        if ps.effective_to is not None and ps.effective_to < period.end:
            raise ServiceError(
                422, "POLICY_SETTINGS_NOT_EFFECTIVE",
                "policy_settings.effective_to is before reporting_period.end.",
            )

    @staticmethod
    def resolve_params(spec: RuleVersionSpec, ps: PolicySettings) -> dict[str, Any]:
        if spec.source != "PREDEFINED" and ps.parameters:
            raise ServiceError(
                422, "UNKNOWN_PARAMETER",
                "Customer rules take no parameters; thresholds are part of the rule definition.",
            )
        params: dict[str, Any] = {name: p.default for name, p in spec.parameters.items()}
        # A parameter without a Securden default (newer rules) must always be stated.
        unstated = sorted(n for n, p in spec.parameters.items() if p.default is None and n not in ps.parameters)
        if unstated:
            raise ServiceError(422, "MISSING_PARAMETER",
                               f"{spec.rule_id} {spec.version} has no default for {', '.join(unstated)}; "
                               "state the value in policy_settings.parameters.")
        for name, value in ps.parameters.items():
            p = spec.parameters.get(name)
            if p is None:
                raise ServiceError(422, "UNKNOWN_PARAMETER", f"Unknown parameter '{name}' for {spec.rule_id} {spec.version}.")
            if p.type == "integer":
                if isinstance(value, bool) or not isinstance(value, int):
                    raise ServiceError(422, "INVALID_PARAMETER", f"Parameter '{name}' must be an integer.")
                if (p.minimum is not None and value < p.minimum) or (p.maximum is not None and value > p.maximum):
                    raise ServiceError(
                        422, "INVALID_PARAMETER", f"Parameter '{name}' must be between {p.minimum} and {p.maximum}."
                    )
            elif p.type == "boolean":
                if not isinstance(value, bool):
                    raise ServiceError(422, "INVALID_PARAMETER", f"Parameter '{name}' must be a boolean.")
            elif p.type == "enum_list":
                if (not isinstance(value, list) or not value or len(set(value)) != len(value)
                        or any(v not in p.items for v in value)):
                    raise ServiceError(422, "INVALID_PARAMETER",
                                       f"Parameter '{name}' must be a non-empty list of distinct values from "
                                       f"{list(p.items)}.")
                value = sorted(value)
            else:
                raise ServiceError(500, "INTERNAL_ERROR", "Unsupported parameter type in catalog.")
            params[name] = value
        params["scope_tags"] = sorted(set(ps.scope_tags))
        return params

    def check_evidence(
        self, spec: RuleVersionSpec, period: ReportingPeriod, evidence: Evidence, exceptions: list[ApprovedException]
    ) -> None:
        if evidence.evidence_type != spec.evidence_type:
            raise ServiceError(
                422, "EVIDENCE_TYPE_MISMATCH",
                f"Rule {spec.rule_id} {spec.version} requires evidence_type '{spec.evidence_type}'.",
            )
        if len(evidence.records) > self.settings.max_records_per_evaluation:
            raise ServiceError(
                413, "TOO_MANY_RECORDS",
                f"At most {self.settings.max_records_per_evaluation} records per evaluation; "
                "aggregate in Securden or split the evaluation.",
            )
        dt_fields = [
            f for f, s in CUSTOM_RULE_FIELDS[spec.evidence_type].items()
            if s["type"] == "datetime" and f not in FUTURE_ALLOWED_FIELDS.get(spec.evidence_type, frozenset())
        ]
        late = sorted(
            rec.record_id
            for rec in evidence.records
            if any((v := getattr(rec, f)) is not None and v > period.end for f in dt_fields)
        )
        if late:
            raise ServiceError(
                422, "EVIDENCE_AFTER_PERIOD_END",
                "Evidence contains timestamps after reporting_period.end; supply the state as of the period end.",
                details={"record_ids": late[:20]},
            )
        ids = [e.exception_id for e in exceptions]
        if len(ids) != len(set(ids)):
            raise ServiceError(422, "DUPLICATE_EXCEPTION", "Duplicate exception_id values.")
        mismatched = sorted(e.exception_id for e in exceptions if e.rule_id != spec.rule_id)
        if mismatched:
            raise ServiceError(
                422, "EXCEPTION_RULE_MISMATCH",
                "Approved exceptions must target the rule being evaluated.",
                details={"exception_ids": mismatched[:20]},
            )

    # ------------------------------------------------------------ execution
    @staticmethod
    def build_input(
        spec: RuleVersionSpec,
        period: ReportingPeriod,
        evidence: Evidence,
        exceptions: list[ApprovedException],
        params: dict[str, Any],
    ) -> dict[str, Any]:
        rule = {"rule_id": spec.rule_id, "rule_version": spec.version}
        if spec.compiled is not None:
            rule = dict(spec.compiled)
        completeness: Completeness = evidence.completeness
        return {
            "rule": rule,
            "reporting_period": {"start": format_utc(period.start), "end": format_utc(period.end)},
            "params": params,
            "evidence": {
                "evidence_type": evidence.evidence_type,
                "records": [r.model_dump(mode="json") for r in sorted(evidence.records, key=lambda r: r.record_id)],
                "completeness": completeness.model_dump(mode="json"),
            },
            "exceptions": [
                e.model_dump(mode="json") for e in sorted(exceptions, key=lambda e: e.exception_id)
            ],
        }

    async def _execute(
        self,
        *,
        tenant_id: str,
        spec: RuleVersionSpec,
        period: ReportingPeriod,
        evidence: Evidence,
        exceptions: list[ApprovedException],
        params: dict[str, Any],
        mode: Mode,
        customer_policy_version: str | None,
        item_reference: str | None,
    ) -> EvaluationResult:
        started = time.perf_counter()
        opa_input = self.build_input(spec, period, evidence, exceptions, params)
        digest = sha256_hex(opa_input)
        try:
            raw = await asyncio.wait_for(
                self.opa.decide(spec.package, opa_input), timeout=self.settings.evaluation_timeout_seconds
            )
        except asyncio.TimeoutError as exc:
            self.metrics.inc("evaluation_errors_total")
            raise ServiceError(504, "EVALUATION_TIMEOUT", "Evaluation exceeded the configured timeout.") from exc
        except ServiceError:
            self.metrics.inc("evaluation_errors_total")
            raise

        decision = self._validate_decision(raw, spec, evidence)
        cap = self.settings.max_evidence_references
        record_ids = sorted(r.record_id for r in evidence.records)

        def findings(items: list[_OpaFinding]) -> list[dict[str, Any]]:
            return [
                {
                    "record_id": f.record_id,
                    "subject_id": f.subject_id,
                    "reasons": sorted(f.reasons),
                    "exception_ids": sorted(f.exception_ids) if f.exception_ids is not None else None,
                }
                for f in sorted(items, key=lambda f: (f.record_id or "", f.subject_id or ""))[:cap]
            ]

        truncated = any(len(x) > cap for x in (decision.violations, decision.excepted, decision.undetermined))
        result = EvaluationResult(
            evaluation_id=f"eval-{uuid.uuid4().hex}",
            correlation_id=correlation_id_var.get(),
            tenant_id=tenant_id,
            item_reference=item_reference,
            rule_id=spec.rule_id,
            rule_version=spec.version,
            policy_bundle_version=decision.bundle_version,
            status=decision.status,
            severity=spec.severity,
            metrics=decision.metrics,
            evidence_references=record_ids[:cap],
            evidence_references_truncated=len(record_ids) > cap,
            violations=findings(decision.violations),
            excepted=findings(decision.excepted),
            undetermined=findings(decision.undetermined),
            findings_truncated=truncated,
            evidence_completeness={
                "complete": decision.completeness.complete,
                "gaps": sorted(decision.completeness.gaps),
                "expected_record_count": decision.completeness.expected_record_count,
                "received_record_count": decision.completeness.received_record_count,
                "evaluated_record_count": decision.evaluated_record_count,
                "in_scope_record_count": decision.in_scope_record_count,
            },
            decision_details={
                "summary": decision.summary,
                "engine": ENGINE if spec.source != "PREDEFINED" else "securden.rules",
                "policy_package": spec.package,
                "rule_source": spec.source,
                "evaluation_mode": mode,
                "as_of": decision.as_of,
                "violation_count": decision.violation_count,
                "tolerance": decision.tolerance,
                "parameters": params,
                "customer_policy_version": customer_policy_version,
                "input_digest": f"sha256:{digest}",
            },
            framework_mappings=list(spec.framework_mappings),
            framework_mapping_disclaimer=self.catalog.disclaimer,
            remediation=spec.remediation,
            reporting_period={"start": format_utc(period.start), "end": format_utc(period.end)},
            evaluated_at=format_utc(datetime.now(timezone.utc)),
        )
        elapsed = time.perf_counter() - started
        self.metrics.inc("evaluations_total")
        self.metrics.inc(f"evaluations_status_{decision.status.lower()}_total")
        self.metrics.observe("evaluation_seconds", elapsed)
        log.info(
            "evaluation complete",
            extra={"fields": {
                "tenant_id": tenant_id, "rule_id": spec.rule_id, "rule_version": spec.version,
                "status": decision.status, "records": len(evidence.records),
                "duration_ms": round(elapsed * 1000, 2), "mode": mode,
            }},
        )
        return result

    def _validate_decision(self, raw: Any, spec: RuleVersionSpec, evidence: Evidence) -> _OpaDecision:
        try:
            decision = _OpaDecision.model_validate(raw)
        except ValidationError as exc:
            raise ServiceError(
                502, "POLICY_DECISION_INVALID", "Policy decision did not match the expected schema."
            ) from exc
        problems = []
        if decision.rule_id != spec.rule_id or decision.rule_version != spec.version:
            problems.append("rule identity")
        if decision.bundle_version != self.catalog.bundle_version:
            raise ServiceError(
                502, "POLICY_VERSION_MISMATCH",
                "Policy engine bundle version differs from the service's rule catalog; refusing to report.",
                details={"expected": self.catalog.bundle_version, "actual": decision.bundle_version},
            )
        if decision.evaluated_record_count != len(evidence.records):
            problems.append("record count")
        if decision.violation_count != len(decision.violations):
            problems.append("violation count")
        if (decision.status == "FAIL") != (decision.violation_count > decision.tolerance):
            problems.append("status/violation consistency")
        if problems:
            raise ServiceError(
                502, "POLICY_DECISION_INCONSISTENT",
                "Policy decision failed consistency checks: " + ", ".join(problems) + ".",
            )
        return decision

    # ------------------------------------------------------------ public API
    async def evaluate(self, tenant_id: str, item: EvaluationItem) -> EvaluationResult:
        self.check_temporal(item, datetime.now(timezone.utc))
        spec = self.resolve_rule(tenant_id, item)
        params = self.resolve_params(spec, item.policy_settings)
        self.check_evidence(spec, item.reporting_period, item.evidence, item.exceptions)
        return await self._execute(
            tenant_id=tenant_id,
            spec=spec,
            period=item.reporting_period,
            evidence=item.evidence,
            exceptions=item.exceptions,
            params=params,
            mode=item.evaluation_mode,
            customer_policy_version=item.policy_settings.policy_version,
            item_reference=item.item_reference,
        )

    async def evaluate_draft(
        self,
        tenant_id: str,
        compiled: CompileResult,
        period: ReportingPeriod,
        evidence: Evidence,
        exceptions: list[ApprovedException],
        scope_tags: list[str],
    ) -> EvaluationResult:
        if period.end > datetime.now(timezone.utc) + timedelta(seconds=self.settings.clock_skew_seconds):
            raise ServiceError(422, "PERIOD_IN_FUTURE", "reporting_period.end lies in the future.")
        assert compiled.definition is not None and compiled.compiled is not None
        spec = custom_spec_from_row(
            {"definition": compiled.definition.model_dump(mode="json"), "status": "DRAFT", "compiled": compiled.compiled}
        )
        spec = replace(spec, source="DRAFT")
        self.check_evidence(spec, period, evidence, exceptions)
        return await self._execute(
            tenant_id=tenant_id,
            spec=spec,
            period=period,
            evidence=evidence,
            exceptions=exceptions,
            params={"scope_tags": sorted(set(scope_tags))},
            mode="TEST",
            customer_policy_version=None,
            item_reference=None,
        )
