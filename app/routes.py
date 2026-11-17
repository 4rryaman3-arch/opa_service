"""HTTP API."""

from __future__ import annotations

import asyncio
import uuid
from collections import Counter
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from . import __version__
from .engine.compiler import compile_rule
from .engine.evaluator import Evaluator, custom_spec_from_row
from .errors import ServiceError
from .logging_config import correlation_id_var
from .models.api import (
    BatchEvaluateRequest,
    BatchEvaluateResponse,
    CustomRuleCreateRequest,
    EvaluateRequest,
    EvaluationResult,
    RuleTestRequest,
    RuleValidateRequest,
    TenantRequest,
)
from .models.common import RuleId, RuleVersion, TenantId, format_utc
from .security import Principal, authenticate, authorize_tenant, require_scope

router = APIRouter()


def _evaluator(request: Request) -> Evaluator:
    return request.app.state.evaluator


# ---------------------------------------------------------------- health


@router.get("/health", include_in_schema=False)
async def health() -> dict:
    return {"status": "ok"}


@router.get("/ready", include_in_schema=False)
async def ready(request: Request) -> JSONResponse:
    state = request.app.state
    checks = {"opa": "fail", "policy_bundle": "fail", "rule_store": "fail"}
    if await state.opa.healthy():
        checks["opa"] = "ok"
        try:
            meta = await state.opa.meta()
            if meta.get("bundle_version") == state.catalog.bundle_version:
                checks["policy_bundle"] = "ok"
        except ServiceError:
            pass
    if state.store.ping():
        checks["rule_store"] = "ok"
    ok = all(v == "ok" for v in checks.values())
    return JSONResponse(status_code=200 if ok else 503, content={"status": "ready" if ok else "not_ready", "checks": checks})


# ---------------------------------------------------------------- metadata


@router.get("/api/v1/version")
async def version(request: Request, _: Principal = Depends(authenticate)) -> dict:
    state = request.app.state
    meta = await state.opa.meta()
    return {
        "service": "securden-opm-service",
        "app_version": __version__,
        "api_version": "v1",
        "opa_version": meta.get("opa_version"),
        "policy_bundle_version": meta.get("bundle_version"),
        "catalog_bundle_version": state.catalog.bundle_version,
        "policy_versions_consistent": meta.get("bundle_version") == state.catalog.bundle_version,
        "custom_rule_engine": "securden.custom.v1",
    }


@router.get("/api/v1/metrics")
async def metrics(request: Request, _: Principal = Depends(require_scope("metrics:read"))) -> dict:
    return request.app.state.metrics.snapshot()


# ---------------------------------------------------------------- rules


@router.get("/api/v1/rules")
async def list_rules(
    request: Request,
    tenant_id: TenantId = Query(...),
    principal: Principal = Depends(require_scope("rules:read")),
) -> dict:
    authorize_tenant(principal, tenant_id)
    state = request.app.state
    predefined = []
    for rule_id, versions in sorted(state.catalog.rules.items()):
        predefined.append({
            "rule_id": rule_id,
            "active_for_tenant": state.store.predefined_active(tenant_id, rule_id),
            "versions": [v.public() for _, v in sorted(versions.items())],
        })
    custom = []
    for row in state.store.list_custom(tenant_id):
        info = custom_spec_from_row(row).public()
        info.update({"digest": row["digest"], "created_at": row["created_at"], "updated_at": row["updated_at"]})
        custom.append(info)
    return {
        "tenant_id": tenant_id,
        "policy_bundle_version": state.catalog.bundle_version,
        "framework_mapping_disclaimer": state.catalog.disclaimer,
        "predefined_rules": predefined,
        "custom_rules": custom,
    }


@router.post("/api/v1/rules/validate")
async def validate_rule(body: RuleValidateRequest, principal: Principal = Depends(require_scope("rules:write"))) -> dict:
    authorize_tenant(principal, body.tenant_id)
    result = compile_rule(body.rule)
    return {
        "tenant_id": body.tenant_id,
        "valid": result.valid,
        "activated": False,
        "errors": result.errors,
        "warnings": result.warnings,
        "definition_digest": f"sha256:{result.digest}" if result.digest else None,
        "compiled": result.compiled,
    }


@router.post("/api/v1/rules/test", response_model=EvaluationResult)
async def test_rule(
    request: Request, body: RuleTestRequest, principal: Principal = Depends(require_scope("rules:write"))
) -> EvaluationResult:
    authorize_tenant(principal, body.tenant_id)
    result = compile_rule(body.rule)
    if not result.valid:
        raise ServiceError(422, "RULE_INVALID", "Rule definition is invalid.", details=result.errors)
    return await _evaluator(request).evaluate_draft(
        body.tenant_id, result, body.reporting_period, body.evidence, body.exceptions, body.scope_tags
    )


@router.post("/api/v1/rules/custom", status_code=201)
async def create_custom_rule(
    request: Request, body: CustomRuleCreateRequest, principal: Principal = Depends(require_scope("rules:admin"))
) -> dict:
    authorize_tenant(principal, body.tenant_id)
    result = compile_rule(body.rule)
    if not result.valid:
        raise ServiceError(422, "RULE_INVALID", "Rule definition is invalid.", details=result.errors)
    row = request.app.state.store.create_custom(
        body.tenant_id, body.rule.model_dump(mode="json"), result.compiled, result.digest, principal.key_id
    )
    return {"rule_id": row["rule_id"], "version": row["version"], "status": row["status"],
            "digest": f"sha256:{row['digest']}", "warnings": result.warnings}


@router.post("/api/v1/rules/custom/{rule_id}/versions/{version}/{action}")
async def change_custom_rule_status(
    request: Request,
    rule_id: RuleId,
    version: RuleVersion,
    action: str,
    body: TenantRequest,
    principal: Principal = Depends(require_scope("rules:admin")),
) -> dict:
    authorize_tenant(principal, body.tenant_id)
    status = {"activate": "ACTIVE", "deactivate": "INACTIVE"}.get(action)
    if status is None:
        raise ServiceError(404, "NOT_FOUND", "Unknown action.")
    row = request.app.state.store.set_custom_status(body.tenant_id, rule_id, version, status, principal.key_id)
    return {"rule_id": row["rule_id"], "version": row["version"], "status": row["status"]}


@router.post("/api/v1/rules/predefined/{rule_id}/{action}")
async def change_predefined_rule_status(
    request: Request,
    rule_id: RuleId,
    action: str,
    body: TenantRequest,
    principal: Principal = Depends(require_scope("rules:admin")),
) -> dict:
    authorize_tenant(principal, body.tenant_id)
    if rule_id not in request.app.state.catalog.rules:
        raise ServiceError(404, "RULE_NOT_FOUND", "Unknown rule_id.")
    active = {"activate": True, "deactivate": False}.get(action)
    if active is None:
        raise ServiceError(404, "NOT_FOUND", "Unknown action.")
    request.app.state.store.set_predefined_active(body.tenant_id, rule_id, active, principal.key_id)
    return {"rule_id": rule_id, "tenant_id": body.tenant_id, "active": active}


# ---------------------------------------------------------------- evaluation


@router.post("/api/v1/evaluate", response_model=EvaluationResult)
async def evaluate(
    request: Request, body: EvaluateRequest, principal: Principal = Depends(require_scope("evaluate"))
) -> EvaluationResult:
    authorize_tenant(principal, body.tenant_id)
    return await _evaluator(request).evaluate(body.tenant_id, body)


@router.post("/api/v1/evaluate/batch", response_model=BatchEvaluateResponse)
async def evaluate_batch(
    request: Request, body: BatchEvaluateRequest, principal: Principal = Depends(require_scope("evaluate"))
) -> BatchEvaluateResponse:
    authorize_tenant(principal, body.tenant_id)
    settings = request.app.state.settings
    if len(body.items) > settings.max_batch_items:
        raise ServiceError(413, "BATCH_TOO_LARGE", f"At most {settings.max_batch_items} items per batch.")
    total_records = sum(len(i.evidence.records) for i in body.items)
    if total_records > settings.max_batch_total_records:
        raise ServiceError(
            413, "BATCH_TOO_LARGE", f"At most {settings.max_batch_total_records} evidence records per batch."
        )
    evaluator = _evaluator(request)
    semaphore = asyncio.Semaphore(settings.batch_concurrency)

    async def run(index: int, item) -> dict:
        async with semaphore:
            try:
                result = await evaluator.evaluate(body.tenant_id, item)
                return {"index": index, "item_reference": item.item_reference, "ok": True, "result": result}
            except ServiceError as exc:
                return {"index": index, "item_reference": item.item_reference, "ok": False, "error": exc.to_dict()}
            except Exception:  # noqa: BLE001 - isolate unexpected per-item failures
                import logging

                logging.getLogger("opm.batch").exception("batch item failed")
                return {
                    "index": index, "item_reference": item.item_reference, "ok": False,
                    "error": {"code": "INTERNAL_ERROR", "message": "Internal error evaluating item."},
                }

    results = await asyncio.gather(*(run(i, item) for i, item in enumerate(body.items)))
    by_status = Counter(r["result"].status for r in results if r["ok"])
    succeeded = sum(1 for r in results if r["ok"])
    request.app.state.metrics.inc("batch_requests_total")
    request.app.state.metrics.inc("batch_items_total", len(results))
    return BatchEvaluateResponse(
        batch_id=f"batch-{uuid.uuid4().hex}",
        correlation_id=correlation_id_var.get(),
        tenant_id=body.tenant_id,
        summary={
            "total": len(results), "succeeded": succeeded, "failed": len(results) - succeeded,
            "by_status": dict(sorted(by_status.items())),
        },
        results=results,
        evaluated_at=format_utc(datetime.now(timezone.utc)),
    )
