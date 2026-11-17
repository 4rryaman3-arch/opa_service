#!/usr/bin/env python3
"""Export JSON Schemas generated from the validating Pydantic models.

  python scripts/export_schemas.py   -> schemas/*.json

The customer rule schema covers structure; the per-evidence-type field and
operator allowlist (semantic layer enforced by app/engine/compiler.py) is
exported alongside it as custom_rule_fields.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.engine.compiler import MAX_TOTAL_CONDITIONS, NULL_OPS, OPS_BY_TYPE  # noqa: E402
from app.models.api import BatchEvaluateRequest, EvaluateRequest, EvaluationResult  # noqa: E402
from app.models.custom_rules import CustomRuleDefinition  # noqa: E402
from app.models.evidence import CUSTOM_RULE_FIELDS, EVIDENCE_MODELS, EVIDENCE_SCHEMA_VERSIONS  # noqa: E402
from regintel import policy_contexts as pctx, policy_controls as pc  # noqa: E402
from regintel.admin_api import BuildFramework, MappingCreate, PrepareCatalog  # noqa: E402
from regintel.plan import PlanResponse, TemplatePage  # noqa: E402


def main() -> int:
    out = ROOT / "schemas"
    out.mkdir(exist_ok=True)
    docs = {
        "custom_rule.schema.json": CustomRuleDefinition.model_json_schema(),
        "evaluate_request.schema.json": EvaluateRequest.model_json_schema(),
        "batch_evaluate_request.schema.json": BatchEvaluateRequest.model_json_schema(),
        "evaluation_result.schema.json": EvaluationResult.model_json_schema(mode="serialization"),
        "evaluation_templates.schema.json": TemplatePage.model_json_schema(mode="serialization"),
        "evaluation_plan.schema.json": PlanResponse.model_json_schema(mode="serialization"),
        "mapping_create.schema.json": MappingCreate.model_json_schema(),
        "job_build_framework.schema.json": BuildFramework.model_json_schema(),
        "job_prepare_catalog.schema.json": PrepareCatalog.model_json_schema(),
        "evidence_records.schema.json": {
            "$comment": "One schema per evidence_type; records are validated against the schema of the request's evidence_type.",
            "evidence_schema_versions": EVIDENCE_SCHEMA_VERSIONS,
            "evidence_types": {name: model.model_json_schema() for name, model in EVIDENCE_MODELS.items()},
        },
        "policy_context_create.schema.json": pctx.PolicyVersionIn.model_json_schema(),
        "policy_context_version_create.schema.json": pctx.PolicyVersionNext.model_json_schema(),
        "collector_capabilities.schema.json": pctx.CollectorCapabilitiesIn.model_json_schema(),
        "evaluation_plan_request.schema.json": pctx.PlanRequest.model_json_schema(),
        "policy_controls.json": {
            "$comment": "Control catalog snapshot (GET /api/v1/catalog/policy-controls is authoritative).",
            "control_catalog_version": pc.CONTROL_CATALOG_VERSION, "schema_subset": pc.SCHEMA_SUBSET,
            "target_types": pc.TARGET_TYPES, "assessment_modes": pc.ASSESSMENT_MODES,
            "items": [pc.public(c, include_evidence_schema=False) for _, c in sorted(pc.CONTROLS.items())],
        },
    }
    fields = {
        "$comment": "Semantic allowlist for customer rules. Only these fields and operators are accepted.",
        "max_total_conditions": MAX_TOTAL_CONDITIONS,
        "max_nesting": "root group -> leaf groups (2 levels)",
        "operators_by_field_type": {t: sorted(ops) for t, ops in OPS_BY_TYPE.items()},
        "null_operators_require_nullable_field": sorted(NULL_OPS),
        "fields": {
            et: {f: {"type": s["type"], "nullable": s["nullable"], **({"values": list(s["values"])} if s["values"] else {})}
                 for f, s in spec.items()}
            for et, spec in CUSTOM_RULE_FIELDS.items()
        },
    }
    docs["custom_rule_fields.json"] = fields
    for name, doc in docs.items():
        (out / name).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print(f"wrote schemas/{name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
