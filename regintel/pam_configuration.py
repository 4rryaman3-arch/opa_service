"""Verified PAM configuration snapshots supplied by the Django collector.

A snapshot records configured values (e.g. the rotation interval of Securden's rotation policy)
observed at ``captured_at``. As a mapping parameter source it has provenance
CUSTOMER_POLICY / PAM_CONFIGURATION: a company setting, never a regulatory threshold. It shows
what was configured at capture time; whether that configuration was enforced during a reporting
period is established only by the rule's evaluation of event evidence for that period.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .db import CatalogDb, CatalogError, digest_of, now_iso

PROVENANCE = {"provenance": "CUSTOMER_POLICY", "source_type": "PAM_CONFIGURATION",
              "assessment_basis": "CONFIGURATION_OBSERVED_AT_CAPTURE",
              "statement": "Configured value observed by the collector at captured_at. It is the organization's "
                           "setting, not a regulatory threshold, and does not by itself prove enforcement during the "
                           "reporting period; the rule verifies behaviour from the period's evidence."}


class Collector(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=40)


class Setting(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str = Field(pattern=r"^[A-Z][A-Z0-9-]{2,40}$")
    parameter: str = Field(pattern=r"^[a-z][a-z0-9_]{1,60}$")
    value: bool | int | list[str]
    setting_reference: str = Field(min_length=3, max_length=300)  # e.g. "Rotation policy 'Default' > interval"


class PamConfigurationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    collector: Collector
    captured_at: datetime
    verified: bool  # the collector read the value from Securden itself (not typed in by a person)
    settings: list[Setting] = Field(min_length=1, max_length=200)


def _value_problem(spec: Any, value: Any) -> str | None:
    if spec.type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            return "must be an integer"
        if (spec.minimum is not None and value < spec.minimum) or (spec.maximum is not None and value > spec.maximum):
            return f"must be between {spec.minimum} and {spec.maximum}"
    elif spec.type == "boolean":
        if not isinstance(value, bool):
            return "must be a boolean"
    elif spec.type == "enum_list":
        if not isinstance(value, list) or not value or any(v not in spec.items for v in value) \
                or len(set(value)) != len(value):
            return f"must be a non-empty list of distinct values from {list(spec.items)}"
    return None


def declare(db: CatalogDb, *, scope: str, actor: str, body: PamConfigurationIn, engine: Any) -> dict[str, Any]:
    if not body.verified:
        raise CatalogError("UNVERIFIED_CONFIGURATION", "only collector-verified configuration is accepted")
    problems = []
    for i, s in enumerate(body.settings):
        versions = [v for v in ((getattr(engine, "rules", {}) or {}).get(s.rule_id) or {}).values() if v.status == "ACTIVE"]
        if not versions:
            problems.append({"path": f"$.settings[{i}].rule_id", "code": "UNKNOWN_RULE"})
            continue
        spec = next((v.parameters[s.parameter] for v in versions if s.parameter in v.parameters), None)
        if spec is None:
            problems.append({"path": f"$.settings[{i}].parameter", "code": "UNKNOWN_PARAMETER"})
            continue
        why = _value_problem(spec, s.value)
        if why:
            problems.append({"path": f"$.settings[{i}].value", "code": "INVALID_VALUE", "message": why})
    keys = [(s.rule_id, s.parameter) for s in body.settings]
    if len(keys) != len(set(keys)):
        problems.append({"path": "$.settings", "code": "DUPLICATE_SETTING"})
    if problems:
        raise CatalogError("INVALID_CONFIGURATION", "configuration snapshot rejected", details={"problems": problems})
    settings = [s.model_dump() for s in sorted(body.settings, key=lambda s: (s.rule_id, s.parameter))]
    when = body.captured_at if body.captured_at.tzinfo else body.captured_at.replace(tzinfo=timezone.utc)
    captured = when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    digest = "sha256:" + digest_of({"collector": body.collector.model_dump(), "captured_at": captured,
                                    "settings": settings})
    with db.tx():
        sid = db.insert("pam_configuration_snapshot", organization_scope=scope, tenant_id=body.tenant_id,
                        collector_info=body.collector.model_dump(), captured_at=captured, config_settings=settings,
                        digest=digest, declared_by=actor, declared_at=now_iso())
        db.audit(actor, "PAM_CONFIGURATION_DECLARED", "pam_configuration_snapshot", sid, tenant_id=body.tenant_id)
    return view(db.one("SELECT * FROM pam_configuration_snapshot WHERE id=?", (sid,)))


def latest(db: CatalogDb, scope: str | None, tenant: str | None) -> dict[str, Any] | None:
    if scope is None or tenant is None:
        return None
    row = db.one("SELECT * FROM pam_configuration_snapshot WHERE organization_scope=? AND tenant_id=? "
                 "ORDER BY id DESC LIMIT 1", (scope, tenant))
    return view(row) if row else None


def view(row: dict[str, Any] | None) -> dict[str, Any]:
    assert row is not None
    return {"snapshot_id": row["id"], "tenant_id": row["tenant_id"], "collector": row["collector_info"],
            "captured_at": row["captured_at"], "settings": row["config_settings"], "digest": row["digest"],
            "declared_at": row["declared_at"], **PROVENANCE}


def value_for(snapshot: dict[str, Any] | None, rule_id: str, parameter: str) -> dict[str, Any] | None:
    if not snapshot:
        return None
    s = next((s for s in snapshot["settings"] if s["rule_id"] == rule_id and s["parameter"] == parameter), None)
    if s is None:
        return None
    return {"value": s["value"], "snapshot_id": snapshot["snapshot_id"], "snapshot_digest": snapshot["digest"],
            "captured_at": snapshot["captured_at"], "setting_reference": s["setting_reference"], **PROVENANCE}
