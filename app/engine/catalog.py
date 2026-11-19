"""Predefined rule catalog.

Loaded from the same policy bundle directory that OPA serves
(``securden/catalog/data.json`` and ``securden/bundle/data.json``), so rule
metadata and decision logic are versioned together. The API also verifies at
readiness time and on every decision that OPA reports the same bundle version.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from ..models.common import UtcDatetime
from ..models.evidence import EVIDENCE_MODELS

_dt = TypeAdapter(UtcDatetime)
PACKAGE_RE = re.compile(r"^securden(\.[a-z0-9_]+)+$")


PARAMETER_TYPES = ("integer", "boolean", "enum_list")


@dataclass(frozen=True)
class ParameterSpec:
    name: str
    type: str  # integer | boolean | enum_list
    default: Any  # None: no Securden default, the caller must state the value
    minimum: int | None
    maximum: int | None
    description: str
    items: tuple[str, ...] = ()  # enum_list: the allowed values


@dataclass(frozen=True)
class RuleVersionSpec:
    rule_id: str
    version: str
    title: str
    status: str  # ACTIVE | RETIRED (predefined) / DRAFT | ACTIVE | INACTIVE (custom)
    effective_from: datetime
    effective_to: datetime | None
    package: str
    severity: str
    description: str
    evidence_type: str
    evidence_requirements: tuple[str, ...]
    parameters: dict[str, ParameterSpec]
    framework_mappings: tuple[dict[str, str], ...]
    remediation: str
    subject_field: str
    source: str  # PREDEFINED | PUBLISHED | CUSTOM | DRAFT
    compiled: dict[str, Any] | None = None

    def covers(self, start: datetime, end: datetime) -> bool:
        if start < self.effective_from:
            return False
        return self.effective_to is None or end <= self.effective_to

    def public(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "title": self.title,
            "status": self.status,
            "source": self.source,
            # stable origin class for rule catalog readers: BUILT_IN (bundle), CUSTOM (customer), GENERATED (OPM RuleSpec)
            "origin": {"CUSTOM": "CUSTOM", "GENERATED": "GENERATED", "DRAFT": "CUSTOM"}.get(self.source, "BUILT_IN"),
            "severity": self.severity,
            "description": self.description,
            "evidence_type": self.evidence_type,
            "evidence_requirements": list(self.evidence_requirements),
            "parameters": {
                p.name: {
                    "type": p.type, "default": p.default, "min": p.minimum,
                    "max": p.maximum, "description": p.description,
                    **({"items": list(p.items)} if p.type == "enum_list" else {}),
                }
                for p in self.parameters.values()
            },
            "effective_from": self.effective_from.isoformat().replace("+00:00", "Z"),
            "effective_to": self.effective_to.isoformat().replace("+00:00", "Z") if self.effective_to else None,
            "framework_mappings": list(self.framework_mappings),
            "remediation": self.remediation,
        }


class Catalog:
    def __init__(self, bundle_version: str, disclaimer: str, rules: dict[str, dict[str, RuleVersionSpec]]):
        self.bundle_version = bundle_version
        self.disclaimer = disclaimer
        self.rules = rules

    @classmethod
    def load(cls, bundle_dir: Path) -> "Catalog":
        bundle = json.loads((bundle_dir / "securden" / "bundle" / "data.json").read_text(encoding="utf-8"))
        raw = json.loads((bundle_dir / "securden" / "catalog" / "data.json").read_text(encoding="utf-8"))
        rules: dict[str, dict[str, RuleVersionSpec]] = {}
        for rule_id, rule in raw["rules"].items():
            versions: dict[str, RuleVersionSpec] = {}
            for version, v in rule["versions"].items():
                if not PACKAGE_RE.match(v["package"]):
                    raise RuntimeError(f"invalid package for {rule_id} {version}")
                if v["evidence_type"] not in EVIDENCE_MODELS:
                    raise RuntimeError(f"unknown evidence type for {rule_id} {version}")
                params = {
                    name: ParameterSpec(
                        name, p["type"], p.get("default"), p.get("min"), p.get("max"), p.get("description", ""),
                        tuple(p.get("items", ())),
                    )
                    for name, p in v.get("parameters", {}).items()
                }
                for p in params.values():
                    if p.type not in PARAMETER_TYPES or (p.type == "enum_list") != bool(p.items):
                        raise RuntimeError(f"invalid parameter '{p.name}' for {rule_id} {version}")
                versions[version] = RuleVersionSpec(
                    rule_id=rule_id,
                    version=version,
                    title=rule["title"],
                    status=v["status"],
                    effective_from=_dt.validate_python(v["effective_from"]),
                    effective_to=_dt.validate_python(v["effective_to"]) if v.get("effective_to") else None,
                    package=v["package"],
                    severity=v["severity"],
                    description=v["description"],
                    evidence_type=v["evidence_type"],
                    evidence_requirements=tuple(v.get("evidence_requirements", [])),
                    parameters=params,
                    framework_mappings=tuple(v.get("framework_mappings", [])),
                    remediation=v.get("remediation", ""),
                    subject_field=rule["subject_field"],
                    # Rules published from the reviewed regulatory catalog are data
                    # for the fixed interpreter (securden.custom.v1), like customer rules.
                    source=v.get("source", "PREDEFINED"),
                    compiled=v.get("compiled"),
                )
                if (versions[version].source == "PUBLISHED") != (versions[version].compiled is not None) or (
                    versions[version].source not in ("PREDEFINED", "PUBLISHED")
                ):
                    raise RuntimeError(f"inconsistent source/compiled definition for {rule_id} {version}")
            rules[rule_id] = versions
        return cls(bundle["version"], raw["framework_mapping_disclaimer"], rules)
