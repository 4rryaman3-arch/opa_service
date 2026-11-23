"""Read PAM's ``vector.db`` and derive deterministic evidence-schema tests.

This module treats the database as untrusted input.  It opens the file
read-only, validates its schema and per-document digests, and never executes
SQL or Python supplied by the database.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Self

from app.models.evidence import (
    CUSTOM_RULE_FIELDS,
    EVIDENCE_MODELS,
    EVIDENCE_SCHEMA_VERSIONS,
)
from pydantic import ValidationError

SCHEMA_NAME = "securden.pam.vector"
SCHEMA_VERSION = "1.0"
REQUIRED_TABLES = frozenset({
    "metadata", "django_model", "django_field", "configuration_constant",
    "capability", "capability_source_model", "document",
})


class PamVectorDbError(ValueError):
    pass


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _loads(value: str | None, default: Any) -> Any:
    if value is None:
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PamVectorDbError("invalid JSON in vector.db") from exc


class PamVectorDatabase:
    """Validated read-only access to a PAM capability knowledge database."""

    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()
        if not self.path.is_file():
            raise PamVectorDbError(f"PAM vector database does not exist: {self.path}")
        uri = f"file:{self.path.as_posix()}?mode=ro&immutable=1"
        try:
            self.connection = sqlite3.connect(uri, uri=True, check_same_thread=False)
        except sqlite3.Error as exc:
            raise PamVectorDbError("unable to open PAM vector database") from exc
        self.connection.row_factory = sqlite3.Row
        try:
            self._validate()
        except Exception:
            self.connection.close()
            raise

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _validate(self) -> None:
        integrity = self.connection.execute("PRAGMA integrity_check").fetchone()
        if not integrity or integrity[0] != "ok":
            raise PamVectorDbError("PAM vector database failed SQLite integrity_check")
        tables = {row[0] for row in self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
        )}
        missing = sorted(REQUIRED_TABLES - tables)
        if missing:
            raise PamVectorDbError(f"PAM vector database is missing tables: {missing}")
        metadata = self.metadata()
        if metadata.get("schema_name") != SCHEMA_NAME:
            raise PamVectorDbError("unsupported PAM vector database schema name")
        if metadata.get("schema_version") != SCHEMA_VERSION:
            raise PamVectorDbError(
                f"unsupported PAM vector database schema version: {metadata.get('schema_version')}"
            )
        bad = []
        for row in self.connection.execute("SELECT document_key, content_json, content_digest FROM document"):
            if _sha256_text(row["content_json"]) != row["content_digest"]:
                bad.append(row["document_key"])
        if bad:
            raise PamVectorDbError(f"PAM vector database has invalid document digests: {bad[:10]}")

    def metadata(self) -> dict[str, str]:
        return {row["key"]: row["value"] for row in self.connection.execute(
            "SELECT key, value FROM metadata ORDER BY key"
        )}

    @property
    def digest(self) -> str:
        return _file_digest(self.path)

    def constants(self, module: str | None = None) -> list[dict[str, Any]]:
        sql = ("SELECT module, name, value_type, value_json, omitted_reason, content_digest "
               "FROM configuration_constant")
        params: tuple[Any, ...] = ()
        if module is not None:
            sql += " WHERE module=?"
            params = (module,)
        sql += " ORDER BY module, name"
        return [{
            "module": row["module"],
            "name": row["name"],
            "value_type": row["value_type"],
            "value": _loads(row["value_json"], None),
            "omitted_reason": row["omitted_reason"],
            "digest": row["content_digest"],
        } for row in self.connection.execute(sql, params)]

    def capabilities(self) -> list[dict[str, Any]]:
        result = []
        for row in self.connection.execute("SELECT * FROM capability ORDER BY evidence_type"):
            cols = row.keys()
            result.append({
                "evidence_type": row["evidence_type"],
                "schema_version": row["schema_version"],
                "collection_status": row["collection_status"],
                "assessment_modes": _loads(row["assessment_modes_json"], []),
                "supported_fields": _loads(row["supported_fields_json"], []),
                "lookup_fields": _loads(row["lookup_fields_json"], []),
                "source_models": _loads(row["source_models_json"], []),
                "caveats": _loads(row["caveats_json"], []),
                "field_meanings": _loads(row["field_meanings_json"], {}),
                "feature": row["feature"] if "feature" in cols else "",
                "scope": row["scope"] if "scope" in cols else "",
                "limitation": row["limitation"] if "limitation" in cols else "",
                "remediation": row["remediation"] if "remediation" in cols else "",
                "digest": row["content_digest"],
            })
        return result

    def setting_sources(self) -> dict[str, str]:
        """Return the dictionary of compliance parameter to PAM model settings sources."""
        try:
            return {row["setting_key"]: row["source_expression"]
                    for row in self.connection.execute("SELECT setting_key, source_expression FROM setting_source ORDER BY setting_key")}
        except sqlite3.OperationalError:
            return _loads(self.metadata().get("settings_sources_json"), {})

    def framework_controls(self, evidence_type: str | None = None) -> list[dict[str, Any]]:
        """Return regulatory framework controls (e.g. NIST SP 800-53) mapped to capabilities."""
        try:
            sql = "SELECT * FROM framework_control"
            params: tuple[Any, ...] = ()
            if evidence_type is not None:
                sql += " WHERE evidence_type=?"
                params = (evidence_type,)
            sql += " ORDER BY control_id"
            rows = self.connection.execute(sql, params).fetchall()
            return [{
                "control_id": row["control_id"],
                "framework_id": row["framework_id"],
                "title": row["title"],
                "requirement_summary": row["requirement_summary"],
                "securden_capability": row["securden_capability"],
                "evidence_type": row["evidence_type"],
                "pam_control_id": row["pam_control_id"],
                "pam_models": _loads(row["pam_models_json"], []),
                "recommended_test": _loads(row["recommended_test_json"], {}),
                "digest": row["content_digest"],
            } for row in rows]
        except sqlite3.OperationalError:
            return []

    def to_collector_handshake(self, collected_only: bool = True) -> list[dict[str, Any]]:
        """Extract evidence capability declarations formatted for the OPM collector handshake."""
        evidence = []
        for cap in self.capabilities():
            if collected_only and cap["collection_status"] != "COLLECTED":
                continue
            item: dict[str, Any] = {
                "evidence_type": cap["evidence_type"],
                "schema_version": cap["schema_version"],
            }
            if cap["assessment_modes"]:
                item["assessment_modes"] = cap["assessment_modes"]
            if cap["supported_fields"]:
                item["supported_fields"] = cap["supported_fields"]
            evidence.append(item)
        return evidence

    def _resolve_model(self, requested_label: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM django_model WHERE lower(label)=lower(?)", (requested_label,)
        ).fetchone()
        resolution = "EXACT"
        if row is None:
            object_name = requested_label.rsplit(".", 1)[-1]
            candidates = self.connection.execute(
                "SELECT * FROM django_model WHERE lower(object_name)=lower(?) ORDER BY label", (object_name,)
            ).fetchall()
            if len(candidates) == 1:
                row, resolution = candidates[0], "OBJECT_NAME"
            elif len(candidates) > 1:
                return {"requested_label": requested_label, "present": False, "resolution": "AMBIGUOUS",
                        "candidates": [item["label"] for item in candidates]}
        if row is None:
            return {"requested_label": requested_label, "present": False, "resolution": "MISSING", "fields": []}
        fields = [{
            "name": field["name"],
            "column": field["column_name"],
            "type": field["internal_type"],
            "null": bool(field["null_allowed"]),
            "relation_target": field["relation_target"],
            "relation_kind": field["relation_kind"],
        } for field in self.connection.execute(
            "SELECT * FROM django_field WHERE model_id=? ORDER BY name", (row["id"],)
        )]
        return {
            "requested_label": requested_label,
            "present": True,
            "resolution": resolution,
            "resolved_label": row["label"],
            "db_table": row["db_table"],
            "fields": fields,
        }

    def capability_context(self, evidence_type: str) -> dict[str, Any]:
        capability = next((item for item in self.capabilities()
                           if item["evidence_type"] == evidence_type), None)
        if capability is None:
            raise PamVectorDbError(f"unknown PAM capability: {evidence_type}")
        return {**capability,
                "model_context": [self._resolve_model(label) for label in capability["source_models"]]}

    def search(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        query = query.strip()
        if not query:
            return []
        limit = max(1, min(int(limit), 100))
        has_fts = self.metadata().get("fts5_enabled") == "true"
        if has_fts:
            # Quote user input so FTS syntax is data, not an expression.
            phrase = '"' + query.replace('"', '""') + '"'
            rows = self.connection.execute(
                "SELECT d.kind, d.document_key, d.title, d.content_json, d.content_digest "
                "FROM document_fts f JOIN document d ON d.id=f.rowid WHERE document_fts MATCH ? "
                "ORDER BY bm25(document_fts), d.document_key LIMIT ?", (phrase, limit)
            ).fetchall()
        else:
            escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            rows = self.connection.execute(
                "SELECT kind, document_key, title, content_json, content_digest FROM document "
                "WHERE search_text LIKE ? ESCAPE '\\' ORDER BY document_key LIMIT ?",
                (f"%{escaped}%", limit),
            ).fetchall()
        return [{"kind": row["kind"], "key": row["document_key"], "title": row["title"],
                 "content": _loads(row["content_json"], {}), "digest": row["content_digest"]} for row in rows]


_ENUM_OVERRIDES = {
    "approval_status": "PENDING",
    "entitlement_status": "AUTHORIZED",
    "last_review_outcome": "CERTIFIED",
    "mfa_status": "NOT_PERFORMED",
    "recording_status": "AVAILABLE",
    "status": "ACTIVE",
}
_NULL_OVERRIDES = {"mfa_method", "idle_timeout_minutes"}


def _sample_value(field: str, spec: dict[str, Any]) -> Any:
    if field in _NULL_OVERRIDES:
        return None
    kind = spec["type"]
    if kind == "string":
        return "PAM-TEST-001" if field == "rule_id" else f"sample-{field.replace('_', '-')}"
    if kind == "boolean":
        return field == "post_review_completed"
    if kind == "enum":
        return _ENUM_OVERRIDES.get(field, (spec.get("values") or ("UNKNOWN",))[0])
    if kind == "integer":
        return 1
    if kind == "datetime":
        late = any(token in field for token in ("end", "expires", "used", "delivery", "review", "rotated"))
        return "2026-01-02T00:00:00Z" if late else "2026-01-01T00:00:00Z"
    if kind == "string_list":
        return []
    raise PamVectorDbError(f"unsupported OPM field type {kind!r} for {field}")


def _valid_record(evidence_type: str, declared_fields: set[str]) -> dict[str, Any]:
    model = EVIDENCE_MODELS[evidence_type]
    catalogue = CUSTOM_RULE_FIELDS[evidence_type]
    record: dict[str, Any] = {}
    for name, model_field in model.model_fields.items():
        if name not in catalogue:
            continue
        if model_field.is_required() or name in declared_fields:
            record[name] = _sample_value(name, catalogue[name])
    # Relationship-safe values for schemas with cross-field validators.
    if evidence_type == "break_glass_event":
        record.update(justification_provided=True, justification_length=1,
                      post_review_completed=True, post_review_at="2026-01-02T00:00:00Z")
    if evidence_type == "mfa_configuration":
        record.update(mfa_enforced=False, mfa_methods=[])
    if evidence_type == "privileged_access_authentication":
        record.update(mfa_status="NOT_PERFORMED", mfa_method=None)
    if evidence_type == "session_policy_configuration":
        record.update(idle_timeout_enabled=False, idle_timeout_minutes=None)
    try:
        return model.model_validate(record).model_dump(mode="json")
    except ValidationError as exc:
        raise PamVectorDbError(f"could not build valid {evidence_type} test record: {exc}") from exc


def generate_test_vectors(database: PamVectorDatabase) -> dict[str, Any]:
    """Generate deterministic collector/evidence contract tests from ``vector.db``.

    These complement rule-specific OPA cases in ``generated_rules.build_cases``:
    this set proves that PAM's advertised fields match OPM's pinned evidence
    schemas and identifies missing source-model metadata before rule generation.
    """
    capabilities = []
    total_cases = 0
    for capability in database.capabilities():
        evidence_type = capability["evidence_type"]
        if evidence_type not in EVIDENCE_MODELS:
            raise PamVectorDbError(f"PAM declares an evidence type OPM does not support: {evidence_type}")
        if capability["schema_version"] != EVIDENCE_SCHEMA_VERSIONS[evidence_type]:
            raise PamVectorDbError(
                f"schema mismatch for {evidence_type}: PAM={capability['schema_version']} "
                f"OPM={EVIDENCE_SCHEMA_VERSIONS[evidence_type]}"
            )
        declared = set(capability["supported_fields"]) | set(capability["lookup_fields"])
        unknown = sorted(declared - set(CUSTOM_RULE_FIELDS[evidence_type]))
        if unknown:
            raise PamVectorDbError(f"unknown fields for {evidence_type}: {unknown}")
        record = _valid_record(evidence_type, declared)
        cases: list[dict[str, Any]] = [
            {"name": "accept_declared_record", "record": record, "expected": "ACCEPT"},
            {"name": "reject_unknown_field", "record": {**record, "undeclared_secret": "blocked"},
             "expected": "REJECT"},
        ]
        model = EVIDENCE_MODELS[evidence_type]
        for field in sorted(declared):
            model_field = model.model_fields.get(field)
            if model_field is not None and model_field.is_required():
                cases.append({"name": f"reject_missing_required_{field}",
                              "record": {key: value for key, value in record.items() if key != field},
                              "expected": "REJECT"})
        total_cases += len(cases)
        context = database.capability_context(evidence_type)
        capabilities.append({
            "evidence_type": evidence_type,
            "schema_version": capability["schema_version"],
            "collection_status": capability["collection_status"],
            "assessment_modes": capability["assessment_modes"],
            "supported_fields": capability["supported_fields"],
            "lookup_fields": capability["lookup_fields"],
            "source_models": context["model_context"],
            "cases": cases,
        })
    return {
        "schema_version": "1.0",
        "source": {"path": str(database.path), "digest": database.digest,
                   "generated_at": database.metadata().get("generated_at")},
        "summary": {"capabilities": len(capabilities), "cases": total_cases,
                    "configuration_constants": len(database.constants())},
        "capabilities": capabilities,
    }


def validate_test_vectors(vectors: dict[str, Any]) -> dict[str, Any]:
    passed = failed = 0
    failures = []
    for capability in vectors.get("capabilities", []):
        evidence_type = capability["evidence_type"]
        model = EVIDENCE_MODELS[evidence_type]
        for case in capability.get("cases", []):
            try:
                model.model_validate(case["record"])
                actual = "ACCEPT"
            except ValidationError:
                actual = "REJECT"
            if actual == case["expected"]:
                passed += 1
            else:
                failed += 1
                failures.append({"evidence_type": evidence_type, "case": case["name"],
                                 "expected": case["expected"], "actual": actual})
    return {"passed": passed, "failed": failed, "failures": failures,
            "validated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


# ---------------------------------------------------------------- use by rule generation

ENV_PATH = "OPM_REGINTEL_VECTOR_DB"


@dataclass(frozen=True)
class GenerationSnapshot:
    """What rule generation uses of one validated vector.db. Local only: nothing here enters a model prompt."""

    digest: str
    schema_tests: int
    collected: dict[str, frozenset[str]]
    stored_null: dict[str, dict[str, str]] = field(default_factory=dict)  # evidence type -> field -> PAM model field

    def not_collected(self, evidence_type: str, fields: set[str]) -> list[str]:
        """Fields (or the whole type) a rule needs that vector.db does not list as collected."""
        if evidence_type not in self.collected:
            return [evidence_type]
        return sorted(fields - self.collected[evidence_type])


def load_for_generation() -> GenerationSnapshot | None:
    """Validated snapshot of the configured vector.db, or None when none is configured. A configured database that is
    missing, invalid or fails its own schema tests raises PamVectorDbError, so generation stops."""
    path = os.environ.get(ENV_PATH)
    if not path:
        return None
    with PamVectorDatabase(path) as database:
        vectors = generate_test_vectors(database)
        result = validate_test_vectors(vectors)
        if result["failed"] or not result["passed"]:
            raise PamVectorDbError(f"vector.db schema tests failed: {result['failures'][:5]}")
        collected, stored_null = {}, {}
        for c in vectors["capabilities"]:
            etype = c["evidence_type"]
            if c["collection_status"] == "COLLECTED":
                collected[etype] = frozenset(c["supported_fields"]) - frozenset(c["lookup_fields"])
            # only a source-model field of exactly the same name counts; anything looser would be a guess
            stored_null[etype] = {f["name"]: f"{m['resolved_label']}.{f['name']}" for m in c["source_models"]
                                  if m["resolution"] == "EXACT" for f in m["fields"] if f["null"]}
        return GenerationSnapshot(database.digest, result["passed"], collected, stored_null)
