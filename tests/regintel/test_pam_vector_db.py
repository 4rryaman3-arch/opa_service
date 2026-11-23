"""Tests for PAM vector database interpretation and evidence schema test generation."""
from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from regintel.pam_vector_db import (
    PamVectorDatabase,
    PamVectorDbError,
    generate_test_vectors,
    validate_test_vectors,
)

FIELDS = [
    "record_id",
    "scope_tags",
    "policy_id",
    "applies_to_privileged",
    "min_length",
    "complexity_required",
    "enforced_on_reset",
    "rotation_period_days",
    "history_count",
    "captured_at",
]


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest(value):
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def fixture_db(tmp_path, unknown_field=False, bad_digest=False):
    path = tmp_path / "vector.db"
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE django_model(id INTEGER PRIMARY KEY, app_label TEXT, model_name TEXT, object_name TEXT,
          label TEXT, db_table TEXT, verbose_name TEXT, managed INTEGER, proxy INTEGER, abstract INTEGER);
        CREATE TABLE django_field(id INTEGER PRIMARY KEY, model_id INTEGER, name TEXT, column_name TEXT,
          field_class TEXT, internal_type TEXT, null_allowed INTEGER, blank_allowed INTEGER, primary_key INTEGER,
          unique_value INTEGER, indexed INTEGER, editable INTEGER, relation_target TEXT, relation_kind TEXT,
          choices_json TEXT, default_json TEXT);
        CREATE TABLE configuration_constant(id INTEGER PRIMARY KEY, module TEXT, name TEXT, value_type TEXT,
          value_json TEXT, omitted_reason TEXT, content_digest TEXT);
        CREATE TABLE capability(evidence_type TEXT PRIMARY KEY, schema_version TEXT, collection_status TEXT,
          assessment_modes_json TEXT, supported_fields_json TEXT, lookup_fields_json TEXT,
          source_models_json TEXT, caveats_json TEXT, field_meanings_json TEXT, content_digest TEXT);
        CREATE TABLE capability_source_model(evidence_type TEXT, model_label TEXT);
        CREATE TABLE document(id INTEGER PRIMARY KEY, kind TEXT, document_key TEXT, title TEXT,
          content_json TEXT, search_text TEXT, content_digest TEXT);
    """
    )
    db.executemany(
        "INSERT INTO metadata VALUES (?, ?)",
        [
            ("schema_name", "securden.pam.vector"),
            ("schema_version", "1.0"),
            ("generated_at", "2026-11-23T00:00:00Z"),
            ("fts5_enabled", "false"),
        ],
    )
    db.execute(
        "INSERT INTO django_model VALUES (1,?,?,?,?,?,?,?,?,?)",
        (
            "accountmanagement",
            "passwordpolicy",
            "PasswordPolicy",
            "accountmanagement.PasswordPolicy",
            "password_policy",
            "password policy",
            1,
            0,
            0,
        ),
    )
    db.execute(
        "INSERT INTO django_field VALUES (1,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "min_length",
            "min_length",
            "django.db.models.IntegerField",
            "IntegerField",
            0,
            0,
            0,
            0,
            0,
            1,
            None,
            None,
            None,
            None,
        ),
    )
    db.execute(
        "INSERT INTO configuration_constant VALUES (1,?,?,?,?,?,?)",
        (
            "configuration.configuration_constants",
            "PASSWORD_MIN_LENGTH",
            "int",
            "12",
            None,
            _digest("12"),
        ),
    )
    supported = FIELDS + (["not_in_opm"] if unknown_field else [])
    cap = {
        "evidence_type": "password_policy_configuration",
        "schema_version": "1.0",
        "collection_status": "COLLECTED",
        "assessment_modes": ["CONFIGURATION_SNAPSHOT"],
        "supported_fields": supported,
        "lookup_fields": [],
        "source_models": ["accountmanagement.PasswordPolicy"],
        "caveats": [],
        "field_meanings": {},
    }
    db.execute(
        "INSERT INTO capability VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            cap["evidence_type"],
            cap["schema_version"],
            cap["collection_status"],
            _json(cap["assessment_modes"]),
            _json(supported),
            "[]",
            _json(cap["source_models"]),
            "[]",
            "{}",
            _digest(_json(cap)),
        ),
    )
    db.execute(
        "INSERT INTO capability_source_model VALUES (?, ?)",
        (cap["evidence_type"], cap["source_models"][0]),
    )
    content = _json(cap)
    db.execute(
        "INSERT INTO document VALUES (1,?,?,?,?,?,?)",
        (
            "capability",
            "capability:password_policy_configuration",
            "password_policy_configuration",
            content,
            "password policy configuration",
            "sha256:bad" if bad_digest else _digest(content),
        ),
    )
    db.commit()
    db.close()
    return path


def test_interprets_models_constants_and_generates_valid_schema_tests(tmp_path):
    with PamVectorDatabase(fixture_db(tmp_path)) as database:
        context = database.capability_context("password_policy_configuration")
        assert context["model_context"][0]["present"] is True
        assert database.constants()[0]["value"] == 12
        handshake = database.to_collector_handshake()
        assert len(handshake) == 1
        assert handshake[0]["evidence_type"] == "password_policy_configuration"
        vectors = generate_test_vectors(database)
    result = validate_test_vectors(vectors)
    assert result["failed"] == 0
    assert result["passed"] == vectors["summary"]["cases"]
    assert any(
        case["name"] == "reject_unknown_field"
        for case in vectors["capabilities"][0]["cases"]
    )


def test_rejects_capability_fields_unknown_to_opm(tmp_path):
    with PamVectorDatabase(fixture_db(tmp_path, unknown_field=True)) as database:
        with pytest.raises(PamVectorDbError, match="unknown fields"):
            generate_test_vectors(database)


def test_rejects_tampered_documents(tmp_path):
    with pytest.raises(PamVectorDbError, match="invalid document digests"):
        PamVectorDatabase(fixture_db(tmp_path, bad_digest=True))
