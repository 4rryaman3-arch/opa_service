"""Catalog database (SQLite).

One file holds the jurisdiction registry, source registry, retrieved documents,
the reviewed catalog and the publication log. The writer is the ``regintel``
CLI / worker on the host; the API opens the same file read-only.

Rollback-journal mode (not WAL) is used on purpose: the API container mounts
the file read-only, and WAL readers need to write the -shm file.

Immutability is enforced in the database, not only in code: once a row leaves
DRAFT its regulatory content can no longer be updated (triggers below).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS jurisdiction (
    code             TEXT PRIMARY KEY,
    kind             TEXT NOT NULL CHECK (kind IN ('COUNTRY_OR_TERRITORY','SUBDIVISION','SUPRANATIONAL','INTERNATIONAL')),
    name             TEXT NOT NULL,
    alpha3           TEXT,
    numeric_code     TEXT,
    parent_code      TEXT REFERENCES jurisdiction(code),
    subdivision_type TEXT,
    languages        TEXT NOT NULL DEFAULT '[]',
    registry_source  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_jurisdiction_parent ON jurisdiction(parent_code);

CREATE TABLE IF NOT EXISTS jurisdiction_membership (
    group_code  TEXT NOT NULL REFERENCES jurisdiction(code),
    member_code TEXT NOT NULL REFERENCES jurisdiction(code),
    valid_from  TEXT NOT NULL,
    valid_to    TEXT,                       -- exclusive
    PRIMARY KEY (group_code, member_code, valid_from)
);

CREATE TABLE IF NOT EXISTS regulatory_authority (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    jurisdiction_code TEXT NOT NULL REFERENCES jurisdiction(code),
    official_domains  TEXT NOT NULL DEFAULT '[]',
    languages         TEXT NOT NULL DEFAULT '[]',
    verification_status TEXT NOT NULL DEFAULT 'UNVERIFIED' CHECK (verification_status IN ('UNVERIFIED','VERIFIED')),
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS regulatory_framework (
    id                TEXT PRIMARY KEY,
    title             TEXT NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('LAW','REGULATION','DIRECTIVE','STANDARD','GUIDELINE','INDUSTRY_FRAMEWORK')),
    adoption          TEXT NOT NULL CHECK (adoption IN ('STATUTORY','VOLUNTARY','CONTRACTUAL')),
    jurisdiction_code TEXT NOT NULL REFERENCES jurisdiction(code),
    authority_id      TEXT REFERENCES regulatory_authority(id),
    industries        TEXT NOT NULL DEFAULT '[]',
    cross_border      INTEGER NOT NULL DEFAULT 0,
    implements_framework_id TEXT REFERENCES regulatory_framework(id),
    published_on      TEXT,
    effective_from    TEXT,
    effective_to      TEXT,                 -- exclusive; set when repealed / superseded
    lifecycle         TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK (lifecycle IN ('UNKNOWN','NOT_YET_IN_FORCE','IN_FORCE','REPEALED','SUPERSEDED')),
    superseded_by     TEXT REFERENCES regulatory_framework(id),
    verification_status TEXT NOT NULL DEFAULT 'UNVERIFIED' CHECK (verification_status IN ('UNVERIFIED','VERIFIED')),
    verified_by       TEXT,
    created_at        TEXT NOT NULL,
    updated_seq       INTEGER,
    organization_scope TEXT                -- NULL = global/official; else the owning namespace
);

-- Opaque org namespaces of the Django rewrite workflow, bound to the first
-- credential that used them. A scope is never readable by another credential.
CREATE TABLE IF NOT EXISTS organization_scope_binding (
    scope      TEXT PRIMARY KEY,
    key_id     TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Idempotency of v1 scoped uploads: one row per (actor, scope, request_key).
CREATE TABLE IF NOT EXISTS upload_request (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    actor         TEXT NOT NULL,
    organization_scope TEXT NOT NULL,
    request_key   TEXT NOT NULL,
    params_digest TEXT NOT NULL,            -- digest of the metadata the upload was made with
    content_sha256 TEXT NOT NULL,           -- digest of the exact upload bytes
    source_id     TEXT NOT NULL REFERENCES source(id),
    document_ids  TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL,
    UNIQUE (actor, organization_scope, request_key)
);

CREATE TABLE IF NOT EXISTS source (
    id                TEXT PRIMARY KEY,
    adapter_type      TEXT NOT NULL,
    name              TEXT NOT NULL,
    authority_id      TEXT NOT NULL REFERENCES regulatory_authority(id),
    jurisdiction_code TEXT NOT NULL REFERENCES jurisdiction(code),
    languages         TEXT NOT NULL DEFAULT '[]',
    config            TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'PROPOSED' CHECK (status IN ('PROPOSED','VERIFIED','REJECTED','DISABLED')),
    proposal_origin   TEXT NOT NULL,        -- SEED | MANUAL | DISCOVERY:<provider>
    proposed_by       TEXT NOT NULL,
    freshness_sla_hours INTEGER NOT NULL DEFAULT 168,
    last_sync_at      TEXT,
    last_sync_status  TEXT,
    last_success_at   TEXT,
    last_change_at    TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL,
    organization_scope TEXT                -- NULL = global/official; else the owning namespace
);

CREATE TABLE IF NOT EXISTS source_verification (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id   TEXT NOT NULL REFERENCES source(id),
    method      TEXT NOT NULL,
    outcome     TEXT NOT NULL CHECK (outcome IN ('VERIFIED','REJECTED')),
    verifier    TEXT NOT NULL,
    evidence    TEXT NOT NULL,              -- what the verifier checked, in their words
    config_digest TEXT NOT NULL,            -- verification is void if the config changes
    verified_at TEXT NOT NULL,
    decision_origin TEXT NOT NULL DEFAULT 'HUMAN',  -- HUMAN | AUTOMATED (engine policy decision)
    policy_version  TEXT                    -- automation policy that made an AUTOMATED decision
);

CREATE TABLE IF NOT EXISTS sync_run (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id   TEXT NOT NULL REFERENCES source(id),
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL,              -- RUNNING | SUCCESS | PARTIAL | FAILED
    documents_seen INTEGER NOT NULL DEFAULT 0,
    versions_new   INTEGER NOT NULL DEFAULT 0,
    versions_changed INTEGER NOT NULL DEFAULT 0,
    errors      TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS regulatory_document (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id    TEXT NOT NULL REFERENCES source(id),
    framework_id TEXT REFERENCES regulatory_framework(id),
    external_id  TEXT NOT NULL,
    title        TEXT,
    url          TEXT NOT NULL,
    language     TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    organization_scope TEXT,               -- NULL = global/official; else the owning namespace
    UNIQUE (source_id, external_id, language)
);

CREATE TABLE IF NOT EXISTS regulatory_document_version (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id    INTEGER NOT NULL REFERENCES regulatory_document(id),
    version_label  TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    format         TEXT NOT NULL,
    byte_length    INTEGER NOT NULL,
    retrieved_at   TEXT NOT NULL,
    retrieved_url  TEXT NOT NULL,
    etag           TEXT,
    last_modified  TEXT,
    published_on   TEXT,
    effective_from TEXT,
    effective_to   TEXT,
    complete       INTEGER NOT NULL,
    incomplete_reason TEXT,
    storage_path   TEXT,
    status         TEXT NOT NULL DEFAULT 'AWAITING_REVIEW' CHECK (status IN ('AWAITING_REVIEW','REVIEWED','REJECTED','SUPERSEDED')),
    supersedes_version_id INTEGER REFERENCES regulatory_document_version(id),
    UNIQUE (document_id, content_sha256)
);

CREATE TABLE IF NOT EXISTS document_section (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id  INTEGER NOT NULL REFERENCES regulatory_document_version(id),
    ordinal     INTEGER NOT NULL,
    section_ref TEXT NOT NULL,
    heading     TEXT,
    text        TEXT NOT NULL,
    UNIQUE (version_id, ordinal)
);

CREATE TABLE IF NOT EXISTS regulatory_change (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id      TEXT NOT NULL REFERENCES source(id),
    document_id    INTEGER NOT NULL REFERENCES regulatory_document(id),
    old_version_id INTEGER REFERENCES regulatory_document_version(id),
    new_version_id INTEGER NOT NULL REFERENCES regulatory_document_version(id),
    detected_at    TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','TRIAGED'))
);

CREATE TABLE IF NOT EXISTS regulatory_requirement (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    framework_id        TEXT NOT NULL REFERENCES regulatory_framework(id),
    document_version_id INTEGER NOT NULL REFERENCES regulatory_document_version(id),
    section_id          INTEGER NOT NULL REFERENCES document_section(id),
    section_ref         TEXT NOT NULL,
    original_language   TEXT NOT NULL,
    original_text       TEXT NOT NULL,      -- verbatim passage from the official text
    obligation_type     TEXT NOT NULL CHECK (obligation_type IN ('MANDATORY','RECOMMENDED','PERMISSIVE','UNDETERMINED')),
    pam_domains         TEXT NOT NULL,
    thresholds          TEXT NOT NULL DEFAULT '[]',  -- only values literally present in original_text
    extraction          TEXT NOT NULL,      -- {method, model, model_version, prompt_version}
    translation_en      TEXT,
    translation_model   TEXT,
    translation_model_version TEXT,
    translation_status  TEXT NOT NULL CHECK (translation_status IN ('NOT_REQUIRED','UNREVIEWED','REVIEWED','REJECTED')),
    translation_reviewer TEXT,
    effective_from      TEXT,
    effective_to        TEXT,
    status              TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','APPROVED','REJECTED','SUPERSEDED','REPEALED','WITHDRAWN')),
    superseded_by       INTEGER REFERENCES regulatory_requirement(id),
    created_by          TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    published_seq       INTEGER,
    organization_scope  TEXT,              -- NULL = global/official; else the owning namespace
    UNIQUE (document_version_id, section_id, original_text)
);

CREATE TABLE IF NOT EXISTS pam_control (
    id          TEXT PRIMARY KEY,
    domain      TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS framework_control_mapping (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    requirement_id INTEGER NOT NULL REFERENCES regulatory_requirement(id),
    pam_control_id TEXT NOT NULL REFERENCES pam_control(id),
    strength       TEXT NOT NULL CHECK (strength IN ('DIRECT','PARTIAL','SUPPORTING')),
    rationale      TEXT NOT NULL CHECK (length(rationale) >= 20),
    limitations    TEXT NOT NULL CHECK (length(limitations) >= 10),
    status         TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','APPROVED','REJECTED','WITHDRAWN')),
    created_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    published_seq  INTEGER,
    organization_scope TEXT                -- NULL = global/official; else the owning namespace
);
-- many-to-many, but only one live mapping per (requirement, control) pair and owner (rebuilt with
-- COALESCE(organization_scope,'') by CatalogDb._migrate)
CREATE UNIQUE INDEX IF NOT EXISTS ux_mapping_live ON framework_control_mapping(requirement_id, pam_control_id)
    WHERE status IN ('DRAFT','APPROVED');

CREATE TABLE IF NOT EXISTS evidence_requirement (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    pam_control_id TEXT NOT NULL REFERENCES pam_control(id),
    evidence_type  TEXT NOT NULL,
    description    TEXT NOT NULL,
    fields         TEXT NOT NULL DEFAULT '[]',
    status         TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','APPROVED','REJECTED','WITHDRAWN')),
    created_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    published_seq  INTEGER
);

CREATE TABLE IF NOT EXISTS applicability_criteria (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    framework_id  TEXT NOT NULL REFERENCES regulatory_framework(id),
    criteria      TEXT NOT NULL,
    rationale     TEXT NOT NULL CHECK (length(rationale) >= 20),
    requirement_ids TEXT NOT NULL DEFAULT '[]',   -- scope provisions this is based on
    status        TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','APPROVED','REJECTED','WITHDRAWN')),
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    published_seq INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_criteria_live ON applicability_criteria(framework_id) WHERE status = 'APPROVED';

CREATE TABLE IF NOT EXISTS opa_rule_definition (
    rule_id        TEXT PRIMARY KEY,
    pam_control_id TEXT NOT NULL REFERENCES pam_control(id),
    kind           TEXT NOT NULL CHECK (kind IN ('PREDEFINED_REGO','STRUCTURED')),
    title          TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rule_version (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id      TEXT NOT NULL REFERENCES opa_rule_definition(rule_id),
    version      TEXT NOT NULL,
    definition   TEXT NOT NULL,            -- structured definition (never Rego)
    digest       TEXT NOT NULL,
    threshold_provenance TEXT NOT NULL DEFAULT '[]',
    tests        TEXT NOT NULL DEFAULT '[]',
    authored_by  TEXT NOT NULL,
    ai_generated INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','APPROVED','REJECTED','RETIRED')),
    created_at   TEXT NOT NULL,
    UNIQUE (rule_id, version)
);

CREATE TABLE IF NOT EXISTS remediation_template (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_category   TEXT NOT NULL,
    pam_control_id     TEXT NOT NULL REFERENCES pam_control(id),
    corrective_actions TEXT NOT NULL,
    securden_capabilities TEXT NOT NULL,
    customer_responsibilities TEXT NOT NULL,
    source_citations   TEXT NOT NULL,       -- [{requirement_id}] and/or [{reference, url}]
    auto_execute       INTEGER NOT NULL DEFAULT 0 CHECK (auto_execute = 0),
    status             TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','APPROVED','REJECTED','WITHDRAWN')),
    created_by         TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    published_seq      INTEGER
);

CREATE TABLE IF NOT EXISTS review_approval (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type   TEXT NOT NULL,
    entity_id     TEXT NOT NULL,
    decision      TEXT NOT NULL CHECK (decision IN ('APPROVED','REJECTED')),
    reviewer      TEXT NOT NULL,
    comment       TEXT NOT NULL DEFAULT '',
    attestations  TEXT NOT NULL DEFAULT '{}',
    entity_digest TEXT NOT NULL,
    decided_at    TEXT NOT NULL,
    decision_origin TEXT NOT NULL DEFAULT 'HUMAN',  -- HUMAN | AUTOMATED (engine policy decision)
    policy_version  TEXT,                   -- automation policy that made an AUTOMATED decision
    attempt_id      INTEGER                 -- extraction_attempt row of the model review pass, if any
);

CREATE TABLE IF NOT EXISTS catalog_publication (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    published_at TEXT NOT NULL,
    published_by TEXT NOT NULL,
    kind         TEXT NOT NULL,             -- CATALOG | WITHDRAWAL | BUNDLE | REGISTRY
    summary      TEXT NOT NULL,
    digest       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS catalog_change (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    publication_seq INTEGER NOT NULL REFERENCES catalog_publication(seq),
    entity_type     TEXT NOT NULL,
    entity_id       TEXT NOT NULL,
    change_type     TEXT NOT NULL CHECK (change_type IN ('UPSERT','WITHDRAW')),
    at              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bundle_version (
    version      TEXT PRIMARY KEY,
    base_version TEXT NOT NULL,
    digest       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    test_report  TEXT NOT NULL,
    active       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS bundle_rule (
    bundle_version TEXT NOT NULL REFERENCES bundle_version(version),
    rule_version_id INTEGER NOT NULL REFERENCES rule_version(id),
    PRIMARY KEY (bundle_version, rule_version_id)
);

-- One row per LLM call during extraction/translation, success or failure.
-- raw_response is the model's generated text only: prompts, system text and any
-- internal reasoning are never stored or returned.
CREATE TABLE IF NOT EXISTS extraction_attempt (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id        TEXT,                     -- admin jobs-queue id; NULL when run from the CLI
    version_id    INTEGER NOT NULL REFERENCES regulatory_document_version(id),
    section_id    INTEGER REFERENCES document_section(id),
    kind          TEXT NOT NULL CHECK (kind IN ('EXTRACTION','TRANSLATION','REVIEW','TRANSLATION_REVIEW')),
    requirement_id INTEGER REFERENCES regulatory_requirement(id),  -- TRANSLATION: the draft translated
    model         TEXT NOT NULL,
    model_version TEXT NOT NULL,            -- weights digest reported by the runtime
    runtime       TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    finished_at   TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('SUCCEEDED','PARTIAL','VALIDATION_FAILED','MALFORMED_OUTPUT','LLM_ERROR')),
    raw_response  TEXT,                     -- verbatim model output, including malformed/truncated
    raw_truncated INTEGER NOT NULL DEFAULT 0,
    raw_unavailable_reason TEXT,            -- set instead of raw_response when output was never returned
    parsed_json   TEXT,                     -- set when the raw output parsed as JSON
    validated_json TEXT,                    -- set when validation accepted at least the shape
    validation_errors TEXT NOT NULL DEFAULT '[]',   -- [{index, path, code, message}]
    accepted_requirement_ids TEXT NOT NULL DEFAULT '[]',
    rejected_candidates TEXT NOT NULL DEFAULT '[]', -- [{index, code, message, candidate}]
    error         TEXT                      -- runtime error summary for LLM_ERROR
);
CREATE INDEX IF NOT EXISTS ix_attempt_version ON extraction_attempt(version_id);

-- ---------------------------------------------------------------- organization policy contexts
-- User-declared organization policy (provenance CUSTOMER_POLICY). Always owned by one
-- organization scope and tenant; never global, never regulatory text.
CREATE TABLE IF NOT EXISTS policy_context (
    id                 TEXT PRIMARY KEY,         -- pctx-<hex>
    organization_scope TEXT NOT NULL,
    tenant_id          TEXT NOT NULL,
    created_by         TEXT NOT NULL,            -- credential key_id
    created_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_policy_context_owner ON policy_context(organization_scope, tenant_id);

CREATE TABLE IF NOT EXISTS policy_context_version (
    id                      TEXT PRIMARY KEY,    -- pcv-<hex>
    context_id              TEXT NOT NULL REFERENCES policy_context(id),
    version                 INTEGER NOT NULL CHECK (version >= 1),
    organization_scope      TEXT NOT NULL,
    tenant_id               TEXT NOT NULL,
    title                   TEXT NOT NULL,
    description             TEXT,
    policy_reference        TEXT NOT NULL,       -- JSON
    effective_from          TEXT NOT NULL,
    effective_to            TEXT,
    policy_controls         TEXT NOT NULL,       -- JSON, pinned control versions + digests
    control_catalog_version TEXT NOT NULL,
    digest                  TEXT NOT NULL,
    request_key             TEXT NOT NULL,
    request_digest          TEXT NOT NULL,
    created_by              TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    UNIQUE (context_id, version),
    UNIQUE (organization_scope, tenant_id, request_key)
);

CREATE TABLE IF NOT EXISTS collector_capability (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_scope TEXT NOT NULL,
    tenant_id          TEXT NOT NULL,
    collector_info     TEXT NOT NULL,            -- JSON {name, version}
    evidence_support   TEXT NOT NULL,            -- JSON {evidence_type: schema_version}
    evidence_detail    TEXT NOT NULL DEFAULT '{}', -- JSON {evidence_type: {assessment_modes[], supported_fields[]}}
    digest             TEXT NOT NULL,
    declared_by        TEXT NOT NULL,
    declared_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_collector_owner ON collector_capability(organization_scope, tenant_id);

CREATE TRIGGER IF NOT EXISTS trg_policy_version_immutable
BEFORE UPDATE ON policy_context_version
BEGIN SELECT RAISE(ABORT, 'policy context versions are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_policy_version_preserved
BEFORE DELETE ON policy_context_version
BEGIN SELECT RAISE(ABORT, 'policy context versions are preserved'); END;

CREATE TRIGGER IF NOT EXISTS trg_collector_capability_immutable
BEFORE UPDATE ON collector_capability
BEGIN SELECT RAISE(ABORT, 'collector capability declarations are immutable'); END;

-- Legacy: validation runs of the removed NIST mapping proposal set. No longer written; kept so
-- existing immutable audit rows survive (the table and its triggers are never dropped).
CREATE TABLE IF NOT EXISTS mapping_proposal_run (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    framework_id          TEXT NOT NULL,
    organization_scope    TEXT,
    tenant_id             TEXT,
    proposal_set_id       TEXT,
    proposal_set_status   TEXT,
    catalog_version       INTEGER,
    policy_bundle_version TEXT,
    proposal_digest       TEXT NOT NULL,
    proposal_result       TEXT NOT NULL,       -- JSON, the full evaluate() body
    created_by            TEXT NOT NULL,
    created_at            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_proposal_run_fw ON mapping_proposal_run(framework_id, organization_scope);

CREATE TRIGGER IF NOT EXISTS trg_proposal_run_immutable
BEFORE UPDATE ON mapping_proposal_run
BEGIN SELECT RAISE(ABORT, 'mapping proposal runs are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_proposal_run_preserved
BEFORE DELETE ON mapping_proposal_run
BEGIN SELECT RAISE(ABORT, 'mapping proposal runs are preserved'); END;

-- Legacy: rows of vendor capability-mapping documents (input removed 2026-11-19; never requirements).
-- No longer written; kept so existing rows and their audit events survive.
CREATE TABLE IF NOT EXISTS capability_mapping_row (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_scope     TEXT NOT NULL,
    document_id            INTEGER NOT NULL REFERENCES regulatory_document(id),
    version_id             INTEGER NOT NULL REFERENCES regulatory_document_version(id),
    row_index              INTEGER NOT NULL,
    framework_id           TEXT NOT NULL REFERENCES regulatory_framework(id),
    control_id             TEXT NOT NULL,
    control_title          TEXT,
    official_control_title TEXT,
    control_family         TEXT,
    requirement_summary    TEXT,
    capability_text        TEXT NOT NULL,
    source_section         TEXT,
    source_origin          TEXT NOT NULL,           -- VENDOR_CAPABILITY_MAPPING
    official_version_id    INTEGER,
    resolution_status      TEXT NOT NULL,           -- RESOLVED | OFFICIAL_CONTROL_WITHOUT_PUBLISHED_REQUIREMENT | CANONICAL_CONTROL_UNRESOLVED
    requirement_ids        TEXT NOT NULL DEFAULT '[]',
    row_digest             TEXT NOT NULL,
    created_by             TEXT NOT NULL,
    created_at             TEXT NOT NULL,
    UNIQUE (organization_scope, version_id, row_index)
);

-- Verified PAM configuration observed by the Django collector (CUSTOMER_POLICY / PAM_CONFIGURATION).
-- Configuration observed at capture time; it never proves historical enforcement.
CREATE TABLE IF NOT EXISTS pam_configuration_snapshot (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_scope TEXT NOT NULL,
    tenant_id          TEXT NOT NULL,
    collector_info     TEXT NOT NULL,
    captured_at        TEXT NOT NULL,
    config_settings    TEXT NOT NULL,            -- JSON [{rule_id, parameter, value, setting_reference}]
    digest             TEXT NOT NULL,
    declared_by        TEXT NOT NULL,
    declared_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_pam_config_owner ON pam_configuration_snapshot(organization_scope, tenant_id);
CREATE TRIGGER IF NOT EXISTS trg_pam_config_immutable
BEFORE UPDATE ON pam_configuration_snapshot
BEGIN SELECT RAISE(ABORT, 'PAM configuration snapshots are immutable'); END;

-- One LLM-assisted mapping decision per (scope, requirement, input digest): proposal, validation, outcome.
CREATE TABLE IF NOT EXISTS llm_mapping_decision (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_scope   TEXT NOT NULL,
    tenant_id            TEXT,
    requirement_id       INTEGER NOT NULL REFERENCES regulatory_requirement(id),
    job_id               TEXT,
    input_digest         TEXT NOT NULL,
    model                TEXT,
    model_digest         TEXT,
    prompt_version       TEXT NOT NULL,
    policy_version       TEXT NOT NULL,
    raw_output           TEXT,
    llm_proposal         TEXT,                   -- JSON (parsed, schema-validated) or NULL
    llm_validation       TEXT NOT NULL,          -- JSON {checks[], problems[]}
    parameter_resolution TEXT NOT NULL DEFAULT '[]',
    outcome              TEXT NOT NULL,          -- PUBLISHED | EXISTING | GAP | NO_MAP | MANUAL_ASSESSMENT
    gap_code             TEXT,
    mapping_id           INTEGER,
    created_at           TEXT NOT NULL,
    UNIQUE (organization_scope, requirement_id, input_digest)
);
CREATE TRIGGER IF NOT EXISTS trg_llm_decision_preserved
BEFORE DELETE ON llm_mapping_decision
BEGIN SELECT RAISE(ABORT, 'LLM mapping decisions are preserved'); END;

-- Rules OPM generated from a validated RuleSpec (regintel.generated_rules): organization-scoped, immutable.
-- The spec, its compiled definition, digests, provenance and test receipts never change; only the
-- lifecycle columns (status, status_reason, activated_at, superseded_by) move forward.
CREATE TABLE IF NOT EXISTS generated_rule_version (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_scope      TEXT NOT NULL,
    tenant_id               TEXT NOT NULL,
    rule_id                 TEXT NOT NULL,           -- PAM-GEN-<12 hex>: digest of scope, tenant, canonical structure
    version                 TEXT NOT NULL,           -- always 1.0: different values give a different rule_id
    pam_control_id          TEXT NOT NULL REFERENCES pam_control(id),
    rule_spec               TEXT NOT NULL,           -- JSON canonical RuleSpec (as validated)
    spec_digest             TEXT NOT NULL,
    structure_digest        TEXT NOT NULL,
    parameter_resolution    TEXT NOT NULL,           -- JSON [{name, value, source_type, provenance, ...}]
    values_digest           TEXT NOT NULL,
    definition              TEXT NOT NULL,           -- JSON rule definition for the fixed interpreter
    compiled_rule           TEXT NOT NULL,           -- JSON compiled structure (input.rule)
    rule_digest             TEXT NOT NULL,
    rego_digest             TEXT NOT NULL,           -- interpreter package + compiled structure
    compiler_version        TEXT NOT NULL,
    evidence_type           TEXT NOT NULL,
    evidence_schema_version TEXT NOT NULL,
    assessment_mode         TEXT NOT NULL,
    collector_digest        TEXT NOT NULL,
    source_references       TEXT NOT NULL,           -- JSON [{requirement_id, document_version_id, section_ref, quotation}]
    llm_provenance          TEXT NOT NULL,           -- JSON {model, model_digest, prompt_version, decision_id}
    validation_result       TEXT NOT NULL,           -- JSON {checks[]}
    tests                   TEXT NOT NULL,           -- JSON generated cases
    test_results            TEXT NOT NULL,           -- JSON [{name, expected, got, passed}] from the real OPA binary
    bundle_version          TEXT NOT NULL,
    rule_limitations        TEXT NOT NULL,
    status                  TEXT NOT NULL CHECK (status IN ('VALIDATED','ACTIVE','SUPERSEDED','FAILED')),
    status_reason           TEXT,
    superseded_by           INTEGER,
    created_at              TEXT NOT NULL,
    activated_at            TEXT,
    UNIQUE (organization_scope, tenant_id, rule_id, version)
);
CREATE INDEX IF NOT EXISTS ix_generated_rule_owner ON generated_rule_version(organization_scope, tenant_id, rule_id);
CREATE TRIGGER IF NOT EXISTS trg_generated_rule_immutable
BEFORE UPDATE OF organization_scope, tenant_id, rule_id, version, rule_spec, spec_digest, structure_digest,
    parameter_resolution, values_digest, definition, compiled_rule, rule_digest, rego_digest, compiler_version,
    collector_digest, source_references, llm_provenance, validation_result, tests, test_results
ON generated_rule_version
BEGIN SELECT RAISE(ABORT, 'generated rule versions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_generated_rule_preserved
BEFORE DELETE ON generated_rule_version
BEGIN SELECT RAISE(ABORT, 'generated rule versions are preserved'); END;

-- One rule-generation decision per (scope, requirement, input digest): raw model output, parsed proposal,
-- deterministic validation and outcome. Raw output is retained for audit and never executed.
CREATE TABLE IF NOT EXISTS rule_generation_decision (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_scope TEXT NOT NULL,
    tenant_id          TEXT,
    requirement_id     INTEGER NOT NULL REFERENCES regulatory_requirement(id),
    job_id             TEXT,
    input_digest       TEXT NOT NULL,
    model              TEXT,
    model_digest       TEXT,
    prompt_version     TEXT NOT NULL,
    compiler_version   TEXT NOT NULL,
    raw_output         TEXT,
    llm_proposal       TEXT,
    llm_validation     TEXT NOT NULL,
    outcome            TEXT NOT NULL,
    gap_code           TEXT,
    generated_rule_version_id INTEGER,
    mapping_id         INTEGER,
    created_at         TEXT NOT NULL,
    UNIQUE (organization_scope, requirement_id, input_digest)
);
CREATE TRIGGER IF NOT EXISTS trg_rule_generation_decision_preserved
BEFORE DELETE ON rule_generation_decision
BEGIN SELECT RAISE(ABORT, 'rule generation decisions are preserved'); END;

CREATE TABLE IF NOT EXISTS audit_event (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '{}'
);

-- ---------------------------------------------------------------- immutability
CREATE TRIGGER IF NOT EXISTS trg_requirement_immutable
BEFORE UPDATE OF original_text, original_language, section_id, section_ref, document_version_id, framework_id, thresholds
ON regulatory_requirement WHEN OLD.status <> 'DRAFT'
BEGIN SELECT RAISE(ABORT, 'regulatory text of a reviewed requirement is immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_rule_version_immutable
BEFORE UPDATE OF definition, digest, tests, threshold_provenance, rule_id, version
ON rule_version WHEN OLD.status <> 'DRAFT'
BEGIN SELECT RAISE(ABORT, 'reviewed rule versions are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_mapping_immutable
BEFORE UPDATE OF requirement_id, pam_control_id, rationale, limitations, strength
ON framework_control_mapping WHEN OLD.status <> 'DRAFT'
BEGIN SELECT RAISE(ABORT, 'reviewed mappings are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_docversion_immutable
BEFORE UPDATE OF content_sha256, document_id, retrieved_url, byte_length, complete
ON regulatory_document_version
BEGIN SELECT RAISE(ABORT, 'retrieved document versions are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_bundle_immutable
BEFORE UPDATE OF digest, base_version, test_report ON bundle_version
BEGIN SELECT RAISE(ABORT, 'bundle versions are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_publication_immutable
BEFORE UPDATE ON catalog_publication
BEGIN SELECT RAISE(ABORT, 'publications are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_review_immutable
BEFORE UPDATE ON review_approval
BEGIN SELECT RAISE(ABORT, 'review decisions are immutable'); END;
"""

JSON_COLUMNS = frozenset({
    "languages", "official_domains", "industries", "config", "errors", "pam_domains", "thresholds",
    "extraction", "fields", "criteria", "requirement_ids", "definition", "threshold_provenance", "tests",
    "corrective_actions", "securden_capabilities", "customer_responsibilities", "source_citations",
    "attestations", "summary", "test_report", "detail", "rule_parameters", "override_constraints",
    "parsed_json", "validated_json", "validation_errors", "accepted_requirement_ids", "rejected_candidates",
    "document_ids", "policy_reference", "policy_controls", "collector_info", "evidence_support",
    "proposal_result", "config_settings", "llm_proposal", "llm_validation", "parameter_resolution",
    "evidence_detail", "rule_spec", "compiled_rule", "source_references", "llm_provenance", "validation_result",
    "test_results", "rule_limitations",
})


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def today() -> str:
    return date.today().isoformat()


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_of(obj: Any) -> str:
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


class CatalogError(Exception):
    """A workflow or integrity rule was violated. ``code`` is stable and testable."""

    def __init__(self, code: str, message: str, details: Any = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details = details  # optional structured payload surfaced in the API error body


def decode(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    out = dict(row)
    for k in out.keys() & JSON_COLUMNS:
        if isinstance(out[k], str):
            out[k] = json.loads(out[k])
    return out


class CatalogDb:
    def __init__(self, path: Path | str, read_only: bool = False) -> None:
        self.path = str(path)
        self.read_only = read_only
        if read_only:
            self._conn = sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro", uri=True, check_same_thread=False)
        else:
            if self.path != ":memory:":
                Path(path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.RLock()
        self._depth = 0
        if not read_only:
            self._conn.execute("PRAGMA journal_mode=DELETE")
            self._conn.executescript(SCHEMA)
            self._migrate()

    def _migrate(self) -> None:
        """Additive, idempotent schema changes for databases created by an earlier version."""
        from .plan import MAPPING_COLUMNS, MAPPING_TRIGGER

        present = {row[1] for row in self._conn.execute("PRAGMA table_info(framework_control_mapping)")}
        missing = [(name, ddl) for name, ddl in MAPPING_COLUMNS if name not in present]
        for name, ddl in missing:
            try:
                self._conn.execute(f"ALTER TABLE framework_control_mapping ADD COLUMN {name} {ddl}")
            except sqlite3.OperationalError as exc:  # another process added it first
                if "duplicate column" not in str(exc):
                    raise
        if missing or not self._conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='trg_mapping_execution_immutable'").fetchone():
            self._conn.executescript(MAPPING_TRIGGER)
        for table, column, ddl in (
            ("review_approval", "decision_origin", "TEXT NOT NULL DEFAULT 'HUMAN'"),
            ("review_approval", "policy_version", "TEXT"),
            ("review_approval", "attempt_id", "INTEGER"),
            ("source_verification", "decision_origin", "TEXT NOT NULL DEFAULT 'HUMAN'"),
            ("source_verification", "policy_version", "TEXT"),
            ("regulatory_framework", "organization_scope", "TEXT"),
            ("source", "organization_scope", "TEXT"),
            ("regulatory_document", "organization_scope", "TEXT"),
            ("regulatory_requirement", "organization_scope", "TEXT"),
            ("framework_control_mapping", "organization_scope", "TEXT"),
            ("collector_capability", "evidence_detail", "TEXT NOT NULL DEFAULT '{}'"),
        ):
            if column not in {row[1] for row in self._conn.execute(f"PRAGMA table_info({table})")}:
                try:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
                except sqlite3.OperationalError as exc:
                    if "duplicate column" not in str(exc):
                        raise
        # One live mapping per (requirement, PAM control) *per owner*: organization-scoped mappings of a global
        # requirement (LLM-assisted or generated) must not collide across organizations.
        live = self._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name='ux_mapping_live'").fetchone()
        if live is None or "organization_scope" not in (live[0] or ""):
            self._conn.executescript(
                "DROP INDEX IF EXISTS ux_mapping_live;"
                "CREATE UNIQUE INDEX ux_mapping_live ON framework_control_mapping(requirement_id, pam_control_id, "
                "COALESCE(organization_scope, '')) WHERE status IN ('DRAFT','APPROVED');")
        # Older databases restrict extraction_attempt.kind to EXTRACTION/TRANSLATION in a CHECK
        # constraint, which SQLite cannot alter in place: rebuild the table once, keeping all rows.
        ddl_row = self._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='extraction_attempt'").fetchone()
        if ddl_row and "'REVIEW'" not in ddl_row[0]:
            create = ddl_row[0].replace("'EXTRACTION','TRANSLATION'",
                                        "'EXTRACTION','TRANSLATION','REVIEW','TRANSLATION_REVIEW'")
            if "'REVIEW'" in create:  # only proceed when the DDL matched the known shape
                with self._lock:
                    # Standard SQLite rebuild: FK enforcement must be off while the
                    # table is dropped and renamed (the pragma is a no-op inside a tx).
                    self._conn.execute("PRAGMA foreign_keys=OFF")
                    self._conn.execute("BEGIN IMMEDIATE")
                    try:
                        self._conn.execute(create.replace("extraction_attempt", "extraction_attempt_new", 1))
                        self._conn.execute("INSERT INTO extraction_attempt_new SELECT * FROM extraction_attempt")
                        self._conn.execute("DROP TABLE extraction_attempt")
                        self._conn.execute("ALTER TABLE extraction_attempt_new RENAME TO extraction_attempt")
                        self._conn.execute(
                            "CREATE INDEX IF NOT EXISTS ix_attempt_version ON extraction_attempt(version_id)")
                        self._conn.execute("COMMIT")
                    except BaseException:
                        self._conn.execute("ROLLBACK")
                        raise
                    finally:
                        self._conn.execute("PRAGMA foreign_keys=ON")

    def close(self) -> None:
        self._conn.close()

    # -- primitives -------------------------------------------------------
    def q(self, sql: str, args: tuple | list = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [decode(r) for r in self._conn.execute(sql, tuple(args)).fetchall()]  # type: ignore[misc]

    def one(self, sql: str, args: tuple | list = ()) -> dict[str, Any] | None:
        with self._lock:
            return decode(self._conn.execute(sql, tuple(args)).fetchone())

    def scalar(self, sql: str, args: tuple | list = ()) -> Any:
        with self._lock:
            row = self._conn.execute(sql, tuple(args)).fetchone()
        return row[0] if row else None

    def x(self, sql: str, args: tuple | list = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, tuple(args))
            return cur.lastrowid or 0

    def insert(self, table: str, **values: Any) -> int:
        cols = list(values)
        vals = [canonical(v) if c in JSON_COLUMNS and not isinstance(v, str) else v for c, v in values.items()]
        return self.x(f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals)

    @contextmanager
    def tx(self) -> Iterator[None]:
        """Re-entrant write transaction: all-or-nothing workflow steps."""
        with self._lock:
            outer = self._depth == 0
            if outer:
                self._conn.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield
            except BaseException:
                self._depth -= 1
                if outer:
                    self._conn.execute("ROLLBACK")
                raise
            else:
                self._depth -= 1
                if outer:
                    self._conn.execute("COMMIT")

    def audit(self, actor: str, action: str, entity_type: str, entity_id: Any, **detail: Any) -> None:
        self.insert("audit_event", at=now_iso(), actor=actor, action=action, entity_type=entity_type,
                    entity_id=str(entity_id), detail=detail)

    # -- publication log --------------------------------------------------
    def publish(self, actor: str, kind: str, changes: list[tuple[str, Any, str]], summary: dict[str, Any]) -> int:
        """Record one immutable publication and its change-feed rows. Returns its seq."""
        at = now_iso()
        body = {"kind": kind, "changes": [[t, str(i), c] for t, i, c in changes], "summary": summary}
        seq = self.insert("catalog_publication", published_at=at, published_by=actor, kind=kind,
                          summary=summary, digest=digest_of(body))
        for etype, eid, ctype in changes:
            self.insert("catalog_change", publication_seq=seq, entity_type=etype, entity_id=str(eid),
                        change_type=ctype, at=at)
        self.audit(actor, "PUBLISH", "catalog_publication", seq, kind=kind, changes=len(changes))
        return seq

    def catalog_version(self) -> int:
        return int(self.scalar("SELECT COALESCE(MAX(seq),0) FROM catalog_publication") or 0)
