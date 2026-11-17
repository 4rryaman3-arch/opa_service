# Evaluation API: PAM evidence in, compliance results out

The Securden PAM/Django app sends **normalized evidence records** (identifiers, flags, counts, timestamps), and OPM
evaluates them with OPA. It returns `PASS`, `FAIL`, `INSUFFICIENT_EVIDENCE` or `NOT_APPLICABLE`. OPM never connects
to the PAM database and **stores no evaluation results**, so PAM must persist the responses it wants to keep. No LLM
is involved.

## 1. Connection and client

| Item | Value |
|---|---|
| Base URL | `https://192.168.7.7` (port 443; `opm.lan`/`arryman` are also on the certificate) |
| TLS | verify against the private CA `ca.crt`; never disable verification |
| mTLS | `client.crt` + `client.key` (or `client.pfx`) on every connection |
| Auth | `Authorization: Bearer <api_token.txt>`; tenants are limited by the credential's allowlist (others get 403) |
| Correlation | optional `X-Correlation-ID` (8–128 chars `[A-Za-z0-9._-]`), echoed back and logged |
| Connectivity | `GET /ready` (client certificate, no token) |

Copy `client/securden_opm_client.py` into the Django project. Its only dependency is `httpx`.

```python
OPM_SERVICE = {
    "BASE_URL": "https://192.168.7.7",
    "CA_BUNDLE": r"<dir>\ca.crt", "CLIENT_CERT": r"<dir>\client.crt",
    "CLIENT_KEY": r"<dir>\client.key", "TOKEN_FILE": r"<dir>\api_token.txt",
    "TIMEOUT_SECONDS": 30,
}

from compliance.opm_client import OpmClient, OpmRequestError, OpmTransientError, OpmResponseError
with OpmClient.from_django_settings() as client:
    result = client.evaluate(tenant_id, item, correlation_id="securden-rotation-acme-20261112")
    results = client.evaluate_batch(tenant_id, items, chunk_size=50)   # [{index, ok, result|error}]
```

Client guarantees: HTTPS only, TLS ≥ 1.2, chain and hostname verified against `CA_BUNDLE`. Timeouts are 5 s to
connect and `TIMEOUT_SECONDS` overall. Retries use up to 4 attempts with exponential backoff (0.5→8 s, jitter, honours
`Retry-After` ≤ 30 s), and only for connect/read errors and 429/502/503/504; TLS failures are never retried. One
correlation id is reused across retries. Responses are validated: a bad shape raises `OpmResponseError`.

Errors: `OpmRequestError` (4xx: fix the request and don't retry it unchanged), `OpmTransientError` (unavailable after
retries: retry later), `OpmResponseError`. **An error is never a compliance result. Never record it as PASS or FAIL.**

## 2. Endpoints

| Method & path | Scope | Purpose |
|---|---|---|
| `GET /health`, `GET /ready` | none | liveness / readiness incl. bundle-version consistency |
| `GET /api/v1/version` | any | app, OPA and policy-bundle versions |
| `GET /api/v1/rules?tenant_id=` | `rules:read` | predefined rule metadata + the tenant's customer rules |
| `POST /api/v1/evaluate` | `evaluate` | one evaluation |
| `POST /api/v1/evaluate/batch` | `evaluate` | `{"tenant_id", "items":[…]}`, up to 100 items / 50,000 records, per-item errors |
| `POST /api/v1/rules/validate`, `/rules/test` | `rules:write` | validate / dry-run a customer rule (not stored) |
| `POST /api/v1/rules/custom`, `…/versions/{v}/activate\|deactivate` | `rules:admin` | store and activate customer rules |
| `POST /api/v1/rules/predefined/{id}/activate\|deactivate` | `rules:admin` | per-tenant enablement |
| `GET /api/v1/metrics` | `metrics:read` | counters + latency histograms |

Regulatory catalog, templates and plans are documented in DJANGO_CONTRACT.md.

## 3. Request

```json
{
  "tenant_id": "default",
  "rule_id": "PAM-ROTATION-001",
  "rule_version": "1.1",
  "evaluation_mode": "CURRENT",
  "reporting_period": {"start": "2026-10-13T00:00:00Z", "end": "2026-11-12T00:00:00Z"},
  "evidence": {
    "evidence_type": "credential_rotation",
    "records": [{"record_id": "rot-acct-101", "account_id": "101", "privileged": true,
                 "last_rotated_at": "2026-08-09T06:00:00Z", "last_rotation_status": "SUCCESS"}],
    "completeness": {"expected_record_count": 1, "received_record_count": 1,
                     "source_complete": true, "collection_errors": 0}
  },
  "policy_settings": {"policy_version": "pam-policy-2026.10", "effective_from": "2026-10-01T00:00:00Z",
                      "parameters": {"max_rotation_age_days": 90}, "scope_tags": []},
  "exceptions": [{"exception_id": "exc-1", "rule_id": "PAM-ROTATION-001", "subject_ids": ["101"],
                  "approved_by": "user-7", "approved_at": "2026-10-01T00:00:00Z", "expires_at": "2026-12-01T00:00:00Z"}],
  "item_reference": "optional-caller-reference"
}
```

Optional: `rule_version` (defaults to the active version), `evaluation_mode`, `policy_settings`, `exceptions` and
`item_reference`. Batch items are the same object without `tenant_id`. Per-type record schemas:
`schemas/evidence_records.schema.json`.

Requests that break these rules are rejected with 422:

- Unknown fields anywhere. Never send passwords, keys, recording content or free text (send `justification_length`).
- Timestamps without a timezone offset. `reporting_period` values are **date-times**, not bare dates.
- Strict types: `"true"` and `"5"` are rejected.
- Identifiers must match `^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$` (convert PKs with `str(pk)`). `tenant_id` must match
  `^[a-z0-9][a-z0-9-]{1,62}$`, and `scope_tags` must match `^[a-z0-9][a-z0-9._:-]{0,63}$` (max 20).
- `record_id` must be unique per request and stable across re-runs, and `received_record_count` must equal `len(records)`.
- `evidence_type` must match the rule, and exceptions must target the evaluated rule.
- No evidence timestamp after `reporting_period.end`, except `expires_at`, `entitlement_valid_to` and `coverage_end`.
  Send the state as of the period end.
- The period must end after it starts, must not be in the future and can be at most 400 days. In `CURRENT` mode it
  must have ended within 35 days. Otherwise use `HISTORICAL` with `rule_version`, `policy_settings.policy_version`
  and `policy_settings.effective_from ≤ start`.

`completeness` decides between PASS and INSUFFICIENT_EVIDENCE, so fill it honestly. A confirmed violation is FAIL
even when the evidence is incomplete. An exception suppresses a violation only if
`approved_at ≤ period end < expires_at`. With `policy_settings.scope_tags` set, only records carrying one of those
tags are evaluated. Pre-aggregate large datasets (for example, failed logins per principal per window).

## 4. Predefined rules and evidence records

Every record has `record_id` and optional `scope_tags`. "nullable" means the key is required but may be `null`.
Parameters go in `policy_settings.parameters`; unknown or out-of-range values are rejected. Threshold boundaries are
inclusive (age == max passes).

| Rule | evidence_type / subject | Violation reasons | Parameters (default) | Severity | ISO 27001:2022 / SOC 2 |
|---|---|---|---|---|---|
| PAM-ROTATION-001 v1.1 (v1.0 retired 2026-07-01) | `credential_rotation` / `account_id` | NEVER_ROTATED, ROTATION_AGE_EXCEEDED, LAST_ROTATION_FAILED | max_rotation_age_days (90, 1–730) | HIGH | 5.17, 8.2 / CC6.1 |
| PAM-SESSREC-001 | `privileged_session` / `session_id` | RECORDING_MISSING, RECORDING_FAILED, RECORDING_PARTIAL; PROCESSING → undetermined | accept_partial_recordings (false) | HIGH | 8.2, 8.15 / CC7.2 |
| PAM-APPROVAL-001 | `privileged_access_request` / `access_id` | NO_APPROVED_REQUEST, APPROVAL_AFTER_ACCESS, APPROVAL_TOO_OLD, SELF_APPROVAL | max_approval_age_hours (24) | CRITICAL | 5.18, 8.2 / CC6.2, CC6.3 |
| PAM-DORMANT-001 | `privileged_account` / `account_id` | DORMANT_SINCE_LAST_USE, NEVER_USED_SINCE_CREATION | dormant_after_days (90, 1–730) | MEDIUM | 5.18, 8.2 / CC6.2 |
| PAM-AUTHFAIL-001 | `authentication_summary` / `principal_id` | FAILED_ATTEMPTS_EXCEEDED; window too long → undetermined | max_failed_attempts (5), window_minutes (15), lockout_is_mitigation (false) | HIGH | 8.5, 8.16 / CC6.1, CC7.2 |
| PAM-UNAUTH-001 | `access_authorization` / `access_id` | NOT_AUTHORIZED, ENTITLEMENT_REVOKED, OUTSIDE_ENTITLEMENT_WINDOW; UNKNOWN → undetermined | – | CRITICAL | 5.15, 5.18, 8.2 / CC6.1, CC6.3 |
| PAM-BREAKGLASS-001 | `break_glass_event` / `event_id` | JUSTIFICATION_MISSING, JUSTIFICATION_TOO_SHORT, TICKET_REFERENCE_MISSING, POST_REVIEW_OVERDUE, POST_REVIEW_LATE | min_justification_length (20), require_ticket_reference (true), post_review_within_hours (72) | HIGH | 5.18, 8.2 / CC6.1, CC6.2 |
| PAM-EXCEPTION-001 | `policy_exception` / `exception_id` | ACTIVE_AFTER_EXPIRY, USED_AFTER_EXPIRY, DURATION_EXCEEDS_MAXIMUM | max_exception_duration_days (365) | MEDIUM | 5.36 / CC5.3 |
| PAM-REVIEW-001 | `access_review` / `account_id` | NEVER_REVIEWED, REVIEW_OVERDUE, SELF_REVIEW, REVOCATION_NOT_ENFORCED | review_interval_days (90) | MEDIUM | 5.18, 8.2 / CC6.2, CC6.3 |
| PAM-AUDITCOMP-001 | `audit_log_coverage` / `source_id` | COVERAGE_STARTS_AFTER_PERIOD_START, COVERAGE_ENDS_BEFORE_PERIOD_END, EVENT_COMPLETENESS_BELOW_MINIMUM, GAP_EXCEEDS_MAXIMUM, INTEGRITY_NOT_VERIFIED | min_completeness_percent (100), max_allowed_gap_seconds (300), require_integrity_verification (true) | HIGH | 8.15 / CC4.1, CC7.2 |
| PAM-MFACFG-001 (configuration snapshot) | `mfa_configuration` / `principal_id` | MFA_NOT_ENFORCED, NO_ACCEPTED_MFA_METHOD; SNAPSHOT_OUTSIDE_PERIOD, MFA_CONFIGURATION_UNKNOWN → undetermined | accepted_methods (**no default**, enum list) | HIGH | – |
| PAM-MFAACC-001 | `privileged_access_authentication` / `access_id` | MFA_NOT_PERFORMED, ACCESS_GRANTED_AFTER_FAILED_MFA, MFA_METHOD_NOT_ACCEPTED; UNKNOWN → undetermined | accepted_methods (**no default**, enum list) | CRITICAL | – |
| PAM-SESSIDLE-001 (configuration snapshot) | `session_policy_configuration` / `policy_id` | IDLE_TIMEOUT_DISABLED, IDLE_TIMEOUT_EXCEEDS_MAXIMUM; SNAPSHOT_OUTSIDE_PERIOD, NO_SESSION_POLICY_SUPPLIED → undetermined | max_idle_minutes (**no default**, 1–1440) | MEDIUM | – |
| PAM-SESSDUR-001 | `privileged_session` / `session_id` | SESSION_DURATION_EXCEEDED, OPEN_SESSION_EXCEEDS_MAXIMUM | max_session_minutes (**no default**, 1–10080) | MEDIUM | – |

The four rules above with **no default** return 422 `MISSING_PARAMETER` unless the value is stated. They are intended
to run from organization policy contexts. Their record fields, and how Django runs them from a plan, are in
[POLICY_CONTEXT_DJANGO_CONTRACT.md](POLICY_CONTEXT_DJANGO_CONTRACT.md) §8.

Record fields:

- **credential_rotation** (one per privileged account): `account_id`, `privileged`, `last_rotated_at` (nullable; last
  *successful* rotation), `last_rotation_status` (`SUCCESS|FAILED|null`, optional).
- **privileged_session** (per session started in the period): `session_id`, `account_id`, `user_id`, `started_at`,
  `ended_at` (opt, ≥ start), `recording_required`, `recording_status`
  (`AVAILABLE|PARTIAL|MISSING|FAILED|PROCESSING`), `recording_reference` (opt id).
- **privileged_access_request**: `access_id`, `user_id`, `account_id`, `accessed_at`, `approval_required`,
  `approval_status` (`APPROVED|PENDING|DENIED|NONE`), optional `approval_id`, `approved_at`, `approver_id`.
  `APPROVED` needs both `approved_at` and `approver_id`.
- **privileged_account**: `account_id`, `privileged`, `enabled`, `created_at`, `last_used_at` (nullable, ≥ created).
- **authentication_summary** (pre-aggregated per principal per window): `principal_id`, `window_start`,
  `window_end` (window ≤ `window_minutes`), `failed_attempts`, `lockout_triggered`.
- **access_authorization**: `access_id`, `user_id`, `account_id`, `accessed_at`, `entitlement_status`
  (`AUTHORIZED|NOT_AUTHORIZED|REVOKED|UNKNOWN`), optional `entitlement_id`, `entitlement_valid_from/to`.
- **break_glass_event**: `event_id`, `user_id`, `account_id`, `activated_at`, `justification_provided`,
  `justification_length`, `ticket_reference` (opt), `post_review_completed`, `post_review_at` (present exactly when
  completed, ≥ activation).
- **policy_exception**: `exception_id`, `rule_id`, `status` (`ACTIVE|EXPIRED|REVOKED`), `approved_at`, `expires_at`
  (> approved), `last_used_at` (opt).
- **access_review**: `account_id`, `privileged`, `enabled`, optional `owner_id`, `reviewer_id`,
  `last_review_completed_at` (nullable), `last_review_outcome` (`CERTIFIED|REVOKED`; required with reviewer once a
  review is completed).
- **audit_log_coverage**: `source_id`, `coverage_start`, `coverage_end`, `expected_event_count`,
  `received_event_count`, `max_gap_seconds`, `integrity_verified`.

## 5. Response

Fields to persist: `evaluation_id`, `evaluated_at`, `correlation_id`, `rule_id`, `rule_version`,
`policy_bundle_version`, `status`, `severity`, `metrics`, `violations[{record_id, subject_id, reasons}]`, `excepted`,
`undetermined`, `evidence_references`, `evidence_completeness`, `decision_details` (`summary`, effective
`parameters`, `evaluation_mode`, `as_of`, `input_digest`), `framework_mappings` with
`framework_mapping_disclaimer`, and `remediation`.

Decision semantics: the reference time is `reporting_period.end`, never the wall clock. Status precedence is
**FAIL** (violations > tolerance) → **INSUFFICIENT_EVIDENCE** → **NOT_APPLICABLE** → **PASS**. Records are sorted
before evaluation, so `input_digest` is identical for identical evidence. Any engine failure is an explicit 5xx and is
never treated as PASS.

> Framework mappings name the ISO 27001 / SOC 2 controls that a test provides evidence toward. They are **not**
> certification or audit conclusions. Keep the disclaimer with any report that shows them.

Batch response: `{"summary": {"total", "succeeded", "failed", "by_status"}, "results": [{"index", "item_reference",
"ok", "result" | "error"}]}`. A failed item is an error, not a status.

## 6. Errors and limits

`{"error": {"code", "message", "details"?}, "correlation_id"}`

| HTTP | Code |
|---|---|
| 401 | `UNAUTHENTICATED` |
| 403 | `TENANT_FORBIDDEN`, `FORBIDDEN` |
| 404 | `RULE_NOT_FOUND`, `RULE_VERSION_NOT_FOUND` |
| 409 | `RULE_INACTIVE` (deactivated for tenant), `RULE_NOT_ACTIVE` |
| 413 | `PAYLOAD_TOO_LARGE`, `TOO_MANY_RECORDS`, `BATCH_TOO_LARGE` |
| 422 | `VALIDATION_ERROR` (`details` = field locations), `EVIDENCE_TYPE_MISMATCH`, `EVIDENCE_AFTER_PERIOD_END`, `HISTORICAL_MODE_REQUIRED`, `PERIOD_IN_FUTURE`, `RULE_VERSION_NOT_EFFECTIVE`, `INVALID_PARAMETER`, `UNKNOWN_PARAMETER`, `EXCEPTION_RULE_MISMATCH` |
| 429 | `RATE_LIMITED` (honour `Retry-After`) |
| 502/503/504 | `POLICY_*`, `EVALUATION_TIMEOUT`: retry later, never assume a result |

A TLS handshake failure means the client certificate or CA file is wrong. Limits: 10,000 records per evaluation, a
5 MiB body, 100 items and 50,000 records per batch, 600 requests/min per token (burst 100), and a 30 s evaluation
timeout.

## 7. Versions and history

Each rule version has `effective_from`/`effective_to` and a status (`ACTIVE`, `RETIRED`). A version applies only if it
covers the **whole** reporting period, so split periods at version boundaries. `CURRENT` mode uses the active version.
`HISTORICAL` mode allows retired versions but needs the explicit version and policy fields listed in §3.

## 8. Customer-defined rules

Schema: `schemas/custom_rule.schema.json`. Field/operator allowlist: `schemas/custom_rule_fields.json`.

```json
{
  "rule_id": "CUST-ACME-DORMANT-001", "version": "1.0", "title": "Production admin accounts unused for 30 days",
  "severity": "HIGH", "evidence_type": "privileged_account", "subject_field": "account_id",
  "scope": {"all": [{"field": "enabled", "op": "eq", "value": true},
                    {"field": "scope_tags", "op": "contains", "value": "prod"}]},
  "violation_when": {"any": [
    {"field": "last_used_at", "op": "older_than_days", "value": 30},
    {"all": [{"field": "last_used_at", "op": "is_null"}, {"field": "created_at", "op": "older_than_days", "value": 30}]}
  ]},
  "tolerance": 0, "effective_from": "2026-01-01T00:00:00Z",
  "framework_mappings": [{"framework": "ISO27001:2022", "control": "8.2"}], "remediation": "Disable the account."
}
```

- Operators: `eq ne gt gte lt lte in not_in is_null not_null older_than_days within_last_days contains`, each
  restricted by field type. `is_null`/`not_null` work only on nullable fields.
- Nesting: a root group plus leaf groups (2 levels), ≤ 25 conditions in total, ≤ 20 per group, ≤ 100 list values.
  A condition on a null value doesn't match (except `is_null`). Each violation lists the condition ids that matched.
- Lifecycle: `validate` → `test` → `custom` (stored as an immutable `DRAFT`) → `activate` (one `ACTIVE` per rule) →
  `deactivate`. Every change is recorded in `rule_events`. Rules are tenant-isolated: another tenant gets
  `404 RULE_NOT_FOUND`.

## 9. Building collectors in Django

1. Write one collector per rule. Map each field explicitly and never serialize model instances wholesale.
2. Compute `completeness` from the inventory count versus the rows collected.
3. Evaluate from a scheduled task, not inside a web request. Store results keyed by `evaluation_id`, and store errors
   separately with their `code`.
4. Smoke test: a rotation record 95 days old must return `FAIL` / `ROTATION_AGE_EXCEEDED`.

Real request/response samples are in `docs/examples/`.
