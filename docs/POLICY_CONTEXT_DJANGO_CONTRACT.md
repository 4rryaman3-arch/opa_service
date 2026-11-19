# Django ↔ OPM: organization policy contexts (CUSTOMER_POLICY)

Contract for the Django service. It covers saving an organization's own PAM policy,
declaring which evidence the collector produces, binding policy to evaluation plans, and
running and reporting the resulting executions. Control catalog version `2026.11.16-1`;
bundle `2026.11.19-1` (examples were captured with bundle `2026.11.16-1`). Every example below was captured from a real OPM run on synthetic
fixture data. IDs, digests and timestamps will differ in your environment.

Transport, the error envelope, mTLS and bearer credentials are unchanged from
[DJANGO_CONTRACT.md](DJANGO_CONTRACT.md) §1–3. All machine-readable request schemas
are in `schemas/`:

| File | Validates |
|---|---|
| `policy_context_create.schema.json` | `POST /admin/policy-contexts` body |
| `policy_context_version_create.schema.json` | `POST /admin/policy-contexts/{id}/versions` body |
| `collector_capabilities.schema.json` | `PUT /admin/collector-capabilities` body |
| `evaluation_plan_request.schema.json` | `POST /evaluation-templates/{id}/plan` body |
| `evaluation_plan.schema.json` | plan response (incl. `policy_context`, `policy_resolution`) |
| `evidence_records.schema.json` | evidence records per type, plus `evidence_schema_versions` |
| `policy_controls.json` | control catalog snapshot (the GET endpoint is authoritative) |

---

## 0. What this is, and what it is not

* A **policy context** is the organization's own policy, for example "rotate privileged
  credentials every 30 days" or "MFA with FIDO2 or TOTP". It is **not legislation**.
  Everything it produces carries `provenance: "CUSTOMER_POLICY"`.
* A policy value only fills a gap where the regulatory text **states no value**
  (`POLICY_CONTEXT_REQUIRED`). It never replaces a threshold stated in regulation. If a
  requirement says 90 days, it is evaluated at 90 days even when the company policy says 30.
* Policy is **active on save**. There is no approval step in OPM. The organization
  declares its own policy, and `policy_reference` records where it came from.
* OPM never accepts Rego, expressions or code. Policy is only parameters for
  pre-defined, versioned controls, validated against a published schema with
  **no defaults**.
* Target IDs are **opaque PAM identifiers**. OPM never treats them as proof of membership
  or authorization. Django resolves membership and partitions evidence.
* No LLM takes part in any outcome described here. Plans and decisions are deterministic.

---

## 1. Endpoints and permissions

Public API: `https://<host>/api/v1/catalog`. Admin API: `https://<host>/api/v1/catalog/admin`.

| Method and path | Scope | Org-scope header |
|---|---|---|
| `GET /policy-controls[?tenant_id=&control_id=&include_evidence_schema=]` | `catalog:read` | optional (needed for `assessability`) |
| `GET /policy-contexts?tenant_id=[&after=&limit=]` | `catalog:read` | **required** |
| `GET /policy-contexts/{context_id}/versions/{version}?tenant_id=` | `catalog:read` | **required** |
| `GET /collector-capabilities?tenant_id=` | `catalog:read` | **required** |
| `GET /evaluation-templates/{framework_id}/plan` (extended, §6) | `catalog:read` | required when policy is selected |
| `POST /evaluation-templates/{framework_id}/plan` (new, §6) | `catalog:read` | required when policy is selected |
| `POST /admin/policy-contexts` | `catalog:operate` | **required** |
| `POST /admin/policy-contexts/{context_id}/versions` | `catalog:operate` | **required** |
| `PUT /admin/collector-capabilities` | `catalog:operate` | **required** |
| `POST /api/v1/evaluate` (unchanged; runs the executions) | `evaluate` | n/a |

* **Tenant.** `tenant_id` must be one of the credential's tenants, otherwise 403 `TENANT_FORBIDDEN`.
* **Organization scope.** Send the header `X-Securden-Organization-Scope: <scope>`, where
  the scope matches `^[A-Za-z0-9_-]{16,128}$`. A scope is bound to the first credential
  (key_id) that uses it. Any other credential gets 403 `SCOPE_FORBIDDEN`. Policy endpoints
  without the header return 422 `SCOPE_REQUIRED`.
* **Ownership and isolation.** A context belongs to exactly one (scope, tenant) pair.
  Another scope's or tenant's context or version returns **404**
  (`UNKNOWN_POLICY_CONTEXT` / `UNKNOWN_POLICY_VERSION`), exactly like one that doesn't exist.
* **Actor.** `declared_by` / `created_by` is always the credential's `key_id`. No request
  field can set it. Django should record its own end user next to the OPM IDs (§9).

---

## 2. Control catalog: `GET /policy-controls`

The response envelope carries the following, plus `items[]`:
- `control_catalog_version`
- `policy_bundle_version`
- `schema_subset`
- `target_types`
- `assessment_modes`
- `collector_capabilities` (only when a tenant and scope are given)

### 2.1 Controls in `2026.11.16-1`

All controls are at version `1.0`. "Gap rule" is the rule whose `POLICY_CONTEXT_REQUIRED`
gap the control can resolve.

| Control | Mode | Parameters (all required) | Targets | Rule / evidence type | Status | Gap rule |
|---|---|---|---|---|---|---|
| PC-CRED-ROTATION | EVENT_HISTORY | `max_rotation_age_days` int 1..730 | ORG, ACCOUNT(_GROUP), RESOURCE(_GROUP) | PAM-ROTATION-001 1.1 / credential_rotation 1.0 | EXECUTABLE | PAM-ROTATION-001 |
| PC-SESSION-RECORDING | EVENT_HISTORY | `accept_partial_recordings` bool | ORG, USER(_GROUP), ACCOUNT(_GROUP), RESOURCE(_GROUP) | PAM-SESSREC-001 1.0 / privileged_session 1.0 | EXECUTABLE | PAM-SESSREC-001 |
| PC-SESSION-IDLE-LIMIT | **CONFIGURATION_SNAPSHOT** | `max_idle_minutes` int 1..1440 | ORG, SESSION_POLICY | PAM-SESSIDLE-001 1.0 / session_policy_configuration 1.0 | EXECUTABLE | PAM-SESSIDLE-001 |
| PC-SESSION-DURATION-LIMIT | EVENT_HISTORY | `max_session_minutes` int 1..10080 | ORG, ACCOUNT(_GROUP), RESOURCE(_GROUP) | PAM-SESSDUR-001 1.0 / privileged_session 1.0 | EXECUTABLE | PAM-SESSDUR-001 |
| PC-MFA-AT-ACCESS | EVENT_HISTORY | `accepted_methods` array of `email_otp\|fido2\|hardware_token\|push\|smart_card\|sms\|totp` (1..7, unique) | ORG, USER(_GROUP), ACCOUNT(_GROUP), RESOURCE(_GROUP) | PAM-MFAACC-001 1.0 / privileged_access_authentication 1.0 | EXECUTABLE | PAM-MFAACC-001 |
| PC-MFA-CONFIGURATION | **CONFIGURATION_SNAPSHOT** | `accepted_methods` (as above) | ORG, USER(_GROUP), ACCOUNT(_GROUP) | PAM-MFACFG-001 1.0 / mfa_configuration 1.0 | EXECUTABLE | **none**: never resolves an MFA gap |
| PC-ACCESS-APPROVAL | EVENT_HISTORY | `max_approval_age_hours` int 1..720 | ORG, USER(_GROUP), ACCOUNT(_GROUP), RESOURCE(_GROUP) | PAM-APPROVAL-001 1.0 / privileged_access_request 1.0 | EXECUTABLE | PAM-APPROVAL-001 |
| PC-ACCESS-AUTHORIZATION | EVENT_HISTORY | *(none: `parameters: {}`)* | ORG, USER(_GROUP), ACCOUNT(_GROUP), RESOURCE(_GROUP) | PAM-UNAUTH-001 1.0 / access_authorization 1.0 | EXECUTABLE | PAM-UNAUTH-001 |
| PC-ACCESS-REVIEW | EVENT_HISTORY | `review_interval_days` int 1..730 | ORG, ACCOUNT(_GROUP), RESOURCE(_GROUP) | PAM-REVIEW-001 1.0 / access_review 1.0 | EXECUTABLE | PAM-REVIEW-001 |
| PC-DORMANT-ACCOUNTS | EVENT_HISTORY | `dormant_after_days` int 1..730 | ORG, ACCOUNT(_GROUP), RESOURCE(_GROUP) | PAM-DORMANT-001 1.0 / privileged_account 1.0 | EXECUTABLE | PAM-DORMANT-001 |
| PC-AUTH-FAILURE-MONITORING | EVENT_HISTORY | `max_failed_attempts` int 1..1000, `window_minutes` int 1..1440, `lockout_is_mitigation` bool | ORG, USER(_GROUP) | PAM-AUTHFAIL-001 1.0 / authentication_summary 1.0 | EXECUTABLE | PAM-AUTHFAIL-001 |
| PC-EMERGENCY-ACCESS | EVENT_HISTORY | `min_justification_length` int 1..2000, `require_ticket_reference` bool, `post_review_within_hours` int 0..2160 | ORG, USER(_GROUP), ACCOUNT(_GROUP), RESOURCE(_GROUP) | PAM-BREAKGLASS-001 1.0 / break_glass_event 1.0 | EXECUTABLE | PAM-BREAKGLASS-001 |
| PC-POLICY-EXCEPTIONS | EVENT_HISTORY | `max_exception_duration_days` int 1..1095 | ORG | PAM-EXCEPTION-001 1.0 / policy_exception 1.0 | EXECUTABLE | PAM-EXCEPTION-001 |
| PC-AUDIT-LOG-COMPLETENESS | EVENT_HISTORY | `min_completeness_percent` int 1..100, `max_allowed_gap_seconds` int 0..604800, `require_integrity_verification` bool | ORG, AUDIT_SOURCE | PAM-AUDITCOMP-001 1.0 / audit_log_coverage 1.0 | EXECUTABLE | PAM-AUDITCOMP-001 |
| PC-PASSWORD-POLICY | CONFIGURATION_SNAPSHOT | `min_length` int 8..256, `required_character_classes` int 0..4, `min_entropy_bits` **number** 0..512, `history_depth` int 0..100 | ORG, ACCOUNT(_GROUP), RESOURCE(_GROUP) | *(none)* | **NOT_IMPLEMENTED** | none |
| PC-SEGREGATION-OF-DUTIES | CONFIGURATION_SNAPSHOT | `conflicting_role_pairs` array (1..50) of `{first_role, second_role}` strings, `enforcement` `PREVENT\|DETECT` | ORG, USER_GROUP | *(none)* | **NOT_IMPLEMENTED** | none |

Distinctions the UI must keep:
* **MFA configuration is not MFA at access.** PC-MFA-CONFIGURATION reports what is
  configured at one instant. Only PC-MFA-AT-ACCESS (per-access events) can resolve an MFA
  requirement.
* **Failed-logon monitoring is not MFA.** PC-AUTH-FAILURE-MONITORING says nothing about MFA.
* **Snapshots are not history.** A CONFIGURATION_SNAPSHOT PASS describes the configuration
  captured at `captured_at`. It does not show the setting was enforced for every session.
  Show the `assessment_mode` next to every result.
* **NOT_IMPLEMENTED controls** can be saved as documented policy. They always carry the
  blocker `NO_EXECUTABLE_RULE` and are never executed.

### 2.2 One item (exact shape)

```json
{
  "control_id": "PC-CRED-ROTATION", "control_version": "1.0", "category": "credential_lifecycle",
  "pam_control_id": "PAMC-CRED-ROTATION",
  "title": "Privileged credential rotation interval",
  "description": "Maximum age of a privileged credential before it must have been rotated successfully.",
  "parameter_schema": {
    "type": "object",
    "properties": {"max_rotation_age_days": {"type": "integer", "minimum": 1, "maximum": 730,
                                             "title": "Maximum credential age"}},
    "required": ["max_rotation_age_days"], "additionalProperties": false},
  "ui": {"order": ["max_rotation_age_days"],
         "parameters": {"max_rotation_age_days": {"label": "Maximum credential age", "unit": "days",
           "help": "Accounts not rotated within this many days before the period end fail."}}},
  "target_types": ["ORGANIZATION", "ACCOUNT", "ACCOUNT_GROUP", "RESOURCE", "RESOURCE_GROUP"],
  "assessment_mode": "EVENT_HISTORY",
  "bindings": [{"rule_id": "PAM-ROTATION-001", "rule_version": "1.1", "evidence_type": "credential_rotation",
                "parameter_map": {"max_rotation_age_days": "max_rotation_age_days"},
                "evidence_schema_version": "1.0", "evidence_schema": {"...": "JSON Schema of one record"}}],
  "implementation": {"status": "EXECUTABLE",
    "limitations": ["Rule 1.1 is effective from 2026-07-01; earlier reporting periods cannot use this control version."]},
  "addresses_gap_rules": ["PAM-ROTATION-001"],
  "definition_digest": "sha256:018bc0b8f471f4cec90c10c2b7af4dceb1d238ce2bffdd5a0d3005eb421ac575",
  "assessability": {"end_to_end_assessable": true, "reason": null, "bindings": [{
    "rule_id": "PAM-ROTATION-001", "rule_version": "1.1", "evidence_type": "credential_rotation",
    "evidence_schema_version": "1.0", "collector_declared_version": "1.0",
    "capability_source": "LEGACY_BRIDGE_DEFAULT", "end_to_end_assessable": true, "blocker_codes": []}]}
}
```

`evidence_schema` is omitted when `include_evidence_schema=false`. `ui.unit` is one of
`days`, `hours`, `minutes`, `seconds`, `percent` or `none`. Render fields in `ui.order`.

**`assessability`**
* Without `tenant_id` and the scope header, it is
  `{"end_to_end_assessable": null, "reason": "<hint>", "bindings": []}`.
* Otherwise it is `true` only when the pinned rule version is in the running bundle, its
  contract matches, and the organization's collector declares the exact evidence schema
  version.
* `reason` is the first blocker code in sorted order: `COLLECTOR_MISSING`,
  `EVIDENCE_SCHEMA_INCOMPATIBLE`, `NO_EXECUTABLE_RULE`, `RULE_CONTRACT_MISMATCH` or
  `RULE_NOT_IN_BUNDLE`.
* **Do not show a control as assessable unless this is `true`.**

### 2.3 Schema subset (`schema_subset`, dialect `securden-policy-schema-subset/1`)

Types and their allowed keywords:

| Type | Keywords |
|---|---|
| boolean | `type`, `title`, `description` |
| integer | + `minimum`, `maximum`, `enum` |
| number | + `minimum`, `maximum` |
| string | + `minLength`, `maxLength`, `pattern`, `enum` |
| array | + `items` (exactly one), `minItems`, `maxItems`, `uniqueItems` |
| object | + `properties`, `required`, `additionalProperties` |

Rules:
* Every object lists **every** property in `required` and sets `additionalProperties: false`.
* There are no optional parameters and no defaults.
* `pattern` is anchored `^…$`.
* `integer` accepts JSON integers only: `true` and `5.0` are rejected.
* `number` accepts integers and finite decimals.
* Any other keyword (`default`, `$ref`, `oneOf`, `format`, `const`, …) is unsupported.

Django can build forms generically from `parameter_schema` plus `ui`. Validate on the
client for UX, but OPM's validation is authoritative.

### 2.4 Target types (`target_types`)

| Type | Kind | Member type | `id` |
|---|---|---|---|
| ORGANIZATION | ALL | – | **must be omitted** |
| ACCOUNT, USER, RESOURCE, SESSION_POLICY, AUDIT_SOURCE | LEAF | – | required, opaque PAM id |
| ACCOUNT_GROUP | GROUP | ACCOUNT | required |
| USER_GROUP | GROUP | USER | required |
| RESOURCE_GROUP | GROUP | RESOURCE | required |

IDs follow the platform `Identifier` pattern: short, no whitespace. Use stable PAM IDs,
not display names.

---

## 3. Collector capability handshake

Until an organization sends a handshake, OPM assumes the **legacy bridge default**
(`capability_source: "LEGACY_BRIDGE_DEFAULT"`): only PAM-ROTATION-001, PAM-SESSREC-001
and PAM-DORMANT-001 are collected. Every other control, including all new ones, reports
`COLLECTOR_MISSING`. Once a handshake exists it **replaces** the default entirely, so
declare every evidence type you collect, including the original three.

`PUT /admin/collector-capabilities`

```json
{"tenant_id": "acme",
 "collector": {"name": "securden-django-bridge", "version": "2.4.0"},
 "evidence": [
   {"evidence_type": "credential_rotation", "schema_version": "1.0"},
   {"evidence_type": "privileged_session", "schema_version": "1.0"},
   {"evidence_type": "privileged_account", "schema_version": "1.0"},
   {"evidence_type": "privileged_access_authentication", "schema_version": "1.0"},
   {"evidence_type": "session_policy_configuration", "schema_version": "1.0"},
   {"evidence_type": "privileged_access_request", "schema_version": "1.0"}]}
```

Response `200`:

```json
{"schema_version": "1.0", "catalog_version": 2, "organization_scope": "<scope>", "changed": true,
 "collector_capabilities": {
   "source": "HANDSHAKE", "digest": "sha256:e3542f03…", "declared_at": "2026-11-16T07:21:40.634794Z",
   "declared_by": "deploy", "collector": {"name": "securden-django-bridge", "version": "2.4.0"},
   "evidence": {"credential_rotation": "1.0", "privileged_access_authentication": "1.0", "…": "…"},
   "evidence_types": [
     {"evidence_type": "access_review", "opm_schema_version": "1.0", "declared_schema_version": null, "compatible": false},
     {"evidence_type": "credential_rotation", "opm_schema_version": "1.0", "declared_schema_version": "1.0", "compatible": true},
     "… one row per OPM evidence type …"]}}
```

* **Declare only what you collect.** Only list an evidence type once the collector really
  produces complete records in that schema version. A declaration is a promise.
* **Repeats are harmless.** Re-sending an identical declaration returns `changed: false`
  and stores nothing. A different declaration is stored as a new immutable row; history
  is kept.
* **Version must match exactly.** An evidence type is usable only when
  `declared_schema_version == opm_schema_version`. Otherwise you get
  `EVIDENCE_SCHEMA_INCOMPATIBLE`.
* **Errors.**
  - `UNKNOWN_EVIDENCE_TYPE` (422, `details.evidence_types`)
  - `INVALID_CAPABILITIES` (422, duplicate type)
  - `VALIDATION_ERROR` (422, shape)
* **Plans go stale.** Changing the declaration changes plan digests (§6.6).
* Call it on deploy and after every collector upgrade. Read it back with `GET /collector-capabilities?tenant_id=`.

---

## 4. Saving policy

### 4.1 Create: `POST /admin/policy-contexts` → 201 (new) or 200 (idempotent replay)

```json
{
  "tenant_id": "acme",
  "request_key": "pam-policy-2026-v1",
  "title": "Privileged access standard",
  "description": "Company PAM thresholds (synthetic example).",
  "policy_reference": {"title": "Information Security Policy - Privileged Access", "identifier": "ISP-07",
                       "section": "7.3", "owner": "CISO office", "approved_on": "2026-10-01"},
  "effective_from": "2026-10-16T06:21:40.000000Z",
  "controls": [
    {"control_id": "PC-MFA-AT-ACCESS", "control_version": "1.0",
     "parameters": {"accepted_methods": ["fido2", "totp"]}, "targets": [{"type": "ORGANIZATION"}]},
    {"control_id": "PC-SESSION-RECORDING", "control_version": "1.0",
     "parameters": {"accept_partial_recordings": false}, "targets": [{"type": "ORGANIZATION"}]},
    {"control_id": "PC-SESSION-IDLE-LIMIT", "control_version": "1.0",
     "parameters": {"max_idle_minutes": 15}, "targets": [{"type": "ORGANIZATION"}]},
    {"control_id": "PC-SESSION-DURATION-LIMIT", "control_version": "1.0",
     "parameters": {"max_session_minutes": 480}, "targets": [{"type": "ACCOUNT_GROUP", "id": "grp-dba"}]},
    {"control_id": "PC-ACCESS-APPROVAL", "control_version": "1.0",
     "parameters": {"max_approval_age_hours": 24}, "targets": [{"type": "ORGANIZATION"}]},
    {"control_id": "PC-ACCESS-REVIEW", "control_version": "1.0",
     "parameters": {"review_interval_days": 90}, "targets": [{"type": "ORGANIZATION"}]},
    {"control_id": "PC-CRED-ROTATION", "control_version": "1.0",
     "parameters": {"max_rotation_age_days": 30}, "targets": [{"type": "ORGANIZATION"}]}
  ]
}
```

Field rules (unknown fields anywhere → 422 `VALIDATION_ERROR`):

| Field | Rule |
|---|---|
| `request_key` | `^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$`. Unique per (scope, tenant) across **all** creates and versions. |
| `title` | 1–200 chars. `description` ≤ 4000, optional. |
| `policy_reference` | `title` 1–300 required. `identifier` ≤128, `section` ≤200, `url` (`https://` only), `owner` ≤200 and `approved_on` (date) are optional. |
| `effective_from` / `effective_to` | UTC timestamps (`Z`). `effective_to` is optional (open-ended) and must be after `effective_from`. The interval is `[from, to)`. |
| `controls` | 1–100 entries. `parameters` ≤ 50 keys. `targets` 1–200. `label` ≤ 120, optional. |

Response (`policy_version`; the first and last controls are shown):

```json
{"schema_version": "1.0", "catalog_version": 2, "organization_scope": "<scope>", "created": true,
 "policy_version": {
  "policy_context_id": "pctx-2cfa71722160443aa7325ed542e2948b",
  "policy_version_id": "pcv-4203b6f36cb841dc8d133af5754ee0ad",
  "version": 1, "organization_scope": "<scope>", "tenant_id": "acme",
  "title": "Privileged access standard", "description": "Company PAM thresholds (synthetic example).",
  "policy_reference": {"approved_on": "2026-10-01", "identifier": "ISP-07", "owner": "CISO office",
                       "section": "7.3", "title": "Information Security Policy - Privileged Access", "url": null},
  "effective_from": "2026-10-16T06:21:40.000000Z", "effective_to": null,
  "status": "ACTIVE",
  "digest": "sha256:365ad87bdb2655dcba303850a51f95121c3de8fc01947857f632b8359c65bc7e",
  "provenance": {"origin": "CUSTOMER_POLICY", "declared_by": "deploy", "declared_at": "2026-11-16T07:21:40.667887Z",
                 "request_key": "pam-policy-2026-v1", "control_catalog_version": "2026.11.16-1",
                 "approval": "NOT_REQUIRED: user-declared organization policy is active on save"},
  "supersession": {"rule": "highest version whose effective interval contains the instant",
                   "in_force_intervals": [{"start": "2026-10-16T06:21:40.000000Z", "end": null}],
                   "superseded_intervals": []},
  "controls": [
   {"entry_id": "ctl-1", "control_id": "PC-MFA-AT-ACCESS", "control_version": "1.0",
    "control_definition_digest": "sha256:f1f0abfb…", "label": null,
    "parameters": {"accepted_methods": ["fido2", "totp"]}, "targets": [{"id": null, "type": "ORGANIZATION"}],
    "provenance": "CUSTOMER_POLICY", "implementation_status": "EXECUTABLE", "assessment_mode": "EVENT_HISTORY",
    "rule_bindings": [{"rule_id": "PAM-MFAACC-001", "rule_version": "1.0",
                       "evidence_type": "privileged_access_authentication", "evidence_schema_version": "1.0",
                       "parameter_map": {"accepted_methods": "accepted_methods"}}],
    "assessment_blockers": []},
   {"entry_id": "ctl-7", "control_id": "PC-CRED-ROTATION", "control_version": "1.0",
    "control_definition_digest": "sha256:018bc0b8…", "label": null,
    "parameters": {"max_rotation_age_days": 30}, "targets": [{"id": null, "type": "ORGANIZATION"}],
    "provenance": "CUSTOMER_POLICY", "implementation_status": "EXECUTABLE", "assessment_mode": "EVENT_HISTORY",
    "rule_bindings": [{"rule_id": "PAM-ROTATION-001", "rule_version": "1.1", "evidence_type": "credential_rotation",
                       "evidence_schema_version": "1.0",
                       "parameter_map": {"max_rotation_age_days": "max_rotation_age_days"}}],
    "assessment_blockers": []}]}}
```

* `entry_id` (`ctl-N`, the 1-based position in `controls`) is stable for that version.
  Targets are stored sorted by (type, id).
* `assessment_blockers` are **computed at read time** against the current bundle and
  handshake. Possible codes:
  - `CONTROL_DEFINITION_UNAVAILABLE`
  - `CONTROL_DEFINITION_CHANGED`
  - `NO_EXECUTABLE_RULE`
  - `COLLECTOR_MISSING`
  - `EVIDENCE_SCHEMA_INCOMPATIBLE`
  - `RULE_NOT_IN_BUNDLE`
  - `RULE_CONTRACT_MISMATCH`
* A version with blockers is still saved. Blockers mean "cannot be assessed now", not
  "invalid".
* The `digest` covers context, version, scope, tenant, title, description, reference,
  effective dates, pinned controls and the catalog version. Store it.

### 4.2 New version: `POST /admin/policy-contexts/{context_id}/versions`

Same body plus `"supersedes_version": <current latest version>`. It returns version
`latest + 1`. A stale `supersedes_version` returns 409 `VERSION_CONFLICT` with
`details.latest_version`: reload and ask the user again. Never auto-retry with the new
number. Versions are never edited or deleted; OPM's storage refuses UPDATE and DELETE.

### 4.3 Idempotency

* **Retries.** Retry a failed or timed-out save with the **same `request_key` and identical
  body**. You get 200, `created: false` and the original version.
* **Conflicts.** The same key with a different body (any field) returns 409
  `IDEMPOTENCY_CONFLICT` with `details.policy_version_id`.
* **Choosing keys.** Generate one new key per user "Save" action. A Django row UUID works
  well, for example `pam-policy-<uuid>`.

### 4.4 Validation errors (422 `INVALID_POLICY_CONTEXT`, every problem at once)

```json
{"error": {"code": "INVALID_POLICY_CONTEXT", "message": "2 problem(s) in the policy context",
  "details": {"problems": [
    {"code": "INVALID_TYPE", "path": "controls[0].parameters.max_rotation_age_days", "message": "expected an integer"},
    {"code": "MISSING_PARAMETER", "path": "controls[1].parameters.max_idle_minutes",
     "message": "required: every value must be stated explicitly (no defaults)"}]}},
 "correlation_id": "opm-983c3292…"}
```

Problem codes:
- `UNKNOWN_CONTROL`
- `UNSUPPORTED_TARGET_TYPE`
- `DUPLICATE_CONTROL_TARGET` (the same control and target twice in one version)
- `MISSING_PARAMETER`
- `UNKNOWN_PARAMETER`
- `INVALID_TYPE`
- `OUT_OF_RANGE`
- `NOT_IN_ENUM`
- `PATTERN_MISMATCH`
- `DUPLICATE_ITEMS`

`path` is relative to the request body. Map it onto form fields.

### 4.5 Reads

* `GET /policy-contexts?tenant_id=acme` returns `items[]`. Each item has
  `policy_context_id`, `created_by`, `created_at`, `latest_version`, `title` and
  `versions[]`. Each entry in `versions[]` has `version`, `policy_version_id`, `digest`,
  `effective_from`, `effective_to`, `created_at` and `control_ids`. Results are paged by
  `after` and `limit` (`has_more`, `next_cursor`).
* `GET /policy-contexts/{id}/versions/{n}?tenant_id=acme` returns the full
  `policy_version` view, as in §4.1, including `supersession`.

---

## 5. Effective dates and supersession (deterministic)

Within one context, at instant *t* the version **in force** is the **highest version
number whose `[effective_from, effective_to)` contains *t***. A new version supersedes
older ones only for the time it covers. Outside that time, older versions stay in force.

Example:
- v1 is effective from 2026-08-01 with no end.
- v2 is effective from 2026-10-27.
- Result: v1 is in force in `[2026-08-01, 2026-10-27)`, and v2 from 2026-10-27 onwards.

The v1 view shows this as follows:

```json
"supersession": {"in_force_intervals": [{"start": "2026-08-01T00:00:00.000000Z", "end": "2026-10-27T00:00:00.000000Z"}],
                 "superseded_intervals": [{"by_version": 2, "by_policy_version_id": "pcv-…", "start": "2026-10-27T00:00:00.000000Z", "end": null}]}
```

* **Selecting versions in a plan.** To cover a reporting period that spans a change,
  select **every** version in force during it, here both v1 and v2. OPM never substitutes
  a version you did not select. Selecting only v1 leaves the v2 time uncovered.
* **Execution segments.** The plan creates one execution per in-force segment, each with
  its own `reporting_period` and parameters.
* **No version in force at all.** A selected version that is not in force at any point in
  the period gets `POLICY_CONTEXT_NOT_EFFECTIVE` and produces no execution.
* **Partial coverage.** A version in force for only part of the period resolves that part.
  The gap becomes `PARTIALLY_RESOLVED` with `uncovered_intervals` and
  `POLICY_CONTEXT_NOT_EFFECTIVE` in `policy_codes`.
* **Rule effective window.** Windows are also clipped to the pinned rule version's
  effective window. For example, PAM-ROTATION-001 1.1 starts 2026-07-01. The clipped-off
  part is reported in `binding.rule_not_effective`.

Back-dating is allowed: the user declares when their policy took effect. `declared_at`
always shows when it was entered. Reports must show both dates (§9).

---

## 6. Plans with policy

### 6.1 Request

Old clients don't change anything. `GET …/plan?tenant_id=` without policy parameters
returns exactly the same plan and digest as before, with no `policy_context` and no
`policy_resolution` fields.

New POST form, which is needed for `target_resolutions`:

```json
POST /api/v1/catalog/evaluation-templates/{framework_id}/plan
{"tenant_id": "acme",
 "policy_version_ids": ["pcv-4203b6f36cb841dc8d133af5754ee0ad"],
 "reporting_period": {"start": "2026-10-17T06:21:40.000000Z", "end": "2026-11-16T06:21:40.000000Z"},
 "target_resolutions": [],
 "as_of": null, "catalog_version": null, "expected_digest": null}
```

The GET equivalent takes `policy_version_id` (repeat it per version) plus
`reporting_period_start` and `reporting_period_end`. GET cannot carry
`target_resolutions`.

| Field | Rule |
|---|---|
| `policy_version_ids` | ≤ 50, `^pcv-[0-9a-f]{32}$`. Requires the scope header (`SCOPE_REQUIRED`) and `reporting_period` (`REPORTING_PERIOD_REQUIRED`). Each version must belong to this scope and tenant, otherwise 404 `UNKNOWN_POLICY_VERSION` with `details.policy_version_id`. |
| `reporting_period` | `end > start`. Without `policy_version_ids` it returns 422 `POLICY_VERSIONS_REQUIRED`. |
| `target_resolutions` | ≤ 500, see §7. Without `policy_version_ids` it returns `POLICY_VERSIONS_REQUIRED`. |
| `as_of` | Defaults to the date of `reporting_period.end` when policy is selected. |
| `expected_digest` / `catalog_version` | As before: a mismatch returns 409 `PLAN_STALE` (§6.6). |

### 6.2 What the plan adds

Regulatory content is unchanged: the same `requirements`, `mappings`, `executions` and
thresholds as without policy. The plan adds:

* `requirements[].policy_resolution`: per-requirement gap status (§6.3).
* `policy_context`: versions, collector capabilities, bindings, policy executions,
  blockers and totals (§6.4).
* `digest_input.policy_context`, which is folded into `plan_digest` (§6.6).

### 6.3 Gap resolution per requirement

```json
{"requirement_id": 2, "assessment": "UNMAPPED", "execution_ids": [],
 "policy_resolution": {
   "gaps": [{"code": "POLICY_CONTEXT_REQUIRED", "topic": "credential rotation", "rule_id": "PAM-ROTATION-001",
             "parameters": ["max_rotation_age_days"],
             "reason": "the passage states no value for max_rotation_age_days; …",
             "status": "RESOLVED_BY_POLICY", "policy_codes": [],
             "binding_ids": ["pcv-4203…#ctl-7"], "uncovered_intervals": [], "target_coverage": "ORGANIZATION"},
            {"code": "PARTIAL_COVERAGE", "rule_id": "PAM-ROTATION-001", "status": "OPEN", "policy_codes": [],
             "binding_ids": ["pcv-4203…#ctl-7"], "uncovered_intervals": [], "target_coverage": null,
             "reason": "the policy-bound rule tests the recorded PAM control only; …"}],
   "policy_execution_ids": ["pexec-3d65e949bd67a86e"],
   "summary": "PARTIALLY_RESOLVED"}}
```

* **`code` comes from the mapping gate**, unchanged. `POLICY_CONTEXT_REQUIRED`,
  `COLLECTOR_MISSING`, `NO_EXECUTABLE_RULE`, `PARTIAL_COVERAGE` and `MAPPING_MISSING` stay
  distinct. COLLECTOR_MISSING is reported **before** POLICY_CONTEXT_REQUIRED, so an
  uncollected rule never becomes "resolved by policy".
* **Only `POLICY_CONTEXT_REQUIRED` can be resolved**, and only by a binding whose control
  lists that rule in `addresses_gap_rules`. Gaps of every other code stay `OPEN`.
  `binding_ids` on those gaps lists related bindings for display only.
* **Organization-defined values.** A gap may carry `organization_defined[]`, the literal
  `[Assignment: …]` / `[Selection: …]` texts of the passage. It is `POLICY_CONTEXT_REQUIRED`
  even when the rule has no parameters, because the passage's selectors (users or roles,
  account classes, circumstances) must come from policy targets and settings. Show these
  texts next to the policy form.
* **Partial coverage after resolution.** Whenever a POLICY_CONTEXT_REQUIRED gap becomes
  `RESOLVED_BY_POLICY` or `PARTIALLY_RESOLVED`, a `PARTIAL_COVERAGE` gap for the same rule
  follows it with status `OPEN`. The bound rule tests its PAM control only. For example,
  MFA at access does not test separate-device or strength conditions, and recording
  availability does not test who may view recordings. The requirement's `summary` is
  therefore `PARTIALLY_RESOLVED` at best. Report the untested remainder.
* **`status` values:**
  - `RESOLVED_BY_POLICY`: the whole period is covered with ORGANIZATION targets.
  - `PARTIALLY_RESOLVED`: part of the period is uncovered (`uncovered_intervals`), or only
    some targets are covered (`target_coverage: "SELECTED_TARGETS"`).
  - `BLOCKED`: matching bindings exist but every one is blocked; see `policy_codes`.
  - `OPEN`: no usable policy.
* **`summary` values:**
  - `NO_GAPS`
  - `RESOLVED_BY_POLICY`: every gap is resolved. Every policy resolution is followed by an
    open `PARTIAL_COVERAGE` entry, so this value does not occur with the current rules.
    Django should still handle it.
  - `PARTIALLY_RESOLVED`: at least one gap is resolved or partially resolved.
  - `OPEN`
* **`assessment` is not changed by policy.** A requirement resolved by policy still says
  `UNMAPPED` or whatever it said before. Its automated evidence comes from the
  `policy_execution_ids`, and the report must label it as assessed against company
  policy (§9).
* **Regulatory thresholds stay.** A requirement with a published regulatory mapping has
  no POLICY_CONTEXT_REQUIRED gap for that rule. Its execution keeps the regulatory value,
  for example 90 days, and `policy_execution_ids` is empty.
* **The operative-text and PAM-scope gates run first.** A recital or other non-operative
  passage (`NON_OPERATIVE_TEXT`), or a passage outside PAM scope (`OUTSIDE_PAM_SCOPE`),
  carries only that gap. Policy never resolves it and never makes it assessable.

### 6.4 `policy_context` section

```json
{"reporting_period": {"start": "…", "end": "…"}, "provenance": "CUSTOMER_POLICY",
 "statement": "Organization policy values are company thresholds declared by the organization, not legislation. …",
 "versions": [{"policy_version_id": "pcv-4203…", "policy_context_id": "pctx-2cfa…", "version": 1,
               "digest": "sha256:365a…", "title": "Privileged access standard",
               "effective_from": "…", "effective_to": null, "in_force_in_period": [{"start": "…", "end": "…"}]}],
 "collector_capabilities": {"source": "HANDSHAKE", "digest": "sha256:e354…", "declared_at": "…", "evidence": {"…": "1.0"}},
 "target_resolutions": [{"target": {"type": "ACCOUNT_GROUP", "id": "grp-dba"}, "complete": true,
                         "valid_from": "…", "valid_to": null, "member_count": 12, "membership_digest": "sha256:…"}],
 "bindings": ["… §6.5 …"], "executions": ["… §8 …"],
 "blockers": [{"code": "COLLECTOR_MISSING", "message": "…", "binding_ids": ["pcv-4203…#ctl-6"]}],
 "totals": {"bindings": 7, "blocked_bindings": 1, "unused_bindings": 4, "executions": 3,
            "requirements_resolved": 0, "requirements_partially_resolved": 3}}
```

### 6.5 Bindings

There is one binding per (selected version × control entry), `binding_id = "<pcv-id>#ctl-N"`:

```json
{"binding_id": "pcv-4203…#ctl-6", "provenance": "CUSTOMER_POLICY",
 "policy_version_id": "pcv-4203…", "policy_context_id": "pctx-2cfa…", "policy_version": 1,
 "policy_version_digest": "sha256:365a…", "policy_effective_from": "…", "policy_effective_to": null,
 "control_id": "PC-ACCESS-REVIEW", "control_version": "1.0", "control_definition_digest": "sha256:bcb9…",
 "assessment_mode": "EVENT_HISTORY", "control_parameters": {"review_interval_days": 90},
 "targets": [{"id": null, "type": "ORGANIZATION"}], "target_set_digest": "sha256:43a1…",
 "rule_id": "PAM-REVIEW-001", "rule_version": "1.0", "evidence_type": "access_review",
 "evidence_schema_version": "1.0", "rule_parameters": {"review_interval_days": 90},
 "windows": [{"start": "…", "end": "…"}],
 "blocker_codes": ["COLLECTOR_MISSING"],
 "blocker_details": [{"code": "COLLECTOR_MISSING", "evidence_type": "access_review",
   "message": "The organization's collector does not declare this evidence type; the control cannot be assessed end to end."}],
 "addresses_requirement_ids": [], "execution_ids": [], "addresses_gap_rules": ["PAM-REVIEW-001"],
 "unused_reason": "NO_MATCHING_GAP: no published requirement of this framework has a POLICY_CONTEXT_REQUIRED gap this control resolves (regulatory thresholds are never replaced by company values)"}
```

Binding blocker codes:

| Code | Meaning | What Django does |
|---|---|---|
| `NO_EXECUTABLE_RULE` | The control is documented only | Show it as policy-only; never assessed |
| `COLLECTOR_MISSING` | The handshake doesn't declare the evidence type | Build the collector, then declare it (§3) |
| `EVIDENCE_SCHEMA_INCOMPATIBLE` | A different schema version was declared | Upgrade the collector |
| `RULE_NOT_IN_BUNDLE` / `RULE_CONTRACT_MISMATCH` / `RULE_VERSION_UNAVAILABLE` | The pinned rule can't run on this OPM | Operator issue; save against a newer control version when one is released |
| `PARAMETERS_INCOMPATIBLE` | The value violates the rule's constraints | Save a corrected version |
| `RULE_INACTIVE_FOR_TENANT` | The rule is deactivated for the tenant | Reactivate it or accept that it's blocked |
| `CONTROL_DEFINITION_UNAVAILABLE` / `CONTROL_DEFINITION_CHANGED` | The pinned control definition is gone or changed | Save a new version |
| `POLICY_CONTEXT_NOT_EFFECTIVE` | Not in force at any time in the period | Select the right version(s) or fix the dates |
| `POLICY_CONFLICT` | Overlapping targets and time with different values for the same rule | Resolve in policy (§7.2) |
| `POLICY_SCOPE_UNRESOLVED` | Overlap can't be decided without membership | Send `target_resolutions` (§7.3) |

A blocked binding produces **no execution**. A binding whose control resolves no gap in
this framework has `unused_reason` and an empty `execution_ids`, and is never run for
this framework.

### 6.6 Digest, staleness and pinning

`plan_digest` = sha256 over the canonical `digest_input`. With policy selected,
`digest_input.policy_context` adds:
- the reporting period
- selected version IDs and digests
- each selected context's **latest** version number
- collector capabilities (source and digest)
- target-resolution summaries (`membership_digest`)
- each binding's blockers, executions and requirements
- each execution's identity
- each requirement's gap statuses

The plan goes stale (409 `PLAN_STALE` on `expected_digest`) when any of these changes:
- a new version is saved in a selected context, even one you didn't select
- the collector declaration changes
- membership changes
- the bundle, catalog or mapping changes

Stale-plan error:

```json
{"error": {"code": "PLAN_STALE", "message": "The catalog or policy bundle changed; resolve a new plan before evaluating.",
  "details": {"catalog_version": 2, "plan_digest": "sha256:3ae1…", "policy_bundle_version": "2026.11.16-1"}}}
```

Before running a saved plan, re-request it with the same inputs plus `expected_digest`.
On 409, show the user what changed and re-plan. Never run executions from a stale plan.

---

## 7. Targeting, membership and conflicts

### 7.1 Who decides membership

Django does, inside the organization. OPM stores target IDs only as labels. It never
looks up PAM objects, and it treats every target ID as untrusted for authorization.

### 7.2 Overlap and conflict rules

Two bindings conflict only when all three hold:
1. They are for the **same rule**.
2. They have **different `rule_parameters`**.
3. They have **overlapping windows and overlapping targets**.

Bindings with identical values never conflict.

How target overlap is decided:

| Pair | Overlap |
|---|---|
| ORGANIZATION vs anything | yes |
| Identical targets | yes |
| Two leaves of the same type (e.g. ACCOUNT a1 vs ACCOUNT a2) | no |
| Group vs leaf or group | decided from `target_resolutions` when complete and covering the window. Otherwise **unknown** |
| Member sets of different kinds (e.g. accounts vs resources) | **unknown**: OPM doesn't hold the relation |

The outcome is `POLICY_CONFLICT` when overlap is known and `POLICY_SCOPE_UNRESOLVED`
when it's unknown. Both bindings are blocked, and each lists the other in
`blocker_details[].with_binding_id` together with the conflicting `window`. OPM never
picks a winner: precedence is a policy decision, so Django must make the user resolve
it, for example by narrowing targets or aligning values.

### 7.3 `target_resolutions` (frozen historical membership)

```json
{"target": {"type": "ACCOUNT_GROUP", "id": "grp-finance"},
 "members": [{"type": "ACCOUNT", "id": "acct-001"}, {"type": "ACCOUNT", "id": "acct-002"}],
 "complete": true,
 "valid_from": "2026-10-16T00:00:00Z", "valid_to": null}
```

* **Groups only.** A resolution covers a GROUP target. `members` must all be of the
  group's member type, up to 10,000.
* **One window.** A resolution is used for a window only when `complete: true` **and**
  `[valid_from, valid_to)` covers the whole window. Current membership alone
  (`valid_from` = today) does **not** cover a past period, so you get
  `POLICY_SCOPE_UNRESOLVED`. That is the "missing historical membership" case.
* **Changing membership.** OPM takes one resolution per target. If membership changed
  during the period, either send the union with `complete: true` (an over-approximation
  for overlap), or shorten the reporting period.
* **No proof value.** OPM records only `member_count` and `membership_digest` in the plan.
  It's for overlap decisions only, never proof of membership.

---

## 8. Running policy executions and partitioning evidence

Each element of `policy_context.executions` is one run:

```json
{"execution_id": "pexec-3d65e949bd67a86e", "provenance": "CUSTOMER_POLICY",
 "rule_id": "PAM-ROTATION-001", "rule_version": "1.1", "parameters": {"max_rotation_age_days": 30},
 "binding_id": "pcv-4203…#ctl-7", "policy_version_digest": "sha256:365a…", "target_set_digest": "sha256:43a1…",
 "reporting_period": {"start": "2026-10-17T06:21:40.000000Z", "end": "2026-11-16T06:21:40.000000Z"},
 "evidence_type": "credential_rotation", "evidence_schema_version": "1.0",
 "evidence_requirements": ["One record per privileged account managed by Securden in the reporting scope", "…"],
 "assessment_mode": "EVENT_HISTORY", "control_id": "PC-CRED-ROTATION", "control_version": "1.0",
 "policy_version_id": "pcv-4203…", "policy_context_id": "pctx-2cfa…",
 "targets": [{"id": null, "type": "ORGANIZATION"}],
 "evaluate_request": {
   "rule_id": "PAM-ROTATION-001", "rule_version": "1.1",
   "reporting_period": {"start": "2026-10-17T06:21:40.000000Z", "end": "2026-11-16T06:21:40.000000Z"},
   "policy_settings": {"policy_version": "pcv-4203…", "effective_from": "2026-10-16T06:21:40.000000Z",
                       "parameters": {"max_rotation_age_days": 30}}},
 "evidence_partition": {"include": "records of objects that are members of any of 'targets' during reporting_period, as resolved by Django inside the organization",
                        "expected_record_count": "the size of that frozen member set (completeness.expected_record_count)",
                        "target_set_digest": "sha256:43a1…"},
 "requirement_ids": [2]}
```

**Call:** `POST /api/v1/evaluate` with `{"tenant_id": …, **evaluate_request, "evidence": {…}}`.

* **Send `evaluate_request` unchanged.** `rule_version`, `policy_version`,
  `effective_from`/`effective_to` and `parameters` are pinned. Never substitute other
  values or versions, and never "fill in" a parameter.
* **Old periods.** If the period ended more than `historical_threshold_days` ago (default
  35), add `"evaluation_mode": "HISTORICAL"`. The pinned fields already satisfy HISTORICAL
  mode's requirements.
* **Period checks.** OPM rejects a period that ends in the future (`PERIOD_IN_FUTURE`).
  It also rejects policy settings that don't cover the period
  (`POLICY_SETTINGS_NOT_EFFECTIVE`); plan segments never trigger this.

**Evidence partition.** Do this for each execution:
1. Resolve the members of `targets` during `reporting_period`. `ORGANIZATION` means every
   in-scope object of the rule's subject type in this organization.
2. Send records **only for those members**, in `evidence_type` at
   `evidence_schema_version`.
3. Set `completeness.expected_record_count` to the member count, `received_record_count`
   to what you send, and `source_complete` honestly. Missing records lead to
   `INSUFFICIENT_EVIDENCE`, never PASS.
4. Freeze the member list and keep it with the result (§9). Its digest should match what
   you sent in `target_resolutions`.

Two non-conflicting bindings for the same rule (e.g. group A 30 days and account X 60
days, disjoint) are **two executions with separate partitions**. Never merge them.
The evidence of the wrong type is rejected: e.g. sending
`authentication_summary` to PAM-MFAACC-001 → 422 `EVIDENCE_TYPE_MISMATCH`.

**Results:** `decision_details.parameters` holds the values used, and
`decision_details.customer_policy_version` holds the `pcv-…` ID. Store both.

### 8.1 New evidence contracts (schema 1.0; full JSON Schema in `schemas/evidence_records.schema.json`)

`privileged_access_authentication` (event history, one record per privileged access attempt):

| Field | Type | Rule |
|---|---|---|
| record_id, access_id, user_id, account_id | string | required |
| accessed_at | UTC timestamp | required; only in-period records are evaluated |
| access_granted | bool | only granted accesses are evaluated |
| mfa_status | `VERIFIED \| NOT_PERFORMED \| FAILED \| UNKNOWN` | required |
| mfa_method | method enum or null | **set exactly when** `mfa_status = VERIFIED` |

Rule outcomes:
- Violations: `MFA_NOT_PERFORMED`, `ACCESS_GRANTED_AFTER_FAILED_MFA` and
  `MFA_METHOD_NOT_ACCEPTED`.
- `UNKNOWN` leads to undetermined `MFA_STATUS_UNKNOWN`, giving INSUFFICIENT_EVIDENCE.

`mfa_configuration` (configuration snapshot, one record per principal):

| Field | Type | Rule |
|---|---|---|
| record_id, principal_id | string | required |
| principal_type | `USER \| ACCOUNT` | required |
| privileged, enabled | bool | only privileged **and** enabled principals are evaluated |
| mfa_enforced | bool or null | null means unknown |
| mfa_methods | list of method enums | unique; non-empty **only when** `mfa_enforced` is true |
| captured_at | UTC timestamp | must lie inside the reporting period |

Rule outcomes:
- Violations: `MFA_NOT_ENFORCED` and `NO_ACCEPTED_MFA_METHOD`.
- Undetermined: `SNAPSHOT_OUTSIDE_PERIOD` and `MFA_CONFIGURATION_UNKNOWN`.
- `metrics.assessment_basis = "CONFIGURATION_SNAPSHOT"`.

`session_policy_configuration` (configuration snapshot, one record per session policy):

| Field | Type | Rule |
|---|---|---|
| record_id, policy_id | string | required |
| applies_to_privileged | bool | only true records are evaluated |
| idle_timeout_enabled | bool | required |
| idle_timeout_minutes | int 1..100000 or null | **set exactly when** enabled |
| captured_at | UTC timestamp | inside the period |

Rule outcomes:
- Violations: `IDLE_TIMEOUT_DISABLED` and `IDLE_TIMEOUT_EXCEEDS_MAXIMUM`.
- Undetermined: `SNAPSHOT_OUTSIDE_PERIOD` and `NO_SESSION_POLICY_SUPPLIED` (no
  privileged policy sent).

PAM-SESSDUR-001 reuses `privileged_session` 1.0:
- Sessions that start in the period are evaluated.
- An open session (`ended_at: null`) is measured up to the period end.
- Violations: `SESSION_DURATION_EXCEEDED` and `OPEN_SESSION_EXCEEDS_MAXIMUM`.

Rules with no Securden default (PAM-MFACFG-001, PAM-MFAACC-001, PAM-SESSIDLE-001,
PAM-SESSDUR-001) return 422 `MISSING_PARAMETER` when a value is not stated.
`accepted_methods` must be a non-empty list of distinct known methods, otherwise
`INVALID_PARAMETER`.

---

## 9. What Django must store and report

### 9.1 Suggested Django migrations

OPM stores policy itself. Django keeps references and frozen evaluation metadata.

| Django table | Columns |
|---|---|
| `opm_policy_context` | org FK, tenant_id, `policy_context_id`, created_by (Django user), created_at |
| `opm_policy_version` | FK, `policy_version_id`, `version`, `digest`, `request_key` (unique), effective_from/to, `declared_at`, Django user who saved it, raw OPM response (JSON) |
| `opm_collector_declaration` | org FK, tenant_id, declared evidence map, OPM `digest`, `declared_at`, collector version |
| `assessment_run` (extend) | framework_id, `plan_digest`, reporting_period start/end, selected `policy_version_ids`, collector `digest` used |
| `assessment_execution_result` (extend) | `execution_id` (`pexec-…` or regulatory), `provenance` (`REGULATORY` / `CUSTOMER_POLICY`), `binding_id`, `policy_version_id`, `policy_version_digest`, `control_id`/`version`, `target_set_digest`, frozen member list (or its digest plus a blob reference), `expected/received_record_count`, OPM result JSON incl. `decision_details` |

Everything is append-only. Never update a stored OPM response; supersede it with a new row.

### 9.2 Report requirements

* **Label provenance.** Mark every policy-based result as **"Assessed against organization
  policy (CUSTOMER_POLICY)"**. It is not a legal threshold. Show the policy title,
  `policy_reference`, version and digest, the parameter values, `effective_from`/`to` and
  `declared_at`.
* **Show coverage.** Show `uncovered_intervals` and `target_coverage: SELECTED_TARGETS` as
  partial coverage. Objects outside the targets were **not** assessed.
* **Keep gaps visible.** Show every open gap with its code. Keep COLLECTOR_MISSING,
  NO_EXECUTABLE_RULE, PARTIAL_COVERAGE, POLICY_CONTEXT_REQUIRED, POLICY_CONFLICT,
  POLICY_SCOPE_UNRESOLVED and POLICY_CONTEXT_NOT_EFFECTIVE separate. Never roll them into
  "pass" or "not applicable".
* **Show the basis.** Show `assessment_mode`. A CONFIGURATION_SNAPSHOT result reads "the
  configuration captured at <captured_at> met the policy", not "enforced throughout the
  period".
* **Regulatory first.** Regulatory executions and their thresholds appear as before.
  Policy results never replace them.
* **Reproducibility.** Keep `plan_digest`, the collector digest, policy version digests,
  `target_set_digest` and the frozen member lists. Together these reproduce the run.

### 9.3 Error summary

| HTTP | Code | When |
|---|---|---|
| 403 | `TENANT_FORBIDDEN`, `SCOPE_FORBIDDEN`, `FORBIDDEN` | wrong tenant, scope owned by another credential, missing scope permission |
| 404 | `UNKNOWN_POLICY_CONTEXT`, `UNKNOWN_POLICY_VERSION`, `UNSUPPORTED_FRAMEWORK` | unknown **or another organization's** object |
| 409 | `IDEMPOTENCY_CONFLICT`, `VERSION_CONFLICT`, `PLAN_STALE` | §4.3, §4.2, §6.6 |
| 422 | `VALIDATION_ERROR`, `INVALID_POLICY_CONTEXT`, `INVALID_CAPABILITIES`, `UNKNOWN_EVIDENCE_TYPE`, `SCOPE_REQUIRED`, `REPORTING_PERIOD_REQUIRED`, `POLICY_VERSIONS_REQUIRED` | request problems |
| 422 | `MISSING_PARAMETER`, `INVALID_PARAMETER`, `EVIDENCE_TYPE_MISMATCH`, `PERIOD_IN_FUTURE`, `POLICY_SETTINGS_NOT_EFFECTIVE`, `HISTORICAL_MODE_REQUIRED` | `/evaluate` |
| 503 | `CATALOG_SCHEMA_OUTDATED` | the catalog DB predates policy tables; start the catalog management process once |

Branch on `error.code`, not the message.

---

## 10. Worked examples

All examples assume the scope header and `tenant_id: "acme"`.

**Rotation, a requirement without a stated interval.** Save PC-CRED-ROTATION
`{"max_rotation_age_days": 30}` for ORGANIZATION. The requirement "regularly change the
passwords of privileged accounts" has a POLICY_CONTEXT_REQUIRED gap. It becomes
RESOLVED_BY_POLICY with one execution at 30 days. A requirement that states "every 90
days" keeps its regulatory execution at 90 days, and its `policy_execution_ids` stay
empty.

**MFA.**
- Save PC-MFA-AT-ACCESS `{"accepted_methods": ["fido2","totp"]}`.
- *Before* declaring `privileged_access_authentication` 1.0 in the handshake, the MFA
  requirement shows `COLLECTOR_MISSING`, status `OPEN`.
- After declaring it, the gap becomes `POLICY_CONTEXT_REQUIRED` → `RESOLVED_BY_POLICY`.
- At run time:
  - A VERIFIED `sms` access fails with `MFA_METHOD_NOT_ACCEPTED`.
  - A NOT_PERFORMED access fails with `MFA_NOT_PERFORMED`.
- Saving only PC-MFA-CONFIGURATION leaves the MFA gap `OPEN`. That binding gets
  `unused_reason`.

**Session recording and limits.**
- PC-SESSION-RECORDING `{"accept_partial_recordings": false}`.
- PC-SESSION-IDLE-LIMIT `{"max_idle_minutes": 15}`: a snapshot. Send
  `session_policy_configuration` captured inside the period.
- PC-SESSION-DURATION-LIMIT `{"max_session_minutes": 480}` for
  `ACCOUNT_GROUP grp-dba`: send only sessions of grp-dba members, with
  expected_record_count matching. The gap is `PARTIALLY_RESOLVED` with
  `target_coverage: "SELECTED_TARGETS"` because only that group is covered.

**Approvals.** PC-ACCESS-APPROVAL `{"max_approval_age_hours": 24}` uses
`privileged_access_request` 1.0 and needs that type in the handshake.

**Access reviews (an unavailable collector).** PC-ACCESS-REVIEW
`{"review_interval_days": 90}` is saved and accepted. Without `access_review` in the
handshake:
- The version view shows `assessment_blockers: [{"code": "COLLECTOR_MISSING", "rule_id": "PAM-REVIEW-001", …}]`.
- The plan binding is blocked with `COLLECTOR_MISSING` and has no execution.
- The review requirement keeps `{"code": "COLLECTOR_MISSING", "status": "OPEN", "policy_codes": ["COLLECTOR_MISSING"]}`.
- The catalog shows `assessability.end_to_end_assessable: false, reason: "COLLECTOR_MISSING"`.

**Documented-only control.** PC-PASSWORD-POLICY `{"min_length": 16,
"required_character_classes": 3, "min_entropy_bits": 70.0, "history_depth": 12}` is
saved. It always carries `NO_EXECUTABLE_RULE` and never runs. Show it as documented
policy.

**Conflict.**
- Group grp-finance at 30 days and account acct-007 at 60 days, with no membership sent:
  both get `POLICY_SCOPE_UNRESOLVED`.
- Send `target_resolutions` for grp-finance (complete, covering the period):
  - If acct-007 is a member: `POLICY_CONFLICT`.
  - If not: two executions, and the gap is `PARTIALLY_RESOLVED` (selected targets only).
- ORGANIZATION at 45 days vs acct-007 at 60 days is always a `POLICY_CONFLICT`.

---

## 11. Rollout checklist (Django)

1. **Get the new OPM build onto the stack.** Deploy it, start the catalog management
   process once (it creates the policy tables), and confirm `/ready` reports bundle
   `2026.11.19-1`. Saved plan digests from the earlier bundle become stale; that's
   expected.
2. **Send the handshake.** `PUT /admin/collector-capabilities` with exactly the evidence
   types the collector produces today: `credential_rotation`, `privileged_session` and
   `privileged_account` for the current bridge.
3. **Build the policy UI.** Generate it from `GET /policy-controls` (`parameter_schema` +
   `ui`). Show `assessability` per control and hide or flag anything not `true`.
4. **Save policy** with fresh `request_key`s. Keep `pcv-…` IDs and digests.
5. **Plan and run.**
   - Request the plan with `policy_version_ids`, `reporting_period` and, for group
     targets, `target_resolutions`.
   - Re-check it with `expected_digest` before running.
   - Run regulatory `executions` and `policy_context.executions` with partitioned
     evidence.
6. **Extend the collectors**, then the handshake: `privileged_access_authentication`,
   `session_policy_configuration`, `mfa_configuration`, `privileged_access_request`,
   `access_review`, and so on. Each one makes its controls assessable without any OPM
   change.
