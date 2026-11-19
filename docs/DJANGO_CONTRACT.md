# Django ↔ OPM catalog contract

The single, current contract for the Securden Django/Ember app that calls the OPM regulatory catalog. It replaces the
earlier per-change handoffs. Evaluation itself is documented in EVALUATION_API.md, and internals in REGINTEL.md.
Every change so far has been additive: no field has been renamed or removed.

## 1. Transport, envelope, errors

- Base URL `https://192.168.7.7` with the same CA, client certificate and bearer token as evaluation. mTLS is
  mandatory.
- Read API prefix: `/api/v1/catalog`. Management API prefix: `/api/v1/catalog/admin`. Management calls need the
  stack started with `--with-catalog-admin`; without it the edge answers 502 with a non-JSON body.
- JSON bodies reject unknown fields with 422, including `actor`: OPM records the credential's `key_id` as the actor.
- Every success body carries `schema_version` and `catalog_version` (an integer that moves only on publication).
- Lists take `after` and `limit` (default 100, max 500) and return `has_more` and `next_cursor`.
- Errors are `{"error": {"code", "message", "details"?}, "correlation_id"}`. Branch on `error.code`. Workflow errors
  fill `details` (for example `PUBLICATION_BLOCKED` → `details.problems`).
- The body limit is 5 MiB. Query parameters show up in the edge access log, so never put secrets in them.
- Treat every returned text as untrusted: escape it and never render uploaded HTML.
- Admin document rows report `complete` as `0/1`. The read, template and plan APIs return real booleans.

| Status | Codes | Caller action |
|---|---|---|
| 401 | `UNAUTHENTICATED` | fix configuration |
| 403 | `FORBIDDEN`, `TENANT_FORBIDDEN`, `SCOPE_FORBIDDEN` | hide the action for this credential |
| 404 | `NOT_FOUND`, `UNKNOWN_*`, `UNSUPPORTED_FRAMEWORK` | the id doesn't exist (or belongs to another organization scope) |
| 409 | workflow codes, `CATALOG_CONFLICT`, `IDEMPOTENCY_CONFLICT`, `PLAN_STALE` | refresh state; don't retry unchanged |
| 413 | `PAYLOAD_TOO_LARGE` | check size before sending |
| 422 | `VALIDATION_ERROR`, `INVALID_*`, `MISSING_*`, `*_REQUIRED`, `EMPTY_UPLOAD`, `INVALID_PDF` | show next to the field |
| 429 / 503 | `RATE_LIMITED`, `CATALOG_BUSY`, `QUEUE_FULL` (`Retry-After`) | back off, re-read state |
| 502 | non-JSON | catalog-admin not running |

Retry rule: the client never replays POSTs. After a timeout on a write, **read first**. Only job submission and scoped
uploads are safe to repeat, because of `request_key`.

## 2. Scopes and the health handshake

| Scope | Allows |
|---|---|
| `catalog:read` | everything under `/api/v1/catalog/*` except `/admin`; 403 on every management path |
| `catalog:operate` | `POST /admin/uploads`, `/jurisdictions`, `/jurisdictions/memberships`, `/authorities`, `/frameworks`, `/sources`, `/mappings`, jobs `sync`/`extract`/`discover` |
| `catalog:review` | `POST /admin/sources/{id}/verify`, `/documents/{id}/review`, `/frameworks/{id}/verify`, `/requirements/{id}/translation-review`, `/reviews/{kind}/{id}` |
| `catalog:publish` | `POST /admin/publish`, `/admin/mappings/{id}/withdraw` |
| `catalog:automate` | job `prepare_catalog` (`catalog:operate` alone gets 403) |
| any management scope | every management GET (draft text, document text, job history, attempts) |

`securden-pam` currently holds all of them. Separate per-reviewer credentials are optional
(`scripts/manage_keys.py add reviewer-<person> --scopes catalog:review,catalog:publish,catalog:read`, then restart).

`GET /api/v1/catalog/admin/health`:

The response advertises `capabilities.bounded_rule_generation_v1` and a
`rule_generation` object. Django must require both
`auto_rule_generation=true` and `auto_publish_validated_rules=true` before it
offers fully automatic PAM-check assignment. Evaluation-plan executions for
generated rules include `generated_rule.required_fields`; collectors must
confirm that every listed field is supported before submitting evidence.

```json
{"status": "ok", "key_id": "securden-pam",
 "scopes": ["catalog:automate", "catalog:operate", "catalog:publish", "catalog:read", "catalog:review"],
 "policy_bundle_version": "2026.11.12-1",
 "automation": {"scope": "catalog:automate", "policy_version": "auto-v3", "enabled": true},
 "rewrite_contract_version": "1.0",
 "capabilities": {"prepare_catalog_v1": true, "scoped_imports_v1": true,
                  "scoped_catalog_v1": true, "bounded_rule_generation_v1": true},
 "rule_generation": {"supported": true, "auto_rule_generation": true,
                     "auto_publish_validated_rules": true,
                     "compiler_version": "pam-rulespec-compiler-1.0", "spec_version": "1.0"},
 "schema_version": "1.0", "catalog_version": 12}
```

Show the automated triggers only when `automation.enabled` is true. Enable the rewrite UI only when all four
capabilities and both rule-generation flags are true, since the capabilities are false without
`catalog:automate`. Compare `policy_bundle_version` with
`GET /api/v1/version` to confirm both processes run one bundle.

## 3. Organization scope (rewrite contract 1.0)

| Rule | Behaviour |
|---|---|
| Header | `X-Securden-Organization-Scope: <opaque id>` matching `^[A-Za-z0-9_-]{16,128}$`, otherwise 422 `INVALID_SCOPE`. OPM never interprets it |
| Binding | the first credential to present a scope owns it. Any other credential gets 403 `SCOPE_FORBIDDEN` |
| Visibility | global rows (official catalog) plus the caller's own scope, never another scope. Another scope's ids return the same 404 as unknown ids |
| Isolated | frameworks created from uploads, sources, documents, requirements, mappings, upload requests, jobs, plans |
| Echo | every scoped response carries `organization_scope` |
| Global only | coverage and metrics. The changes feed hides other scopes' publications |
| Without the header | legacy behaviour (an operator view that lists all jobs). The rewrite UI must always send it |

## 4. Management API

### 4.1 Registry

ISO countries and subdivisions are already present; read them via `GET /api/v1/catalog/jurisdictions` and consume all
pages (249 countries). Register in order: jurisdiction → authority → framework → source or upload.

| Call | Body | Success |
|---|---|---|
| `POST /jurisdictions` | `code` (`XX`, `XXX`, `XX-YYY`), `kind` (`COUNTRY_OR_TERRITORY`, `SUBDIVISION`, `SUPRANATIONAL`, `INTERNATIONAL`), `name`, opt `parent_code` | 201 `REGISTERED` |
| `POST /jurisdictions/memberships` | `group`, `member`, `valid_from`, opt `valid_to` (exclusive) | 201 |
| `POST /authorities` | `id` (slug), `name`, `jurisdiction`, `official_domains`, opt `languages` | 201 `UNVERIFIED` |
| `POST /frameworks` | `id` (`[A-Z0-9-]{2,48}`), `title`, `kind` (`LAW`…`INDUSTRY_FRAMEWORK`), `adoption` (`STATUTORY`, `VOLUNTARY`, `CONTRACTUAL`), `jurisdiction`, `authority_id`, opt `industries`, `cross_border` | 201 `UNVERIFIED` |
| `POST /sources` | `id`, `adapter_type` (`eurlex`, `static_list`, `index_page`), `name`, `authority_id`, `jurisdiction`, `languages`, `config` (opt `section_screen`; see REGINTEL.md §7; `static_list` accepts `pdf`) | 201 `PROPOSED` |
| `GET /authorities`, `/frameworks`, `/frameworks/{id}`, `/sources` | – | not paginated. Frameworks add `review_status` and `last_review`; detail adds `reviews` |

Duplicates return 409 `CATALOG_CONFLICT`; unknown references return 404 `UNKNOWN_JURISDICTION` / `UNKNOWN_AUTHORITY`.
A new jurisdiction isn't announced in `/changes`, so re-fetch the list.

### 4.2 Uploads: `POST /uploads`

The body is the **raw file bytes** (`application/octet-stream`, not multipart). Query parameters: `filename`
(`^[A-Za-z0-9][A-Za-z0-9._-]*\.(pdf|html|txt)$`, ≤ 150; sanitize first), `language` (BCP 47, default `en`),
`provenance` (30–2000), `license_note` (3–300).

| | Legacy (no scope header) | Scoped (header present) |
|---|---|---|
| `framework_id` | required, with an authority (422 `FRAMEWORK_AUTHORITY_REQUIRED`) | optional; empty means auto-detect at import |
| `jurisdictions` | – | required JSON array, e.g. `["EU"]` (422 `INVALID_JURISDICTIONS`) |
| `request_key` | – | required, 8–100 (422 `REQUEST_KEY_REQUIRED`) |
| Result | 201 `{source_id, status:"PROPOSED", sha256, bytes, next_step}`. Nothing is parsed until a human verifies the source and a `sync` job runs. Uploading twice creates two sources | 201 `{organization_scope, document_ids, content_sha256, source_id, source_origin:"UPLOADED_DOCUMENT"}`. The file is parsed immediately and the source is auto-verified as **organization-scoped working input, never official**. Same key with the same bytes and metadata: 200 replay. Changed: 409 `IDEMPOTENCY_CONFLICT` |

Shared errors: 413 `PAYLOAD_TOO_LARGE` (5 MiB), 422 `EMPTY_UPLOAD`, `INVALID_PDF`. Scanned PDFs come back incomplete
because there is no OCR.

### 4.3 Verification and review

| Call | Body | Notes |
|---|---|---|
| `POST /sources/{id}/verify` | `outcome` `VERIFIED`/`REJECTED`, `evidence` (30–4000) | the uploader may verify its own source; returns `next_step` |
| `POST /frameworks/{id}/verify` | `decision` `APPROVED`/`REJECTED`, `findings` (required for rejections) | needs no document. Optional `lifecycle`, `published_on`, `effective_from/to`, `superseded_by` need `evidence_version_id` (a reviewed version), else 409 `EVIDENCE_NOT_REVIEWED` / 422 `MISSING_*`. Decisions can be changed and all are kept |
| `POST /documents/{version_id}/review` | `decision`, `comment` (3–4000), opt dates, `supersede_previous` | 409 `ALREADY_REVIEWED`, `DOCUMENT_INCOMPLETE`, `SOURCE_NOT_VERIFIED` |
| `POST /reviews/requirement/{id}` | `decision`, `comment`, `reviewed_in_original_language` | 409 `NOT_DRAFT`, `DOCUMENT_NOT_REVIEWED`, `TRANSLATION_UNREVIEWED`, `SOURCE_ATTRIBUTION_MISMATCH`, `INVENTED_THRESHOLD` |
| `POST /reviews/{kind}/{id}` | same | `mapping`, `evidence_requirement`, `applicability_criteria`, `remediation` |
| `POST /requirements/{id}/translation-review` | `decision` `REVIEWED`/`REJECTED`, opt `corrected_translation` | 409 `NO_TRANSLATION` |
| `GET /pending` → `POST /publish` | – | publishes the **whole** pending queue; 409 `PUBLICATION_BLOCKED` lists the reasons. Show `/pending` before confirming |

Decisions are final: a second decision on the same item returns 409. After publishing, consume `/changes` and refresh
the cache.

### 4.4 Jobs: `POST /jobs` → 202 `{job}`

| Action | Body (plus `request_key` 8–100) | Scope |
|---|---|---|
| `sync` | `source_id` | operate |
| `extract` | `version_id`, `translate` | operate |
| `discover` | `jurisdiction`, `include_inherited` (default true), `as_of` | operate |
| `prepare_catalog` | §5 (schema `job_prepare_catalog.schema.json`) | automate + scope header |

- `build_framework` was **removed** (2026-11-19): a submission is 422 `VALIDATION_ERROR`, and a job queued before the
  upgrade fails with `ACTION_REMOVED`. `prepare_catalog` runs the same pipeline per framework.
- `prepare_catalog` also accepts optional `languages` (`["en"]`) and `screening`
  (`none` | `pam-keyword-screen-v1`). When omitted, the operator defaults apply (this host: English and PAM
  screening). Results carry `options` and the counts `sections_screened_out`, `sections_already_extracted`,
  `model_calls_extraction` and `drafts_left_unscreened`. Unset fields are left out of the stored payload, so
  existing request keys dedupe as before.
- Running jobs report the current framework, stage and section or candidate counter in `progress`
  (e.g. `{"stage":"candidate_review","framework_id":"EU-DORA","framework":"1/4","candidate":"5/22"}`).
- Dedup is per (credential, `request_key`): the same payload returns the same job, a different payload returns 409
  `IDEMPOTENCY_CONFLICT`, and more than 100 waiting jobs returns 503 `QUEUE_FULL`. Persist the key and reuse it after a
  lost response.
  Counting stages also carry `done`, `total` and `unit` (`section` in `extract`, `candidate` in
  `candidate_review`), and `progress.timing` holds the step timing the ETA is computed from (internal; read the
  progress endpoint instead).
- `GET /jobs/{id}`; `GET /jobs?status=&after=&limit=` (newest first, `seq` cursor). Statuses: `QUEUED`, `RUNNING`,
  then `SUCCEEDED`, `PARTIAL`, `FAILED` or `INTERRUPTED`. Running jobs expose `progress {stage, at, …}`.
- `GET /jobs/{id}/progress` (management read scopes; same organization-scope visibility as `GET /jobs/{id}`, 404
  `UNKNOWN_JOB` otherwise). Client: `job_progress(job_id)`. Returns `progress` and `eta_reasons`:

  | Field | Meaning |
  |---|---|
  | `status`, `action`, `stage`, `framework_id`, `framework` (`n/m`), `version` (`n/m`) | Where the job is |
  | `elapsed_seconds`, `updated_at`, `seconds_since_update` | Running time and freshness of the last marker; a long gap means a slow model call, not a failure |
  | `queue_position` | QUEUED only: 1 = next (running job counted) |
  | `step {stage, unit, done, total, percent, seconds_per_unit, basis, eta_seconds, eta_at, reason}` | The current counted step (one stage of one framework/version); null when the stage does not count units |
  | `eta {seconds, at, percent, scope:"job", basis, reason, projected_candidates?}` | Whole-job estimate; `seconds` is null with a `reason` when it cannot be known |
  | `completed_steps[]` | Finished counted steps with `seconds` and `seconds_per_unit` |

  `basis`: `measured` (this step's own rate), `reference` (median rate of the last 20 succeeded jobs, used until the
  step has two samples), `projected` (during the last version's `extract`: remaining sections plus projected
  candidates = drafted × total ÷ done, at the reference review rate), `finished`. Reasons for a null ETA: `QUEUED`,
  `NOT_COUNTED` (resolve, sources, retrieve, document_review, sync, discover), `INSUFFICIENT_SAMPLES`,
  `MORE_WORK_UNKNOWN` (further frameworks or versions follow), `NO_REFERENCE_RATE` (no finished job has a review
  rate yet), `FINAL_STAGES` (publish, mappings, readiness; seconds). In `candidate_review` of the last framework the
  job ETA equals the step ETA; the short final stages are not added. Show the ETA as approximate and keep using the
  step counters as the primary progress signal.
- One worker runs jobs in order. Poll every 3–5 s from a background task. `PARTIAL` is not success. `INTERRUPTED`
  means the worker restarted: check what exists, then submit again with a **new** key. All stages are idempotent.
- `sync` result: `documents_seen`, `versions_new/changed/unchanged`, `versions[]` (`version_id`, outcome, `complete`,
  `sections`, `content_sha256`), `warnings`, `errors`. Zero matches is `SUCCEEDED` with a warning.
- `extract` result: `drafted`, `duplicates`, `llm_errors`, `translation_failures`, `rejected[]`, `requirement_ids[]`,
  `model`, `model_version`, `runtime`, `prompt_version`, `warnings`.
- `discover` result: `scope` (the jurisdiction path, with `via` and membership), `authorities`, `frameworks`, `sources`
  by status, child `sync_jobs`, `outcome` (`SYNC_TRIGGERED` | `AWAITING_HUMAN_REVIEW` | `SOURCE_CONFIGURATION_REQUIRED`,
  which is FAILED and has `blockers[0].supply`), and `next_actions`. It never searches the web and always finishes.
- Per framework, `prepare_catalog` reports in `frameworks[]` what the pipeline did: `documents`, `extraction`,
  `review` (`approved[]`, and `rejected[]` with `problems` and `LEFT_DRAFT_FOR_HUMAN_REVIEW`), `publication`,
  `blockers`, and `outcome` (`PUBLISHED`, `NOTHING_TO_PUBLISH`, `FRAMEWORK_NOT_APPROVED`,
  `SOURCE_CONFIGURATION_REQUIRED`). It publishes only its own automated approvals.

### 4.5 Reads for review screens

| Call | Returns |
|---|---|
| `GET /documents?source_id=&status=` | versions: `id`, `status` (`AWAITING_REVIEW`, `REVIEWED`, `REJECTED`, `SUPERSEDED`), `complete`, `incomplete_reason`, `content_sha256`, `format`, `title`, `framework_id`, `language` |
| `GET /documents/{version_id}` | document plus parsed `items` (sections: `ordinal`, `section_ref`, `heading`, `text`) |
| `GET /documents/{version_id}/processing` | jobs, `requirement_counts`, `models`, `attempt_counts`, and every draft with its section text |
| `GET /documents/{version_id}/attempts?kind=&status=` | one row per model call (`EXTRACTION`, `TRANSLATION`, `REVIEW`, `TRANSLATION_REVIEW`; status `SUCCEEDED`, `PARTIAL`, `VALIDATION_FAILED`, `MALFORMED_OUTPUT`, `LLM_ERROR`): `section`, `raw_response` (≤ 200k, `raw_truncated`), `parsed_json`, `validated_json`, `validation_errors[{index, path, message, code}]`, `accepted_requirement_ids`, `rejected_candidates`, `error`. Read-only; prompts are not stored |
| `GET /requirements?status=&version_id=&framework_id=` | default `status=DRAFT`. Fields: `original_text`, `section_ref`, `original_language`, `obligation_type`, `pam_domains`, `thresholds`, `translation_en`, `translation_status`, `extraction`, `status`, `created_by` (`llm:<model>`), `published_seq` |
| `GET /requirements/{id}` | requirement with section, document, review history |
| `GET /reviews` | every decision, with `decision_origin` (`HUMAN`/`AUTOMATED`), `policy_version`, `attempt_id`. Label automated ones "automated (policy <policy_version>)" |
| `GET /jurisdictions/{code}/coverage?include_inherited=&as_of=` | per-scope-entry `stage` and counts (`fully_supported` always null), `evaluation_templates`, `next_actions` (method, path, scope, ids ≤ 100), `statement` |

### 4.6 Mappings

`GET /rule-catalog` lists the rules and parameters a mapping may reference.

```json
POST /mappings
{"requirement_id": 1, "assessment": "AUTOMATED", "rule_id": "PAM-ROTATION-001",
 "rule_version_min": "1.1", "rule_version_max": null, "coverage": "PARTIAL",
 "parameters": {"max_rotation_age_days": 90},
 "override_constraints": {"max_rotation_age_days": {"min": 1, "max": 90}},
 "control_reference": "Art. 7", "rationale": "≥ 20 chars", "limitations": "≥ 10 chars"}
```

- The requirement must be approved. `AUTOMATED` needs a bundled rule/version in range and **every** rule parameter
  within range (no silent defaults). `MANUAL` names a `pam_control_id` and has no rule fields.
- A parameter without a constraint is fixed. A constraint must contain the approved value; set `max` = approved value
  to mean "stricter allowed, weaker not".
- Errors: 404 `NOT_FOUND`; 409 `REQUIREMENT_NOT_APPROVED`, `CATALOG_CONFLICT`; 422 `UNKNOWN_RULE`,
  `RULE_VERSION_UNAVAILABLE`, `INVALID_RULE_VERSION`, `EVIDENCE_TYPE_MISMATCH`, `MISSING_PARAMETER`,
  `INVALID_PARAMETER`, `INVALID_OVERRIDE_CONSTRAINT`, `INVALID_MAPPING` (`details.problems` lists each); 503
  `RULE_CATALOG_UNAVAILABLE`.
- Then `POST /reviews/mapping/{id}` and `/publish`. Reads: `GET /mappings?framework_id=&requirement_id=&status=` and
  `/mappings/{id}`.
- Reviewed mappings are immutable. To change one, `POST /mappings/{id}/withdraw {"reason"}` (published immediately as
  `WITHDRAW`), then draft a new one: same `mapping_key` (`<framework>:<requirement>:<control>`), next
  `mapping_version`. A mapping has no dates of its own.

## 5. Automated preparation: `prepare_catalog`

```json
{"action": "prepare_catalog", "mode": "import", "jurisdictions": ["EU"], "industry": null,
 "requested_framework_ids": [], "include_inherited": true, "document_ids": [41],
 "translate": true, "as_of": null, "request_key": "prep-2026-11-16-0001"}
```

The service returns 202 `{organization_scope, job}`. Submit-time errors: 422 `SCOPE_REQUIRED`, 404
`UNKNOWN_JURISDICTION`, 404 `UNKNOWN_FRAMEWORK`, 422 `DOCUMENTS_REQUIRED`, 404 `UNKNOWN_DOCUMENT`, 403 `FORBIDDEN`.

- **import**: works on uploaded documents of this scope. Each document's framework is the one given at upload, or a
  match against visible registered frameworks, or a new scoped framework `ORG-<digest12>`. Everything produced is
  scoped.
- **discovery**: runs over the global frameworks registered for the jurisdiction closure (filtered by `industry` or
  `requested_framework_ids`). It uses registered sources only and never the open internet. Results go into the
  **global** official catalog.
- Both modes run the automated framework pipeline per framework, then deterministic mapping preparation
  (REGINTEL.md §7) and publication of the new mappings. Then come LLM-assisted assignment of existing rules (§5.2)
  and, when it is requested, bounded rule generation (§5.4).

Result: `mode`, `organization_scope`, `status` (`SUCCESS`/`PARTIAL`/`FAILED`), `outcome` (`PREPARED`, `NOTHING_NEW`,
`NOTHING_TO_PREPARE`), `frameworks[]` (per-framework run summary and `mapping_candidates`), `mappings` (`prepared`,
`unmapped`, `errors`), `gaps[]`, `readiness[]`, `coverage`, `counts` (`frameworks_processed`,
`requirements_published`, `mappings_prepared`, `unmapped_requirements`, `gaps`, `llm_errors`).

| Gap code | Meaning |
|---|---|
| `SOURCE_CONFIGURATION_REQUIRED` | no registered framework or eligible source for the jurisdiction |
| `FRAMEWORK_NOT_APPROVED` | framework identity not approved |
| `FRAMEWORK_IDENTITY_UNRESOLVED` / `AMBIGUOUS_FRAMEWORK_SELECTION` | an import document can't be tied to one framework |
| `INCOMPLETE_DOCUMENTS` | document review failed (includes scanned pages: no OCR) |
| `MODEL_VALIDATION_FAILED` | second-pass review or code checks rejected a candidate |
| `UNSUPPORTED_RULE` | published requirement with no executable rule (stays a selectable gap). Carries `mapping_gap_codes` (the reasons) |
| `OPERATIVE_SECTIONS_UNPROCESSED` | operative sections of a version were never extracted (`version_id`, `section_refs`, first 50) |

Per-requirement detail is in `mapping_gaps[]`: `{requirement_id, framework_id, section_ref, status`
(`UNMAPPED`/`PARTIAL_COVERAGE`)`, executable_rules[], gaps[{code, reason, rule_id?, topic?, parameters?}],
auto_mapping}`. `counts.mapping_gaps_by_code` summarizes it. Codes and meanings are in REGINTEL.md §7.

**Automatic PAM-check assignment (policy `auto-v3`, recipe set `pam-recipes-v1`, 2026-11-17).**
`prepare_catalog` drafts, auto-reviews and publishes a mapping, with no Django approval click, only when every one
of these holds:
- the requirement is MANDATORY, operative and in PAM scope;
- it is not a licensing, copyright or document-provenance statement;
- it is fully parsed (balanced brackets, quote located in its source);
- exactly one rule is resolved across all matching recipes;
- that rule has exactly one ACTIVE version in the running bundle, with the recipe's evidence type;
- its evidence is collected (`OPM_REGINTEL_BRIDGE_COLLECTED_RULES`, default ROTATION, DORMANT and SESSREC);
- every rule parameter is stated in the passage (no `[Assignment]`/`[Selection]`, no rule defaults, exactly one
  value per parameter);
- no different live mapping exists for the requirement;
- coverage (always `PARTIAL`), rationale and limitations validate.

Recipes come in two kinds:
- **TEXT recipes** (any framework, privileged wording): rotation, dormancy, session recording.
- **CANONICAL recipes** (NIST SP 800-53, matched on canonical ID, clause and control title):

  | NIST control | Rule |
  |---|---|
  | IA-5 f | PAM-ROTATION-001 |
  | AC-2(3) | PAM-DORMANT-001 |
  | AU-14 a | PAM-SESSREC-001 |
  | AC-2 j | PAM-REVIEW-001 |
  | AC-2 i | PAM-UNAUTH-001 |
  | IA-2(1), IA-2(2), IA-2(6) | PAM-MFAACC-001 |
  | AC-3(2) | PAM-APPROVAL-001 |
  | AC-11 a | PAM-SESSIDLE-001 |
  | AC-7 a | PAM-AUTHFAIL-001 |

Session recording binds `accept_partial_recordings=false` only when the passage requires recording of
all/every/each session.

**Result fields.**
- `mappings.decisions[]`: one per requirement, `{requirement_id, canonical_reference, decision
  (PROPOSED/EXISTING/NOT_MAPPED), code, message, recipe_id?, rule_id?, rule_version?, evidence_type?, parameters?,
  parameter_provenance[{name, value, provenance: "SOURCE_TEXT", source_text}]?, coverage?, mapping_id?, …}`.
- `mappings.recipes[]`: each recipe's `support_status`, one of `SUPPORTED`, `COLLECTOR_UNAVAILABLE`,
  `PARAMETERS_NEVER_IN_SOURCE`, `RULE_UNAVAILABLE`, `RULE_VERSION_AMBIGUOUS` or `EVIDENCE_SCHEMA_INCOMPATIBLE`.
  Support is never claimed beyond it.
- `mappings.prepared[]` now carries `rule_version`, `recipe_id`, `parameter_provenance`, `coverage` and
  `policy_version`.

`NOT_MAPPED` codes:
- `NOT_MANDATORY`
- `NON_OPERATIVE_TEXT` (also licensing and provenance statements)
- `OUTSIDE_PAM_SCOPE`
- `PARTIALLY_PARSED`
- `NO_EXECUTABLE_RULE`
- `MAPPING_MISSING`
- `AMBIGUOUS_REQUIREMENT`
- `RULE_UNAVAILABLE`
- `RULE_VERSION_AMBIGUOUS`
- `EVIDENCE_SCHEMA_INCOMPATIBLE`
- `COLLECTOR_MISSING`
- `POLICY_CONTEXT_REQUIRED`
- `PARAMETER_NOT_SOURCE_GROUNDED`
- `MAPPING_CONFLICT`
- `VALIDATION_FAILED`

**`auto_mapping`.** Every `mapping_gaps[]` item (job result, admin and public mapping-gaps) carries
`auto_mapping{decision, code?, message?, recipe_id?, rule_id?, rule_version?, mapping_id?}`.

**Published mappings.**
- The rule version range is pinned: `rule_version_min` = `rule_version_max` = the single ACTIVE version, so
  PAM-ROTATION-001 binds 1.1, never the retired 1.0.
- Numeric parameters get override constraints `{min, max: stated value}`: local policy may be stricter, never
  weaker.
- The review row has `decision_origin=AUTOMATED`, `policy_version=auto-v3`, and `attestations{recipe_set_version,
  recipe_id, source_requirement{requirement_id, framework_id, section_ref, document_version_id, canonical_id,
  clause}, rule_id, rule_version, evidence_type, parameters, parameter_provenance, coverage, limitations}`.
- Readiness is recomputed in `readiness[]`, and the mapping and execution appear in `GET
  /evaluation-templates/{id}/plan`.

**Live NIST (catalog 20).** All 41 requirements are `NOT_MAPPED`, because the official text leaves every
recipe parameter organization-defined:

| Code | Count |
|---|---|
| `MAPPING_MISSING` | 20 |
| `NO_EXECUTABLE_RULE` | 13 |
| `NOT_MANDATORY` | 4 |
| `COLLECTOR_MISSING` | 3 (AC-2 i, AC-7 a, IA-2(6)) |
| `POLICY_CONTEXT_REQUIRED` | 1 (AU-14 a) |

Earlier decisions keep `auto-v1`/`auto-v2`.

**Live view: `GET /api/v1/catalog/frameworks/{id}/mapping-gaps[?tenant_id=]`** (`catalog:read`, public API).
The admin path `/api/v1/catalog/admin/frameworks/{id}/mapping-gaps` returns the same items. It covers published
global requirements plus the caller's scope.

- **Collector state.** With `tenant_id` and the scope header, `COLLECTOR_MISSING` follows that organization's
  collector handshake. Without them, it follows the legacy bridge default (`collector_capability_source`).
- **Response.** `{framework_id, items[], counts{requirements, gaps_by_code}, gap_codes, collected_rules,
  collector_capability_source, policy_bundle_version}`.
- **Items.** Each item is `{requirement_id, framework_id, section_ref, canonical_reference, executable_rules[],
  gaps[], status}`.
- **Gap fields.** A gap can carry `organization_defined[]`: the literal `[Assignment: …]` / `[Selection: …]` texts
  of the passage. These values belong to the organization and are never filled in. They yield
  `POLICY_CONTEXT_REQUIRED` even for a rule without parameters (e.g. NIST AU-14 users or roles and circumstances).
  Automation never maps such a passage.
- **Unknown or cross-scope frameworks** return 404 `UNSUPPORTED_FRAMEWORK`.

**`canonical_reference`** (derived, never stored; published rows are immutable):
`{canonical_id, control_id, control_title, enhancement, enhancement_title, clause, location, method, status}`.
For example `{"canonical_id": "AC-7", "clause": "b", "location": "CONTROL_STATEMENT",
"method": "DERIVED_FROM_SOURCE_HEADINGS", "status": "DERIVED"}`.

- **Where it comes from.** It is read from the control and enhancement headings of the official text: `AC-2 ACCOUNT
  MANAGEMENT Control:` and `(2) ACCOUNT MANAGEMENT | …`. An enhancement counts only if its base title matches the
  preceding control.
- **`location`.** `DISCUSSION` marks a passage taken from discussion text, which is guidance, not the control
  statement.
- **`status`.** It is `DERIVED`, `QUOTE_NOT_LOCATED`, `NO_CONTROL_HEADING_BEFORE_PASSAGE` or `NO_SOURCE_SECTION`.
  When no heading layout exists (e.g. EU acts), `canonical_id` is null. Keep displaying `section_ref`.

**`GET /api/v1/catalog/frameworks/{id}/control-coverage[?family=AC&family=AU&family=IA]`** (`catalog:read`) returns:
- per-requirement canonical references
- `multiple_requirements_per_clause` (more than one published requirement on one clause; review them for
  duplicates, but never merge them automatically)
- `discussion_text_requirements` and `unresolved`
- per document version: `content_sha256`, `control_headings_found`, `controls_with_published_requirements` and
  `omitted_controls_in_families` (controls of the official text with no published requirement)

The published requirements are an extracted subset. Never present them as the complete control catalog.

### 5.1 Mapping proposals (removed 2026-11-19)

The static proposal set (`GET /frameworks/{id}/mapping-proposals`, the admin proposal runs) and the vendor
capability-matrix path were removed. Rules are now assigned automatically by `prepare_catalog`: existing rules
first (§5.2), then bounded generation (§5.4). Both endpoints return 404, and `capability_document_ids` in a
`prepare_catalog` body is 422. The legacy `mapping_proposal_run` and `capability_mapping_row` tables stay, untouched,
for audit.

### 5.2 LLM-assisted rule assignment (policy `llm-auto-v1`, prompt `llm-map-v1`, 2026-11-17)

This step runs inside `prepare_catalog` after the deterministic recipes and needs no human step. The order is:

1. canonical control resolution
2. semantic candidate rules
3. the local LLM proposes one decision as strict JSON
4. deterministic parameter resolution
5. deterministic validation
6. draft
7. automated review (`decision_origin=AUTOMATED_LLM`)
8. scoped publication
9. readiness recomputation

Create, review and publication are separate audit records. Every mapping it produces is **organization-scoped**, including mappings on global requirements: the inputs (collector declaration, organization settings, PAM configuration) belong to one organization. Other organizations never see them.

New `prepare_catalog` body fields, all optional:
- `tenant_id`: whose collector handshake, policy and PAM configuration apply. The default is the scope's single declared tenant.
- `llm_mapping`: default `true`.
- The fields of §5.4 (`auto_rule_generation`, `auto_publish_validated_rules`, `collector_capability_digest`).

**Vendor capability matrices are not inputs.** An uploaded document that reads as a vendor control/capability
matrix (title or stored bytes) is skipped with the job gap `CAPABILITY_DOCUMENT_NOT_SUPPORTED`. It never creates
requirements, frameworks or mappings. Upload only compliance documents (regulations, standards, the organization's
own policies). `capability_document_ids` is rejected with 422.

**Verified PAM configuration**:
- `PUT /pam-configuration` (`catalog:operate`, scope header) takes this body:
  ```json
  {"tenant_id": "acme", "collector": {"name": "securden-django", "version": "1.0"},
   "captured_at": "2026-11-10T08:00:00Z", "verified": true,
   "settings": [{"rule_id": "PAM-ROTATION-001", "parameter": "max_rotation_age_days", "value": 30,
                 "setting_reference": "Rotation policy 'Privileged default' > interval"}]}
  ```
  It returns 201 `{pam_configuration}`.
- `verified:false` is rejected with 422 `UNVERIFIED_CONFIGURATION`: only values the collector read from Securden count.
- An unknown rule or parameter, an out-of-range value or a duplicate setting gives 422 `INVALID_CONFIGURATION` with `problems[]`.
- Snapshots are immutable. `GET /pam-configuration?tenant_id=` returns the latest one.
- Values carry `provenance=CUSTOMER_POLICY`, `source_type=PAM_CONFIGURATION` and `assessment_basis=CONFIGURATION_OBSERVED_AT_CAPTURE`. They are the organization's settings, **never NIST thresholds**.
- A snapshot says what was configured at `captured_at`. Only the rule's evaluation of the reporting period's evidence shows enforcement.

**Semantic candidates.** These are candidate relationships only; validation still applies.

| Control | Candidate rules |
|---|---|
| AC-2 j | REVIEW |
| AC-2 i | UNAUTH |
| AC-2, AC-2(3) | DORMANT |
| AC-3 | APPROVAL, UNAUTH |
| AC-3(2) | APPROVAL |
| AC-7 | AUTHFAIL |
| AC-11 | SESSIDLE |
| IA-2 enhancements | MFAACC |
| IA-5 f | ROTATION, pinned to 1.1 |
| AU-14 a | SESSREC |

For a framework without control headings, the candidates are the passage's tested-behaviour topics. The model may choose only from the candidates it is given. It cannot generate Rego, expressions, rule IDs or values.

**Parameter order.** This is deterministic. The model's binding must equal the result and cite the same source.
1. The regulatory text. A value is used only when it is stated outside `[Assignment: …]` placeholders, exactly once and within range.
2. An approved organization policy version in force now, with an `ORGANIZATION` target, pinning the rule's control.
3. The latest verified PAM configuration snapshot.
4. Otherwise `PARAMETER_SOURCE_MISSING`.

Vendor documents never ground a value. The source types are `REGULATORY_TEXT`, `POLICY_DOCUMENT` (organization settings) and `PAM_CONFIGURATION`.

When an organization value changes, the replacement mapping is created and the superseded one withdrawn in one transaction, so a failed replacement leaves the old mapping live.

**Validation.** All of these must hold:
- the rule is a candidate
- the version is the single ACTIVE version (and the pinned one where pinned)
- the evidence type matches
- the collector handshake declares the evidence (no MFA mapping until Django declares it)
- confidence ≥ `OPM_REGINTEL_LLM_MAPPING_MIN_CONFIDENCE` (default 0.8)
- every parameter is resolved and bound identically, with every quotation found in the cited source
- rationale, limitations and the applicable population are present
- no different live mapping exists (global or this organization's)
- ownership matches

Coverage is always published as `PARTIAL`. A `FULL` proposal is recorded as `coverage_adjusted_from_full`. Organization-defined parts of the passage that are not established (for example AU-14 users/roles and circumstances) become limitations.

**Decision record.** One row per (scope, requirement, input digest) goes in `llm_mapping_decision`. Each records the model and digest, prompt and policy versions, raw output, parsed proposal, validation, parameter resolution, outcome and gap code. Rows are preserved; deletion is blocked.

Re-runs with unchanged inputs reuse the recorded decision without a model call, so the job is idempotent. New inputs, such as a PAM configuration snapshot, a policy, a handshake or a model change, lead to a new decision.

The review attestations hold:
- model, model digest, prompt and policy versions
- input digest and job id
- confidence
- source requirement
- rule and version
- parameters with provenance
- coverage, limitations and applicable population
- checks passed

**Outcomes and gap codes.**
- Outcomes: `PUBLISHABLE`, `EXISTING`, `GAP`, `NO_MAP`, `MANUAL_ASSESSMENT`.
- Gap codes:
  - `LLM_MAPPING_AMBIGUOUS` (confidence below threshold)
  - `PARAMETER_SOURCE_MISSING`
  - `COLLECTOR_MISSING`
  - `NO_EXECUTABLE_RULE`
  - `POLICY_CONFLICT`
  - `SOURCE_GROUNDING_FAILED`
  - `CANONICAL_CONTROL_UNRESOLVED`
  - `RULE_VERSION_INVALID`
  - `EVIDENCE_SCHEMA_INCOMPATIBLE`
  - `LLM_OUTPUT_INVALID`
  - `LLM_ERROR`
  - `LLM_NO_MAP`
  - `MANUAL_ASSESSMENT_RECOMMENDED`
  - pre-gate codes `NON_OPERATIVE_TEXT`, `OUTSIDE_PAM_SCOPE`, `NOT_MANDATORY`, `PARTIALLY_PARSED`
  - `VALIDATION_FAILED`

**Where results appear.**
- The job result carries `llm_mapping{decisions[], counts, model, model_digest, …}`.
- `counts` gains `llm_candidates`, `mappings_validated`, `mappings_published`, `ambiguous_candidates`, `missing_parameters`, `missing_collectors` and `unsupported_requirements` (with §5.4 these are the orchestration totals).
- `mapping_gaps[]` and `GET /frameworks/{id}/mapping-gaps` carry `llm_mapping` (this organization's latest decision) for each requirement.
- `executable_rules` counts global mappings plus this organization's mappings only.
- Published mappings appear in this organization's `/evaluation-templates/{id}/plan`.

### 5.3 Organization settings for automatic assignment (2026-11-17)

Standards such as NIST leave most values organization-defined. The organization supplies them once through an
**organization settings form** in Django. OPM has no separate endpoint for this: the form is a front end for
organization policy contexts ([POLICY_CONTEXT_DJANGO_CONTRACT.md](POLICY_CONTEXT_DJANGO_CONTRACT.md) §4), which
§5.2 reads as parameter source 2.

**Form → policy controls.** Each form section maps to one or more `PC-*` controls, all at `control_version` `1.0`
and all with `targets: [{"type": "ORGANIZATION"}]`. Controls with other targets never ground an automatic mapping.

| Form section | Controls | Parameters |
|---|---|---|
| Passwords and accounts | PC-CRED-ROTATION, PC-DORMANT-ACCOUNTS, PC-ACCESS-REVIEW | `max_rotation_age_days`, `dormant_after_days`, `review_interval_days` |
| Login security | PC-MFA-AT-ACCESS, PC-MFA-CONFIGURATION, PC-AUTH-FAILURE-MONITORING | `accepted_methods` (the same value sent to both MFA controls), `max_failed_attempts`, `window_minutes`, `lockout_is_mitigation` |
| Sessions | PC-SESSION-IDLE-LIMIT, PC-SESSION-DURATION-LIMIT, PC-SESSION-RECORDING | `max_idle_minutes`, `max_session_minutes`, `accept_partial_recordings` |
| Approvals and emergency access | PC-ACCESS-APPROVAL, PC-EMERGENCY-ACCESS | `max_approval_age_hours`, `min_justification_length`, `require_ticket_reference`, `post_review_within_hours` |
| Policy exceptions | PC-POLICY-EXCEPTIONS | `max_exception_duration_days` |
| Audit evidence | PC-AUDIT-LOG-COMPLETENESS | `min_completeness_percent`, `max_allowed_gap_seconds`, `require_integrity_verification` |

PAM-UNAUTH-001 has no parameters and needs no field. PC-PASSWORD-POLICY and PC-SEGREGATION-OF-DUTIES are
`NOT_IMPLEMENTED` and are not on the form.

**Confirmation.**
- Django may pre-fill the catalog defaults (`GET /policy-controls`).
- It sends a section's controls **only after a user confirms that section**. A section that is not confirmed is
  left out of the version, and OPM treats its parameters as missing.
- OPM has no "confirmed" flag: a value present in an in-force version *is* the confirmation.
- `accepted_methods`, `max_idle_minutes` and `max_session_minutes` have no default and must be typed in.

**Saving.**
- First save: `POST /admin/policy-contexts` with `policy_reference.title` "Organization PAM settings",
  `effective_from` = now, and the confirmed sections' controls.
- Later saves: `POST /admin/policy-contexts/{context_id}/versions` with `supersedes_version` and the **full** set of
  confirmed controls. A version replaces the previous one; it is not a patch.
- Keep one settings context per (organization scope, tenant). The scope header is required.
- A 422 `INVALID_POLICY_CONTEXT` lists every problem; show each next to its field.

**Re-run after a save.**
- Django starts `prepare_catalog` again (`mode: "import"`, the same `document_ids` and `tenant_id`, a new
  `request_key`) for each standard the organization uploaded.
- Changed settings change the §5.2 input digest, so the affected requirements are decided again. Unchanged ones
  reuse their decision without a model call.
- When a setting changes, OPM **replaces** its own earlier automatic mapping for the same rule: it withdraws the old
  mapping and publishes a new one with the new value. The decision carries `replaced_mapping_ids`.
- When a section is removed from the settings, OPM **withdraws** the automatic mapping that relied on it. The
  decision becomes `PARAMETER_SOURCE_MISSING` with `withdrawn_mapping_ids`.
- Only mappings that an `llm-auto-v1` decision created for this organization with an organization-defined value
  (`provenance=CUSTOMER_POLICY`) are replaced or withdrawn. Human, global and other-rule mappings still give
  `POLICY_CONFLICT`.

**Standard values win.**
- A value stated in the standard's text is the mapping's parameter; the settings value is not used for it.
- The organization may be stricter only at evaluation time, within `override_constraints` (§7), never weaker.
  For maximums (ages, intervals, durations, attempt counts) the stated value is the upper bound. For `min_*`
  parameters and `window_minutes` it is the lower bound.
- Only day, hour, minute and attempt-count parameters are ever read from a standard's text. Character lengths,
  percentages and seconds come only from settings or a verified PAM configuration.

**What the UI shows per requirement** (from `llm_mapping` on `GET /frameworks/{id}/mapping-gaps`):

| Outcome or gap code | Show |
|---|---|
| `PUBLISHABLE`, `EXISTING` | Assigned: the rule, its version, and each parameter with its source (standard text, organization settings version, or PAM configuration snapshot) |
| `PARAMETER_SOURCE_MISSING` | "Fill in and confirm: <field>", linked to the form section |
| `LLM_MAPPING_AMBIGUOUS` | "Needs review": the suggested rule, not assigned |
| `NO_EXECUTABLE_RULE`, `LLM_NO_MAP`, `OUTSIDE_PAM_SCOPE` | "Not covered by PAM" |
| `NON_OPERATIVE_TEXT`, `NOT_MANDATORY` | Hidden by default |
| `COLLECTOR_MISSING` | "Evidence not collected yet": a Django collector task, not a setting |
| any other code | The code and its `message`; never fail on an unknown code |

**Withdrawal.** Automatic assignments carry `decision_origin=AUTOMATED_LLM`. Withdraw them like any other mapping
(`POST /admin/mappings/{id}/withdraw`).

**ISO.** ISO licences forbid AI processing of the text. Do not upload ISO standards for automatic assignment.

### 5.4 Automatic rule orchestration: bounded rule generation (2026-11-19)

When no existing rule fits a PAM-applicable requirement (§5.2 decision `NO_EXECUTABLE_RULE` or `LLM_NO_MAP`),
`prepare_catalog` can generate one. The local LLM proposes only a **JSON RuleSpec 1.0**
(`schemas/generated_rule_spec_v1.schema.json`). It never writes Rego, expressions, URLs, paths, rule ids or values.
OPM's own code then validates the spec, resolves its values, compiles it, tests it and (only when asked) activates it.

**Service flags** (both default `false`; operator settings, not job fields):
`REGINTEL_AUTO_RULE_GENERATION` and `REGINTEL_AUTO_PUBLISH_GENERATED_RULES` (an `OPM_` prefix also works).
`OPM_REGINTEL_RULE_GENERATION_MIN_CONFIDENCE` defaults to 0.8.

**Job fields** (`prepare_catalog`, all optional):

| Field | Default | Rule |
|---|---|---|
| `auto_rule_generation` | `false` | needs the generation flag (else 422 `RULE_GENERATION_DISABLED`) and `llm_mapping: true` |
| `auto_publish_validated_rules` | `false` | needs `auto_rule_generation`, the publish flag (else 422 `RULE_PUBLICATION_DISABLED`), an explicit `tenant_id` (else 422 `TENANT_REQUIRED`) and `collector_capability_digest` (else 422 `CAPABILITY_DIGEST_REQUIRED`) |
| `collector_capability_digest` | null | `sha256:<64 hex>`, the `collector_capabilities.digest` the user reviewed; must equal the tenant's current declaration (else 409 `STALE_CAPABILITY_DIGEST`). Only with `auto_rule_generation` (else 422 `INVALID_RULE_GENERATION`) |

Without `auto_publish_validated_rules`, rules that pass every gate are stored as `VALIDATED` and nothing is
activated or mapped.

**Collector handshake detail** (`PUT /admin/collector-capabilities`). Each `evidence[]` entry may also carry
`assessment_modes` (`EVENT_HISTORY` and/or `CONFIGURATION_SNAPSHOT`) and `supported_fields` (field names of OPM's
evidence schema; an unknown field is 422 `UNKNOWN_EVIDENCE_FIELD`). Generated rules are possible **only** for
evidence types that declare both, and may use only the declared fields. The response carries `evidence_detail`.
Declarations without the detail keep their earlier digest.

Each entry may also carry `collection_status`: `COLLECTED` (default, sent with evaluations today) or
`LOOKUP_AVAILABLE` (the PAM database holds the data but the collector does not send it yet; needs both
`assessment_modes` and `supported_fields`), plus informational `caveats[]` (shown to the rule generator) and
`source_models[]`. Lookup types never count as collected (the `evidence` map, readiness and existing-rule matching
ignore them). The rule generator designs, compiles and OPA-tests rules on them, then stores them as
`GENERATED_RULE_VALIDATED` with `gap_code: COLLECTOR_MISSING` and `waiting_for_collector {evidence_type, fields[]}`:
Django's list of what to collect. Once Django re-declares the type as `COLLECTED`, the next job re-checks the stored
proposal (no new model call) and activates it. The body may be the PAM capability inventory file as-is:
`evidence_capabilities` is accepted for `evidence`, and top-level `schema_version` and `settings_sources`
(where each threshold lives in the PAM; the values themselves come from `PUT /admin/pam-configuration`) are accepted.

Each entry may also carry `field_meanings {field: {meaning, shows}}` (strings up to 300 characters; only for fields
in its `supported_fields`, else 422 `UNKNOWN_EVIDENCE_FIELD`): what the field means in this PAM and which kind of
obligation a test on it can evidence. The rule generator reasons from these meanings, not from field names. Without
them OPM uses its framework-neutral defaults (`regintel/data/field_meanings.json`, one entry per field). Meanings
are part of the declaration digest only when given.

**Gates, in order** (the first failing one is the outcome):
1. Forbidden content anywhere in the output: code (Rego/Python), URLs, file paths, templates, credential material,
   claims of full coverage → `RULE_SPEC_INVALID`.
2. Strict schema (unknown fields or operators) → `RULE_SPEC_INVALID`. `decision: NO_RULE` → `NO_RULE_PROPOSED`.
   `MANUAL_ASSESSMENT` → `MANUAL_ASSESSMENT_REQUIRED`. Confidence below threshold → `RULE_PROPOSAL_AMBIGUOUS`.
3. `source_requirement_ids` must be exactly the requirement → `SOURCE_GROUNDING_FAILED`.
4. Evidence type not declared → `COLLECTOR_MISSING`. Schema version, assessment mode or a field the collector does
   not populate → `EVIDENCE_SCHEMA_INCOMPATIBLE`.
5. Fields, operator/type fit and units against OPM's pinned evidence schema; **every numeric or duration threshold must
   be a declared parameter**, never a literal → `RULE_SPEC_INVALID`.
6. Parameter values, in this order: the regulatory text (days, hours, minutes or attempts stated once outside
   `[Assignment: …]`, with the quotation), then an in-force organization setting (`policy_control` binding, §5.3).
   The model never supplies a value. If neither exists → `PARAMETER_SOURCE_MISSING` (with `parameters_missing`).
7. Compilation into the fixed interpreter `securden.custom.v1` → `RULE_COMPILATION_FAILED` on error.
8. Generated cases run against the **real OPA binary** with the service's bundle: passing, failing, empty, empty and
   incomplete, missing required field (or schema rejection), outside the reporting period, out-of-scope entity and
   tag, numeric/duration boundaries. Any mismatch → `RULE_TEST_FAILED` (with `test_results`).
9. Activation (with auto-publish): the pinned digest is re-checked (a change → `EVIDENCE_SCHEMA_INCOMPATIBLE`,
   "stale"). A different live mapping (human, global, recipe or §5.2) → `POLICY_CONFLICT`, and it is kept.

**Activation.** The rule is written to the evaluator's tenant rule store as an ACTIVE custom rule. Then an
organization-scoped mapping is created (exactly version `1.0`, coverage `PARTIAL`, no parameters), reviewed
automatically (`decision_origin=AUTOMATED_LLM`, policy `rule-gen-v1`, attestations with the generated-rule
provenance) and published scoped. An earlier generated mapping of the same requirement is withdrawn in the same
transaction as the replacement's creation. If a crash happens between activation and mapping, the next run finds
the active rule and creates only the mapping.

**Identity.** `rule_id` is `PAM-GEN-<12 hex>`: the digest of organization scope, tenant, canonical structure and
resolved values. The version is always `1.0`, so different values give a new rule id. An equivalent specification
reuses the existing rule and mapping. Generated rules never appear for other organizations, in `/rules` or in
`/pam-controls`.

**Records** (preserved, deletion blocked): `generated_rule_version` holds the spec and its digests, parameter
resolution, definition, compiled rule, rule digest, `rego_digest` (interpreter plus compiled structure), compiler
`pam-rulespec-compiler-1.0`, evidence type, schema version and mode, collector digest, source references, model
provenance, checks, cases and OPA results, bundle version, limitations and status (`VALIDATED`, `ACTIVE`,
`SUPERSEDED`, `FAILED`). `rule_generation_decision` holds one row per (scope, requirement, input digest) with the
raw output. A retry with identical inputs re-checks the stored output without calling the model.

**Job result additions.**
- `rule_generation_decisions[]`: `{requirement_id, decision_id, outcome, gap_code, message, rule_id, rule_version,
  mapping_id, generated_rule_version_id, evidence_type, evidence_schema_version, assessment_mode, coverage,
  rule_spec_digest, rego_digest, source_references, limitations, parameters_missing?, replaced_mapping_ids?}`.
- `rule_generation`: `{compiler_version, prompt_version, policy_version, model, model_digest,
  collector_capability_digest, publish, counts, mapping_ids, publication}`.
- `mapping_decisions[]`: the §5.2 decisions, each with `orchestration_outcome` and, when generation ran,
  `rule_generation{decision_id, outcome, gap_code, rule_id, mapping_id, message}`.
- `counts` adds `requirements_processed`, `pam_applicable_requirements`, `existing_rules_assigned`,
  `rule_proposals_created`, `rules_generated`, `rules_activated`, `generated_mappings_published`,
  `ambiguous_requirements` and `orchestration_outcomes{code: n}`. `mappings_published`, `missing_collectors`,
  `missing_parameters` and `unsupported_requirements` become the orchestration totals.
- `stages[]` and `progress` carry `orchestration_stage`: `resolve_documents`, `extract_requirements`,
  `validate_requirements`, `resolve_canonical_controls`, `match_existing_rules`, `propose_missing_rules`,
  `validate_rule_specs`, `compile_generated_rules`, `test_generated_rules`, `publish_generated_rules`,
  `publish_mappings`, `recompute_readiness`, `complete`. Generation stages report `completed` and `total`. Result
  stages also carry `job_id` and `at`.
- While rules are generated (`stage` `propose_missing_rules`), `GET /admin/jobs/{id}/progress` is a counted step:
  `step` (`done`/`total`, `unit` `requirements`, `seconds_per_unit`, `eta_seconds`) and a job `eta`, as for
  `candidate_review`. It also returns `orchestration_stage` and `rule_generation`:
  `{done, total, substep, current{requirement_id, section_ref, control_id, clause}, outcomes{code: n},
  rules_activated, rules_validated, seconds_per_requirement, recent[]}`. `substep` is `propose` (started),
  `analyse` (model reasons in plain text), `write` (model writes the RuleSpec), `validate`, `judge` (model reviews
  the finished rule), `compile`, `test`, `activate` or `done`; `outcomes` uses the `orchestration_outcome` codes.
  Existing-rule matching before it is also counted: stage `llm_mapping` (`orchestration_stage`
  `match_existing_rules`), `unit` `requirements`, `current{requirement_id}`; its job `eta` is null with
  `MORE_WORK_UNKNOWN` when generation follows. `recent[]`
  holds the last 5 decisions: `{requirement_id, section_ref, control_id, clause, outcome, rule_id, reason,
  model_called}`. `reason` says why no rule was generated (e.g. "declared parameters not used by the condition").
  `rule_generation` is null in every other stage. These per-requirement markers are not added to `stages[]`.
- Generation (prompt `rule-spec-v15`) asks the model in three steps, each re-used from the stored decision on an
  identical retry: **analyse** (plain text, no grammar: the obligation, what a compliant and a violating record look
  like, the field that tells them apart; ends `VERDICT: TESTABLE <type>.<field>`, `NOT_TESTABLE` →
  `NO_RULE_PROPOSED` or `PERSON_JUDGES` → `MANUAL_ASSESSMENT_REQUIRED`, with the reasoning in `message`), **write**
  (the RuleSpec under the grammar, given the analysis and only the chosen evidence type), and after the
  deterministic gates **judge** (plain text: does a failing record mean the obligation was breached; `JUDGE: NO` →
  `RULE_SPEC_INVALID` "review (NO)"). The decision's `llm_validation` keeps `analysis {text, verdict, evidence_type,
  field}` and `review {text, verdict, spec_digest}`; a judged rule has the check `judged_by_model`. With a runtime
  that cannot answer in plain text the analyse and judge steps are skipped and the word gate below decides.
- Generation only asks the model about a requirement whose wording relates to a declared
  evidence type with a collected non-null timestamp (screen `rule-screen-v2`: each evidence type has a keyword list, and only the types whose
  keywords the requirement uses are offered to the model). Any other requirement is
  `COLLECTOR_MISSING` with `model_called: false`. The model decodes against a per-requirement grammar whose
  identifiers (PAM controls, evidence types, fields, settings) are enums of what exists. Declared parameters the
  condition never uses are dropped and recorded under `checks`. A condition that tests only the record's own id or
  period is rejected (`RULE_SPEC_INVALID`). The condition must also test at least one field whose meaning the
  requirement text states (gate `rule-grounding-v3`; e.g. `enabled` needs "enable"/"disable", `recording_status`
  needs "recording(s)"/"recorded"); otherwise `RULE_SPEC_INVALID` with the tested fields in `reason`. When the judge
  step runs, this gate is a hint (`condition_not_word_grounded` is recorded and the judge is told) and the judge
  decides. Always rejected: a condition repeating a population filter (filters take only scope flags such as
  `privileged`, `*_required`, `applies_to_*`), a condition requiring accounts to be enabled, and limitations copied
  from the prompt's worked example.

**Generation only** (`POST /admin/jobs`, action `generate_rules`, scope `catalog:automate` and the organization
header): `{action, requested_framework_ids[1..20], tenant_id?, auto_publish_validated_rules?,
collector_capability_digest?, request_key}`. It runs existing-rule matching and generation for the requirements
already published in this scope for those frameworks, without retrieving, extracting or re-validating documents.
Same gates as `auto_rule_generation` above (flags, tenant, pinned digest). The result has `status`,
`existing_rule_matching` (counts), `counts`, `rule_generation_decisions[]`, `mapping_ids`, `stages[]`; monitor it
with `GET /admin/jobs/{id}/progress` exactly as above. Readiness is not recomputed by this job.
Client: `OpmClient.generate_rules(framework_ids=..., request_key=..., tenant_id=..., auto_publish_validated_rules=...,
collector_capability_digest=...)`.

**Orchestration outcome per requirement** (`orchestration_outcome`):
`EXISTING_RULE_ASSIGNED`, `GENERATED_RULE_ACTIVATED`, `GENERATED_RULE_VALIDATED`, `PARAMETER_SOURCE_MISSING`,
`COLLECTOR_MISSING`, `EVIDENCE_SCHEMA_INCOMPATIBLE`, `RULE_PROPOSAL_AMBIGUOUS`, `RULE_SPEC_INVALID`,
`RULE_COMPILATION_FAILED`, `RULE_TEST_FAILED`, `SOURCE_GROUNDING_FAILED`, `POLICY_CONFLICT`, `OUTSIDE_PAM_SCOPE`,
`MANUAL_ASSESSMENT_REQUIRED`. Also seen: `NO_RULE_PROPOSED`, `LLM_OUTPUT_INVALID`, `LLM_ERROR`, and the §5.2 codes
when generation did not run (`NO_EXECUTABLE_RULE`, `LLM_NO_MAP`, `NON_OPERATIVE_TEXT`, `NOT_MANDATORY`, …).
Render unknown codes with their `message`.

**Reads.**
- `GET /frameworks/{id}/mapping-gaps?tenant_id=` items carry `rule_generation` (this organization's latest decision:
  `outcome`, `gap_code`, `message`, `rule_id`, `mapping_id`, digests). `executable_rules` includes this tenant's
  active generated rules.
- Plans (`/evaluation-templates/{id}/plan?tenant_id=`, POST plan) list generated executions with
  `rule_source: "GENERATED"` and `generated_rule{rule_origin, generated_rule_version_id, spec_digest, rule_digest,
  rego_digest, compiler_version, evidence_type, evidence_schema_version, assessment_mode, required_fields,
  collector_capability_digest, status, source_references, limitations}`. Evaluate them like any custom rule:
  `POST /evaluate` with the same `tenant_id`, `rule_id`, `rule_version` "1.0" and the declared evidence type.
- `GET /admin/rule-catalog` (with the scope header) adds this organization's generated rules. Every item has
  `origin`: `BUILT_IN`, `GENERATED` or `CUSTOM`, and each version's `public()` also carries `origin`.

**What the UI shows.** `GENERATED_RULE_ACTIVATED`: "Assigned (generated rule)", with the rule title, partial
coverage, its limitations and the source quotation. `GENERATED_RULE_VALIDATED`: "Validated, not activated".
`RULE_SPEC_INVALID`, `RULE_TEST_FAILED`, `RULE_COMPILATION_FAILED`: "Not covered (automatic rule rejected)".
`COLLECTOR_MISSING` and `EVIDENCE_SCHEMA_INCOMPATIBLE`: a collector task. `PARAMETER_SOURCE_MISSING`: the settings
form (§5.3). Generated coverage is always PARTIAL. Never present a framework as fully assessable.

**Bundle.** Bundle `2026.11.19-1` adds optional `period_field` and `required_fields` to the custom-rule input
(older custom rules are unchanged). Saved plan digests computed against `2026.11.16-1` change once.

## 6. Read API (`catalog:read`)

| Path under `/api/v1/catalog` | Content |
|---|---|
| `/meta` | schema and catalog version, active bundle |
| `/jurisdictions`, `/jurisdictions/{code}` | registry (`kind`, `parent` filters); overlap and coverage |
| `/frameworks`, `/frameworks/{id}` | `jurisdiction`, `include_overlapping`, `industry`, `as_of`, `verified_only`; detail includes documents |
| `/sources` | references, licensing, verification, freshness |
| `/requirements` | published requirements with citation (`framework_id`, `pam_domain`, `as_of`, `include_historical`). With the scope header and `framework_id`: all of the caller's own statuses plus published global ones |
| `/pam-controls`, `/mappings`, `/evidence-requirements`, `/rules`, `/remediations` | published reference data |
| `/evaluation-templates`, `/evaluation-templates/{framework_id}/plan` | §7 |
| `/changes?since=<catalog_version>` | ordered incremental feed; one publication is never split across pages |
| `/coverage`, `/coverage/unverified` | global dashboard metrics |
| `POST /applicability` | stateless screening |

Text from sources whose licence forbids redistribution is withheld (`text_withheld_reason`), and the citation is
still returned. If the catalog DB is missing, these endpoints return 503 `CATALOG_UNAVAILABLE`.

## 7. Templates, plans, evaluation

> **Organization policy, collector handshake and policy-bound plans** are specified in
> [POLICY_CONTEXT_DJANGO_CONTRACT.md](POLICY_CONTEXT_DJANGO_CONTRACT.md). That covers `GET /policy-controls`,
> `/admin/policy-contexts`, `/admin/collector-capabilities`, `POST …/plan`, and the `policy_version_id` +
> `reporting_period_*` plan parameters. Plans requested without those parameters are unchanged.

**`GET /evaluation-templates`** (`jurisdiction`, `include_inherited`, `include_unapproved`, `as_of`). Each item has
`framework_id`, `title`, `review_status`, `lifecycle`, `jurisdiction_code`, `jurisdiction_match` (`EXACT`/`INHERITED`),
`jurisdiction_path`, `source_origin` (`UPLOADED_DOCUMENT`, `OFFICIAL_DISCOVERY`, `MIXED`), `updated_at`,
`published_requirements`, `assessable_requirements`, `automated/manual/unmapped/blocked_requirements`,
`mapping_count`, `execution_count`, `readiness`, `blockers`.

- Readiness is `NOT_READY` when the framework is unapproved or nothing can execute, `READY` when every requirement is
  automated, and `PARTIAL` otherwise. This is engine coverage, never a compliance result.
- Items with zero executable checks stay listed. Django adds its own `MISSING_COLLECTOR` blockers.

**`GET /evaluation-templates/{framework_id}/plan`** (`tenant_id` required, `as_of`, `catalog_version`,
`expected_digest`) returns `framework` (with cited `documents`), `tenant_id`, `as_of`, `catalog_version`,
`policy_bundle_version`, `readiness`, `totals`, `blockers`, `requirements[]`, `executions[]`, `aggregation`,
`digest_input`, `plan_digest`. Unknown framework: 404 `UNSUPPORTED_FRAMEWORK`.

- `requirements[]` lists every published requirement in effect, with `assessment` (`AUTOMATED`, `MANUAL`, `UNMAPPED`,
  `BLOCKED`), `technical_coverage` (`FULL`, `PARTIAL`, `NONE`), `original_text` or `text_withheld_reason`,
  `source_reference`, `requirement_digest`, `execution_ids` and `mappings[]`.
- Only approved **and** published mappings are used. The pinned version is the highest `ACTIVE` in-range version
  effective on `as_of`. If none exists the requirement is `BLOCKED`; a version is never substituted. The same rule
  with identical values is one execution with several `requirement_ids`.
- Blockers: `FRAMEWORK_NOT_APPROVED`, `NO_PUBLISHED_REQUIREMENTS`, `NO_EXECUTABLE_MAPPINGS`, `RULE_NOT_IN_BUNDLE`,
  `RULE_VERSION_UNAVAILABLE`, `EVIDENCE_TYPE_MISMATCH`, `PARAMETERS_INCOMPATIBLE`, `RULE_INACTIVE_FOR_TENANT`.
- Digest: `"sha256:" + SHA-256(JSON(digest_input))`, with sorted keys, no whitespace and unescaped non-ASCII. It
  excludes `as_of`, `generated_at`, `catalog_version` and free text. Scoped plans include `organization_scope` in the
  digest input; unscoped digests are unchanged. Re-request with `expected_digest` before running a saved plan.
  409 `PLAN_STALE` (with the current digest, version and bundle) means resolve again. Prefer `expected_digest` over
  `catalog_version`, which also moves on unrelated publications.

**Evaluate is unchanged.** For each execution, send `rule_id`, the pinned `rule_version`, `reporting_period`,
`evidence`, and `policy_settings.parameters` = the reviewed parameters, adjusted only within `override_constraints`.
OPM doesn't enforce constraints at evaluate time, so Django must (`effective_parameters()` does). Keep the
framework/mapping/plan association in Django, and check that the result's `rule_version` and `policy_bundle_version`
match the plan. `INCOMPLETE`, `MANUAL_REVIEW` and `UNMAPPED` are Django report states, not engine statuses.

## 8. Workflows

Manual (human checkpoints):

```text
register jurisdiction/authority/framework → POST /uploads (legacy) or POST /sources
→ [review] verify source → job sync → [review] document review → job extract
→ [review] translation + requirement review → [publish] /publish
→ draft mapping → [review] mapping → /publish → templates / plan → evaluate
```

Automated: approve the framework identity and configure a source (inputs), then run `prepare_catalog` (discovery).
Rejected drafts stay in the manual queue.

Automatic rules (§5.2–§5.4): declare the collector (with `assessment_modes` and `supported_fields`) → save the
organization settings → `prepare_catalog` with `tenant_id`, `auto_rule_generation`, `auto_publish_validated_rules`
and the reviewed `collector_capability_digest` → show `mapping_decisions[].orchestration_outcome` → scoped plan →
evaluate (generated rules too).

Rewrite 1.0 (scoped): `GET /admin/health` (check capabilities) → scoped `POST /uploads` → `prepare_catalog` (import)
or `prepare_catalog` (discovery) → poll the job → scoped templates/plan → evaluate.

What Django builds: server-held tokens (never in the browser) and its own permission/CSRF checks; an upload view with
a 5 MiB pre-check and filename sanitising; a background job poller; review and processing screens backed by
`/processing` and `/attempts` (escaped, with no approve buttons on the transparency screen); a publish confirmation
showing `/pending`; error display keyed on `error.code` that logs `correlation_id`.

## 9. Client (`client/securden_opm_client.py`, `httpx` only)

| Method | Use |
|---|---|
| `catalog_get`, `catalog_iter`, `catalog_changes`, `applicability` | read API |
| `evaluation_templates`, `evaluation_plan` (verifies the digest); module functions `plan_digest`, `effective_parameters` | templates/plans |
| `catalog_admin_get`, `catalog_admin_iter`, `catalog_admin_action` (never retried) | any management call |
| `catalog_upload` | legacy upload |
| `catalog_discover`, `catalog_job`, `wait_for_job` | jobs (`catalog_build_framework` was removed) |
| `jurisdiction_coverage`, `document_attempts` | coverage / attempts |
| `OpmClient(…, organization_scope=…)` + `upload_document`, `prepare_catalog` (also `tenant_id`, `llm_mapping`, `auto_rule_generation`, `auto_publish_validated_rules`, `collector_capability_digest`) | rewrite 1.0 (raise `SCOPE_REQUIRED` without a scope) |

## 10. Schemas, samples, tests

- Schemas (`scripts/export_schemas.py` → `schemas/`): `evaluation_templates`, `evaluation_plan`, `mapping_create`,
  `job_prepare_catalog`, `generated_rule_spec_v1` (RuleSpec 1.0, §5.4), `collector_capabilities`, plus the
  evaluation schemas. Samples (synthetic):
  `docs/examples/framework_evaluation/`.
- Tests: `tests/regintel/test_evaluation_plan.py` (templates/plans/mappings), `test_admin_api.py` (management,
  restart → `INTERRUPTED`, idempotency), `test_discovery.py`, `test_mapping_policy.py` (auto-v2 applicability gate, mapping gaps), `test_automation.py` (rejections, retries,
  scoped publication), `test_rewrite_contract.py` (handshake, scope binding, scoped uploads, import/discovery, isolation,
  zero checks, retry `NOTHING_NEW`), `test_llm_mapping.py` (§5.2/§5.3, vendor matrices skipped),
  `test_rule_generation.py` (§5.4: gating, generation, rejections, idempotent retry, interruption, stale digest,
  isolation, cases against OPA), `tests/test_generated_rule_evaluate.py` (a generated rule through `/evaluate` and a
  real OPA server). Rego: `policy-tests/custom_v1_period_test.rego`. Full suite: 392 passed, 4 skipped (Caddy E2E).

## 11. Not provided / limits

- No API edit or delete of registry entries or uploads, and no withdrawal of requirements (host CLI only). No job
  cancellation, no webhooks (poll), no OCR, no multipart upload.
- No admin endpoint for manual requirement entry.
- Re-approving an approved framework creates a duplicate registry publication. Pin `expected_digest` to avoid false
  `PLAN_STALE` results.
- Real EU frameworks have no content yet. Only the synthetic fixture `SYNTHETIC-PAM-TEST` is populated, and it must
  never be presented as legal interpretation.
