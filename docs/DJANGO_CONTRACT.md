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
| `catalog:automate` | jobs `build_framework` and `prepare_catalog` (`catalog:operate` alone gets 403) |
| any management scope | every management GET (draft text, document text, job history, attempts) |

`securden-pam` currently holds all of them. Separate per-reviewer credentials are optional
(`scripts/manage_keys.py add reviewer-<person> --scopes catalog:review,catalog:publish,catalog:read`, then restart).

`GET /api/v1/catalog/admin/health`:

```json
{"status": "ok", "key_id": "securden-pam",
 "scopes": ["catalog:automate", "catalog:operate", "catalog:publish", "catalog:read", "catalog:review"],
 "policy_bundle_version": "2026.11.12-1",
 "automation": {"scope": "catalog:automate", "policy_version": "auto-v3", "enabled": true},
 "rewrite_contract_version": "1.0",
 "capabilities": {"prepare_catalog_v1": true, "scoped_imports_v1": true, "scoped_catalog_v1": true},
 "schema_version": "1.0", "catalog_version": 12}
```

Show the automated triggers only when `automation.enabled` is true. Enable the rewrite UI only when all three
capabilities are true, since they are false without `catalog:automate`. Compare `policy_bundle_version` with
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
| `build_framework` | `framework_id`, opt `version_ids`, `translate`, `as_of` (schema `job_build_framework.schema.json`) | automate |
| `prepare_catalog` | §5 (schema `job_prepare_catalog.schema.json`) | automate + scope header |

- `build_framework` and `prepare_catalog` also accept optional `languages` (`["en"]`) and `screening`
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
- `build_framework` result: `stages[]` (`resolve`, `sources`, `retrieve`, `document_review`, `extract`,
  `candidate_review`, `publish`), `sources`, `documents`, `extraction`, `review` (`approved[]`, and `rejected[]` with
  `problems` and `LEFT_DRAFT_FOR_HUMAN_REVIEW`), `publication`, `coverage`, `readiness`, `counts`, `blockers`,
  `next_actions`, `statement`. `outcome` is `PUBLISHED`, `NOTHING_TO_PUBLISH`, `FRAMEWORK_NOT_APPROVED` (FAILED) or
  `SOURCE_CONFIGURATION_REQUIRED` (FAILED). It publishes only its own automated approvals.

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
- Both modes run `build_framework` per framework, then deterministic mapping preparation (REGINTEL.md §7) and
  publication of the new mappings.

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

### 5.1 Mapping proposals (source-grounded, read-only)

A framework can have a proposal set (`regintel/data/mapping_proposals/<framework_id>.json`, today only
`NIST-SP-800-53-R5`, `proposal_set_id` `nist-sp800-53r5-pam-v1`, status `PROPOSED_UNREVIEWED`). It holds one proposal
per published requirement: a `CANDIDATE` rule or a structured `REJECTED` reason. Proposals never create, approve or
publish a mapping.

**`GET /api/v1/catalog/frameworks/{id}/mapping-proposals[?tenant_id]`** (`catalog:read`; with `tenant_id`, send the
scope header). It validates the set live and returns `{framework_id, proposal_set{proposal_set_id, status,
prepared_by, source, statement}, policy_bundle_version, collected_rules[], items[], counts{requirements, candidates,
rejected, eligible_for_publication, by_effective_code}, blocker_codes[], proposal_digest}`. It returns 404
`NO_PROPOSAL_SET` when the framework has none, and 404 `UNSUPPORTED_FRAMEWORK` for unknown or cross-scope frameworks.

Each item contains:
- **`citation`**: `{framework_id, requirement_id, document_version_id, section_ref, canonical_id, clause, location,
  quote}`. The `quote` is the exact stored requirement text. Show it with the canonical ID.
- **Proposal status**: `proposal_status` is `VALID`, `INVALID` (with `source_problems[]`: canonical ID, clause or
  quote prefix differs from the stored text) or `NO_PROPOSAL`.
- **Codes**: `classification` (`CANDIDATE` | `REJECTED`), `proposed_code`, `detail_code` and `engine_gap_codes[]`
  (the mapping-gaps result). `effective_code` is the code to display. For a candidate it is the live
  handshake-dependent code of the candidate rule.
- **`organization_defined[]`** and `rationale`.
- **Candidate only**: `candidate{rule_id, rule_version, evidence_type, evidence_schema, policy_control_id, coverage,
  technical_coverage, tests, parameters[{name, provenance, source_text?, note?}], organization_defined_inputs[],
  required_new_evidence_fields[], validation_problems[], collected, limitations}` and `residual_gaps[]`
  (`PARTIAL_COVERAGE` for partial coverage).
- **Rejected only**: `rejection{code, detail_code, reason, rejected_rules[{rule_id, reason}]}`, and optionally
  `proposed_new_rule` (status `NOT_IMPLEMENTED`).
- **`publication{eligible, blockers[], route}`**:
  - `blockers` come from `PROPOSAL_UNREVIEWED`, `PROPOSAL_SOURCE_MISMATCH`, `CANDIDATE_INVALID`,
    `ORGANIZATION_DEFINED_INPUTS`, `PARAMETER_NOT_IN_SOURCE`, `COLLECTOR_MISSING`, `REJECTED` and `NO_PROPOSAL`.
  - `route` is `{provenance: "CUSTOMER_POLICY", policy_control_id, resolves: "POLICY_CONTEXT_REQUIRED",
    result_at_best: "PARTIALLY_RESOLVED"}` when a customer policy version can bind the rule in a plan. Otherwise it
    is null.

Values used in these fields:
- **Parameter `provenance`**:
  - `SOURCE_TEXT` (value stated in the passage; the only provenance a regulatory mapping may use)
  - `ORGANIZATION_DEFINED` (an `[Assignment]`/`[Selection]`; it must come from a policy context)
  - `NOT_IN_SOURCE` (the rule needs a value the passage does not address; it must come from a policy context)

  No value is ever taken from an OPA default or a vendor document.
- **`detail_code`**: `PROCEDURAL_OBLIGATION`, `NO_RULE_FOR_BEHAVIOUR`, `LOOKALIKE_RULE_REJECTED`,
  `PRODUCT_CAPABILITY`, `PARTIAL_COVERAGE`, `MOBILE_DEVICE_MANAGEMENT`, `DATA_STORE_AUDITING` and
  `REGISTRATION_PROCESS`.

**Preserved runs (admin).**
- `POST /api/v1/catalog/admin/frameworks/{id}/mapping-proposals/runs` with body `{tenant_id?}` (`catalog:operate`;
  scope header required with `tenant_id`). It stores the full result, accepted candidates and rejected proposals
  with reasons, as an immutable `mapping_proposal_run` row and returns `{run_id, …result}`.
- `GET …/admin/frameworks/{id}/mapping-proposals/runs` and `GET …/admin/mapping-proposal-runs/{run_id}`
  (`catalog:read`) read them back. A scoped run is 404 for other scopes. Update and delete are blocked by triggers.

**Migration.** The `mapping_proposal_run` table and its triggers are created idempotently at service start. No
existing table changes.

**NIST state at catalog version 20** (bundle `2026.11.16-1`; handshake credential_rotation, privileged_account and
privileged_session, all 1.0):

| Totals | Count |
|---|---|
| Requirements | 41 |
| Candidates | 5 |
| Rejected | 36 |
| Eligible for publication | 0 |
| Effective `POLICY_CONTEXT_REQUIRED` | 1 |
| Effective `COLLECTOR_MISSING` | 4 |
| Effective `NO_EXECUTABLE_RULE` | 33 |
| Effective `OUTSIDE_PAM_SCOPE` | 3 |

No mapping was published, so templates and saved plans are unchanged (readiness `NOT_READY`).

| Requirement | Canonical | Effective code | Candidate / rejection |
|---|---|---|---|
| 354 | AU-14 a | POLICY_CONTEXT_REQUIRED | PAM-SESSREC-001 1.0, `privileged_session` 1.0, PARTIAL, route PC-SESSION-RECORDING; `accept_partial_recordings` NOT_IN_SOURCE; users/roles, selection and circumstances ORGANIZATION_DEFINED. Tests "record" only. |
| 360 | IA-2(6) | COLLECTOR_MISSING | PAM-MFAACC-001 1.0, `privileged_access_authentication` 1.0, PARTIAL; `accepted_methods` ORGANIZATION_DEFINED; PAM-MFACFG-001 rejected (configuration is not MFA-at-access history). |
| 299 | AC-2 i | COLLECTOR_MISSING | PAM-UNAUTH-001 1.0, `access_authorization` 1.0, PARTIAL (item 1 only). |
| 326 / 327 | AC-7 a / b | COLLECTOR_MISSING | PAM-AUTHFAIL-001 1.0, `authentication_summary` 1.0, PARTIAL; all three parameters ORGANIZATION_DEFINED or NOT_IN_SOURCE. |
| 372 | IA-5 i | NO_EXECUTABLE_RULE | PAM-ROTATION-001 rejected (`LOOKALIKE_RULE_REJECTED`); proposed new rule PAM-MEMBERROT-001 NOT_IMPLEMENTED. |
| 328, 353, 391 | AC-7(2), AU-12(4), IA-5(16) | OUTSIDE_PAM_SCOPE | mobile device management, data-store auditing, registration process |
| others | | NO_EXECUTABLE_RULE | procedural duty, no rule for the behaviour, product capability, or a look-alike rule rejected |

**New evidence fields needed before the candidates can go beyond partial coverage** (not in schema 1.0; proposals
only):
- `privileged_access_authentication`: `access_channel` (LOCAL/NETWORK/REMOTE), `account_class`
  (PRIVILEGED/NON_PRIVILEGED), `factor_on_separate_device` (boolean), `device_strength_profile`. These cover
  IA-2(6) (a) and (b).
- `authentication_summary`: `action_taken` (LOCKED_TIMED, LOCKED_UNTIL_RELEASE, DELAYED, ADMIN_NOTIFIED, OTHER or
  NONE) and `lock_duration_seconds`. These cover AC-7 b.
- `shared_account_membership_change` 1.0 (new type, for IA-5 i): `account_id`, `account_kind`,
  `membership_change_id`, `membership_changed_at`, `change_type`, `authenticator_changed_at`.

**Getting a NIST result today.** The only executable route is AU-14 a through a customer policy. Save a policy
version with `PC-SESSION-RECORDING`, with the organization's own targets (USER, USER_GROUP or ORGANIZATION) and
`accept_partial_recordings`. Then `POST /evaluation-templates/NIST-SP-800-53-R5/plan` with `tenant_id`,
`policy_version_ids` and `reporting_period`, and run `policy_context.executions[].evaluate_request` through
`/evaluate`. The requirement reports `POLICY_CONTEXT_REQUIRED/PARTIALLY_RESOLVED` or `RESOLVED_BY_POLICY`,
followed by `PARTIAL_COVERAGE/OPEN`. It is never shown as full AU-14 compliance. The other 40 stay gaps and must
never be rendered as PASS.

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

Create, review and publication are separate audit records. Every mapping it produces is **organization-scoped**, including mappings on global requirements: the inputs (collector declaration, policy, PAM configuration, uploaded matrices) belong to one organization. Other organizations never see them.

New `prepare_catalog` body fields, all optional:
- `tenant_id`: whose collector handshake, policy and PAM configuration apply. The default is the scope's single declared tenant.
- `capability_document_ids`: a subset of `document_ids` to treat as vendor capability matrices. Other matrices are detected from their tables.
- `llm_mapping`: default `true`.

**Capability-mapping documents** (for example the Securden NIST SP 800-53 control mapping matrix):
- Upload them like any document (`POST /uploads`), then include them in an import job.
- They are **not regulations**. They never go through `build_framework` and never create requirements or `ORG-` frameworks.
- Table rows are extracted from PDF (layout mode) or HTML `<table>`s as `{control_id, control_title, requirement_summary, capability_text, source_section}`. They are stored scoped with `source_origin=VENDOR_CAPABILITY_MAPPING`.
- Rows are resolved against the official control headings of the framework's reviewed global source. The framework is the one requested, the document's own, or a unique ID match. Resolution status is one of:
  - `RESOLVED`, linked to the published requirements with that canonical control
  - `OFFICIAL_CONTROL_WITHOUT_PUBLISHED_REQUIREMENT`
  - `CANONICAL_CONTROL_UNRESOLVED`
- A row is supplemental capability evidence for the analyst. It is never evidence of compliance.
- The result carries `capability_documents[]`. Job gaps are `CAPABILITY_TABLE_NOT_FOUND` and `CANONICAL_CONTROL_UNRESOLVED`.

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

Vendor capability text can ground only the strict reading of a boolean, never a number. For example, "full video playbacks" gives `accept_partial_recordings=false`, published PARTIAL for the named protocols. "automated rotation schedules" and "accounts not used for a while" establish no interval.

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

Re-runs with unchanged inputs reuse the recorded decision without a model call, so the job is idempotent. New inputs, such as a PAM configuration snapshot, a policy, a handshake, matrix rows or a model change, lead to a new decision.

The review attestations hold:
- model, model digest, prompt and policy versions
- input digest and job id
- confidence
- source requirement
- rule and version
- parameters with provenance
- capability row ids
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
- `counts` gains `llm_candidates`, `mappings_validated`, `mappings_published`, `ambiguous_candidates`, `missing_parameters`, `missing_collectors`, `unsupported_requirements` and `capability_rows`.
- `mapping_gaps[]` and `GET /frameworks/{id}/mapping-gaps` carry `llm_mapping` (this organization's latest decision) for each requirement.
- `executable_rules` counts global mappings plus this organization's mappings only.
- Published mappings appear in this organization's `/evaluation-templates/{id}/plan`.

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

Automated: approve the framework identity and configure a source (inputs), then run `build_framework`. Rejected drafts
stay in the manual queue.

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
| `catalog_discover`, `catalog_build_framework`, `catalog_job`, `wait_for_job` | jobs |
| `jurisdiction_coverage`, `document_attempts` | coverage / attempts |
| `OpmClient(…, organization_scope=…)` + `upload_document`, `prepare_catalog` | rewrite 1.0 (raise `SCOPE_REQUIRED` without a scope) |

## 10. Schemas, samples, tests

- Schemas (`scripts/export_schemas.py` → `schemas/`): `evaluation_templates`, `evaluation_plan`, `mapping_create`,
  `job_build_framework`, `job_prepare_catalog`, plus the evaluation schemas. Samples (synthetic):
  `docs/examples/framework_evaluation/`.
- Tests: `tests/regintel/test_evaluation_plan.py` (templates/plans/mappings), `test_admin_api.py` (management,
  restart → `INTERRUPTED`, idempotency), `test_discovery.py`, `test_mapping_policy.py` (auto-v2 applicability gate, mapping gaps), `test_automation.py` (rejections, retries,
  scoped publication), `test_rewrite_contract.py` (handshake, scope binding, scoped uploads, import/discovery, isolation,
  zero checks, retry `NOTHING_NEW`). Full suite: 321 passed, 4 skipped (Caddy E2E).

## 11. Not provided / limits

- No API edit or delete of registry entries or uploads, and no withdrawal of requirements (host CLI only). No job
  cancellation, no webhooks (poll), no OCR, no multipart upload.
- No admin endpoint for manual requirement entry.
- Re-approving an approved framework creates a duplicate registry publication. Pin `expected_digest` to avoid false
  `PLAN_STALE` results.
- Real EU frameworks have no content yet. Only the synthetic fixture `SYNTHETIC-PAM-TEST` is populated, and it must
  never be presented as legal interpretation.
