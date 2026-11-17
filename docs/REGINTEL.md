# Regulatory intelligence internals (`regintel/`)

`regintel` maintains a worldwide, **source-verified** regulatory catalog for PAM compliance. A new country,
subdivision, regional body, standard or industry framework is added as *data* (registry rows and source
configuration), never as code. This file covers the internals and the operator CLI. The HTTP contract for Django is
in DJANGO_CONTRACT.md.

> **What this is not.** The catalog ships with a full jurisdiction *registry* and **no regulatory content**. A
> jurisdiction gains coverage only as its sources are verified and its documents, requirements, mappings and rules
> are approved and published. No endpoint has a "fully supported" state.

## 1. Architecture and principles

```
official sources ─HTTPS, domain allowlist─▶ sync ─▶ document versions (immutable)
local model (Ollama, loopback) ─▶ extract / translate ─▶ DRAFT requirements
review (human, or automated policy auto-v2) ─▶ APPROVED ─publish─▶ data/regintel/catalog.db
approved rule versions ─build + opa test─▶ bundle-store/versions/<v>/ (immutable) ─▶ OPA + API
```

- **Evaluation stays deterministic.** `app/` has no LLM call and no network egress. Published rules are data for the
  fixed interpreter `securden.custom.v1`, and no Rego is generated.
- **The model only proposes.** Its output is schema-validated and grounded against the source text before it becomes
  a `DRAFT`. Drafts are never served publicly.
- **Approval, then a separate publication.** Every entity goes `DRAFT → APPROVED → published`. A human may review a
  draft they authored. Model identities (`llm:*`) can never review, and executable rule versions still need a second
  reviewer. Automated approvals are recorded as `decision_origin=AUTOMATED` by `engine:<key_id>` (§7).
- **Writes happen only in catalog-admin.** The evaluation API opens `catalog.db` read-only.

| Layer | Entity | Meaning |
|---|---|---|
| `EXPLICIT_OBLIGATION` | `RegulatoryRequirement` | verbatim passage with document version, section and language |
| `INTERPRETIVE_MAPPING` | `FrameworkControlMapping` | reviewed reading that a PAM control/rule supports the passage (rationale, limitations) |
| `CUSTOMER_POLICY` | request-time `policy_settings`, `CUST-` rules | customer thresholds, never stored as regulation |
| `EXECUTABLE_RULE` | `OPARuleDefinition` / `RuleVersion` | a structured test for OPA, linked to regulation only through mappings |

A threshold declared `REGULATORY` must appear literally in an approved requirement's text. Converted or inferred
values must be declared `SECURDEN_DEFAULT` or `CUSTOMER_POLICY`.

## 2. Data model (`data/regintel/catalog.db`)

`jurisdiction` (+ dated `jurisdiction_membership`), `regulatory_authority`, `regulatory_framework`, `source`,
`source_verification`, `regulatory_document`, `regulatory_document_version` (+ `document_section`),
`regulatory_requirement`, `pam_control`, `framework_control_mapping`, `evidence_requirement`,
`applicability_criteria`, `opa_rule_definition`, `rule_version`, `remediation_template`, `review_approval`,
`catalog_publication` (+ `catalog_change`), `bundle_version`, `regulatory_change`, `sync_run`, `extraction_attempt`,
`job`, `organization_scope_binding`, `upload_request`, `audit_event`.

- Triggers make reviewed text, mappings, rule versions, document versions, decisions, publications and bundles
  immutable. A correction is a new row plus a withdrawal.
- Organization-scoped rows (`organization_scope` on framework, source, document, requirement and mapping) come from
  scoped uploads. Global rows have `organization_scope IS NULL`. An LLM-assisted mapping is scoped to the organization
  even on a global requirement (its `mapping_key` then carries a scope digest).
- `capability_mapping_row` (vendor capability matrix rows, scoped), `pam_configuration_snapshot` (verified collector
  configuration, immutable) and `llm_mapping_decision` (one per scope/requirement/input digest, never deleted).
- Review records carry `decision_origin` (`HUMAN`|`AUTOMATED`|`AUTOMATED_LLM`, the last for mappings only), `policy_version` and `attempt_id`.
  `extraction_attempt.kind` is one of `EXTRACTION`, `TRANSLATION`, `REVIEW`, `TRANSLATION_REVIEW`.
- Migrations are additive and run when catalog-admin starts. Back up `catalog.db` before upgrading.
- Organization policy (CUSTOMER_POLICY) lives in `policy_context` and `policy_context_version`, which are immutable
  and never deleted. Collector handshakes live in `collector_capability`, which is append-only. Policy never alters
  regulatory rows. The Django contract is in
  [POLICY_CONTEXT_DJANGO_CONTRACT.md](POLICY_CONTEXT_DJANGO_CONTRACT.md).

## 3. Jurisdictions and frameworks

`python -m regintel init --actor <you>` can safely be repeated. It loads 249 ISO 3166-1 countries/territories and
5,046 ISO 3166-2 subdivisions (pycountry 26.2.16, LGPL-2.1), `EU` with dated memberships, `INT`, and the PAM controls
with their predefined rules. Inheritance is evaluated per date (`DE-BY → DE → EU`). A framework can name the framework
it implements (`implements_framework_id`).

Frameworks start `UNVERIFIED` with no dates. Approving a framework's identity needs no document. Recording lifecycle
and dates (`verify-framework`) needs a reviewed, complete document version of that framework.

## 4. Sources and retrieval

Each source declares an official-domain allowlist (a subset of the authority's domains), formats, discovery method,
version identification, change detection, rate limit, licensing and verification method.

| Adapter | Use |
|---|---|
| `static_list` | explicit document URLs on the authority's domain (html, txt or pdf) |
| `index_page` | official gazette index; links leaving the allowlist are ignored |
| `eurlex` | EU law by CELEX via `publications.europa.eu`, one request per language |
| `file_drop` | operator-obtained files (also used by uploads); nothing is downloaded |

On every hop, including redirects, the fetcher enforces HTTPS with certificate validation, the allowlist, the rate
limit, a request budget and a size cap. Any status other than 200 is an error. Document language comes from the
config and is never guessed.

Source lifecycle: `PROPOSED → VERIFIED | REJECTED`. Verification is bound to the exact config, and editing the config
returns the source to `PROPOSED`. Only verified sources are synced. Sync stores each distinct content hash as an
immutable version, and a changed hash records a `regulatory_change`. Truncated, empty or unparseable documents and
PDFs without a text layer are stored as **incomplete**. They can't be reviewed or extracted from, because there is no
OCR. PDF parsing needs `pypdf` (`requirements-catalog.txt`). A sync that matches nothing succeeds with a warning: an
empty result is not evidence of absence.

`init --starter-sources` proposes `eurlex-core` (NIS2, DORA, GDPR by CELEX; en/de/fr). It stays `PROPOSED` until a
real reviewer verifies it.

## 5. Local model (Ollama)

```dotenv
OPM_REGINTEL_LLM_URL=http://127.0.0.1:11434
OPM_REGINTEL_LLM_MODEL=gemma3:4b
OPM_REGINTEL_REQUIRE_GPU=1
OPM_REGINTEL_LLM_NUM_CTX=4096
OPM_REGINTEL_LLM_NUM_PREDICT=2048
OPM_REGINTEL_LLM_TIMEOUT=600
OPM_REGINTEL_LLM_KEEP_ALIVE=5m
```

Check the model with `python -m regintel llm-check`, which runs real inference and reports the model, its digest and
GPU placement.

- The endpoint must resolve to a loopback or private address; there is no path to a hosted LLM. `REQUIRE_GPU=1`
  needs nonzero VRAM and still allows partial CPU offload. On the RTX 3050 Ti (4 GB), `gemma3:4b` runs partly on the
  CPU.
- Calls use structured outputs, temperature 0, a fixed seed and bounded output. Truncated or malformed output fails
  explicitly.
- A candidate becomes a draft only if it is schema-valid, its quote occurs **verbatim** in its section (after
  whitespace/quote normalization only), and every threshold appears in that quote. Document, framework, language and
  section always come from the database row, never from the model.
- Every model call (extraction, translation, review, translation review), including failures, is stored in
  `extraction_attempt` with raw, parsed and validated output, errors and accepted/rejected candidates.
- Non-English drafts need a reviewed translation, or an original-language attestation, before approval. Unreviewed
  translations are never served, and every translation is `authoritative: false`.
- Grounding proves the quote exists. It doesn't prove the quote is relevant: live runs drafted an irrelevant filler
  passage. That's why review exists.

## 6. Manual review and publication (CLI)

The same steps are available over HTTP (DJANGO_CONTRACT.md §4).

```
python -m regintel verify-source <id> --actor R --outcome VERIFIED --evidence "<real findings>"
python -m regintel sync <id> --actor O
python -m regintel review-document <version_id> --decision APPROVED --comment "…" --actor R
python -m regintel extract <version_id> --actor O
python -m regintel review requirement <id> --decision APPROVED --comment "…" --actor R
python -m regintel add mapping --file mapping.json --actor A ; review mapping <id> …
python -m regintel list pending ; publish --actor R
python -m regintel withdraw requirement <id> --reason "…" --actor R
```

- `add` also accepts `evidence-requirement`, `applicability-criteria`, `remediation`, `rule`, `requirement` (manual
  entry, same grounding) and the registry kinds.
- `publish` re-validates the whole pending queue and is all-or-nothing. Withdrawal is its own publication and cascades
  to dependent mappings.
- Approving a new document version with `--supersede-previous` marks the old requirements `SUPERSEDED`. They stay
  available for `as_of` queries.
- Remediation templates need actions, capabilities, customer responsibilities and a citation. `auto_execute` is
  always false.
- Never use a fabricated reviewer identity, and never claim verification just because a download succeeded.

**EU staging package** (`scripts/prepare_catalog_documents.py`, with `--fetch-only` / `--all-sections` options):
downloads the English NIS2/DORA/GDPR texts and pre-drafts candidates into `data/regintel/staging/eu-starter/`
(`EU-*-en.json`, hashed `.html`, `summary.json`, `REVIEW.md`). It resumes where it stopped, and it creates no
verification, approval or publication. The texts are the original acts, not consolidated law.

## 7. Automated pipeline (policy `auto-v3`)

`build_framework` and `prepare_catalog` jobs need `catalog:automate`. They run every stage without waiting for a
person.

| Stage | Automated rule |
|---|---|
| Source verification | network adapters only (never `file_drop`) whose whole allowlist is within the authority's official domains. Scoped uploads are verified as organization-scoped working input (`SCOPED_UPLOAD_PROVENANCE_RECORD`) and are never labelled official |
| Document review | parser marked the version complete and it has ≥ 1 section; otherwise blocker `INCOMPLETE_DOCUMENTS` |
| Applicability gate (first, no model call) | `regintel/mapping_policy.py`: the passage must be **operative**, so not a recital (`(preamble)` section, or before the enacting formula "HAVE ADOPTED THIS REGULATION/DIRECTIVE" in its version, including PDF pages). It must also be **addressed to the organization**: not to Member States, the Commission, ENISA, CSIRTs, competent/supervisory authorities or the ESAs (for list points, the subject of the introducing clause is checked), and not a data-subject right. Failures stay `DRAFT` with `NON_OPERATIVE_TEXT` / `OUTSIDE_PAM_SCOPE` |
| Candidate approval | **both** a schema-valid `APPROVE` from a second model review (`review-v1`) of the candidate against its section, **and** the code checks (verbatim grounding, attribution, reviewed document + verified source, literal thresholds, no duplicate, date order, valid PAM domains) |
| Translation | model translation review **and** a code check that no new numbers appear |
| Publication | only this job's automated approvals (`publish_scoped`), never the general pending queue |
| Mappings (`prepare_catalog`) | deterministic recipes (`regintel/mapping_recipes.py`, `pam-recipes-v1`), never model-assigned `pam_domains`. TEXT recipes: privileged wording, any framework. CANONICAL recipes: NIST SP 800-53 control ID, clause and title. A mapping is auto-published only when the passage is `MANDATORY`, operative, in scope, not a licensing/provenance statement and fully parsed, **exactly one** rule and ACTIVE version is resolved, its evidence is collected (`OPM_REGINTEL_BRIDGE_COLLECTED_RULES`, default `PAM-ROTATION-001,PAM-DORMANT-001,PAM-SESSREC-001`), **every** parameter is stated in the passage (one value; no `[Assignment]`; never a rule default or company policy), and no conflicting mapping exists. Session recording binds `accept_partial_recordings=false` only for "all/every/each session". Coverage is always `PARTIAL`, the version is pinned, the override max is the stated value, and the review records recipe, source requirement, rule version, parameters with provenance, coverage and limitations. Every requirement gets a structured decision (`auto_mapping`) and `mapping_gaps` (below); the codes are in DJANGO_CONTRACT.md §5 |
| LLM-assisted mappings (`prepare_catalog`, `llm-auto-v1`) | `regintel/llm_mapping.py`. The local model is the analyst: per published requirement with semantic candidate rules it proposes one strict-JSON decision. Deterministic code is the gate. It resolves parameters itself (regulatory text, then in-force organization policy, then verified PAM configuration snapshot, else `PARAMETER_SOURCE_MISSING`; vendor capability text only grounds a strict boolean reading) and checks candidate rule, single ACTIVE pinned version, declared collector, confidence threshold, identical bindings with located quotations, rationale/limitations/population, no conflict and ownership. Results are organization-scoped, PARTIAL, reviewed with origin `AUTOMATED_LLM` and recorded in `llm_mapping_decision` (idempotent per input digest). Vendor capability matrices (`regintel/capability_tables.py`) become scoped `capability_mapping_row`s attached to official controls, never requirements. Contract: DJANGO_CONTRACT.md §5.2 |
| Section coverage | `section_coverage[]` per version: operative vs. recital sections, and operative sections never extracted (`unprocessed_refs`). These become gap `OPERATIVE_SECTIONS_UNPROCESSED`: publishing some requirements does not establish coverage of the rest. Bounded (screened) runs skip recitals entirely (`non_operative`) |

**Mapping gap codes** (technical mapping observations, not determinations of legal applicability):

| Code | Meaning |
|---|---|
| `NON_OPERATIVE_TEXT` | recital/preamble: explains the act, imposes no duty |
| `OUTSIDE_PAM_SCOPE` | addressed to a public body, or a data-subject right |
| `POLICY_CONTEXT_REQUIRED` | a collected rule tests the behaviour, but the passage states no value for its parameter (e.g. "password changes" with no interval), or it leaves selectors, values or circumstances to the organization (`organization_defined`: NIST `[Assignment: …]` / `[Selection: …]`). Resolved only by an organization policy context (CUSTOMER_POLICY, [POLICY_CONTEXT_DJANGO_CONTRACT.md](POLICY_CONTEXT_DJANGO_CONTRACT.md)); automation never maps it |
| `COLLECTOR_MISSING` | the rule exists in the bundle (e.g. `PAM-APPROVAL-001`, `PAM-REVIEW-001`), but the bridge supplies no evidence for it; agree a collector schema with the Django side first |
| `NO_EXECUTABLE_RULE` | a named behaviour that no rule tests: strong authentication, cryptography, change management, event-triggered authenticator change (not age-based rotation), temporary/emergency account expiry (not dormancy), separation of duties, password composition/blocklists, mobile-device purge, audit record content/review/retention/protection (beyond log completeness) |
| `MAPPING_MISSING` | in scope, but no deterministic signal; needs a human mapping decision |
| `PARTIAL_COVERAGE` | mapped, or resolved by organization policy: the rule tests the recorded PAM control only and the rest of the passage is not assessed |

Catalog-style standards (NIST SP 800-53) get a derived `canonical_reference` (control, enhancement, clause) from the
headings of the official text (`regintel/control_ids.py`). Stored page references are unchanged. See
`GET /frameworks/{id}/control-coverage` for clause duplicates and omitted controls (DJANGO_CONTRACT.md §5).

Rejected candidates stay `DRAFT` (`LEFT_DRAFT_FOR_HUMAN_REVIEW`) for the manual workflow. Framework identity
approval and source configuration remain inputs to the pipeline. Every stage is idempotent, so a retry converges to
`NOTHING_NEW` / `NOTHING_TO_PUBLISH`. A section with a completed extraction attempt is never sent to the model again.

**Work bounds.** Jobs accept `languages` (e.g. `["en"]`) and `screening` (`none` | `pam-keyword-screen-v1`).
Unset values fall back to `OPM_REGINTEL_AUTOMATION_LANGUAGES` / `OPM_REGINTEL_AUTOMATION_SCREENING` in `.env`. This
host is set to `en` + `pam-keyword-screen-v1`. With screening, only sections that mention PAM subjects are processed,
and only their matching lines (± 1 line) are sent to the model. Grounding still checks the full section text.
Screened-out sections and drafts from them (for example, from an earlier unscreened run) are counted and left `DRAFT`,
never treated as "no obligation". Measured on this GPU: about 6 s per screened extraction call and about 8 s per
review, against about 60 s per full-section call. A full EU discovery now takes minutes instead of days.

**Source screens.** A source config may declare `section_screen: {include: [regex…], excerpt: [regex…]}`. When
screening is on, it replaces the keyword screen for that source. A section is sent only if an `include` pattern
matches, and only the `excerpt` matches (merged, in document order) are sent; an included section with no excerpt
match is sent whole. Provenance records `pam-keyword-screen-v1+source`. Because the screen is part of the config,
changing it sends the source back to `PROPOSED`. Example: the `nist-sp800-53r5` source includes only the AC-2/5/6/7/12,
AU-2/6/9/11/12/14 and IA-2/4/5 control pages, 32 of 492, and sends only their `Control:` statements and enhancement
statements (about 29k characters in total). NIST values are `[Assignment: organization-defined …]`, so automatic
mappings stay `UNMAPPED` until a human sets the thresholds.

**Progress and ETA (`regintel/progress.py`).** `Jobs.set_progress` stores each marker with a `timing` block: the
current step (stage, framework, version), its start, the first counter sample, and a bounded history of finished
counted steps with seconds per unit. `extract` (and the single-version `extract` job) count sections, and
`candidate_review` counts candidates. `GET /jobs/{id}/progress` turns this into a step ETA from the step's own rate,
falling back to the median rate of the last 20 succeeded jobs. It gives a job ETA only when the remaining work is
known: the last framework's `candidate_review`, or its last version's `extract` plus projected candidates at the
reference review rate. Otherwise the ETA is null with a reason code (see DJANGO_CONTRACT.md). The estimate is
computed on read; nothing extra is written beyond the marker.

**Preloading the staging package.** `scripts/import_staging.py --actor <you>` imports the offline candidates from
`data/regintel/staging/eu-starter/` as model drafts. It only imports documents byte-identical to a catalog version,
re-grounds every candidate and records an import attempt, so later jobs skip those sections. Nothing is approved by
the import itself.

## 8. Applicability

`POST /api/v1/catalog/applicability` (or `python -m regintel applicability`) is a pure function of the profile, the
catalog and the date. In the profile, `null` means "not stated" and `[]` means "none".

| Outcome | When |
|---|---|
| `APPLICABLE` | customer-selected or contractual, or reviewed criteria are fully met |
| `POTENTIALLY_APPLICABLE` | a nexus exists but facts are missing, or the criteria add nothing beyond jurisdiction |
| `NOT_APPLICABLE` | not in force, voluntary and not selected, or a criterion is contradicted |
| `REQUIRES_LEGAL_REVIEW` | nexus without reviewed criteria, unverified framework, cross-border, or unknown framework |

A country match alone is never `APPLICABLE`. Every response carries the reasons and a not-legal-advice statement.

## 9. Rule bundles and rollback

```
python -m regintel add rule --file rule.json --actor A        # definition + threshold provenance + ≥1 PASS and ≥1 FAIL test
python -m regintel review rule <id> --decision APPROVED --actor R   # R ≠ A
python -m regintel bundle-build --actor R
python -m regintel bundle-activate <version|base> --actor R
```

`bundle-build` copies the base bundle, adds the approved `REG-` rules as compiled data and runs `opa check --strict`,
the Rego tests, a consistency check and every rule's test cases with the real OPA binary. A failure discards the
build; a success becomes read-only with its digest recorded. `bundle-activate` verifies the digest and updates
`bundle-store/ACTIVE`. Then restart the stack. Until OPA and the API run the same bundle, `/ready` fails and
evaluations return `502 POLICY_VERSION_MISMATCH`.

## 10. Coverage

`GET /api/v1/catalog/coverage` or `python -m regintel coverage [--json]` counts global content only. Stages go
`REGISTERED_ONLY → SOURCE_PROPOSED → SOURCE_VERIFIED → DOCUMENTS_RETRIEVED → DOCUMENTS_REVIEWED →
REQUIREMENTS_PUBLISHED → MAPPINGS_PUBLISHED`. A group's coverage (for example the EU) is not credited to its members.

## 11. Current catalog state and limits

- `EU-NIS2`, `EU-DORA` and `EU-GDPR` are registered and identity-approved but have **no documents, requirements or
  mappings**. Their templates are correctly `NOT_READY` / `NO_PUBLISHED_REQUIREMENTS`. Populating them needs a human
  to attest provenance, licensing and applicability, either by verifying `eurlex-core` or by uploading the official
  texts.
- The live catalog keeps one explicitly **synthetic** reference fixture: framework `SYNTHETIC-PAM-TEST`, authority
  `synthetic-test-authority`, requirements 2–3 and mapping 2 (readiness `PARTIAL`). It is not legal interpretation.
- Tests (`tests/regintel/`) use synthetic fixtures only ("Synthetic Access Security Act", `*.example` domains) and a
  scripted model stand-in.
- Limits: no OCR. No bundled search-based discovery provider (discovery uses registered sources only). No admin
  endpoint for manual requirement entry. CLI reviewer identity is the `--actor` value.
