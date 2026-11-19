# Securden OPM Compliance Policy Evaluation Service

A standalone, deterministic compliance evaluation service for the Securden PAM Django application. Securden sends
**normalized audit evidence** over HTTPS. The service evaluates it with **Open Policy Agent (Rego)** and returns
`PASS / FAIL / INSUFFICIENT_EVIDENCE / NOT_APPLICABLE`. The evaluation path uses no LLM.

A second package, **`regintel/`**, maintains a source-verified regulatory catalog. It covers the jurisdiction
registry, official-source adapters, local-model extraction, human or automated review, organization-scoped uploads,
evaluation templates and execution plans. It ships with **no regulatory content**.

```
Securden Django ──HTTPS + mTLS + bearer──▶ Caddy :443 ─┬─▶ FastAPI :8000 ──▶ OPA :8181      (evaluation + catalog reads)
                                                       └─▶ catalog-admin :8001 ──▶ Ollama  (catalog writes, jobs)
```

## Documentation

| Doc | For |
|---|---|
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | starting the stack, certificates, credentials/scopes, security design, tests, benchmarks |
| [docs/EVALUATION_API.md](docs/EVALUATION_API.md) | PAM evidence collectors: request/response, rules, record schemas, errors, customer rules |
| [docs/DJANGO_CONTRACT.md](docs/DJANGO_CONTRACT.md) | Django catalog integration: management API, jobs, organization scope, templates, plans |
| [docs/REGINTEL.md](docs/REGINTEL.md) | catalog internals and operator CLI: sources, model, review, automation policy, bundles |
| [docs/examples/](docs/examples/) | real request/response samples (synthetic data) |
| [schemas/](schemas/) | JSON Schemas generated from the validating models (`scripts/export_schemas.py`) |

## Quick start (this host, native)

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-catalog.txt
.\.venv\Scripts\python.exe scripts\run_native.py --with-ollama --with-catalog-admin
```

There is no hot reload, so restart after every change. If a previous run was killed, stop orphaned `opa`/`caddy`
processes first (details in OPERATIONS.md). A Docker Compose deployment is also provided but has not been run on this
host.

## Repository layout

| Path | What |
|---|---|
| `app/` | FastAPI evaluation service (auth, validation, rule registry, evaluator, OPA client) |
| `regintel/` | regulatory catalog: registry, sources, extraction, review, automation, plans, read and admin APIs, `python -m regintel` CLI |
| `policy-bundle/`, `policy-tests/` | OPA bundle (10 predefined rules, customer-rule interpreter, authz) and Rego tests |
| `client/securden_opm_client.py` | drop-in `httpx` client for Django |
| `deploy/`, `docker-compose.yml`, `Dockerfile` | Caddy edge config and container deployment |
| `scripts/` | `run_native.py`, `bootstrap.py`, `gen_certs.py`, `manage_keys.py`, `smoke_https.py`, `benchmark.py`, `export_schemas.py` |
| `tests/` | pytest suite (`tests/regintel/` uses synthetic fixtures only) |

## Status (2026-11-19)

- Test suite: **392 passed, 4 skipped** (Caddy E2E); Rego 27/27. OPA-backed tests need
  `OPM_TEST_OPA_BINARY=.tools\opa.exe`.
- Verified live over `https://192.168.7.7` with mTLS: evaluation, the manual catalog workflow end to end, plan
  staleness, and the automated pipeline (then the `build_framework` job, now inside `prepare_catalog`), all on the
  synthetic fixture `SYNTHETIC-PAM-TEST`. Requests from the Django machine have reached the edge.
- Automatic rule orchestration (`prepare_catalog`): existing rules are assigned first. Where none fits, a bounded
  RuleSpec generator can propose, validate, compile, OPA-test and (behind two service flags, both off by default)
  activate an organization-scoped `PAM-GEN-*` rule with PARTIAL coverage (DJANGO_CONTRACT.md §5.4). Covered by
  synthetic tests; not yet exercised live.
- `prepare_catalog` and organization-scoped uploads (rewrite contract 1.0) are covered by tests but not yet demoed
  live.
- **No real regulatory content is published.** `EU-NIS2`, `EU-DORA` and `EU-GDPR` are registered but empty until a
  human attests sources, documents and mappings.
- Model quality on real legal text is not established (gemma3:4b, partial CPU offload on a 4 GB GPU). No OCR.
