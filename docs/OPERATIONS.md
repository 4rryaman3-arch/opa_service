# Operations: deployment, security, performance

## 1. How this host runs today (native Windows stack)

The OMEN (`192.168.7.7`) runs the **native** stack. Docker is not installed and has never been run on this host.

```powershell
Set-Location D:\personal_projects\opa_sevice
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-catalog.txt
.\.venv\Scripts\python.exe scripts\run_native.py --with-ollama --with-catalog-admin
```

| Process | Listens on | Role |
|---|---|---|
| Caddy | `OPM_HTTPS_PORT` (default 443) | TLS 1.2/1.3 + mandatory mTLS edge. Routes `/api/v1/catalog/admin/*` to catalog-admin and everything else to FastAPI |
| FastAPI (`app/`) | loopback 8000 | evaluation API + read-only catalog API |
| catalog-admin (`regintel.admin_api`) | loopback 8001 | catalog writes, job worker, DB migrations at start |
| OPA | loopback 8181 | Rego evaluation, token-authenticated |
| Ollama | loopback 11434 | local model for catalog extraction/review only (`--with-ollama`) |

- `--with-ollama` reuses a running Ollama or starts the installed one. It checks for a real structured-JSON response
  and GPU placement before starting anything else, and it never downloads models. Without the flag, the
  evaluation API works and only catalog extraction needs the model.
- `--with-catalog-admin` is needed for every `/api/v1/catalog/admin/*` call. Without it the edge answers 502.
- There is no hot reload. **Restart after every code or credential change.** Ctrl+C stops the processes the
  launcher started.
- **Windows orphans children.** If the supervisor is killed (for example by a low-memory event), `opa`/`caddy`
  keep running and the next start fails to bind port 8181. Stop them by PID first:
  `Get-Process opa,caddy | Stop-Process`.
- Logs are in `logs/`: `llm-check.log`, `opa.log`, `api.log`, `caddy.log`.
- After `bundle-activate`, the launcher reads `bundle-store/ACTIVE`.

## 2. Docker Compose alternative (not exercised on this host)

`docker compose up -d --build` runs Caddy, the API and OPA with pinned images, read-only root filesystems,
`cap_drop: ALL`, non-root users and internal networks. Compose does **not** start catalog-admin. That needs a
separately deployed management service and `OPM_CATALOG_ADMIN_UPSTREAM` on Caddy. Never make the evaluation
container's catalog mount writable as a shortcut.

Host prerequisites: Docker Desktop with the WSL2 backend (Windows), or Docker Engine + Compose v2 (Ubuntu;
`chown 10001:10001 secrets/api_clients.json && chmod 400`, `chmod 600 .env deploy/certs/*.key`).

## 3. Host preparation

1. Reserve `192.168.7.7` in the router's DHCP settings (it is a SAN on the server certificate). Set the Wi-Fi
   profile to **Private**.
2. Firewall: allow 443 only from the Securden server.
   ```powershell
   New-NetFirewallRule -DisplayName "Securden OPM HTTPS" -Direction Inbound -Protocol TCP `
     -LocalPort 443 -RemoteAddress <SECURDEN_SERVER_IP> -Profile Private -Action Allow
   ```
3. Disable sleep/hibernate on AC power.
4. Optional: point the LAN DNS name `opm.lan` at `192.168.7.7`.

## 4. Certificates and client trust

`scripts/bootstrap.py` (or `scripts/gen_certs.py`) writes `deploy/certs/`:

| File | Purpose | Goes to |
|---|---|---|
| `ca.crt` | private root CA (ECDSA P-384, 10 y) | Securden server (trust anchor) |
| `ca.key` | CA key | offline storage after issuing |
| `server.crt/key` | Caddy cert, SANs from `--dns/--ip`, 397 d | stays on the OMEN |
| `client-ca.crt` | CA that Caddy trusts for client certs | stays on the OMEN |
| `client.crt/key` | Securden's mTLS client cert | Securden server |

Renew by re-running `gen_certs.py` (it reuses the CA) before `notAfter`, then restart the stack. A publicly
trusted `server.crt` (ACME DNS-01) can replace the private one; mTLS stays private either way.

The Django client loads `ca.crt`, `client.crt`, `client.key` and the token from paths that only its service account
can read. It points `CA_BUNDLE` at the CA file explicitly, so the OS trust store is not changed and verification can't
be disabled. The current client bundle lives in `secrets/pam-client/` (never commit it or print its contents).

Verify from the Securden server:
`python scripts/smoke_https.py --url https://192.168.7.7 --ca … --cert … --key … --token-file … --tenant <tenant>`.

## 5. Credentials and scopes

`secrets/api_clients.json` holds per-client `key_id`, a SHA-256 secret digest, scopes and a tenant allowlist.
Manage it with `scripts/manage_keys.py add|rotate|disable|grant-scope <key_id> …`, then restart.

| Scope | Allows |
|---|---|
| `evaluate`, `rules:read`, `rules:write`, `rules:admin`, `metrics:read` | evaluation API (see EVALUATION_API.md) |
| `catalog:read` | published catalog, templates, plans |
| `catalog:operate` / `catalog:review` / `catalog:publish` | catalog management writes (see DJANGO_CONTRACT.md) |
| `catalog:automate` | automated pipeline jobs (`build_framework`, `prepare_catalog`) |

The deployment credential `securden-pam` currently holds every catalog scope, including `catalog:automate`.

## 6. Security design

| Boundary | Control |
|---|---|
| LAN → Caddy | TLS 1.2/1.3, **mTLS required**, body limit (5 MiB), timeouts, no HTTP listener, no admin API |
| Caddy → API | loopback (native) / internal network (Compose); API not exposed |
| API request | bearer `<key_id>.<secret>` (256-bit, digest stored, constant-time compare), per-client scopes, tenant allowlist, token-bucket rate limit (600/min, burst 100), auth-failure throttling |
| API → OPA | OPA `--authentication=token --authorization=basic`; `system.authz` allows only `GET /health` and `POST /v1/data/securden/...` (tested in `policy-tests/authz_test.rego`) |
| Customer rules | strict JSON → allowlisted fields/operators → compiled data for a fixed Rego interpreter; no customer Rego |
| LLM | loopback/private endpoint only; never on the evaluation path |

Fail-secure behaviour:

| Failure | Result |
|---|---|
| bad, missing or disabled credential | 401 |
| wrong scope or tenant | 403 (same response whether or not the tenant exists) |
| client cert missing or untrusted | TLS handshake rejected |
| OPA unreachable / timeout | 503 `POLICY_ENGINE_UNAVAILABLE` / 504 |
| undefined decision or schema mismatch | 502 `POLICY_DECISION_*` |
| OPA bundle ≠ API catalog version | 502 `POLICY_VERSION_MISMATCH`; `/ready` 503 |
| catalog DB missing | catalog reads 503 `CATALOG_UNAVAILABLE`; evaluation unaffected |

Data minimisation: evidence models forbid extra fields and carry only identifiers, flags, counts and timestamps.
Logs are JSON with no bodies. Bearer tokens and `password=`/`secret=`/`token=` patterns are redacted, and Caddy
redacts `Authorization`.

Known limitations: the OPA token is passed via `.env`. Rate limits and metrics are in-process, so they apply per
replica. Dependencies are version-pinned but not hash-pinned. `strict_sni_host insecure_off` allows connecting by IP
and is safe only while the Caddyfile has a single mTLS site.

## 7. Configuration and storage

- All `OPM_*` settings are in `app/config.py` and `.env.example`. The local LLM uses `OPM_REGINTEL_LLM_*` (see
  REGINTEL.md §5). OpenAPI docs stay off unless `OPM_ENABLE_DOCS=true`.
- `OPM_MAX_BODY_BYTES` and Caddy's `OPM_MAX_BODY_SIZE` must be changed together.
- `OPM_REGINTEL_AUTOMATION_LANGUAGES=en` and `OPM_REGINTEL_AUTOMATION_SCREENING=pam-keyword-screen-v1` bound
  automated catalog jobs (REGINTEL.md §7). Remove them to process every language and section, which takes days on
  this GPU.
- Windows may show stale "last modified" times on `logs/*.log` while the stack holds them open. Read the tail of the
  file to check activity.
- Customer rules: SQLite (WAL) `data/opm.db`. Regulatory catalog: `data/regintel/catalog.db`, migrated
  automatically when catalog-admin starts (back it up before upgrades). Policy bundles: `policy-bundle/` (base) and
  `bundle-store/versions/<v>/` (immutable, built).

## 8. Updating the policy bundle

1. Never edit a released rule version in place. Add a new version package and catalog entry, set
   `effective_from`, and retire the old version.
2. Bump `policy-bundle/securden/bundle/data.json` → `version`.
3. Run `opa check --strict policy-bundle`, `opa test policy-bundle policy-tests`, and `pytest` (below).
4. Restart and confirm that `GET /api/v1/version` shows `"policy_versions_consistent": true`.

## 9. Tests

```powershell
$env:OPM_TEST_OPA_BINARY = (Resolve-Path .tools\opa.exe).Path   # without it ~87 tests skip
.\.venv\Scripts\python.exe -m pytest tests -q
```

Current result (2026-11-16): **321 passed, 4 skipped**. The skips are the Caddy end-to-end tests; set
`OPM_TEST_CADDY_BINARY` to run them.

## 10. Performance (2026-11-12, native, loopback, no TLS)

`scripts/benchmark.py --local --reps 30 --concurrency 8` on an OMEN with 16 logical CPUs, OPA 1.4.2 and one uvicorn
worker, using `PAM-ROTATION-001` evidence. Raw data: `docs/benchmarks/2026-11-12-omen-native-loopback.json`.

| Workload | p50 | p95 | Throughput |
|---|---:|---:|---:|
| single, 100 records | 12.3 ms | 14.7 ms | – |
| single, 1,000 records | 74.3 ms | 79.3 ms | – |
| single, 10,000 records | 679 ms | 707 ms | – |
| 8 concurrent clients, 100 records | 42.3 ms | 78.7 ms | 158 req/s |
| batch 100 × 100 records | 513 ms | 562 ms | ≈19.5k records/s |

Rego evaluation costs ≈44 µs per record and dominates, so latency scales linearly with record count. The default
limits (10,000 records per evaluation, 50,000 per batch) keep a single evaluation under ~1 s. TLS overhead has not
been measured. To measure the real path, run `scripts/benchmark.py --url https://…` from the Securden server.
