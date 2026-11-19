"""Securden OPM compliance service client.

Standalone module intended to be copied into the Securden Django project
(e.g. ``securden/compliance/opm_client.py``). Only dependency: ``httpx``.

Security properties:
  * TLS verification is always on; it can only be pointed at a CA bundle,
    never disabled (passing verify=False raises).
  * Optional mTLS client certificate.
  * Bearer token loaded by the caller from Django settings / a secret store.
  * Bounded retries with exponential backoff + jitter, only for transient
    failures (connect errors, timeouts, 429, 502, 503, 504). Evaluations are
    side-effect free, so retrying them is safe.
  * Correlation ID per logical call, reused across retries.
  * Responses are schema-checked before being returned; a malformed response
    raises instead of being treated as a compliance result.

Django settings example::

    OPM_SERVICE = {
        "BASE_URL": "https://opm.lan",
        "CA_BUNDLE": "/etc/securden/opm/ca.crt",
        "CLIENT_CERT": "/etc/securden/opm/client.crt",
        "CLIENT_KEY": "/etc/securden/opm/client.key",
        "TOKEN_FILE": "/etc/securden/opm/api_token",
        "TIMEOUT_SECONDS": 30,
    }

    client = OpmClient.from_django_settings()
    result = client.evaluate(tenant_id="acme", item={...})
"""

from __future__ import annotations

import hashlib
import json as _json
import logging
import random
import ssl
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

import httpx

log = logging.getLogger("securden.opm_client")

STATUSES = frozenset({"PASS", "FAIL", "INSUFFICIENT_EVIDENCE", "NOT_APPLICABLE"})
RETRYABLE_STATUS = frozenset({429, 502, 503, 504})


class OpmError(Exception):
    """Base error. ``code`` mirrors the service error code when available."""

    def __init__(self, message: str, *, code: str = "CLIENT_ERROR", status_code: int | None = None,
                 correlation_id: str | None = None, details: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.correlation_id = correlation_id
        self.details = details

    def __str__(self) -> str:
        base = super().__str__()
        return f"{base} (code={self.code}, status={self.status_code}, correlation_id={self.correlation_id})"


class OpmTransientError(OpmError):
    """Service unavailable after all retries; safe to retry later."""


class OpmRequestError(OpmError):
    """Request rejected (4xx). Fix the request; do not retry unchanged."""


class OpmResponseError(OpmError):
    """Service answered with something that is not a valid result."""


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 4
    base_delay: float = 0.5
    max_delay: float = 8.0
    max_retry_after: float = 30.0

    def delay(self, attempt: int, retry_after: str | None = None) -> float:
        if retry_after and retry_after.isdigit():
            return min(float(retry_after), self.max_retry_after)
        exp = min(self.max_delay, self.base_delay * (2 ** (attempt - 1)))
        return random.uniform(exp / 2, exp)  # jitter


@dataclass
class OpmClient:
    base_url: str
    token: str = field(repr=False)
    ca_bundle: str | Path
    client_cert: tuple[str | Path, str | Path] | None = None
    timeout_seconds: float = 30.0
    connect_timeout_seconds: float = 5.0
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    # Django rewrite contract 1.0: opaque org namespace sent as X-Securden-Organization-Scope
    # on every request. Compute it server-side from the OPM tenant and the authenticated PAM
    # organization; NEVER from browser input. One client instance per organization scope.
    organization_scope: str | None = None
    _http: httpx.Client | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.base_url.startswith("https://"):
            raise ValueError("base_url must use https://")
        if self.ca_bundle is False or self.ca_bundle in (None, ""):  # type: ignore[comparison-overlap]
            raise ValueError("ca_bundle is required; TLS verification cannot be disabled")
        if not Path(self.ca_bundle).is_file():
            raise ValueError(f"CA bundle not found: {self.ca_bundle}")
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(self.ca_bundle))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        if self.client_cert:
            ctx.load_cert_chain(str(self.client_cert[0]), str(self.client_cert[1]))
        self._http = httpx.Client(
            base_url=self.base_url.rstrip("/"),
            verify=ctx,
            timeout=httpx.Timeout(self.timeout_seconds, connect=self.connect_timeout_seconds),
            headers={"Authorization": f"Bearer {self.token}", "User-Agent": "securden-opm-client/1.0",
                     **({"X-Securden-Organization-Scope": self.organization_scope}
                        if self.organization_scope else {})},
            follow_redirects=False,
        )

    @classmethod
    def from_django_settings(cls) -> "OpmClient":  # pragma: no cover - requires Django
        from django.conf import settings

        cfg = settings.OPM_SERVICE
        token = Path(cfg["TOKEN_FILE"]).read_text(encoding="utf-8").strip() if cfg.get("TOKEN_FILE") else cfg["TOKEN"]
        cert = (cfg["CLIENT_CERT"], cfg["CLIENT_KEY"]) if cfg.get("CLIENT_CERT") else None
        return cls(
            base_url=cfg["BASE_URL"], token=token, ca_bundle=cfg["CA_BUNDLE"], client_cert=cert,
            timeout_seconds=float(cfg.get("TIMEOUT_SECONDS", 30)),
        )

    def close(self) -> None:
        if self._http is not None:
            self._http.close()

    def __enter__(self) -> "OpmClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------ transport
    def _request(self, method: str, path: str, *, json: Any = None, params: dict | None = None,
                 correlation_id: str | None = None, content: bytes | None = None,
                 retry_safe: bool = True) -> dict[str, Any]:
        assert self._http is not None
        cid = correlation_id or f"securden-{uuid.uuid4().hex}"
        last_exc: Exception | None = None
        attempts = self.retry.max_attempts if retry_safe else 1
        for attempt in range(1, attempts + 1):
            try:
                resp = self._http.request(method, path, json=json, params=params, content=content,
                                          headers={"X-Correlation-ID": cid,
                                                   **({"Content-Type":"application/octet-stream"} if content is not None else {})})
            except httpx.TransportError as exc:
                # Certificate verification failures surface as ConnectError with
                # an SSL cause; they are NOT retried (fail fast & loud).
                if _is_tls_verification_error(exc):
                    raise OpmError("TLS certificate verification failed", code="TLS_VERIFICATION_FAILED",
                                   correlation_id=cid) from exc
                last_exc = exc
                if attempt == attempts:
                    break
                delay = self.retry.delay(attempt)
                log.warning("opm transient transport error; retrying",
                            extra={"correlation_id": cid, "attempt": attempt, "delay": round(delay, 2),
                                   "error": type(exc).__name__})
                time.sleep(delay)
                continue

            if resp.status_code in RETRYABLE_STATUS and attempt < attempts:
                delay = self.retry.delay(attempt, resp.headers.get("Retry-After"))
                log.warning("opm transient HTTP status; retrying",
                            extra={"correlation_id": cid, "attempt": attempt, "status": resp.status_code,
                                   "delay": round(delay, 2)})
                time.sleep(delay)
                continue
            return self._handle(resp, cid)
        raise OpmTransientError("OPM service unavailable after retries", code="UNAVAILABLE",
                                correlation_id=cid) from last_exc

    @staticmethod
    def _handle(resp: httpx.Response, cid: str) -> dict[str, Any]:
        try:
            body = resp.json()
        except ValueError:
            raise OpmResponseError("Non-JSON response", code="INVALID_RESPONSE",
                                   status_code=resp.status_code, correlation_id=cid) from None
        if resp.status_code >= 400:
            err = body.get("error", {}) if isinstance(body, dict) else {}
            cls = OpmTransientError if resp.status_code in RETRYABLE_STATUS else OpmRequestError
            raise cls(err.get("message", "request failed"), code=err.get("code", "HTTP_ERROR"),
                      status_code=resp.status_code, correlation_id=cid, details=err.get("details"))
        if not isinstance(body, dict):
            raise OpmResponseError("Unexpected response shape", code="INVALID_RESPONSE", correlation_id=cid)
        return body

    # ------------------------------------------------------------ API
    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health")

    def ready(self) -> dict[str, Any]:
        return self._request("GET", "/ready")

    def version(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/version")

    def list_rules(self, tenant_id: str) -> dict[str, Any]:
        return self._request("GET", "/api/v1/rules", params={"tenant_id": tenant_id})

    def evaluate(self, tenant_id: str, item: dict[str, Any], *, correlation_id: str | None = None) -> dict[str, Any]:
        body = self._request("POST", "/api/v1/evaluate", json={"tenant_id": tenant_id, **item},
                             correlation_id=correlation_id)
        validate_evaluation_result(body, tenant_id=tenant_id, expected_rule_id=item.get("rule_id"))
        return body

    def evaluate_batch(self, tenant_id: str, items: Iterable[dict[str, Any]], *, chunk_size: int = 50,
                       correlation_id: str | None = None) -> list[dict[str, Any]]:
        """Evaluate many items, chunked to respect the service batch limit.

        Returns per-item results in input order. Per-item errors are returned as
        ``{"ok": False, "error": {...}}`` and must be handled by the caller; they
        are never converted into a status.
        """
        items = list(items)
        cid = correlation_id or f"securden-{uuid.uuid4().hex}"
        out: list[dict[str, Any]] = []
        for offset in range(0, len(items), chunk_size):
            chunk = items[offset: offset + chunk_size]
            body = self._request("POST", "/api/v1/evaluate/batch",
                                 json={"tenant_id": tenant_id, "items": chunk},
                                 correlation_id=f"{cid}-{offset // chunk_size}")
            results = body.get("results")
            if body.get("tenant_id") != tenant_id or not isinstance(results, list) or len(results) != len(chunk):
                raise OpmResponseError("Batch response does not match request", code="INVALID_RESPONSE",
                                       correlation_id=cid)
            for r in sorted(results, key=lambda r: r["index"]):
                if r.get("ok"):
                    validate_evaluation_result(r["result"], tenant_id=tenant_id,
                                               expected_rule_id=chunk[r["index"]].get("rule_id"))
                r["index"] += offset
                out.append(r)
        return out

    # ------------------------------------------------------------ regulatory catalog
    # Global reference data (needs a token with the ``catalog:read`` scope).
    # Customer configuration, evidence collection, assessment and reporting stay
    # in the Django application; this only mirrors the published catalog.

    def catalog_get(self, resource: str, **params: Any) -> dict[str, Any]:
        """One request, e.g. ``catalog_get("frameworks", jurisdiction="DE", industry="banking")``."""
        body = self._request("GET", f"/api/v1/catalog/{resource}",
                             params={k: v for k, v in params.items() if v is not None})
        _validate_catalog_envelope(body)
        return body

    def catalog_admin_get(self, resource: str, **params: Any) -> dict[str, Any]:
        """Management reads: sources, documents/{id}, requirements, pending, reviews, jobs/{id}."""
        body = self._request("GET", f"/api/v1/catalog/admin/{resource}",
                             params={k: v for k, v in params.items() if v is not None})
        _validate_catalog_envelope(body)
        return body

    def catalog_admin_iter(self, resource: str, *, page_size: int = 200, **params: Any) -> Iterator[dict[str, Any]]:
        """All items of a paginated management listing (documents, documents/{id}
        sections, requirements, reviews), following ``next_cursor``."""
        after: str | None = None
        while True:
            page = self.catalog_admin_get(resource, limit=page_size, after=after, **params)
            if not isinstance(page.get("items"), list):
                raise OpmResponseError("Catalog page has no items list", code="INVALID_RESPONSE")
            yield from page["items"]
            if not page.get("has_more"):
                return
            after = page.get("next_cursor")
            if not after:
                raise OpmResponseError("Catalog page says more data exists but gave no cursor", code="INVALID_RESPONSE")

    def catalog_admin_action(self, resource: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Explicit review/publication action. No automatic retry of mutations.

        Job submissions require a stable request_key; resubmit the same payload
        and key after an ambiguous transport failure to recover the job ID.
        """
        body = self._request("POST", f"/api/v1/catalog/admin/{resource}", json=payload, retry_safe=False)
        _validate_catalog_envelope(body)
        return body

    def catalog_upload(self, content: bytes, *, framework_id: str, filename: str, language: str,
                       provenance: str, license_note: str) -> dict[str, Any]:
        """Upload PDF/HTML/TXT bytes; creates a proposed file source, never approval."""
        body = self._request("POST", "/api/v1/catalog/admin/uploads", content=content, retry_safe=False,
            params={"framework_id":framework_id, "filename":filename, "language":language,
                    "provenance":provenance, "license_note":license_note})
        _validate_catalog_envelope(body)
        return body

    # -------------------------------------------- regulatory intelligence (jurisdiction trigger)

    def catalog_discover(self, jurisdiction: str, *, request_key: str, include_inherited: bool = True,
                         as_of: str | None = None) -> dict[str, Any]:
        """Start Regulatory Intelligence for one jurisdiction (scope ``catalog:operate``).

        Returns the 202 envelope; the persisted job is under ``["job"]``. The same
        ``request_key`` with the same payload always returns the same job (safe to
        resubmit after an ambiguous failure); a different payload under the same key
        is rejected with ``IDEMPOTENCY_CONFLICT``. Poll with :meth:`catalog_job`.
        Discovery only reads sources a human verified; it never searches the web."""
        payload: dict[str, Any] = {"action": "discover", "jurisdiction": jurisdiction,
                                   "include_inherited": include_inherited, "request_key": request_key}
        if as_of is not None:
            payload["as_of"] = as_of
        return self.catalog_admin_action("jobs", payload)

    def upload_document(self, content: bytes, *, filename: str, jurisdictions: list[str], provenance: str,
                        license_note: str, request_key: str, framework_id: str = "",
                        language: str = "en") -> dict[str, Any]:
        """Scoped upload (rewrite contract 1.0; the client's ``organization_scope`` must be set).

        Streams the exact bytes; returns ``{organization_scope, document_ids,
        content_sha256, source_id, source_origin: "UPLOADED_DOCUMENT"}`` with
        201 (or 200 on an idempotent replay of the same key + content).
        ``framework_id`` empty requests auto-identification during
        prepare_catalog. Changed bytes or metadata under the same key: 409."""
        if not self.organization_scope:
            raise OpmError("upload_document requires organization_scope on the client", code="SCOPE_REQUIRED")
        import json as _json
        body = self._request("POST", "/api/v1/catalog/admin/uploads", content=content, retry_safe=False,
                             params={"filename": filename, "jurisdictions": _json.dumps(jurisdictions),
                                     "provenance": provenance, "license_note": license_note,
                                     "request_key": request_key, "framework_id": framework_id,
                                     "language": language})
        _validate_catalog_envelope(body)
        return body

    def prepare_catalog(self, *, mode: str, jurisdictions: list[str], request_key: str,
                        document_ids: list[int] | None = None, requested_framework_ids: list[str] | None = None,
                        industry: str | None = None, include_inherited: bool = True, translate: bool = True,
                        as_of: str | None = None, tenant_id: str | None = None, llm_mapping: bool = True,
                        auto_rule_generation: bool = False, auto_publish_validated_rules: bool = False,
                        collector_capability_digest: str | None = None) -> dict[str, Any]:
        """Submit a prepare_catalog job (rewrite contract 1.0; scopes catalog:automate +
        the client's ``organization_scope``). mode 'discovery' uses OPM's registered
        authorities/sources for the jurisdictions; mode 'import' processes
        ``document_ids`` from :meth:`upload_document`. Poll with :meth:`wait_for_job`."""
        if not self.organization_scope:
            raise OpmError("prepare_catalog requires organization_scope on the client", code="SCOPE_REQUIRED")
        payload: dict[str, Any] = {"action": "prepare_catalog", "mode": mode, "jurisdictions": jurisdictions,
                                   "include_inherited": include_inherited, "translate": translate,
                                   "request_key": request_key}
        if document_ids is not None:
            payload["document_ids"] = document_ids
        if requested_framework_ids:
            payload["requested_framework_ids"] = requested_framework_ids
        if industry is not None:
            payload["industry"] = industry
        if as_of is not None:
            payload["as_of"] = as_of
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        if not llm_mapping:
            payload["llm_mapping"] = False
        if auto_rule_generation:  # bounded rule generation (DJANGO_CONTRACT §5.4); defaults are left out
            payload["auto_rule_generation"] = True
        if auto_publish_validated_rules:
            payload["auto_publish_validated_rules"] = True
        if collector_capability_digest is not None:
            payload["collector_capability_digest"] = collector_capability_digest
        return self.catalog_admin_action("jobs", payload)

    def catalog_job(self, job_id: str) -> dict[str, Any]:
        """One job with status, started/finished timestamps, result and error."""
        body = self.catalog_admin_get(f"jobs/{job_id}")
        job = body.get("job")
        if not isinstance(job, dict) or not isinstance(job.get("status"), str):
            raise OpmResponseError("Malformed job response", code="INVALID_RESPONSE")
        return job

    def job_progress(self, job_id: str) -> dict[str, Any]:
        """Current step (stage, unit, done/total, rate) and ETA of one job. ``eta.seconds``
        is null with ``eta.reason`` when the remaining work is not yet known."""
        body = self.catalog_admin_get(f"jobs/{job_id}/progress")
        progress = body.get("progress")
        if not isinstance(progress, dict) or not isinstance(progress.get("eta"), dict):
            raise OpmResponseError("Malformed job progress response", code="INVALID_RESPONSE")
        return progress

    def wait_for_job(self, job_id: str, *, timeout_seconds: float = 600.0,
                     poll_seconds: float = 2.0) -> dict[str, Any]:
        """Poll until the job leaves QUEUED/RUNNING; returns the final job row.
        Raises :class:`OpmTransientError` on timeout (the job keeps running)."""
        deadline = time.monotonic() + timeout_seconds
        while True:
            job = self.catalog_job(job_id)
            if job["status"] not in ("QUEUED", "RUNNING"):
                return job
            if time.monotonic() >= deadline:
                raise OpmTransientError(f"Job {job_id} still {job['status']} after {timeout_seconds}s",
                                        code="JOB_TIMEOUT")
            time.sleep(poll_seconds)

    def jurisdiction_coverage(self, code: str, *, include_inherited: bool = True,
                              as_of: str | None = None) -> dict[str, Any]:
        """Evidence-based coverage for one jurisdiction (management scopes): per-scope
        pipeline counts (``items``, inherited entries marked with ``via``/``membership``),
        evaluation-template readiness and the open ``next_actions`` checkpoints.
        Registration of a jurisdiction never implies regulatory coverage."""
        return self.catalog_admin_get(f"jurisdictions/{code}/coverage",
                                      include_inherited=include_inherited, as_of=as_of)

    def document_attempts(self, version_id: int, *, kind: str | None = None, status: str | None = None,
                          page_size: int = 50) -> Iterator[dict[str, Any]]:
        """Every LLM processing attempt for one document version: raw model output
        (or an explicit unavailable reason), parsed/validated JSON, validation
        errors with JSON paths, accepted draft ids and rejected candidates.
        Display only; viewing never approves, publishes or reruns anything."""
        return self.catalog_admin_iter(f"documents/{version_id}/attempts", page_size=page_size,
                                       kind=kind, status=status)

    def catalog_iter(self, resource: str, *, page_size: int = 200, **params: Any) -> Iterator[dict[str, Any]]:
        """All items of a paginated catalog resource, following ``next_cursor``."""
        after: str | None = None
        while True:
            page = self.catalog_get(resource, limit=page_size, after=after, **params)
            if not isinstance(page.get("items"), list):
                raise OpmResponseError("Catalog page has no items list", code="INVALID_RESPONSE")
            yield from page["items"]
            if not page.get("has_more"):
                return
            after = page.get("next_cursor")
            if not after:
                raise OpmResponseError("Catalog page says more data exists but gave no cursor", code="INVALID_RESPONSE")

    def catalog_changes(self, since: int, *, page_size: int = 500) -> tuple[list[dict[str, Any]], int]:
        """Incremental sync. Pass the ``catalog_version`` you last applied (0 for
        a first sync); returns ``(changes, new_catalog_version)``. Store the new
        version only after applying every change. Each change names an entity
        (``entity_type``, ``entity_id``) to re-fetch (UPSERT) or remove (WITHDRAW).
        A 409 ``CATALOG_VERSION_AHEAD`` means the local copy must be rebuilt."""
        changes: list[dict[str, Any]] = []
        while True:
            page = self.catalog_get("changes", since=since, limit=page_size)
            synced_to = page.get("synced_to")
            if not isinstance(page.get("items"), list) or not isinstance(synced_to, int) or synced_to < since:
                raise OpmResponseError("Malformed catalog change page", code="INVALID_RESPONSE")
            changes.extend(page["items"])
            if not page.get("has_more"):
                return changes, synced_to
            if synced_to == since:
                raise OpmResponseError("Catalog change feed did not advance", code="INVALID_RESPONSE")
            since = synced_to

    def evaluation_templates(self, *, jurisdiction: str | None = None, include_inherited: bool = False,
                             include_unapproved: bool = False, as_of: str | None = None) -> list[dict[str, Any]]:
        """Frameworks selectable for an assessment, with engine coverage counts,
        ``readiness`` (NOT_READY | PARTIAL | READY) and ``blockers``. Readiness is
        not a compliance result."""
        return list(self.catalog_iter("evaluation-templates", jurisdiction=jurisdiction, as_of=as_of,
                                      include_inherited=include_inherited, include_unapproved=include_unapproved))

    def evaluation_plan(self, framework_id: str, *, tenant_id: str, as_of: str | None = None,
                        catalog_version: int | None = None, expected_digest: str | None = None) -> dict[str, Any]:
        """Execution plan for one framework. Persist the whole response with the
        assessment. Before evaluating a saved plan, call again with
        ``expected_digest=plan["plan_digest"]``: 409 ``PLAN_STALE`` means it must
        be re-resolved. The digest is verified locally before returning."""
        body = self._request("GET", f"/api/v1/catalog/evaluation-templates/{framework_id}/plan",
                             params={k: v for k, v in {"tenant_id": tenant_id, "as_of": as_of,
                                                       "catalog_version": catalog_version,
                                                       "expected_digest": expected_digest}.items() if v is not None})
        _validate_catalog_envelope(body)
        if body.get("tenant_id") != tenant_id or not isinstance(body.get("requirements"), list) \
                or not isinstance(body.get("executions"), list) or not isinstance(body.get("digest_input"), dict):
            raise OpmResponseError("Malformed evaluation plan", code="INVALID_RESPONSE")
        if plan_digest(body["digest_input"]) != body.get("plan_digest"):
            raise OpmResponseError("Evaluation plan digest does not match its content", code="INVALID_RESPONSE")
        return body

    def applicability(self, profile: dict[str, Any]) -> dict[str, Any]:
        """Deterministic screening of an organization profile. Results are a
        screening aid, never a legal determination; keep the disclaimer with them."""
        body = self._request("POST", "/api/v1/catalog/applicability", json=profile)
        _validate_catalog_envelope(body)
        if not isinstance(body.get("results"), list) or not isinstance(body.get("disclaimer"), str):
            raise OpmResponseError("Malformed applicability response", code="INVALID_RESPONSE")
        return body


def plan_digest(digest_input: dict[str, Any]) -> str:
    """Canonical digest of a plan: sorted keys, no whitespace, UTF-8, non-ASCII unescaped."""
    text = _json.dumps(digest_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def effective_parameters(execution: dict[str, Any], overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Parameters to send for one plan execution. ``overrides`` (local PAM
    policy values) are accepted only inside the plan's ``override_constraints``;
    anything else raises instead of being clamped or replaced by a default."""
    params = dict(execution["parameters"])
    for name, value in (overrides or {}).items():
        rule = execution["override_constraints"].get(name)
        if name not in params or rule is None:
            raise OpmError(f"Parameter '{name}' may not be overridden for {execution['rule_id']}", code="OVERRIDE_NOT_PERMITTED")
        if "values" in rule:
            ok = isinstance(value, bool) and value in rule["values"]
        else:
            ok = isinstance(value, int) and not isinstance(value, bool) and rule["min"] <= value <= rule["max"]
        if not ok:
            raise OpmError(f"Value for '{name}' is outside the reviewed constraint {rule}", code="OVERRIDE_NOT_PERMITTED")
        params[name] = value
    return params


def _validate_catalog_envelope(body: dict[str, Any]) -> None:
    version = body.get("schema_version")
    if not isinstance(version, str) or version.split(".")[0] != "1":
        raise OpmResponseError(f"Unsupported catalog schema_version {version!r}", code="UNSUPPORTED_SCHEMA")
    if not isinstance(body.get("catalog_version"), int):
        raise OpmResponseError("Catalog response has no catalog_version", code="INVALID_RESPONSE")


def _is_tls_verification_error(exc: Exception) -> bool:
    cause: BaseException | None = exc
    while cause is not None:
        if isinstance(cause, ssl.SSLCertVerificationError):
            return True
        cause = cause.__cause__ or cause.__context__
    return "CERTIFICATE_VERIFY_FAILED" in str(exc)


_REQUIRED = {
    "evaluation_id": str, "tenant_id": str, "rule_id": str, "rule_version": str,
    "policy_bundle_version": str, "status": str, "severity": str, "metrics": dict,
    "evidence_references": list, "violations": list, "evidence_completeness": dict,
    "decision_details": dict, "framework_mappings": list, "evaluated_at": str,
}


def validate_evaluation_result(body: Any, *, tenant_id: str, expected_rule_id: str | None = None) -> None:
    if not isinstance(body, dict):
        raise OpmResponseError("Evaluation result is not an object", code="INVALID_RESPONSE")
    for key, typ in _REQUIRED.items():
        if not isinstance(body.get(key), typ):
            raise OpmResponseError(f"Evaluation result field '{key}' missing or invalid", code="INVALID_RESPONSE")
    if body["status"] not in STATUSES:
        raise OpmResponseError(f"Unknown status {body['status']!r}", code="INVALID_RESPONSE")
    if body["tenant_id"] != tenant_id:
        raise OpmResponseError("Result tenant does not match request tenant", code="TENANT_MISMATCH")
    if expected_rule_id and body["rule_id"] != expected_rule_id:
        raise OpmResponseError("Result rule does not match request rule", code="INVALID_RESPONSE")
    digest = body["decision_details"].get("input_digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise OpmResponseError("Missing input digest", code="INVALID_RESPONSE")
