"""Minimal OPA REST client.

Every failure mode raises; nothing here returns a default decision.
Inputs are never logged.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from ..errors import ServiceError
from .catalog import PACKAGE_RE


class OpaClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        connect_timeout: float,
        timeout: float,
        max_connections: int,
        metrics,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._metrics = metrics
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=httpx.Timeout(timeout, connect=connect_timeout),
            limits=httpx.Limits(max_connections=max_connections, max_keepalive_connections=max_connections),
            transport=transport,
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            resp = await self._client.post(path, json=payload)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            self._metrics.inc("opa_errors_total")
            raise ServiceError(503, "POLICY_ENGINE_UNAVAILABLE", "Policy engine is unavailable.") from exc
        except httpx.TimeoutException as exc:
            self._metrics.inc("opa_errors_total")
            raise ServiceError(504, "POLICY_ENGINE_TIMEOUT", "Policy engine did not respond in time.") from exc
        except httpx.TransportError as exc:
            self._metrics.inc("opa_errors_total")
            raise ServiceError(503, "POLICY_ENGINE_UNAVAILABLE", "Policy engine is unavailable.") from exc
        finally:
            self._metrics.observe("opa_request_seconds", time.perf_counter() - started)
        if resp.status_code != 200:
            self._metrics.inc("opa_errors_total")
            raise ServiceError(
                502, "POLICY_EVALUATION_FAILED",
                f"Policy engine returned HTTP {resp.status_code}.",
            )
        try:
            body = resp.json()
        except ValueError as exc:
            raise ServiceError(502, "POLICY_EVALUATION_FAILED", "Policy engine returned invalid JSON.") from exc
        if not isinstance(body, dict) or "result" not in body:
            # Undefined decision: the policy produced no result for this input.
            raise ServiceError(
                502, "POLICY_DECISION_UNDEFINED",
                "Policy engine produced no decision for this input; refusing to infer a result.",
            )
        return body

    async def decide(self, package: str, input_doc: dict[str, Any]) -> dict[str, Any]:
        if not PACKAGE_RE.match(package):
            raise ServiceError(500, "INTERNAL_ERROR", "Invalid policy package.")
        path = "/v1/data/" + package.replace(".", "/") + "/decision"
        body = await self._post(path, {"input": input_doc})
        return body["result"]

    async def meta(self) -> dict[str, Any]:
        body = await self._post("/v1/data/securden/meta", {"input": {}})
        result = body["result"]
        if not isinstance(result, dict):
            raise ServiceError(502, "POLICY_EVALUATION_FAILED", "Unexpected policy engine metadata.")
        return result

    async def healthy(self) -> bool:
        try:
            resp = await self._client.get("/health")
        except httpx.HTTPError:
            return False
        return resp.status_code == 200
