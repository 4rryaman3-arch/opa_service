"""Pure-ASGI middleware: correlation IDs, request body size limit, sanitized
access logging and security headers. Bodies are never logged."""

from __future__ import annotations

import json
import logging
import re
import time
import uuid

from .logging_config import client_id_var, correlation_id_var

log = logging.getLogger("opm.access")
CORRELATION_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")

SECURITY_HEADERS = [
    (b"cache-control", b"no-store"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
]




class ServiceMiddleware:
    def __init__(self, app, max_body_bytes: int, metrics) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.metrics = metrics

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        cid = headers.get("x-correlation-id", "")
        if not CORRELATION_RE.match(cid):
            cid = f"opm-{uuid.uuid4().hex}"
        cid_token = correlation_id_var.set(cid)
        client_token = client_id_var.set(None)
        started = time.perf_counter()
        status_holder = {"status": 500}
        state = {"too_large": False, "started": False}

        async def send_wrapper(message):
            if state["too_large"] and not message.get("_opm_reject"):
                return  # suppress the app's response; a 413 is sent instead
            message.pop("_opm_reject", None)
            if message["type"] == "http.response.start":
                state["started"] = True
                status_holder["status"] = message["status"]
                hdrs = list(message.get("headers", []))
                hdrs.append((b"x-correlation-id", cid.encode("ascii")))
                hdrs.extend(SECURITY_HEADERS)
                message = {**message, "headers": hdrs}
            await send(message)

        try:
            declared = headers.get("content-length")
            if declared is not None:
                if not declared.isdigit():
                    return await self._reject(send_wrapper, 400, "BAD_REQUEST", "Invalid Content-Length.", cid)
                if int(declared) > self.max_body_bytes:
                    return await self._reject(
                        send_wrapper, 413, "PAYLOAD_TOO_LARGE",
                        f"Request body exceeds {self.max_body_bytes} bytes.", cid,
                    )
            received = 0

            async def limited_receive():
                nonlocal received
                if state["too_large"]:
                    return {"type": "http.disconnect"}
                message = await receive()
                if message["type"] == "http.request":
                    received += len(message.get("body", b""))
                    if received > self.max_body_bytes and not state["started"]:
                        # Stop reading; the app sees a disconnect and its
                        # response (whatever it is) is replaced by a 413.
                        state["too_large"] = True
                        return {"type": "http.disconnect"}
                return message

            try:
                await self.app(scope, limited_receive, send_wrapper)
            except Exception:
                if not state["too_large"]:
                    raise
            if state["too_large"]:
                await self._reject(
                    send_wrapper, 413, "PAYLOAD_TOO_LARGE", f"Request body exceeds {self.max_body_bytes} bytes.", cid
                )
        finally:
            duration = time.perf_counter() - started
            self.metrics.inc(f"http_responses_{status_holder['status'] // 100}xx_total")
            self.metrics.observe("http_request_seconds", duration)
            log.info(
                "request",
                extra={"fields": {
                    "method": scope.get("method"),
                    "path": scope.get("path"),  # path only: no query string
                    "status": status_holder["status"],
                    "duration_ms": round(duration * 1000, 2),
                }},
            )
            correlation_id_var.reset(cid_token)
            client_id_var.reset(client_token)

    @staticmethod
    async def _reject(send, status: int, code: str, message: str, cid: str) -> None:
        body = json.dumps({"error": {"code": code, "message": message}, "correlation_id": cid}).encode()
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
            "_opm_reject": True,
        })
        await send({"type": "http.response.body", "body": body, "_opm_reject": True})
