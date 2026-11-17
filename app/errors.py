"""Structured service errors.

Every failure is returned as an explicit error document. Nothing in the
evaluation path converts an error into a compliance status.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .logging_config import correlation_id_var


class ServiceError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        self.headers = headers

    def to_dict(self) -> dict[str, Any]:
        err: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details is not None:
            err["details"] = self.details
        return err


def error_body(code: str, message: str, details: Any = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if details is not None:
        err["details"] = details
    return {"error": err, "correlation_id": correlation_id_var.get()}


def sanitize_validation_errors(errors: list[dict[str, Any]], limit: int = 50) -> list[dict[str, Any]]:
    """Strip the offending input values: they may contain evidence data."""
    out = []
    for e in errors[:limit]:
        msg = str(e.get("msg", "invalid"))
        out.append(
            {
                "loc": [str(p) for p in e.get("loc", ())],
                "msg": msg[:300],
                "type": e.get("type", "value_error"),
            }
        )
    return out


async def service_error_handler(_: Request, exc: ServiceError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=error_body(exc.code, exc.message, exc.details),
        headers=exc.headers,
    )


async def validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=error_body(
            "VALIDATION_ERROR",
            "Request failed schema validation.",
            sanitize_validation_errors(list(exc.errors())),
        ),
    )


async def http_error_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}.get(exc.status_code, "HTTP_ERROR")
    return JSONResponse(
        status_code=exc.status_code,
        content=error_body(code, str(exc.detail) if exc.status_code < 500 else "Server error."),
        headers=getattr(exc, "headers", None),
    )


async def unhandled_error_handler(_: Request, exc: Exception) -> JSONResponse:
    import logging

    logging.getLogger("opm.errors").error(
        "unhandled exception", exc_info=(type(exc), exc, None)
    )
    return JSONResponse(
        status_code=500, content=error_body("INTERNAL_ERROR", "Internal server error.")
    )
