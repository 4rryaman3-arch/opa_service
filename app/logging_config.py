"""Structured JSON logging with credential redaction.

Request/response bodies are never logged anywhere in this service. The
redaction filter is a second line of defence in case a library logs a header
or token-like string.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
from datetime import datetime, timezone

correlation_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)
client_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "client_id", default=None
)

_REDACTIONS = [
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(authorization['\"]?\s*[:=]\s*['\"]?)[^'\",\s]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)((?:password|secret|token|private_key)['\"]?\s*[:=]\s*['\"]?)[^'\",\s]+"), r"\1[REDACTED]"),
]


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        cid = correlation_id_var.get()
        if cid:
            payload["correlation_id"] = cid
        client = client_id_var.get()
        if client:
            payload["client_id"] = client
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            payload.update({k: v for k, v in extra.items() if k not in payload})
        if record.exc_info and record.exc_info[0] is not None:
            # Exception type only: messages/tracebacks may embed request data.
            payload["exc_type"] = record.exc_info[0].__name__
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # uvicorn's access log is replaced by our own sanitized access log.
    logging.getLogger("uvicorn.access").disabled = True
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
