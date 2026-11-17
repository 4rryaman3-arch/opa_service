"""Shared constrained types."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import AfterValidator, AwareDatetime, PlainSerializer, StringConstraints


def to_utc(v: datetime) -> datetime:
    return v.astimezone(timezone.utc)


def format_utc(v: datetime) -> str:
    return v.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# Timezone-aware timestamps only (naive timestamps are rejected), normalised
# to UTC and serialised as RFC 3339 with a 'Z' suffix and microseconds.
UtcDatetime = Annotated[
    AwareDatetime,
    AfterValidator(to_utc),
    PlainSerializer(format_utc, return_type=str, when_used="json"),
]

Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")]
TenantId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
RuleId = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9]{1,15}(-[A-Z0-9]{1,20}){1,4}$")]
RuleVersion = Annotated[str, StringConstraints(pattern=r"^\d{1,3}\.\d{1,3}$")]
Tag = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._:-]{0,63}$")]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Status = Literal["PASS", "FAIL", "INSUFFICIENT_EVIDENCE", "NOT_APPLICABLE"]
