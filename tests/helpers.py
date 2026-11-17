"""Synthetic test data builders. All identifiers and values are fictitious."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

TOKENS: dict[str, str] = {}  # key_id -> full bearer token, filled by conftest


def auth(key_id: str = "securden-a") -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKENS[key_id]}"}


def z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def recent_period(days: int = 30) -> tuple[datetime, datetime]:
    end = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    return end - timedelta(days=days), end


def item(
    rule_id: str,
    evidence_type: str,
    records: list[dict[str, Any]],
    *,
    period: tuple[datetime, datetime] | None = None,
    expected: int | None = None,
    source_complete: bool = True,
    collection_errors: int = 0,
    **extra: Any,
) -> dict[str, Any]:
    start, end = period or recent_period()
    body = {
        "rule_id": rule_id,
        "reporting_period": {"start": z(start), "end": z(end)},
        "evidence": {
            "evidence_type": evidence_type,
            "records": records,
            "completeness": {
                "expected_record_count": len(records) if expected is None else expected,
                "received_record_count": len(records),
                "source_complete": source_complete,
                "collection_errors": collection_errors,
            },
        },
    }
    body.update(extra)
    return body


def request(tenant: str, rule_id: str, evidence_type: str, records, **kw) -> dict[str, Any]:
    return {"tenant_id": tenant, **item(rule_id, evidence_type, records, **kw)}


# ------------------------------------------------------------ record builders


def rotation(i: int, *, rotated_at: datetime | None, privileged: bool = True, status: str | None = "SUCCESS",
             tags: list[str] | None = None) -> dict[str, Any]:
    rec = {
        "record_id": f"rot-{i:05d}",
        "account_id": f"acct-{i:05d}",
        "privileged": privileged,
        "last_rotated_at": z(rotated_at) if rotated_at else None,
        "last_rotation_status": status,
    }
    if tags is not None:
        rec["scope_tags"] = tags
    return rec


def session(i: int, *, started: datetime, status: str = "AVAILABLE", required: bool = True) -> dict[str, Any]:
    return {
        "record_id": f"sess-{i:05d}",
        "session_id": f"s-{i:05d}",
        "account_id": f"acct-{i:05d}",
        "user_id": f"user-{i:05d}",
        "started_at": z(started),
        "ended_at": z(started + timedelta(minutes=30)),
        "recording_required": required,
        "recording_status": status,
        "recording_reference": f"rec-ref-{i:05d}" if status == "AVAILABLE" else None,
    }


def access_request(i: int, *, accessed: datetime, status: str = "APPROVED", approved: datetime | None = None,
                   approver: str | None = "approver-1", user: str = "user-1") -> dict[str, Any]:
    return {
        "record_id": f"acc-{i:05d}",
        "access_id": f"a-{i:05d}",
        "user_id": user,
        "account_id": f"acct-{i:05d}",
        "accessed_at": z(accessed),
        "approval_required": True,
        "approval_status": status,
        "approval_id": f"apr-{i:05d}" if status == "APPROVED" else None,
        "approved_at": z(approved) if approved else None,
        "approver_id": approver if status == "APPROVED" else None,
    }


def account(i: int, *, created: datetime, last_used: datetime | None, enabled: bool = True) -> dict[str, Any]:
    return {
        "record_id": f"pa-{i:05d}",
        "account_id": f"acct-{i:05d}",
        "privileged": True,
        "enabled": enabled,
        "created_at": z(created),
        "last_used_at": z(last_used) if last_used else None,
    }


def auth_summary(i: int, *, start: datetime, failed: int, minutes: int = 15, lockout: bool = False) -> dict[str, Any]:
    return {
        "record_id": f"auth-{i:05d}",
        "principal_id": f"user-{i:05d}",
        "window_start": z(start),
        "window_end": z(start + timedelta(minutes=minutes)),
        "failed_attempts": failed,
        "lockout_triggered": lockout,
    }


def authorization(i: int, *, accessed: datetime, status: str = "AUTHORIZED",
                  valid_from: datetime | None = None, valid_to: datetime | None = None) -> dict[str, Any]:
    return {
        "record_id": f"authz-{i:05d}",
        "access_id": f"a-{i:05d}",
        "user_id": f"user-{i:05d}",
        "account_id": f"acct-{i:05d}",
        "accessed_at": z(accessed),
        "entitlement_status": status,
        "entitlement_id": f"ent-{i:05d}",
        "entitlement_valid_from": z(valid_from) if valid_from else None,
        "entitlement_valid_to": z(valid_to) if valid_to else None,
    }


def break_glass(i: int, *, activated: datetime, provided: bool = True, length: int = 50,
                ticket: str | None = "INC-1001", reviewed_at: datetime | None = None) -> dict[str, Any]:
    return {
        "record_id": f"bg-{i:05d}",
        "event_id": f"bge-{i:05d}",
        "user_id": f"user-{i:05d}",
        "account_id": f"acct-{i:05d}",
        "activated_at": z(activated),
        "justification_provided": provided,
        "justification_length": length if provided else 0,
        "ticket_reference": ticket,
        "post_review_completed": reviewed_at is not None,
        "post_review_at": z(reviewed_at) if reviewed_at else None,
    }


def policy_exception(i: int, *, approved: datetime, expires: datetime, status: str = "ACTIVE",
                     last_used: datetime | None = None) -> dict[str, Any]:
    return {
        "record_id": f"pex-{i:05d}",
        "exception_id": f"ex-{i:05d}",
        "rule_id": "PAM-ROTATION-001",
        "status": status,
        "approved_at": z(approved),
        "expires_at": z(expires),
        "last_used_at": z(last_used) if last_used else None,
    }


def review(i: int, *, completed: datetime | None, outcome: str | None = "CERTIFIED",
           reviewer: str | None = "reviewer-1", owner: str | None = "owner-1") -> dict[str, Any]:
    return {
        "record_id": f"rev-{i:05d}",
        "account_id": f"acct-{i:05d}",
        "privileged": True,
        "enabled": True,
        "owner_id": owner,
        "reviewer_id": reviewer if completed else None,
        "last_review_completed_at": z(completed) if completed else None,
        "last_review_outcome": outcome if completed else None,
    }


def coverage(i: int, *, start: datetime, end: datetime, expected: int = 1000, received: int = 1000,
             gap: int = 10, integrity: bool = True) -> dict[str, Any]:
    return {
        "record_id": f"cov-{i:05d}",
        "source_id": f"src-{i:05d}",
        "coverage_start": z(start),
        "coverage_end": z(end),
        "expected_event_count": expected,
        "received_event_count": received,
        "max_gap_seconds": gap,
        "integrity_verified": integrity,
    }


def exception_doc(exc_id: str, rule_id: str, subjects: list[str], approved: datetime, expires: datetime) -> dict:
    return {
        "exception_id": exc_id,
        "rule_id": rule_id,
        "subject_ids": subjects,
        "approved_by": "ciso-1",
        "approved_at": z(approved),
        "expires_at": z(expires),
    }
