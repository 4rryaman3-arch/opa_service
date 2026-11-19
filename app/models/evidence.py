"""Normalized evidence record schemas, one per evidence type.

Design constraints:
  * ``extra="forbid"``: unknown fields (e.g. ``password``, ``private_key``,
    ``recording_blob``, ``justification_text``) are rejected, so secrets and
    raw content cannot be smuggled into the policy engine.
  * Only identifiers, flags, counts and timestamps. No free text.
  * Strict scalar types: "5" is not an int and "true" is not a bool.
  * Timestamps must carry a timezone; they are normalised to UTC.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator

from .common import Identifier, RuleId, Tag, UtcDatetime

Count = Annotated[StrictInt, Field(ge=0, le=10_000_000_000)]


class BaseRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: Identifier
    scope_tags: list[Tag] = Field(default_factory=list, max_length=20)


class CredentialRotationRecord(BaseRecord):
    account_id: Identifier
    privileged: StrictBool
    last_rotated_at: UtcDatetime | None
    last_rotation_status: Literal["SUCCESS", "FAILED"] | None = None


class PrivilegedSessionRecord(BaseRecord):
    session_id: Identifier
    account_id: Identifier
    user_id: Identifier
    started_at: UtcDatetime
    ended_at: UtcDatetime | None = None
    recording_required: StrictBool
    recording_status: Literal["AVAILABLE", "PARTIAL", "MISSING", "FAILED", "PROCESSING"]
    recording_reference: Identifier | None = None

    @model_validator(mode="after")
    def _check(self):
        if self.ended_at is not None and self.ended_at < self.started_at:
            raise ValueError("ended_at precedes started_at")
        return self


class PrivilegedAccessRequestRecord(BaseRecord):
    access_id: Identifier
    user_id: Identifier
    account_id: Identifier
    accessed_at: UtcDatetime
    approval_required: StrictBool
    approval_status: Literal["APPROVED", "PENDING", "DENIED", "NONE"]
    approval_id: Identifier | None = None
    approved_at: UtcDatetime | None = None
    approver_id: Identifier | None = None

    @model_validator(mode="after")
    def _check(self):
        if self.approval_status == "APPROVED" and (self.approved_at is None or self.approver_id is None):
            raise ValueError("APPROVED requests require approved_at and approver_id")
        return self


class PrivilegedAccountRecord(BaseRecord):
    account_id: Identifier
    privileged: StrictBool
    enabled: StrictBool
    created_at: UtcDatetime
    last_used_at: UtcDatetime | None

    @model_validator(mode="after")
    def _check(self):
        if self.last_used_at is not None and self.last_used_at < self.created_at:
            raise ValueError("last_used_at precedes created_at")
        return self


class AuthenticationSummaryRecord(BaseRecord):
    principal_id: Identifier
    window_start: UtcDatetime
    window_end: UtcDatetime
    failed_attempts: Count
    lockout_triggered: StrictBool

    @model_validator(mode="after")
    def _check(self):
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be after window_start")
        return self


class AccessAuthorizationRecord(BaseRecord):
    access_id: Identifier
    user_id: Identifier
    account_id: Identifier
    accessed_at: UtcDatetime
    entitlement_status: Literal["AUTHORIZED", "NOT_AUTHORIZED", "REVOKED", "UNKNOWN"]
    entitlement_id: Identifier | None = None
    entitlement_valid_from: UtcDatetime | None = None
    entitlement_valid_to: UtcDatetime | None = None


class BreakGlassEventRecord(BaseRecord):
    event_id: Identifier
    user_id: Identifier
    account_id: Identifier
    activated_at: UtcDatetime
    justification_provided: StrictBool
    justification_length: Annotated[StrictInt, Field(ge=0, le=100_000)]
    ticket_reference: Identifier | None = None
    post_review_completed: StrictBool
    post_review_at: UtcDatetime | None = None

    @model_validator(mode="after")
    def _check(self):
        if self.post_review_completed != (self.post_review_at is not None):
            raise ValueError("post_review_at must be set exactly when post_review_completed is true")
        if not self.justification_provided and self.justification_length != 0:
            raise ValueError("justification_length must be 0 when no justification was provided")
        if self.post_review_at is not None and self.post_review_at < self.activated_at:
            raise ValueError("post_review_at precedes activated_at")
        return self


class PolicyExceptionRecord(BaseRecord):
    exception_id: Identifier
    rule_id: RuleId
    status: Literal["ACTIVE", "EXPIRED", "REVOKED"]
    approved_at: UtcDatetime
    expires_at: UtcDatetime
    last_used_at: UtcDatetime | None = None

    @model_validator(mode="after")
    def _check(self):
        if self.expires_at <= self.approved_at:
            raise ValueError("expires_at must be after approved_at")
        return self


class AccessReviewRecord(BaseRecord):
    account_id: Identifier
    privileged: StrictBool
    enabled: StrictBool
    owner_id: Identifier | None = None
    reviewer_id: Identifier | None = None
    last_review_completed_at: UtcDatetime | None
    last_review_outcome: Literal["CERTIFIED", "REVOKED"] | None = None

    @model_validator(mode="after")
    def _check(self):
        if self.last_review_completed_at is not None and (
            self.last_review_outcome is None or self.reviewer_id is None
        ):
            raise ValueError("a completed review requires last_review_outcome and reviewer_id")
        return self


class AuditLogCoverageRecord(BaseRecord):
    source_id: Identifier
    coverage_start: UtcDatetime
    coverage_end: UtcDatetime
    expected_event_count: Count
    received_event_count: Count
    max_gap_seconds: Count
    integrity_verified: StrictBool

    @model_validator(mode="after")
    def _check(self):
        if self.coverage_end <= self.coverage_start:
            raise ValueError("coverage_end must be after coverage_start")
        return self


class AuditEventRecord(BaseRecord):
    """One audit log entry, reduced to identifiers. It records which elements the entry carries (NIST AU-3 style
    content: type, time, location, source, outcome, identities), never message text. Null means the source log
    entry did not contain that element."""

    event_id: Identifier
    occurred_at: UtcDatetime
    event_type: Identifier | None = None
    location_id: Identifier | None = None     # system/component where the event occurred
    source_id: Identifier | None = None       # originating host, address or client (as an identifier)
    outcome: Literal["SUCCESS", "FAILURE", "DENIED", "ERROR"] | None = None
    actor_id: Identifier | None = None        # individual or subject that performed the action
    target_id: Identifier | None = None       # object or entity acted upon


MfaMethod = Literal["totp", "push", "fido2", "smart_card", "hardware_token", "sms", "email_otp"]
MFA_METHODS: tuple[str, ...] = ("totp", "push", "fido2", "smart_card", "hardware_token", "sms", "email_otp")


class MfaConfigurationRecord(BaseRecord):
    """Configuration snapshot: whether MFA is enforced for a principal at ``captured_at``.
    It says nothing about whether MFA was actually performed at each access."""

    principal_id: Identifier
    principal_type: Literal["USER", "ACCOUNT"]
    privileged: StrictBool
    enabled: StrictBool
    mfa_enforced: StrictBool | None
    mfa_methods: list[MfaMethod] = Field(default_factory=list, max_length=len(MFA_METHODS))
    captured_at: UtcDatetime

    @model_validator(mode="after")
    def _check(self):
        if len(set(self.mfa_methods)) != len(self.mfa_methods):
            raise ValueError("mfa_methods must not repeat a method")
        if self.mfa_enforced is not True and self.mfa_methods:
            raise ValueError("mfa_methods may only be listed when mfa_enforced is true")
        return self


class PrivilegedAccessAuthenticationRecord(BaseRecord):
    """Event history: the authentication performed for one privileged access."""

    access_id: Identifier
    user_id: Identifier
    account_id: Identifier
    accessed_at: UtcDatetime
    access_granted: StrictBool
    mfa_status: Literal["VERIFIED", "NOT_PERFORMED", "FAILED", "UNKNOWN"]
    mfa_method: MfaMethod | None = None

    @model_validator(mode="after")
    def _check(self):
        if (self.mfa_status == "VERIFIED") != (self.mfa_method is not None):
            raise ValueError("mfa_method must be set exactly when mfa_status is VERIFIED")
        return self


class SessionPolicyConfigurationRecord(BaseRecord):
    """Configuration snapshot of one session policy at ``captured_at``."""

    policy_id: Identifier
    applies_to_privileged: StrictBool
    idle_timeout_enabled: StrictBool
    idle_timeout_minutes: Annotated[StrictInt, Field(ge=1, le=100_000)] | None
    captured_at: UtcDatetime

    @model_validator(mode="after")
    def _check(self):
        if self.idle_timeout_enabled != (self.idle_timeout_minutes is not None):
            raise ValueError("idle_timeout_minutes must be set exactly when idle_timeout_enabled is true")
        return self


EVIDENCE_MODELS: dict[str, type[BaseRecord]] = {
    "credential_rotation": CredentialRotationRecord,
    "privileged_session": PrivilegedSessionRecord,
    "privileged_access_request": PrivilegedAccessRequestRecord,
    "privileged_account": PrivilegedAccountRecord,
    "authentication_summary": AuthenticationSummaryRecord,
    "access_authorization": AccessAuthorizationRecord,
    "break_glass_event": BreakGlassEventRecord,
    "policy_exception": PolicyExceptionRecord,
    "access_review": AccessReviewRecord,
    "audit_log_coverage": AuditLogCoverageRecord,
    "audit_event": AuditEventRecord,
    "mfa_configuration": MfaConfigurationRecord,
    "privileged_access_authentication": PrivilegedAccessAuthenticationRecord,
    "session_policy_configuration": SessionPolicyConfigurationRecord,
}

# Versioned evidence contracts. A collector declares the versions it produces
# (collector capability handshake); a change to a record schema bumps its version.
EVIDENCE_SCHEMA_VERSIONS: dict[str, str] = {name: "1.0" for name in EVIDENCE_MODELS}

EvidenceType = Literal[
    "credential_rotation",
    "privileged_session",
    "privileged_access_request",
    "privileged_account",
    "authentication_summary",
    "access_authorization",
    "break_glass_event",
    "policy_exception",
    "access_review",
    "audit_log_coverage",
    "audit_event",
    "mfa_configuration",
    "privileged_access_authentication",
    "session_policy_configuration",
]

# Timestamp fields that may legitimately lie after the reporting period end
# (validity/expiry horizons, or log coverage that continues past the period).
# Every other timestamp must be <= reporting_period.end, so evaluations only
# use facts known at the as_of instant.
FUTURE_ALLOWED_FIELDS: dict[str, frozenset[str]] = {
    "access_authorization": frozenset({"entitlement_valid_to"}),
    "policy_exception": frozenset({"expires_at"}),
    "audit_log_coverage": frozenset({"coverage_end"}),
}


# ---------------------------------------------------------------------------
# Field catalogue for customer-defined rules (explicit allowlist).
# type: string | enum | boolean | integer | datetime | string_list
# ---------------------------------------------------------------------------


def _f(type_: str, nullable: bool = False, values: tuple[str, ...] = ()) -> dict:
    return {"type": type_, "nullable": nullable, "values": values}


_COMMON = {"record_id": _f("string"), "scope_tags": _f("string_list")}

CUSTOM_RULE_FIELDS: dict[str, dict[str, dict]] = {
    "credential_rotation": {
        **_COMMON,
        "account_id": _f("string"),
        "privileged": _f("boolean"),
        "last_rotated_at": _f("datetime", True),
        "last_rotation_status": _f("enum", True, ("SUCCESS", "FAILED")),
    },
    "privileged_session": {
        **_COMMON,
        "session_id": _f("string"),
        "account_id": _f("string"),
        "user_id": _f("string"),
        "started_at": _f("datetime"),
        "ended_at": _f("datetime", True),
        "recording_required": _f("boolean"),
        "recording_status": _f("enum", False, ("AVAILABLE", "PARTIAL", "MISSING", "FAILED", "PROCESSING")),
        "recording_reference": _f("string", True),
    },
    "privileged_access_request": {
        **_COMMON,
        "access_id": _f("string"),
        "user_id": _f("string"),
        "account_id": _f("string"),
        "accessed_at": _f("datetime"),
        "approval_required": _f("boolean"),
        "approval_status": _f("enum", False, ("APPROVED", "PENDING", "DENIED", "NONE")),
        "approval_id": _f("string", True),
        "approved_at": _f("datetime", True),
        "approver_id": _f("string", True),
    },
    "privileged_account": {
        **_COMMON,
        "account_id": _f("string"),
        "privileged": _f("boolean"),
        "enabled": _f("boolean"),
        "created_at": _f("datetime"),
        "last_used_at": _f("datetime", True),
    },
    "authentication_summary": {
        **_COMMON,
        "principal_id": _f("string"),
        "window_start": _f("datetime"),
        "window_end": _f("datetime"),
        "failed_attempts": _f("integer"),
        "lockout_triggered": _f("boolean"),
    },
    "access_authorization": {
        **_COMMON,
        "access_id": _f("string"),
        "user_id": _f("string"),
        "account_id": _f("string"),
        "accessed_at": _f("datetime"),
        "entitlement_status": _f("enum", False, ("AUTHORIZED", "NOT_AUTHORIZED", "REVOKED", "UNKNOWN")),
        "entitlement_id": _f("string", True),
        "entitlement_valid_from": _f("datetime", True),
        "entitlement_valid_to": _f("datetime", True),
    },
    "break_glass_event": {
        **_COMMON,
        "event_id": _f("string"),
        "user_id": _f("string"),
        "account_id": _f("string"),
        "activated_at": _f("datetime"),
        "justification_provided": _f("boolean"),
        "justification_length": _f("integer"),
        "ticket_reference": _f("string", True),
        "post_review_completed": _f("boolean"),
        "post_review_at": _f("datetime", True),
    },
    "policy_exception": {
        **_COMMON,
        "exception_id": _f("string"),
        "rule_id": _f("string"),
        "status": _f("enum", False, ("ACTIVE", "EXPIRED", "REVOKED")),
        "approved_at": _f("datetime"),
        "expires_at": _f("datetime"),
        "last_used_at": _f("datetime", True),
    },
    "access_review": {
        **_COMMON,
        "account_id": _f("string"),
        "privileged": _f("boolean"),
        "enabled": _f("boolean"),
        "owner_id": _f("string", True),
        "reviewer_id": _f("string", True),
        "last_review_completed_at": _f("datetime", True),
        "last_review_outcome": _f("enum", True, ("CERTIFIED", "REVOKED")),
    },
    "audit_log_coverage": {
        **_COMMON,
        "source_id": _f("string"),
        "coverage_start": _f("datetime"),
        "coverage_end": _f("datetime"),
        "expected_event_count": _f("integer"),
        "received_event_count": _f("integer"),
        "max_gap_seconds": _f("integer"),
        "integrity_verified": _f("boolean"),
    },
    "audit_event": {
        **_COMMON,
        "event_id": _f("string"),
        "occurred_at": _f("datetime"),
        "event_type": _f("string", True),
        "location_id": _f("string", True),
        "source_id": _f("string", True),
        "outcome": _f("enum", True, ("SUCCESS", "FAILURE", "DENIED", "ERROR")),
        "actor_id": _f("string", True),
        "target_id": _f("string", True),
    },
    "mfa_configuration": {
        **_COMMON,
        "principal_id": _f("string"),
        "principal_type": _f("enum", False, ("USER", "ACCOUNT")),
        "privileged": _f("boolean"),
        "enabled": _f("boolean"),
        "mfa_enforced": _f("boolean", True),
        "mfa_methods": _f("string_list"),
        "captured_at": _f("datetime"),
    },
    "privileged_access_authentication": {
        **_COMMON,
        "access_id": _f("string"),
        "user_id": _f("string"),
        "account_id": _f("string"),
        "accessed_at": _f("datetime"),
        "access_granted": _f("boolean"),
        "mfa_status": _f("enum", False, ("VERIFIED", "NOT_PERFORMED", "FAILED", "UNKNOWN")),
        "mfa_method": _f("enum", True, MFA_METHODS),
    },
    "session_policy_configuration": {
        **_COMMON,
        "policy_id": _f("string"),
        "applies_to_privileged": _f("boolean"),
        "idle_timeout_enabled": _f("boolean"),
        "idle_timeout_minutes": _f("integer", True),
        "captured_at": _f("datetime"),
    },
}
