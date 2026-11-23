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
    captured_at: UtcDatetime | None = None
    # optional (Securden documents both; sent once the collector reads them)
    breached: StrictBool | None = None  # credential found in a breached-password check
    policy_compliant: StrictBool | None = None  # credential meets its assigned password policy


class PrivilegedSessionRecord(BaseRecord):
    session_id: Identifier
    account_id: Identifier
    user_id: Identifier
    started_at: UtcDatetime
    ended_at: UtcDatetime | None = None
    recording_required: StrictBool
    recording_status: Literal["AVAILABLE", "PARTIAL", "MISSING", "FAILED", "PROCESSING"]
    recording_reference: Identifier | None = None
    credential_reset_after_use: StrictBool | None = None
    shadowed: StrictBool | None = None  # an administrator watched the session live
    terminated_by_admin: StrictBool | None = None  # an administrator ended the session
    credential_disclosed: StrictBool | None = None  # the password was shown to the user (False: injected)

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
    ticket_reference: Identifier | None = None  # ITSM ticket the access was validated against
    justification_provided: StrictBool | None = None
    auto_approved: StrictBool | None = None  # approved by an automatic-approval policy, not a person
    approvals_required: Count | None = None  # approver levels the workflow requires
    approvals_received: Count | None = None
    access_expires_at: UtcDatetime | None = None  # end of the just-in-time access window
    revoked_at: UtcDatetime | None = None  # when access was actually taken away
    credential_reset_after_use: StrictBool | None = None  # password changed after the release ended

    @model_validator(mode="after")
    def _check(self):
        if self.approval_status == "APPROVED" and (self.approved_at is None or self.approver_id is None):
            raise ValueError("APPROVED requests require approved_at and approver_id")
        if self.revoked_at is not None and self.revoked_at < self.accessed_at:
            raise ValueError("revoked_at precedes accessed_at")
        return self


class PrivilegedAccountRecord(BaseRecord):
    account_id: Identifier
    privileged: StrictBool
    enabled: StrictBool
    created_at: UtcDatetime
    last_used_at: UtcDatetime | None
    owner_id: Identifier | None = None  # account owner (Securden: no account may be left without one)

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


# ---------------------------------------------------------------------------
# Further Securden capabilities (published product documentation, 2026-11-20). Declared LOOKUP_AVAILABLE in
# pam_capability_inventory.json until the collector sends them.
# ---------------------------------------------------------------------------


class EndpointElevationRecord(BaseRecord):
    """Event history: temporary privilege elevation on managed endpoints (AC-6(10), CM-11)."""

    elevation_id: Identifier
    user_id: Identifier
    device_id: Identifier
    requested_at: UtcDatetime
    approval_status: Literal["APPROVED", "AUTO_APPROVED", "PENDING", "DENIED"]
    application_id: Identifier | None = None
    approver_id: Identifier | None = None
    approved_at: UtcDatetime | None = None
    elevation_expires_at: UtcDatetime | None = None
    revoked_at: UtcDatetime | None = None

    @model_validator(mode="after")
    def _check(self):
        if self.approval_status == "APPROVED" and (self.approved_at is None or self.approver_id is None):
            raise ValueError("APPROVED elevations require approved_at and approver_id")
        if self.revoked_at is not None and self.revoked_at < self.requested_at:
            raise ValueError("revoked_at precedes requested_at")
        if self.elevation_expires_at is not None and self.elevation_expires_at < self.requested_at:
            raise ValueError("elevation_expires_at precedes requested_at")
        if self.approved_at is not None and self.approved_at < self.requested_at:
            raise ValueError("approved_at precedes requested_at")
        return self


class LocalAdminMembershipRecord(BaseRecord):
    """Configuration snapshot: membership in local administrator / sudoers groups on endpoints (AC-6(5))."""

    device_id: Identifier
    account_id: Identifier
    approved_member: StrictBool
    captured_at: UtcDatetime


class ApplicationControlPolicyRecord(BaseRecord):
    """Configuration snapshot: allowlist / blocklist application control policy (CM-7(4), CM-7(5))."""

    policy_id: Identifier
    mode: Literal["ALLOWLIST", "BLOCKLIST", "MONITOR"]
    enforced: StrictBool
    captured_at: UtcDatetime


class PasswordPolicyConfigurationRecord(BaseRecord):
    """Configuration snapshot: password complexity, length, and history configuration (IA-5(1))."""

    policy_id: Identifier
    applies_to_privileged: StrictBool
    min_length: Annotated[StrictInt, Field(ge=0, le=1024)]
    complexity_required: StrictBool
    enforced_on_reset: StrictBool
    captured_at: UtcDatetime
    rotation_period_days: Count | None = None
    history_count: Count | None = None


class AuditForwardingConfigurationRecord(BaseRecord):
    """Configuration snapshot: real-time audit log export / SIEM forwarding destination (AU-4(1), AU-6(4))."""

    destination_id: Identifier
    protocol: Literal["SYSLOG", "API", "OTHER"]
    enabled: StrictBool
    captured_at: UtcDatetime
    last_delivery_at: UtcDatetime | None = None


class BackupConfigurationRecord(BaseRecord):
    """Configuration snapshot: scheduled and encrypted backup configuration (CP-9(8))."""

    backup_id: Identifier
    scheduled: StrictBool
    encrypted: StrictBool
    captured_at: UtcDatetime
    last_backup_at: UtcDatetime | None = None
    last_backup_status: Literal["SUCCESS", "FAILED"] | None = None


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
    "endpoint_elevation": EndpointElevationRecord,
    "local_admin_membership": LocalAdminMembershipRecord,
    "application_control_policy": ApplicationControlPolicyRecord,
    "password_policy_configuration": PasswordPolicyConfigurationRecord,
    "audit_forwarding_configuration": AuditForwardingConfigurationRecord,
    "backup_configuration": BackupConfigurationRecord,
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
    "endpoint_elevation",
    "local_admin_membership",
    "application_control_policy",
    "password_policy_configuration",
    "audit_forwarding_configuration",
    "backup_configuration",
]

# Timestamp fields that may legitimately lie after the reporting period end
# (validity/expiry horizons, or log coverage that continues past the period).
# Every other timestamp must be <= reporting_period.end, so evaluations only
# use facts known at the as_of instant.
FUTURE_ALLOWED_FIELDS: dict[str, frozenset[str]] = {
    "access_authorization": frozenset({"entitlement_valid_to"}),
    "policy_exception": frozenset({"expires_at"}),
    "audit_log_coverage": frozenset({"coverage_end"}),
    "privileged_access_request": frozenset({"access_expires_at"}),
    "endpoint_elevation": frozenset({"elevation_expires_at"}),
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
        "captured_at": _f("datetime", False),
        "breached": _f("boolean", True),
        "policy_compliant": _f("boolean", True),
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
        "credential_reset_after_use": _f("boolean", True),
        "shadowed": _f("boolean", True),
        "terminated_by_admin": _f("boolean", True),
        "credential_disclosed": _f("boolean", True),
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
        "ticket_reference": _f("string", True),
        "justification_provided": _f("boolean", True),
        "auto_approved": _f("boolean", True),
        "approvals_required": _f("integer", True),
        "approvals_received": _f("integer", True),
        "access_expires_at": _f("datetime", True),
        "revoked_at": _f("datetime", True),
        "credential_reset_after_use": _f("boolean", True),
    },
    "privileged_account": {
        **_COMMON,
        "account_id": _f("string"),
        "privileged": _f("boolean"),
        "enabled": _f("boolean"),
        "created_at": _f("datetime"),
        "last_used_at": _f("datetime", True),
        "owner_id": _f("string", True),
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
    "endpoint_elevation": {
        **_COMMON,
        "elevation_id": _f("string"),
        "user_id": _f("string"),
        "device_id": _f("string"),
        "requested_at": _f("datetime"),
        "approval_status": _f("enum", False, ("APPROVED", "AUTO_APPROVED", "PENDING", "DENIED")),
        "application_id": _f("string", True),
        "approver_id": _f("string", True),
        "approved_at": _f("datetime", True),
        "elevation_expires_at": _f("datetime", True),
        "revoked_at": _f("datetime", True),
    },
    "local_admin_membership": {
        **_COMMON,
        "device_id": _f("string"),
        "account_id": _f("string"),
        "approved_member": _f("boolean"),
        "captured_at": _f("datetime"),
    },
    "application_control_policy": {
        **_COMMON,
        "policy_id": _f("string"),
        "mode": _f("enum", False, ("ALLOWLIST", "BLOCKLIST", "MONITOR")),
        "enforced": _f("boolean"),
        "captured_at": _f("datetime"),
    },
    "password_policy_configuration": {
        **_COMMON,
        "policy_id": _f("string"),
        "applies_to_privileged": _f("boolean"),
        "min_length": _f("integer"),
        "complexity_required": _f("boolean"),
        "enforced_on_reset": _f("boolean"),
        "captured_at": _f("datetime"),
        "rotation_period_days": _f("integer", True),
        "history_count": _f("integer", True),
    },
    "audit_forwarding_configuration": {
        **_COMMON,
        "destination_id": _f("string"),
        "protocol": _f("enum", False, ("SYSLOG", "API", "OTHER")),
        "enabled": _f("boolean"),
        "captured_at": _f("datetime"),
        "last_delivery_at": _f("datetime", True),
    },
    "backup_configuration": {
        **_COMMON,
        "backup_id": _f("string"),
        "scheduled": _f("boolean"),
        "encrypted": _f("boolean"),
        "captured_at": _f("datetime"),
        "last_backup_at": _f("datetime", True),
        "last_backup_status": _f("enum", True, ("SUCCESS", "FAILED")),
    },
}
