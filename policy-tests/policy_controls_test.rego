package securden.rules.policy_controls_test

import data.securden.rules.pam_mfaacc_001.v1_0 as mfaacc
import data.securden.rules.pam_mfacfg_001.v1_0 as mfacfg
import data.securden.rules.pam_sessdur_001.v1_0 as sessdur
import data.securden.rules.pam_sessidle_001.v1_0 as sessidle

period := {"start": "2026-10-01T00:00:00Z", "end": "2026-10-31T00:00:00Z"}

inp(rule, evidence_type, params, records) := {
	"rule": {"rule_id": rule, "rule_version": "1.0"},
	"reporting_period": period,
	"params": object.union(params, {"scope_tags": []}),
	"evidence": {
		"evidence_type": evidence_type,
		"records": records,
		"completeness": {"expected_record_count": count(records), "received_record_count": count(records), "source_complete": true, "collection_errors": 0},
	},
	"exceptions": [],
}

# ------------------------------------------------------------- MFA configuration

cfg(id, enforced, methods, at) := {"record_id": id, "scope_tags": [], "principal_id": id, "principal_type": "USER", "privileged": true, "enabled": true, "mfa_enforced": enforced, "mfa_methods": methods, "captured_at": at}

cfg_in(records) := inp("PAM-MFACFG-001", "mfa_configuration", {"accepted_methods": ["fido2", "totp"]}, records)

test_mfacfg_pass_and_fail if {
	ok := mfacfg.decision with input as cfg_in([cfg("u1", true, ["totp"], "2026-10-30T00:00:00Z")])
	ok.status == "PASS"
	ok.metrics.assessment_basis == "CONFIGURATION_SNAPSHOT"
	bad := mfacfg.decision with input as cfg_in([
		cfg("u1", false, [], "2026-10-30T00:00:00Z"),
		cfg("u2", true, ["sms"], "2026-10-30T00:00:00Z"),
	])
	bad.status == "FAIL"
	{v.subject_id: v.reasons | some v in bad.violations} == {"u1": {"MFA_NOT_ENFORCED"}, "u2": {"NO_ACCEPTED_MFA_METHOD"}}
}

test_mfacfg_snapshot_outside_period_is_undetermined if {
	d := mfacfg.decision with input as cfg_in([cfg("u1", true, ["totp"], "2026-09-01T00:00:00Z")])
	d.status == "INSUFFICIENT_EVIDENCE"
	{u.reasons | some u in d.undetermined} == {{"SNAPSHOT_OUTSIDE_PERIOD"}}
}

test_mfacfg_unknown_configuration_is_undetermined if {
	d := mfacfg.decision with input as cfg_in([cfg("u1", null, [], "2026-10-30T00:00:00Z")])
	d.status == "INSUFFICIENT_EVIDENCE"
	{u.reasons | some u in d.undetermined} == {{"MFA_CONFIGURATION_UNKNOWN"}}
}

test_mfacfg_version_routing_guard if {
	not mfacfg.decision with input as inp("PAM-MFAACC-001", "mfa_configuration", {"accepted_methods": ["totp"]}, [])
}

# ------------------------------------------------------------- MFA at access

acc(id, granted, status, method) := {"record_id": id, "scope_tags": [], "access_id": id, "user_id": "u", "account_id": "a", "accessed_at": "2026-10-10T00:00:00Z", "access_granted": granted, "mfa_status": status, "mfa_method": method}

acc_in(records) := inp("PAM-MFAACC-001", "privileged_access_authentication", {"accepted_methods": ["fido2"]}, records)

test_mfaacc_reasons if {
	d := mfaacc.decision with input as acc_in([
		acc("x1", true, "VERIFIED", "fido2"),
		acc("x2", true, "NOT_PERFORMED", null),
		acc("x3", true, "FAILED", null),
		acc("x4", true, "VERIFIED", "sms"),
		acc("x5", false, "FAILED", null),
	])
	d.status == "FAIL"
	{v.subject_id: v.reasons | some v in d.violations} == {
		"x2": {"MFA_NOT_PERFORMED"},
		"x3": {"ACCESS_GRANTED_AFTER_FAILED_MFA"},
		"x4": {"MFA_METHOD_NOT_ACCEPTED"},
	}
	d.metrics.granted_accesses == 4
}

test_mfaacc_unknown_is_insufficient if {
	d := mfaacc.decision with input as acc_in([acc("x1", true, "UNKNOWN", null)])
	d.status == "INSUFFICIENT_EVIDENCE"
}

# ------------------------------------------------------------- session idle timeout

pol(id, enabled, minutes, at) := {"record_id": id, "scope_tags": [], "policy_id": id, "applies_to_privileged": true, "idle_timeout_enabled": enabled, "idle_timeout_minutes": minutes, "captured_at": at}

idle_in(records) := inp("PAM-SESSIDLE-001", "session_policy_configuration", {"max_idle_minutes": 15}, records)

test_sessidle_boundary if {
	ok := sessidle.decision with input as idle_in([pol("p1", true, 15, "2026-10-30T00:00:00Z")])
	ok.status == "PASS"
	over := sessidle.decision with input as idle_in([pol("p1", true, 16, "2026-10-30T00:00:00Z"), pol("p2", false, null, "2026-10-30T00:00:00Z")])
	over.status == "FAIL"
	{v.subject_id: v.reasons | some v in over.violations} == {"p1": {"IDLE_TIMEOUT_EXCEEDS_MAXIMUM"}, "p2": {"IDLE_TIMEOUT_DISABLED"}}
}

test_sessidle_no_policy_is_missing_evidence if {
	d := sessidle.decision with input as idle_in([])
	d.status == "INSUFFICIENT_EVIDENCE"
	{u.reasons | some u in d.undetermined} == {{"NO_SESSION_POLICY_SUPPLIED"}}
}

# ------------------------------------------------------------- session duration

sess(id, start, end) := {"record_id": id, "scope_tags": [], "session_id": id, "account_id": "a", "user_id": "u", "started_at": start, "ended_at": end, "recording_required": false, "recording_status": "AVAILABLE"}

dur_in(records) := inp("PAM-SESSDUR-001", "privileged_session", {"max_session_minutes": 60}, records)

test_sessdur_boundary_and_open_sessions if {
	ok := sessdur.decision with input as dur_in([sess("s1", "2026-10-10T00:00:00Z", "2026-10-10T01:00:00Z")])
	ok.status == "PASS"
	d := sessdur.decision with input as dur_in([
		sess("s1", "2026-10-10T00:00:00Z", "2026-10-10T01:00:01Z"),
		sess("s2", "2026-10-30T22:00:00Z", null),
		sess("s3", "2026-10-30T23:30:00Z", null),
	])
	d.status == "FAIL"
	{v.subject_id: v.reasons | some v in d.violations} == {"s1": {"SESSION_DURATION_EXCEEDED"}, "s2": {"OPEN_SESSION_EXCEEDS_MAXIMUM"}}
	d.metrics.longest_session_minutes == 120
}
