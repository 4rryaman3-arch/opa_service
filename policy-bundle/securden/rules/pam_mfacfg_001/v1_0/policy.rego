# PAM-MFACFG-001 v1.0 - MFA enforcement configured for privileged principals
#
# Configuration snapshot: the result describes the configuration captured at
# captured_at. It is not evidence that MFA was performed at each access
# (PAM-MFAACC-001) and is unrelated to failed-logon monitoring (PAM-AUTHFAIL-001).
package securden.rules.pam_mfacfg_001.v1_0

import data.securden.lib

rule_id := "PAM-MFACFG-001"

rule_version := "1.0"

accepted := {m | some m in input.params.accepted_methods}

evaluated := [rec | some rec in lib.scoped_records; rec.privileged; rec.enabled]

# A snapshot taken outside the reporting period says nothing about this period.
current(rec) if lib.in_period(rec.captured_at)

determinable(rec) if {
	current(rec)
	rec.mfa_enforced != null
}

failed("MFA_NOT_ENFORCED", rec) if rec.mfa_enforced == false

failed("NO_ACCEPTED_MFA_METHOD", rec) if {
	rec.mfa_enforced == true
	count({m | some m in rec.mfa_methods; m in accepted}) == 0
}

reasons(rec) := {r |
	some r in ["MFA_NOT_ENFORCED", "NO_ACCEPTED_MFA_METHOD"]
	failed(r, rec)
}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; determinable(rec); r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.principal_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.principal_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.principal_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.principal_id)
	count(ids) > 0
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.principal_id, "reasons": {"SNAPSHOT_OUTSIDE_PERIOD"}} if {
	some rec in evaluated
	not current(rec)
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.principal_id, "reasons": {"MFA_CONFIGURATION_UNKNOWN"}} if {
	some rec in evaluated
	current(rec)
	rec.mfa_enforced == null
}

metrics := {
	"assessment_basis": "CONFIGURATION_SNAPSHOT",
	"privileged_principals": count(evaluated),
	"mfa_enforced_principals": count([1 | some rec in evaluated; determinable(rec); rec.mfa_enforced == true]),
	"accepted_methods": sort(accepted),
	"earliest_snapshot": lib.min_or_null([rec.captured_at | some rec in evaluated]),
	"latest_snapshot": lib.max_or_null([rec.captured_at | some rec in evaluated]),
}

decision := lib.decision(rule_id, rule_version, violations, excepted, undetermined, count(evaluated), 0, metrics)
