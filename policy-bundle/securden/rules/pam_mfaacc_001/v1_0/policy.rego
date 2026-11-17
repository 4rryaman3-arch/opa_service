# PAM-MFAACC-001 v1.0 - privileged access granted without accepted MFA
#
# Event history: one record per privileged access in the reporting period.
package securden.rules.pam_mfaacc_001.v1_0

import data.securden.lib

rule_id := "PAM-MFAACC-001"

rule_version := "1.0"

accepted := {m | some m in input.params.accepted_methods}

evaluated := [rec |
	some rec in lib.scoped_records
	lib.in_period(rec.accessed_at)
	rec.access_granted
]

failed("MFA_NOT_PERFORMED", rec) if rec.mfa_status == "NOT_PERFORMED"

failed("ACCESS_GRANTED_AFTER_FAILED_MFA", rec) if rec.mfa_status == "FAILED"

failed("MFA_METHOD_NOT_ACCEPTED", rec) if {
	rec.mfa_status == "VERIFIED"
	not rec.mfa_method in accepted
}

reasons(rec) := {r |
	some r in ["MFA_NOT_PERFORMED", "ACCESS_GRANTED_AFTER_FAILED_MFA", "MFA_METHOD_NOT_ACCEPTED"]
	failed(r, rec)
}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.access_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.access_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.access_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.access_id)
	count(ids) > 0
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.access_id, "reasons": {"MFA_STATUS_UNKNOWN"}} if {
	some rec in evaluated
	rec.mfa_status == "UNKNOWN"
}

metrics := {
	"assessment_basis": "EVENT_HISTORY",
	"granted_accesses": count(evaluated),
	"accesses_without_accepted_mfa": count(failing),
	"accepted_methods": sort(accepted),
	"accesses_out_of_period": count([1 | some rec in lib.scoped_records; not lib.in_period(rec.accessed_at)]),
}

decision := lib.decision(rule_id, rule_version, violations, excepted, undetermined, count(evaluated), 0, metrics)
