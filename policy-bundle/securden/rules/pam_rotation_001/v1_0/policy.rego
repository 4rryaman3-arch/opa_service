# PAM-ROTATION-001 v1.0 (RETIRED 2026-07-01, kept for historical evaluations)
package securden.rules.pam_rotation_001.v1_0

import data.securden.lib

rule_id := "PAM-ROTATION-001"

rule_version := "1.0"

max_age_ns := input.params.max_rotation_age_days * lib.ns_per_day

evaluated := [rec | some rec in lib.scoped_records; rec.privileged]

failed("NEVER_ROTATED", rec) if rec.last_rotated_at == null

failed("ROTATION_AGE_EXCEEDED", rec) if {
	rec.last_rotated_at != null
	lib.as_of_ns - lib.ts(rec.last_rotated_at) > max_age_ns
}

reasons(rec) := {r | some r in ["NEVER_ROTATED", "ROTATION_AGE_EXCEEDED"]; failed(r, rec)}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.account_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.account_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.account_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.account_id)
	count(ids) > 0
}

ages := [floor((lib.as_of_ns - lib.ts(rec.last_rotated_at)) / lib.ns_per_day) |
	some rec in evaluated
	rec.last_rotated_at != null
]

metrics := {
	"password_age_days": lib.max_or_null(ages),
	"maximum_allowed_days": input.params.max_rotation_age_days,
	"accounts_evaluated": count(evaluated),
	"accounts_never_rotated": count([1 | some rec in evaluated; rec.last_rotated_at == null]),
}

decision := lib.decision(rule_id, rule_version, violations, excepted, set(), count(evaluated), 0, metrics)
