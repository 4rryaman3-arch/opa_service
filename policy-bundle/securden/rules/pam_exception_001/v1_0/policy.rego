# PAM-EXCEPTION-001 v1.0 - expired policy exceptions
package securden.rules.pam_exception_001.v1_0

import data.securden.lib

rule_id := "PAM-EXCEPTION-001"

rule_version := "1.0"

max_duration_ns := input.params.max_exception_duration_days * lib.ns_per_day

evaluated := [rec | some rec in lib.scoped_records; lib.ts(rec.approved_at) <= lib.as_of_ns]

failed("ACTIVE_AFTER_EXPIRY", rec) if {
	rec.status == "ACTIVE"
	lib.ts(rec.expires_at) <= lib.as_of_ns
}

failed("USED_AFTER_EXPIRY", rec) if {
	rec.last_used_at != null
	lib.ts(rec.last_used_at) >= lib.ts(rec.expires_at)
}

failed("DURATION_EXCEEDS_MAXIMUM", rec) if {
	lib.ts(rec.expires_at) - lib.ts(rec.approved_at) > max_duration_ns
}

reasons(rec) := {r |
	some r in ["ACTIVE_AFTER_EXPIRY", "USED_AFTER_EXPIRY", "DURATION_EXCEEDS_MAXIMUM"]
	failed(r, rec)
}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.exception_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.exception_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.exception_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.exception_id)
	count(ids) > 0
}

metrics := {
	"exceptions_evaluated": count(evaluated),
	"exceptions_active_after_expiry": count([1 | some rec in evaluated; failed("ACTIVE_AFTER_EXPIRY", rec)]),
	"exceptions_used_after_expiry": count([1 | some rec in evaluated; failed("USED_AFTER_EXPIRY", rec)]),
	"max_exception_duration_days": input.params.max_exception_duration_days,
}

decision := lib.decision(rule_id, rule_version, violations, excepted, set(), count(evaluated), 0, metrics)
