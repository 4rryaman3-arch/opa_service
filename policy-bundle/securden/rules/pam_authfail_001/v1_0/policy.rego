# PAM-AUTHFAIL-001 v1.0 - excessive failed authentication attempts
# Evidence is pre-aggregated per principal per window to avoid shipping raw logs.
package securden.rules.pam_authfail_001.v1_0

import data.securden.lib

rule_id := "PAM-AUTHFAIL-001"

rule_version := "1.0"

window_ns := input.params.window_minutes * lib.ns_per_minute

in_period_records := [rec | some rec in lib.scoped_records; lib.in_period(rec.window_start)]

valid_window(rec) if lib.ts(rec.window_end) - lib.ts(rec.window_start) <= window_ns

evaluated := [rec | some rec in in_period_records; valid_window(rec)]

mitigated(rec) if {
	input.params.lockout_is_mitigation
	rec.lockout_triggered
}

failed("FAILED_ATTEMPTS_EXCEEDED", rec) if {
	rec.failed_attempts > input.params.max_failed_attempts
	not mitigated(rec)
}

reasons(rec) := {r | some r in ["FAILED_ATTEMPTS_EXCEEDED"]; failed(r, rec)}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.principal_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.principal_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.principal_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.principal_id)
	count(ids) > 0
}

# A window longer than configured cannot be compared fairly with the threshold.
undetermined contains {"record_id": rec.record_id, "subject_id": rec.principal_id, "reasons": {"WINDOW_LONGER_THAN_CONFIGURED"}} if {
	some rec in in_period_records
	not valid_window(rec)
}

metrics := {
	"max_failed_attempts_observed": lib.max_or_null([rec.failed_attempts | some rec in evaluated]),
	"max_failed_attempts_allowed": input.params.max_failed_attempts,
	"window_minutes": input.params.window_minutes,
	"principal_windows_evaluated": count(evaluated),
	"principals_exceeding": count({rec.principal_id | some [rec, _] in failing}),
}

decision := lib.decision(rule_id, rule_version, violations, excepted, undetermined, count(in_period_records), 0, metrics)
