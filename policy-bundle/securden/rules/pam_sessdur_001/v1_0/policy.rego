# PAM-SESSDUR-001 v1.0 - privileged sessions exceeding the maximum duration
#
# Event history: sessions that started in the reporting period. A session still
# open at the period end (ended_at null) is measured up to the period end.
package securden.rules.pam_sessdur_001.v1_0

import data.securden.lib

rule_id := "PAM-SESSDUR-001"

rule_version := "1.0"

limit_ns := input.params.max_session_minutes * lib.ns_per_minute

evaluated := [rec | some rec in lib.scoped_records; lib.in_period(rec.started_at)]

end_ns(rec) := lib.ts(rec.ended_at) if {
	rec.ended_at != null
} else := lib.as_of_ns

duration_ns(rec) := end_ns(rec) - lib.ts(rec.started_at)

failed("SESSION_DURATION_EXCEEDED", rec) if {
	rec.ended_at != null
	duration_ns(rec) > limit_ns
}

failed("OPEN_SESSION_EXCEEDS_MAXIMUM", rec) if {
	rec.ended_at == null
	duration_ns(rec) > limit_ns
}

reasons(rec) := {r |
	some r in ["SESSION_DURATION_EXCEEDED", "OPEN_SESSION_EXCEEDS_MAXIMUM"]
	failed(r, rec)
}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.session_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.session_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.session_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.session_id)
	count(ids) > 0
}

metrics := {
	"assessment_basis": "EVENT_HISTORY",
	"sessions_evaluated": count(evaluated),
	"max_session_minutes": input.params.max_session_minutes,
	"longest_session_minutes": lib.max_or_null([floor(duration_ns(rec) / lib.ns_per_minute) | some rec in evaluated]),
	"sessions_out_of_period": count([1 | some rec in lib.scoped_records; not lib.in_period(rec.started_at)]),
}

decision := lib.decision(rule_id, rule_version, violations, excepted, set(), count(evaluated), 0, metrics)
