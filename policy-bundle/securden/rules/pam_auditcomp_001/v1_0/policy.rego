# PAM-AUDITCOMP-001 v1.0 - audit evidence completeness
package securden.rules.pam_auditcomp_001.v1_0

import data.securden.lib

rule_id := "PAM-AUDITCOMP-001"

rule_version := "1.0"

evaluated := lib.scoped_records

failed("COVERAGE_STARTS_AFTER_PERIOD_START", rec) if lib.ts(rec.coverage_start) > lib.period_start_ns

failed("COVERAGE_ENDS_BEFORE_PERIOD_END", rec) if lib.ts(rec.coverage_end) < lib.as_of_ns

# Integer arithmetic: received/expected < min% <=> received*100 < min%*expected
failed("EVENT_COMPLETENESS_BELOW_MINIMUM", rec) if {
	rec.expected_event_count > 0
	rec.received_event_count * 100 < input.params.min_completeness_percent * rec.expected_event_count
}

failed("GAP_EXCEEDS_MAXIMUM", rec) if rec.max_gap_seconds > input.params.max_allowed_gap_seconds

failed("INTEGRITY_NOT_VERIFIED", rec) if {
	input.params.require_integrity_verification
	not rec.integrity_verified
}

reasons(rec) := {r |
	some r in [
		"COVERAGE_STARTS_AFTER_PERIOD_START", "COVERAGE_ENDS_BEFORE_PERIOD_END",
		"EVENT_COMPLETENESS_BELOW_MINIMUM", "GAP_EXCEEDS_MAXIMUM", "INTEGRITY_NOT_VERIFIED",
	]
	failed(r, rec)
}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.source_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.source_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.source_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.source_id)
	count(ids) > 0
}

# No audit sources at all is missing evidence, not "not applicable".
undetermined contains {"record_id": null, "subject_id": null, "reasons": {"NO_AUDIT_SOURCES_SUPPLIED"}} if {
	count(evaluated) == 0
}

metrics := {
	"sources_evaluated": count(evaluated),
	"min_completeness_percent_observed": lib.min_or_null([floor((rec.received_event_count * 100) / rec.expected_event_count) |
		some rec in evaluated
		rec.expected_event_count > 0
	]),
	"max_gap_seconds_observed": lib.max_or_null([rec.max_gap_seconds | some rec in evaluated]),
	"min_completeness_percent_required": input.params.min_completeness_percent,
	"max_allowed_gap_seconds": input.params.max_allowed_gap_seconds,
}

decision := lib.decision(rule_id, rule_version, violations, excepted, undetermined, count(evaluated), 0, metrics)
