# PAM-BREAKGLASS-001 v1.0 - break-glass access without required justification
package securden.rules.pam_breakglass_001.v1_0

import data.securden.lib

rule_id := "PAM-BREAKGLASS-001"

rule_version := "1.0"

review_window_ns := input.params.post_review_within_hours * lib.ns_per_hour

evaluated := [rec | some rec in lib.scoped_records; lib.in_period(rec.activated_at)]

failed("JUSTIFICATION_MISSING", rec) if not rec.justification_provided

failed("JUSTIFICATION_TOO_SHORT", rec) if {
	rec.justification_provided
	rec.justification_length < input.params.min_justification_length
}

failed("TICKET_REFERENCE_MISSING", rec) if {
	input.params.require_ticket_reference
	rec.ticket_reference == null
}

failed("POST_REVIEW_OVERDUE", rec) if {
	input.params.post_review_within_hours > 0
	not rec.post_review_completed
	lib.as_of_ns - lib.ts(rec.activated_at) > review_window_ns
}

failed("POST_REVIEW_LATE", rec) if {
	input.params.post_review_within_hours > 0
	rec.post_review_completed
	lib.ts(rec.post_review_at) - lib.ts(rec.activated_at) > review_window_ns
}

reasons(rec) := {r |
	some r in [
		"JUSTIFICATION_MISSING", "JUSTIFICATION_TOO_SHORT", "TICKET_REFERENCE_MISSING",
		"POST_REVIEW_OVERDUE", "POST_REVIEW_LATE",
	]
	failed(r, rec)
}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.event_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.event_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.event_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.event_id)
	count(ids) > 0
}

metrics := {
	"break_glass_activations": count(evaluated),
	"activations_non_compliant": count(failing),
	"min_justification_length": input.params.min_justification_length,
	"post_review_within_hours": input.params.post_review_within_hours,
}

decision := lib.decision(rule_id, rule_version, violations, excepted, set(), count(evaluated), 0, metrics)
