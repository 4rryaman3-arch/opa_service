# PAM-REVIEW-001 v1.0 - missing privileged access reviews
package securden.rules.pam_review_001.v1_0

import data.securden.lib

rule_id := "PAM-REVIEW-001"

rule_version := "1.0"

interval_ns := input.params.review_interval_days * lib.ns_per_day

evaluated := [rec | some rec in lib.scoped_records; rec.privileged; rec.enabled]

failed("NEVER_REVIEWED", rec) if rec.last_review_completed_at == null

failed("REVIEW_OVERDUE", rec) if {
	rec.last_review_completed_at != null
	lib.as_of_ns - lib.ts(rec.last_review_completed_at) > interval_ns
}

failed("SELF_REVIEW", rec) if {
	rec.reviewer_id != null
	rec.owner_id != null
	rec.reviewer_id == rec.owner_id
}

failed("REVOCATION_NOT_ENFORCED", rec) if rec.last_review_outcome == "REVOKED"

reasons(rec) := {r |
	some r in ["NEVER_REVIEWED", "REVIEW_OVERDUE", "SELF_REVIEW", "REVOCATION_NOT_ENFORCED"]
	failed(r, rec)
}

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

metrics := {
	"privileged_accounts_evaluated": count(evaluated),
	"accounts_never_reviewed": count([1 | some rec in evaluated; rec.last_review_completed_at == null]),
	"max_days_since_review": lib.max_or_null([floor((lib.as_of_ns - lib.ts(rec.last_review_completed_at)) / lib.ns_per_day) |
		some rec in evaluated
		rec.last_review_completed_at != null
	]),
	"review_interval_days": input.params.review_interval_days,
}

decision := lib.decision(rule_id, rule_version, violations, excepted, set(), count(evaluated), 0, metrics)
