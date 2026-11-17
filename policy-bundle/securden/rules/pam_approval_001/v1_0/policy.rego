# PAM-APPROVAL-001 v1.0 - privileged access without required approval
package securden.rules.pam_approval_001.v1_0

import data.securden.lib

rule_id := "PAM-APPROVAL-001"

rule_version := "1.0"

max_age_ns := input.params.max_approval_age_hours * lib.ns_per_hour

evaluated := [rec |
	some rec in lib.scoped_records
	lib.in_period(rec.accessed_at)
	rec.approval_required
]

approved(rec) if {
	rec.approval_status == "APPROVED"
	rec.approved_at != null
}

failed("NO_APPROVED_REQUEST", rec) if not approved(rec)

failed("APPROVAL_AFTER_ACCESS", rec) if {
	approved(rec)
	lib.ts(rec.approved_at) > lib.ts(rec.accessed_at)
}

failed("APPROVAL_TOO_OLD", rec) if {
	approved(rec)
	lib.ts(rec.accessed_at) - lib.ts(rec.approved_at) > max_age_ns
}

failed("SELF_APPROVAL", rec) if {
	approved(rec)
	rec.approver_id == rec.user_id
}

reasons(rec) := {r |
	some r in ["NO_APPROVED_REQUEST", "APPROVAL_AFTER_ACCESS", "APPROVAL_TOO_OLD", "SELF_APPROVAL"]
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

metrics := {
	"access_events_requiring_approval": count(evaluated),
	"access_events_without_valid_approval": count(failing),
	"maximum_approval_age_hours": input.params.max_approval_age_hours,
}

decision := lib.decision(rule_id, rule_version, violations, excepted, set(), count(evaluated), 0, metrics)
