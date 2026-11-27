# PAM-ENDELEV-001 v1.0 - endpoint privilege elevation approval
#
# Events: approved elevations requested in the period. A manual approval must come from someone other than the
# requester; an automatic approval must name the application it allowed. Pending and denied requests granted
# nothing. Justification is not judged: the evidence does not carry it.
package securden.rules.pam_endelev_001.v1_0

import data.securden.lib

rule_id := "PAM-ENDELEV-001"

rule_version := "1.0"

evaluated := [rec | some rec in lib.scoped_records; rec.approval_status in {"APPROVED", "AUTO_APPROVED"}; lib.in_period(rec.requested_at)]

current(rec) if lib.in_period(rec.requested_at)

failed("SELF_APPROVED", rec) if {
	rec.approval_status == "APPROVED"
	rec.approver_id != null
	rec.approver_id == rec.user_id
}

unknown("APPROVER_UNKNOWN", rec) if {
	rec.approval_status == "APPROVED"
	rec.approver_id == null
}

unknown("APPLICATION_UNKNOWN", rec) if {
	rec.approval_status == "AUTO_APPROVED"
	rec.application_id == null
}

reasons(rec) := {r |
	some r in ["SELF_APPROVED"]
	failed(r, rec)
}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; current(rec); r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.elevation_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.elevation_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.elevation_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.elevation_id)
	count(ids) > 0
}

unknown_reasons(rec) := {r |
	some r in ["APPROVER_UNKNOWN", "APPLICATION_UNKNOWN"]
	unknown(r, rec)
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.elevation_id, "reasons": r} if {
	some rec in evaluated
	current(rec)
	count(reasons(rec)) == 0
	r := unknown_reasons(rec)
	count(r) > 0
}

metrics := {
	"assessment_basis": "EVENT_HISTORY",
	"records_evaluated": count(evaluated),
	"auto_approved": count([1 | some rec in evaluated; rec.approval_status == "AUTO_APPROVED"]),
}

decision := lib.decision(rule_id, rule_version, violations, excepted, undetermined, count(evaluated), 0, metrics)
