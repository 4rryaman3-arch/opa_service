# PAM-AUDEVENT-001 v1.0 - audit event record content
#
# Events in the period must record what happened and its result. Actor and target are not required: system events
# and logons legitimately leave them empty. Gaps in the trail are PAM-AUDITCOMP-001's subject, not this rule's.
package securden.rules.pam_audevent_001.v1_0

import data.securden.lib

rule_id := "PAM-AUDEVENT-001"

rule_version := "1.0"

evaluated := [rec | some rec in lib.scoped_records; lib.in_period(rec.occurred_at)]

current(rec) if lib.in_period(rec.occurred_at)

failed("EVENT_TYPE_MISSING", rec) if rec.event_type == null

failed("OUTCOME_MISSING", rec) if rec.outcome == null

# every field this rule uses is mandatory in the evidence schema
unknown(r, _) if r == "never"

reasons(rec) := {r |
	some r in ["EVENT_TYPE_MISSING", "OUTCOME_MISSING"]
	failed(r, rec)
}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; current(rec); r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.event_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.event_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.event_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.event_id)
	count(ids) > 0
}

unknown_reasons(rec) := {r |
	some r in ["NOTHING_UNKNOWN"]
	unknown(r, rec)
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.event_id, "reasons": r} if {
	some rec in evaluated
	current(rec)
	count(reasons(rec)) == 0
	r := unknown_reasons(rec)
	count(r) > 0
}

# Nothing supplied is missing evidence, not "not applicable".
undetermined contains {"record_id": null, "subject_id": null, "reasons": {"NO_AUDIT_EVENTS_SUPPLIED"}} if {
	count(evaluated) == 0
}

metrics := {
	"assessment_basis": "EVENT_HISTORY",
	"records_evaluated": count(evaluated),
}

decision := lib.decision(rule_id, rule_version, violations, excepted, undetermined, count(evaluated), 0, metrics)
