# PAM-AUDCFG-001 v1.0 - audit log forwarding configuration
#
# Configuration snapshot: at least one forwarding destination must be enabled, and every enabled destination must
# have delivered. Transport encryption is not judged: the evidence does not carry it.
package securden.rules.pam_audcfg_001.v1_0

import data.securden.lib

rule_id := "PAM-AUDCFG-001"

rule_version := "1.0"

evaluated := [rec | some rec in lib.scoped_records]

current(rec) if lib.in_period(rec.captured_at)

active := [rec | some rec in evaluated; current(rec); rec.enabled]

# A disabled destination matters only when no destination is enabled.
failed("FORWARDING_DISABLED", rec) if {
	not rec.enabled
	count(active) == 0
}

unknown("DELIVERY_NOT_RECORDED", rec) if {
	rec.enabled
	rec.last_delivery_at == null
}

unknown("DELIVERY_AFTER_SNAPSHOT", rec) if {
	rec.enabled
	rec.last_delivery_at != null
	lib.ts(rec.last_delivery_at) > lib.ts(rec.captured_at)
}

reasons(rec) := {r |
	some r in ["FORWARDING_DISABLED"]
	failed(r, rec)
}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; current(rec); r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.destination_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.destination_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.destination_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.destination_id)
	count(ids) > 0
}

unknown_reasons(rec) := {r |
	some r in ["DELIVERY_NOT_RECORDED", "DELIVERY_AFTER_SNAPSHOT"]
	unknown(r, rec)
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.destination_id, "reasons": r} if {
	some rec in evaluated
	current(rec)
	count(reasons(rec)) == 0
	r := unknown_reasons(rec)
	count(r) > 0
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.destination_id, "reasons": {"SNAPSHOT_OUTSIDE_PERIOD"}} if {
	some rec in evaluated
	not current(rec)
}

# Nothing supplied is missing evidence, not "not applicable".
undetermined contains {"record_id": null, "subject_id": null, "reasons": {"NO_FORWARDING_DESTINATION_SUPPLIED"}} if {
	count(evaluated) == 0
}

metrics := {
	"assessment_basis": "CONFIGURATION_SNAPSHOT",
	"records_evaluated": count(evaluated),
	"enabled_destinations": count(active),
}

decision := lib.decision(rule_id, rule_version, violations, excepted, undetermined, count(evaluated), 0, metrics)
