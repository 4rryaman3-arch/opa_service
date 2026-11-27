# PAM-LOCADM-001 v1.0 - local administrator membership
#
# Configuration snapshot: every discovered local administrator must be an approved member.
package securden.rules.pam_locadm_001.v1_0

import data.securden.lib

rule_id := "PAM-LOCADM-001"

rule_version := "1.0"

evaluated := [rec | some rec in lib.scoped_records]

current(rec) if lib.in_period(rec.captured_at)

failed("UNAPPROVED_LOCAL_ADMINISTRATOR", rec) if not rec.approved_member

# every field this rule uses is mandatory in the evidence schema
unknown(r, _) if r == "never"

reasons(rec) := {r |
	some r in ["UNAPPROVED_LOCAL_ADMINISTRATOR"]
	failed(r, rec)
}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; current(rec); r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.record_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.record_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.record_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.record_id)
	count(ids) > 0
}

unknown_reasons(rec) := {r |
	some r in ["NOTHING_UNKNOWN"]
	unknown(r, rec)
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.record_id, "reasons": r} if {
	some rec in evaluated
	current(rec)
	count(reasons(rec)) == 0
	r := unknown_reasons(rec)
	count(r) > 0
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.record_id, "reasons": {"SNAPSHOT_OUTSIDE_PERIOD"}} if {
	some rec in evaluated
	not current(rec)
}

# Nothing supplied is missing evidence, not "not applicable".
undetermined contains {"record_id": null, "subject_id": null, "reasons": {"NO_LOCAL_ADMIN_MEMBERSHIP_SUPPLIED"}} if {
	count(evaluated) == 0
}

metrics := {
	"assessment_basis": "CONFIGURATION_SNAPSHOT",
	"records_evaluated": count(evaluated),
	"devices": count({rec.device_id | some rec in evaluated}),
}

decision := lib.decision(rule_id, rule_version, violations, excepted, undetermined, count(evaluated), 0, metrics)
