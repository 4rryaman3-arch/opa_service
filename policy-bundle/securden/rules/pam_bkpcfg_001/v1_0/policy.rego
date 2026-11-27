# PAM-BKPCFG-001 v1.0 - backup schedule, encryption and last result
#
# Configuration snapshot. The age of the last backup is measured at captured_at, the instant the snapshot describes.
package securden.rules.pam_bkpcfg_001.v1_0

import data.securden.lib

rule_id := "PAM-BKPCFG-001"

rule_version := "1.0"

evaluated := [rec | some rec in lib.scoped_records]

current(rec) if lib.in_period(rec.captured_at)

age_ns(rec) := lib.ts(rec.captured_at) - lib.ts(rec.last_backup_at) if rec.last_backup_at != null

failed("BACKUP_NOT_SCHEDULED", rec) if not rec.scheduled

failed("BACKUP_NOT_ENCRYPTED", rec) if not rec.encrypted

failed("LAST_BACKUP_FAILED", rec) if rec.last_backup_status == "FAILED"

failed("LAST_BACKUP_TOO_OLD", rec) if age_ns(rec) > input.params.max_backup_age_hours * lib.ns_per_hour

unknown("LAST_BACKUP_UNKNOWN", rec) if rec.last_backup_at == null

unknown("LAST_BACKUP_UNKNOWN", rec) if rec.last_backup_status == null

unknown("BACKUP_AFTER_SNAPSHOT", rec) if age_ns(rec) < 0

reasons(rec) := {r |
	some r in ["BACKUP_NOT_SCHEDULED", "BACKUP_NOT_ENCRYPTED", "LAST_BACKUP_FAILED", "LAST_BACKUP_TOO_OLD"]
	failed(r, rec)
}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; current(rec); r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.backup_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.backup_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.backup_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.backup_id)
	count(ids) > 0
}

unknown_reasons(rec) := {r |
	some r in ["LAST_BACKUP_UNKNOWN", "BACKUP_AFTER_SNAPSHOT"]
	unknown(r, rec)
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.backup_id, "reasons": r} if {
	some rec in evaluated
	current(rec)
	count(reasons(rec)) == 0
	r := unknown_reasons(rec)
	count(r) > 0
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.backup_id, "reasons": {"SNAPSHOT_OUTSIDE_PERIOD"}} if {
	some rec in evaluated
	not current(rec)
}

# Nothing supplied is missing evidence, not "not applicable".
undetermined contains {"record_id": null, "subject_id": null, "reasons": {"NO_BACKUP_CONFIGURATION_SUPPLIED"}} if {
	count(evaluated) == 0
}

metrics := {
	"assessment_basis": "CONFIGURATION_SNAPSHOT",
	"records_evaluated": count(evaluated),
	"max_backup_age_hours": input.params.max_backup_age_hours,
}

decision := lib.decision(rule_id, rule_version, violations, excepted, undetermined, count(evaluated), 0, metrics)
