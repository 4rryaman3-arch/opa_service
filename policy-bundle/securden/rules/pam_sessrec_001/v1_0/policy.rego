# PAM-SESSREC-001 v1.0 - privileged sessions missing required recordings
package securden.rules.pam_sessrec_001.v1_0

import data.securden.lib

rule_id := "PAM-SESSREC-001"

rule_version := "1.0"

evaluated := [rec |
	some rec in lib.scoped_records
	lib.in_period(rec.started_at)
	rec.recording_required
]

failed("RECORDING_MISSING", rec) if rec.recording_status == "MISSING"

failed("RECORDING_FAILED", rec) if rec.recording_status == "FAILED"

failed("RECORDING_PARTIAL", rec) if {
	rec.recording_status == "PARTIAL"
	not input.params.accept_partial_recordings
}

reasons(rec) := {r |
	some r in ["RECORDING_MISSING", "RECORDING_FAILED", "RECORDING_PARTIAL"]
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

# Recording still being processed: compliance cannot be determined yet.
undetermined contains {"record_id": rec.record_id, "subject_id": rec.session_id, "reasons": {"RECORDING_PROCESSING"}} if {
	some rec in evaluated
	rec.recording_status == "PROCESSING"
}

metrics := {
	"sessions_requiring_recording": count(evaluated),
	"sessions_without_compliant_recording": count(failing),
	"sessions_out_of_period": count([1 | some rec in lib.scoped_records; not lib.in_period(rec.started_at)]),
}

decision := lib.decision(rule_id, rule_version, violations, excepted, undetermined, count(evaluated), 0, metrics)
