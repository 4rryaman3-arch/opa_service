# PAM-SESSIDLE-001 v1.0 - privileged session idle timeout configuration
#
# Configuration snapshot of the session policies that apply to privileged
# sessions; not a measurement of individual sessions' idle time.
package securden.rules.pam_sessidle_001.v1_0

import data.securden.lib

rule_id := "PAM-SESSIDLE-001"

rule_version := "1.0"

evaluated := [rec | some rec in lib.scoped_records; rec.applies_to_privileged]

current(rec) if lib.in_period(rec.captured_at)

failed("IDLE_TIMEOUT_DISABLED", rec) if not rec.idle_timeout_enabled

failed("IDLE_TIMEOUT_EXCEEDS_MAXIMUM", rec) if {
	rec.idle_timeout_enabled
	rec.idle_timeout_minutes > input.params.max_idle_minutes
}

reasons(rec) := {r |
	some r in ["IDLE_TIMEOUT_DISABLED", "IDLE_TIMEOUT_EXCEEDS_MAXIMUM"]
	failed(r, rec)
}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; current(rec); r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.policy_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.policy_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.policy_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.policy_id)
	count(ids) > 0
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.policy_id, "reasons": {"SNAPSHOT_OUTSIDE_PERIOD"}} if {
	some rec in evaluated
	not current(rec)
}

# No session policy applying to privileged sessions is missing evidence, not "not applicable".
undetermined contains {"record_id": null, "subject_id": null, "reasons": {"NO_SESSION_POLICY_SUPPLIED"}} if {
	count(evaluated) == 0
}

metrics := {
	"assessment_basis": "CONFIGURATION_SNAPSHOT",
	"session_policies": count(evaluated),
	"max_idle_minutes": input.params.max_idle_minutes,
	"longest_configured_idle_minutes": lib.max_or_null([rec.idle_timeout_minutes |
		some rec in evaluated
		rec.idle_timeout_enabled
	]),
}

decision := lib.decision(rule_id, rule_version, violations, excepted, undetermined, count(evaluated), 0, metrics)
