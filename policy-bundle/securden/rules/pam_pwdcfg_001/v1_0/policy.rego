# PAM-PWDCFG-001 v1.0 - password policy configuration
#
# Configuration snapshot of the password policies that apply to privileged accounts.
# Rotation and history are not judged: the catalog defines no threshold for them.
package securden.rules.pam_pwdcfg_001.v1_0

import data.securden.lib

rule_id := "PAM-PWDCFG-001"

rule_version := "1.0"

evaluated := [rec | some rec in lib.scoped_records; rec.applies_to_privileged]

current(rec) if lib.in_period(rec.captured_at)

failed("MIN_LENGTH_BELOW_REQUIRED", rec) if rec.min_length < input.params.min_length

failed("COMPLEXITY_NOT_REQUIRED", rec) if {
	input.params.require_complexity
	not rec.complexity_required
}

# every field this rule uses is mandatory in the evidence schema
unknown(r, _) if r == "never"

reasons(rec) := {r |
	some r in ["MIN_LENGTH_BELOW_REQUIRED", "COMPLEXITY_NOT_REQUIRED"]
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

unknown_reasons(rec) := {r |
	some r in ["NOTHING_UNKNOWN"]
	unknown(r, rec)
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.policy_id, "reasons": r} if {
	some rec in evaluated
	current(rec)
	count(reasons(rec)) == 0
	r := unknown_reasons(rec)
	count(r) > 0
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.policy_id, "reasons": {"SNAPSHOT_OUTSIDE_PERIOD"}} if {
	some rec in evaluated
	not current(rec)
}

# Nothing supplied is missing evidence, not "not applicable".
undetermined contains {"record_id": null, "subject_id": null, "reasons": {"NO_PRIVILEGED_PASSWORD_POLICY_SUPPLIED"}} if {
	count(evaluated) == 0
}

metrics := {
	"assessment_basis": "CONFIGURATION_SNAPSHOT",
	"records_evaluated": count(evaluated),
	"required_min_length": input.params.min_length,
	"shortest_configured_min_length": lib.min_or_null([rec.min_length | some rec in evaluated]),
}

decision := lib.decision(rule_id, rule_version, violations, excepted, undetermined, count(evaluated), 0, metrics)
